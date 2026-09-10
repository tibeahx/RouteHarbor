#!/usr/bin/env python3
"""Run MIPS64 ABI suites on separately booted signed OpenWrt Malta guests.

Usage: GO=/absolute/go python3 scripts/lab-openwrt-mips64.py /absolute/verified-inputs /absolute/private-state [be64|le64]
Download nothing; kernels/checksum manifests must already be present per the lab README.
"""
import hashlib
import os
import re
import pathlib
import subprocess
import sys
import uuid

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUTPUT = ROOT / 'test-results' / 'openwrt-mips64'


def run(args, timeout=180, include_stderr=False):
    result = subprocess.run(args, cwd=ROOT, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'))
    return result.stdout + (result.stderr if include_stderr else b'')


def main():
    if len(sys.argv) not in (3, 4):
        raise RuntimeError(__doc__)
    inputs, state = [pathlib.Path(value) for value in sys.argv[1:3]]
    for directory in [inputs, state]:
        if not directory.is_absolute() or not directory.is_dir() or directory.is_symlink():
            raise RuntimeError('Use existing absolute real input/state directories')
    if state.stat().st_mode & 0o077:
        raise RuntimeError('The lab state directory must be private (0700)')
    profiles = [sys.argv[3]] if len(sys.argv) == 4 else ['be64', 'le64']
    if any(profile not in ['be64', 'le64'] for profile in profiles):
        raise RuntimeError('Only be64/le64 are supported')
    go = os.environ.get('GO', 'go')
    os.environ['GOTOOLCHAIN'] = 'local'
    version = run([go, 'version'])
    if b'go1.27.1 ' not in version:
        raise RuntimeError('This evidence uses the pinned Go 1.27.1 toolchain')
    OUTPUT.mkdir(parents=True, exist_ok=True)
    OUTPUT.chmod(0o755)
    (OUTPUT / 'source-environment.txt').write_bytes(version + run(['git', 'rev-parse', 'HEAD']) + run(['git', 'status', '--short']))
    (OUTPUT / 'host-tools.txt').write_bytes(run(['docker', 'image', 'inspect', 'routeharbor-malta-lab:24.10.7', '--format', '{{.Id}} {{.Architecture}}']) + run(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL', 'routeharbor-malta-lab:24.10.7', 'sh', '-c', 'uname -sm; dpkg-query -W qemu-system-mips']))
    failures = []
    for profile in profiles:
        out = OUTPUT / profile
        out.mkdir(exist_ok=True)
        out.chmod(0o755)
        signature = run(['docker', 'run', '--rm', '--platform', 'linux/amd64', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                        '--mount', 'type=bind,source=' + str(inputs) + ',target=/inputs,readonly',
                        '--entrypoint', '/usr/bin/usign', 'routeharbor-openwrt-deps:24.10.7', '-V', '-P', '/etc/opkg/keys',
                        '-m', '/inputs/' + profile + '/sha256sums', '-x', '/inputs/' + profile + '/sha256sums.sig'], include_stderr=True)
        (out / 'signature-verification.log').write_bytes(signature)
        kernel = inputs / profile / ('openwrt-24.10.7-malta-' + profile + '-vmlinux-initramfs.elf')
        digest = hashlib.sha256(kernel.read_bytes()).hexdigest()
        checksums = (inputs / profile / 'sha256sums').read_text().splitlines()
        if not any(line.split() in ([digest, kernel.name], [digest, '*' + kernel.name]) for line in checksums):
            raise RuntimeError('Kernel does not match the authenticated checksum manifest')
        os.environ.update(CGO_ENABLED='0', GOOS='linux', GOARCH='mips64' if profile == 'be64' else 'mips64le', GOMIPS64='softfloat')
        for suite, package in [('stdlib', './scripts/testdata/abi-netpoll'), ('selection', './internal/selection'),
                               ('config', './internal/config'), ('release', './cmd/routeharbor-release')]:
            binary = out / (suite + '.test')
            build = [go, 'build'] if suite == 'stdlib' else [go, 'test', '-c']
            run([*build, '-o', str(binary), package])
            binary.chmod(0o755)
        name = 'routeharbor-malta-' + profile + '-lab'
        cidfile = state / ('.container-' + uuid.uuid4().hex)
        args = ['docker', 'run', '--rm', '--cidfile', str(cidfile), '--name', name, '--label', 'org.routeharbor.lab=malta-abi',
                '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m',
                '--mount', 'type=bind,source=' + str(inputs) + ',target=/inputs,readonly',
                '--mount', 'type=bind,source=' + str(state) + ',target=/state',
                '--mount', 'type=bind,source=' + str(OUTPUT) + ',target=/tests,readonly',
                '--mount', 'type=bind,source=' + str(ROOT / 'docker/lab-malta') + ',target=/lab,readonly',
                'routeharbor-malta-lab:24.10.7', 'python3', '/lab/run.py', profile]
        try:
            result = subprocess.run(args, cwd=ROOT, timeout=900)
        except subprocess.TimeoutExpired:
            if cidfile.exists():
                container_id = cidfile.read_text().strip()
                if re.fullmatch('[0-9a-f]{64}', container_id):
                    # Stop only the exact container created by this invocation.
                    run(['docker', 'stop', '--time', '5', container_id], timeout=20)
            raise
        finally:
            cidfile.unlink(missing_ok=True)
        for filename in ['environment.txt', 'results.json', 'stdlib.log', 'selection.log', 'config.log', 'release.log', 'alignment-before.txt', 'alignment-after.txt']:
            source = state / profile / filename
            if source.exists():
                (out / filename).write_bytes(source.read_bytes())
        if result.returncode:
            failures.append(profile)
    if failures:
        raise RuntimeError('Full-system execution failed: ' + ', '.join(failures))


if __name__ == '__main__':
    main()
