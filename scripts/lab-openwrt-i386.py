#!/usr/bin/env python3
"""Execute i386 suites on the separately booted, signed OpenWrt x86/generic VM.

Start it with OPENRHP_VM_PROFILE=x86-generic scripts/lab-openwrt-vm.sh first.
This never installs packages, changes networking, or touches the x86_64 lab.
"""
import hashlib
import json
import os
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUTPUT = ROOT / 'test-results' / 'openwrt-i386'
CONTAINER = 'openrhp-openwrt-i386-lab'
CONTROL = '/lab/vmctl-i386.py'
IMAGE_SHA256 = '394014a15bfb1efd0cd47242897d72493f6a2b3be81b7099a340490384457b82'


def run(args, data=None, timeout=120):
    result = subprocess.run(args, input=data, capture_output=True, timeout=timeout, cwd=ROOT)
    if result.returncode:
        raise RuntimeError(result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'))
    return result.stdout


def guest(script, timeout=120):
    return run(['docker', 'exec', '-i', CONTAINER, 'python3', CONTROL, 'exec'], script.encode(), timeout)


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    inspect = json.loads(run(['docker', 'inspect', CONTAINER]))[0]
    if (inspect['HostConfig']['NetworkMode'] != 'none' or
            inspect['Config']['Labels'].get('org.openrhp.lab') != 'full-boot'):
        raise RuntimeError('Refusing a container outside the isolated full-boot lab')
    info = json.loads(run(['docker', 'exec', CONTAINER, 'python3', CONTROL, 'info']))
    if info['image_sha256'] != IMAGE_SHA256:
        raise RuntimeError('Unexpected 32-bit OpenWrt image')
    environment = guest('uname -a\ncat /etc/openwrt_release\ncat /proc/1/comm\n')
    if b'i686' not in environment or b"DISTRIB_TARGET='x86/generic'" not in environment:
        raise RuntimeError('This check requires the actual 32-bit OpenWrt guest kernel')
    go = os.environ.get('GO', 'go')
    os.environ['GOTOOLCHAIN'] = 'local'
    version = run([go, 'version'])
    if b'go1.27.1 ' not in version:
        raise RuntimeError('Use the pinned Go 1.27.1 toolchain for this evidence')
    (OUTPUT / 'environment.txt').write_bytes(environment + version +
        run(['git', 'rev-parse', 'HEAD']) + run(['git', 'status', '--short']) +
        run(['docker', 'exec', CONTAINER, 'qemu-system-x86_64', '--version']))
    os.environ.update(CGO_ENABLED='0', GOOS='linux', GOARCH='386')
    results = []
    for name, package in [('stdlib', './scripts/testdata/abi-netpoll'),
                          ('selection', './internal/selection'), ('config', './internal/config'),
                          ('release', './cmd/openrhp-release')]:
        binary = OUTPUT / (name + '.test')
        args = [go, 'build'] if name == 'stdlib' else [go, 'test', '-c']
        run([*args, '-o', str(binary), package], timeout=180)
        binary.chmod(0o755)
        remote = '/tmp/openrhp-i386-' + name
        run(['docker', 'cp', str(binary), CONTAINER + ':' + remote])
        run(['docker', 'exec', CONTAINER, 'python3', CONTROL, 'put', remote, remote])
        arguments = '' if name == 'stdlib' else ' -test.timeout 90s -test.v'
        try:
            output = guest('chmod 0755 ' + remote + '\n' + remote + arguments + '\n',
                           timeout=40 if name == 'stdlib' else 110)
            (OUTPUT / (name + '.log')).write_bytes(output)
            results.append({'suite': name, 'result': 'PASS',
                            'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()})
            print('PASS actual OpenWrt i386 kernel: ' + name, flush=True)
        finally:
            guest('rm -f ' + remote + '\n')
    (OUTPUT / 'results.json').write_text(json.dumps({
        'image_sha256': IMAGE_SHA256, 'kind': 'actual-OpenWrt-guest-kernel', 'results': results,
        'limits': 'QEMU TCG virtual machine; no physical device, package installation or radio acceptance',
    }, indent=2) + '\n')


if __name__ == '__main__':
    main()
