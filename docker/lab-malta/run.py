#!/usr/bin/env python3
"""Boot a fixed signed Malta image and run supplied ABI tests; no package changes."""
import hashlib
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import threading
import time
import uuid

IMAGES = {
    'be64': ('qemu-system-mips64', '2ad942f521fa5faf97377ad9f1830c584bfe069fd1d270a187885b674ad95ce5'),
    'le64': ('qemu-system-mips64el', '2e3560c8a9fbac2d5f0d89f62b9a206159baa7332e8f37786e6a1759bc9e656a'),
}


def command(args, data=None, timeout=30):
    result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'))
    return result.stdout


class Serial:
    def __init__(self, process, destination):
        self.process = process
        self.buffer = b''
        self.condition = threading.Condition()
        self.log = destination.open('wb')
        self.thread = threading.Thread(target=self.pump, daemon=True)
        self.thread.start()

    def pump(self):
        while True:
            data = os.read(self.process.stdout.fileno(), 4096)
            if not data:
                return
            self.log.write(data)
            self.log.flush()
            with self.condition:
                self.buffer = (self.buffer + data)[-(1 << 20):]
                self.condition.notify_all()

    def wait(self, pattern, timeout=90):
        deadline = time.monotonic() + timeout
        with self.condition:
            while time.monotonic() < deadline:
                found = re.search(pattern, self.buffer)
                if found:
                    return self.buffer
                if self.process.poll() is not None:
                    raise RuntimeError('QEMU exited before serial readiness')
                self.condition.wait(min(1, deadline - time.monotonic()))
        raise RuntimeError('Serial deadline expired: ' + self.buffer[-2000:].decode(errors='replace'))

    def execute(self, script):
        marker = 'OPENRHP_' + uuid.uuid4().hex
        self.process.stdin.write((script + '\necho ' + marker + '\n').encode())
        self.process.stdin.flush()
        return self.wait(rb'\n' + marker.encode() + rb'\r?\n')

    def close(self):
        self.thread.join(timeout=5)
        self.log.close()


def main():
    os.umask(0o077)
    profile = sys.argv[1]
    if profile not in IMAGES:
        raise RuntimeError('Only fixed be64/le64 profiles are supported')
    emulator, expected = IMAGES[profile]
    image = pathlib.Path('/inputs') / profile / ('openwrt-24.10.7-malta-' + profile + '-vmlinux-initramfs.elf')
    if hashlib.sha256(image.read_bytes()).hexdigest() != expected:
        raise RuntimeError('Pinned OpenWrt image hash mismatch')
    state = pathlib.Path('/state') / profile
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    (state / 'results.json').unlink(missing_ok=True)
    key = state / 'client-key'
    if not key.exists():
        command(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)])
    public = key.with_suffix('.pub').read_text().strip()
    known = state / 'known_hosts'
    args = [emulator, '-M', 'malta', '-cpu', 'MIPS64R2-generic', '-m', '512', '-accel', 'tcg,thread=single',
            '-kernel', str(image), '-append', 'console=ttyS0,115200', '-display', 'none', '-vga', 'none',
            '-serial', 'stdio', '-monitor', 'none', '-no-reboot', '-nic', 'none',
            '-netdev', 'user,id=lab,restrict=on,hostfwd=tcp:127.0.0.1:10022-:22',
            '-device', 'pcnet,netdev=lab,romfile=']
    process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    serial = Serial(process, state / 'serial.log')
    results = []
    try:
        serial.wait(rb'Please press Enter to activate this console')
        process.stdin.write(b'\n')
        process.stdin.flush()
        serial.wait(rb'root@[^\r\n]+[#] ')
        # An ephemeral client key and address live only in this initramfs guest.
        script = "mkdir -p /etc/dropbear; chmod 0700 /etc/dropbear\n" + \
            "printf '%s\\n' " + shlex.quote(public) + " > /etc/dropbear/authorized_keys\n" + \
            "chmod 0600 /etc/dropbear/authorized_keys\n" + \
            "while ! ip link show br-lan >/dev/null 2>&1; do sleep 1; done\n" + \
            "ip addr add 10.0.2.15/24 dev br-lan; ip link set br-lan up\n" + \
            "/etc/init.d/dropbear restart\n" + \
            "while [ ! -s /etc/dropbear/dropbear_ed25519_host_key ]; do sleep 1; done\n" + \
            "dropbearkey -y -f /etc/dropbear/dropbear_ed25519_host_key\n"
        response = serial.execute(script)
        host = re.findall(rb'\n(ssh-ed25519 [A-Za-z0-9+/=]+)(?: |\r?\n)', response)
        if not host:
            raise RuntimeError('No trusted serial host key was obtained')
        known.write_text('[127.0.0.1]:10022 ' + host[-1].decode() + '\n')
        common = ['-i', str(key), '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                  '-o', 'UserKnownHostsFile=' + str(known), '-o', 'ConnectTimeout=5', '-o', 'LogLevel=ERROR']
        ssh = ['ssh', *common, '-p', '10022', 'root@127.0.0.1', 'sh', '-s']
        deadline = time.monotonic() + 45
        while True:
            try:
                environment = command(ssh, b'uname -a\ncat /etc/openwrt_release\ncat /proc/1/comm\n', timeout=10)
                break
            except (RuntimeError, subprocess.TimeoutExpired):
                if time.monotonic() > deadline:
                    raise
                time.sleep(1)
        if ('malta/' + profile).encode() not in environment or b'procd' not in environment:
            raise RuntimeError('Unexpected OpenWrt guest environment')
        (state / 'environment.txt').write_bytes(environment + command([emulator, '--version']))
        counter_script = b'mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true\nif [ -r /sys/kernel/debug/mips/unaligned_instructions ]; then cat /sys/kernel/debug/mips/unaligned_instructions; else echo unavailable; fi\n'
        (state / 'alignment-before.txt').write_bytes(command(ssh, counter_script))
        print('BOOTED ' + profile + ' actual OpenWrt kernel and procd', flush=True)
        for suite in ['stdlib', 'selection', 'config', 'release']:
            binary = pathlib.Path('/tests') / profile / (suite + '.test')
            remote = '/tmp/openrhp-abi-' + suite
            command(['scp', '-O', *common, '-P', '10022', str(binary), 'root@127.0.0.1:' + remote], timeout=60)
            arguments = '' if suite == 'stdlib' else ' -test.timeout 120s -test.v'
            try:
                result = subprocess.run(ssh, input=('chmod 0755 ' + remote + '\n' + remote + arguments + '\n').encode(), capture_output=True, timeout=40 if suite == 'stdlib' else 145)
            except subprocess.TimeoutExpired as error:
                (state / (suite + '.log')).write_bytes((error.stdout or b'') + (error.stderr or b'') + b'\nGuest execution deadline expired.\n')
                results.append({'suite': suite, 'result': 'TIMEOUT', 'exit_code': None,
                                'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()})
                raise
            (state / (suite + '.log')).write_bytes(result.stdout + result.stderr)
            outcome = 'PASS' if result.returncode == 0 else 'FAIL'
            results.append({'suite': suite, 'result': outcome, 'exit_code': result.returncode,
                            'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()})
            print(profile + ' ' + suite + ' ' + outcome, flush=True)
            command(ssh, ('rm -f ' + remote + '\n').encode())
        (state / 'alignment-after.txt').write_bytes(command(ssh, counter_script))
    finally:
        (state / 'results.json').write_text(json.dumps({'profile': profile, 'image_sha256': expected,
            'cpu': 'MIPS64R2-generic', 'kind': 'actual-OpenWrt-guest-kernel', 'results': results,
            'limits': 'TCG initramfs VM; no physical device, persistent storage, package lifecycle or radio acceptance'}, indent=2) + '\n')
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        serial.close()
    return 0 if len(results) == 4 and all(row['result'] == 'PASS' for row in results) else 1


if __name__ == '__main__':
    sys.exit(main())
