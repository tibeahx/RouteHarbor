#!/usr/bin/env python3
"""Full-boot OpenWrt VM transport; only runs inside the private Docker lab.

No host networking, published ports, physical NICs or disk devices are used.
The supplied official image is immutable; writes go to a private qcow2 overlay.
"""
import fcntl
import hashlib
import json
import os
import pathlib
import re
import secrets
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
import zlib

STATE = pathlib.Path('/state')
SOCKETS = pathlib.Path('/run/openrhp-vm')
IMAGE = pathlib.Path('/inputs/openwrt.img.gz')
SHA256 = '3caea69f186b2bce80938d265e5e2a3dfd0f8713aed101df35d60b88d7270d1f'
GUEST = '10.44.0.1'
QEMU_CPU = 'qemu64'
CONTAINER = 'openrhp-openwrt-boot-lab'
WAN_PREFIX = '198.18.0'


def run(args, data=None, check=True, timeout=30):
    result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f'{args[0]} failed ({result.returncode}): {result.stderr.decode(errors="replace")}')
    return result


def require_lab():
    if not pathlib.Path('/.dockerenv').exists() or os.geteuid() != 0:
        raise RuntimeError('This harness requires container root in the isolated Docker lab')
    if not STATE.is_dir() or STATE.is_symlink() or STATE.stat().st_mode & 0o077:
        raise RuntimeError('Mount a private real state directory at /state (0700)')
    links = json.loads(run(['ip', '-d', '-j', 'link', 'show']).stdout)
    kernel_defaults = {'tunl0': 'ipip', 'gre0': 'gre', 'gretap0': 'gretap',
                       'erspan0': 'erspan', 'ip_vti0': 'vti', 'ip6_vti0': 'vti6',
                       'sit0': 'sit', 'ip6tnl0': 'ip6tnl', 'ip6gre0': 'ip6gre'}
    for link in links:
        name = link['ifname']
        if name == 'lo' or name.startswith(('vm-', 'tap-')):
            continue
        # Loaded Docker-kernel tunnel modules create inert wildcard devices in
        # every new namespace. Accept only their exact down/unconfigured shape.
        details = link.get('linkinfo', {})
        if (kernel_defaults.get(name) == details.get('info_kind') and
                link.get('operstate') == 'DOWN' and 'UP' not in link.get('flags', []) and
                details.get('info_data', {}).get('remote') == 'any'):
            continue
        raise RuntimeError(f'Refusing non-lab interface {name}; use --network none')


def ip(*args, check=True):
    return run(['ip', *args], check=check)


def network():
    ip('link', 'set', 'lo', 'up')
    for suffix in ('lan', 'wan'):
        bridge = 'vm-' + suffix
        if not pathlib.Path('/sys/class/net/' + bridge).exists():
            ip('link', 'add', bridge, 'type', 'bridge')
        ip('link', 'set', bridge, 'up')
        tap = 'tap-' + suffix
        if not pathlib.Path('/sys/class/net/' + tap).exists():
            ip('tuntap', 'add', 'dev', tap, 'mode', 'tap')
        ip('link', 'set', tap, 'master', bridge)
        ip('link', 'set', tap, 'up')
    ip('address', 'replace', '10.44.0.2/24', 'dev', 'vm-lan')
    ip('-6', 'address', 'replace', 'fd44:1::2/64', 'dev', 'vm-lan')
    present = run(['ip', 'netns', 'list']).stdout.decode()
    for name, bridge, address, address6, gateway, gateway6 in (
        ('openrhp-client', 'vm-lan', '10.44.0.20/24', 'fd44:1::20/64', GUEST, 'fd44:1::1'),
        ('openrhp-wan', 'vm-wan', f'{WAN_PREFIX}.1/24', 'fd44:2::1/64', '', ''),
    ):
        if name not in present:
            ip('netns', 'add', name)
            outside = 'vm-c' if name == 'openrhp-client' else 'vm-w'
            ip('link', 'add', outside, 'type', 'veth', 'peer', 'name', 'peer0')
            ip('link', 'set', 'peer0', 'netns', name)
            ip('link', 'set', outside, 'master', bridge)
            ip('link', 'set', outside, 'up')
        ip('-n', name, 'link', 'set', 'lo', 'up')
        ip('-n', name, 'link', 'set', 'peer0', 'up')
        ip('-n', name, 'address', 'replace', address, 'dev', 'peer0')
        ip('-n', name, '-6', 'address', 'replace', address6, 'dev', 'peer0')
        if gateway:
            ip('-n', name, 'route', 'replace', 'default', 'via', gateway)
            ip('-n', name, '-6', 'route', 'replace', 'default', 'via', gateway6)
    ip('-n', 'openrhp-wan', 'address', 'replace', '8.8.8.8/32', 'dev', 'lo')
    ip('-n', 'openrhp-wan', '-6', 'address', 'replace', '2001:4860:4860::8888/128', 'dev', 'lo')
    ip('-n', 'openrhp-wan', 'route', 'replace', '10.44.0.0/24', 'via', f'{WAN_PREFIX}.2')
    ip('-n', 'openrhp-wan', '-6', 'route', 'replace', 'fd44:1::/64', 'via', 'fd44:2::2')


def prepare_disk():
    if hashlib.sha256(IMAGE.read_bytes()).hexdigest() != SHA256:
        raise RuntimeError('Official image checksum mismatch')
    owner = STATE / 'owner.json'
    identity = {'project': 'OpenRHP isolated full-boot lab', 'image_sha256': SHA256}
    if owner.exists():
        if json.loads(owner.read_text()) != identity:
            raise RuntimeError('Foreign VM state directory')
    elif list(STATE.iterdir()):
        raise RuntimeError('Refusing nonempty state without its lab ownership marker')
    else:
        owner.write_text(json.dumps(identity) + '\n')
    if not (STATE / 'router.qcow2').exists():
        # Official combined images append signed sysupgrade metadata after the
        # complete gzip member. The whole artifact was hashed above; zlib checks
        # the member CRC while intentionally leaving that verified trailer alone.
        data = zlib.decompress(IMAGE.read_bytes(), 16 + zlib.MAX_WBITS)
        (STATE / 'base.img').write_bytes(data)
        os.chmod(STATE / 'base.img', 0o400)
        run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'raw', '-b', '/state/base.img', '/state/router.qcow2'])
    if not (STATE / 'identity').exists():
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', '/state/identity'])


def running_pid():
    try:
        pid = int((STATE / 'qemu.pid').read_text())
        cmdline = pathlib.Path(f'/proc/{pid}/cmdline').read_bytes()
        if b'qemu-system-x86_64' in cmdline and b'/state/router.qcow2' in cmdline:
            return pid
    except (FileNotFoundError, ValueError):
        pass
    return None


def start():
    if running_pid():
        return
    # Unix sockets belong on native container storage. A macOS Docker bind
    # mount can refuse unlinking its socket inode after a QEMU SIGKILL.
    SOCKETS.mkdir(mode=0o700, parents=True, exist_ok=True)
    if SOCKETS.is_symlink() or SOCKETS.stat().st_mode & 0o077:
        raise RuntimeError('QEMU socket directory must be private and real')
    for name in ('serial.sock', 'qmp.sock'):
        (SOCKETS / name).unlink(missing_ok=True)
    (STATE / 'qemu.pid').unlink(missing_ok=True)
    args = ['qemu-system-x86_64', '-machine', 'pc', '-accel', 'tcg,thread=single', '-cpu', QEMU_CPU,
            '-m', '512', '-smp', '1', '-display', 'none', '-no-reboot', '-daemonize', '-pidfile', '/state/qemu.pid',
            '-drive', 'file=/state/router.qcow2,format=qcow2,if=virtio', '-boot', 'c',
            '-chardev', 'socket,id=console,path=/run/openrhp-vm/serial.sock,server=on,wait=off,logfile=/state/serial.log,logappend=on',
            '-serial', 'chardev:console', '-qmp', 'unix:/run/openrhp-vm/qmp.sock,server=on,wait=off']
    for index, suffix in enumerate(('lan', 'wan'), 1):
        args += ['-netdev', f'tap,id={suffix},ifname=tap-{suffix},script=no,downscript=no',
                 '-device', f'virtio-net-pci,netdev={suffix},mac=52:54:00:44:00:0{index}']
    run(args)


def serial(script, timeout=120):
    with (STATE / 'serial.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(1)
            sock.connect(str(SOCKETS / 'serial.sock'))
            sock.sendall(b'\n')
            ready, deadline = b'', time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    ready += sock.recv(65536)
                except TimeoutError:
                    sock.sendall(b'\n')
                    continue
                if re.search(rb'root@[^\r\n]+# ', ready):
                    break
            else:
                raise TimeoutError('Guest root serial shell did not become ready')
            token = secrets.token_hex(12)
            begin, end = ('__VM_' + label + '_' + token + '__' for label in ('BEGIN', 'END'))
            payload = f"printf '\\n{begin}\\n'\n(\n".encode() + script + f"\n)\nvm_rc=$?\nprintf '\\n{end}:%s\\n' \"$vm_rc\"\n".encode()
            # Run the complete script with sh -c so any console line-editor echo
            # finishes before the begin marker. Serial logs are private recovery
            # artifacts; use SSH stdin for credentials and routine API operations.
            sock.sendall(('/bin/sh -c ' + shlex.quote(payload.decode()) + '\n').encode())
            data = b''
            while time.monotonic() < deadline:
                try:
                    data += sock.recv(65536)
                except TimeoutError:
                    continue
                normalized = data.replace(b'\r\n', b'\n')
                match = re.search((r'(?:^|\n)' + end + r':([0-9]+)\n').encode(), normalized)
                first = re.search((r'(?:^|\n)' + begin + r'\n').encode(), normalized)
                if match and first:
                    return normalized[first.end():match.start()], int(match.group(1))
            raise TimeoutError('Guest serial command timed out')


def ssh_args():
    return ['-i', '/state/identity', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=/state/known_hosts',
            '-o', 'ConnectTimeout=2', '-o', 'LogLevel=ERROR']


def guest(script, check=True, timeout=120):
    return run(['ssh', *ssh_args(), 'root@' + GUEST, '/bin/sh -se'], data=script, check=check, timeout=timeout)


def wait_ssh(previous_boot=None):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        result = guest(b'cat /proc/sys/kernel/random/boot_id\n', check=False, timeout=5)
        if result.returncode == 0 and (previous_boot is None or result.stdout != previous_boot):
            (STATE / 'last-boot-id').write_bytes(result.stdout)
            return result.stdout.decode().strip()
        time.sleep(0.5)
    raise TimeoutError('Pinned guest SSH did not become ready')


def bootstrap():
    if (STATE / 'initialized').exists():
        return
    public = (STATE / 'identity.pub').read_text().strip()
    script = f'''set -e
vm_wait=0
until uci -q get network.lan >/dev/null && test -f /etc/dropbear/dropbear_ed25519_host_key; do
 vm_wait=$((vm_wait+1)); test $vm_wait -lt 60; sleep 1
done
mkdir -p /etc/dropbear
chmod 0700 /etc/dropbear
printf '%s\\n' '{public}' > /etc/dropbear/authorized_keys
chmod 0600 /etc/dropbear/authorized_keys
uci set network.lan.ipaddr='10.44.0.1'
uci set network.lan.netmask='255.255.255.0'
uci -q delete network.lan.ip6assign || true
uci set network.lan.ip6addr='fd44:1::1/64'
uci set network.wan.proto='static'
uci set network.wan.ipaddr='{WAN_PREFIX}.2'
uci set network.wan.netmask='255.255.255.0'
uci set network.wan.gateway='{WAN_PREFIX}.1'
uci set network.wan.ip6addr='fd44:2::2/64'
uci set network.wan.ip6gw='fd44:2::1'
uci -q delete network.wan6 || true
uci commit network
/etc/init.d/network restart
/etc/init.d/dropbear restart
sleep 1
dropbearkey -y -f /etc/dropbear/dropbear_ed25519_host_key
'''.encode()
    output, status = serial(script)
    if status:
        raise RuntimeError('Fresh lab guest bootstrap failed: ' + output.decode(errors='replace'))
    match = re.search(rb'(?m)^(ssh-ed25519 [A-Za-z0-9+/=]{68})(?: |$)', output)
    if not match:
        raise RuntimeError('Could not pin guest host identity through its trusted serial console')
    (STATE / 'known_hosts').write_text(GUEST + ' ' + match.group(1).decode() + '\n')
    os.chmod(STATE / 'known_hosts', 0o600)
    wait_ssh()
    (STATE / 'initialized').write_text('Fresh guest bootstrap completed; never rewrite user configuration on restart\n')


def info():
    return {'container': CONTAINER, 'guest': GUEST, 'guest_lan_ipv6': 'fd44:1::1',
            'guest_wan': f'{WAN_PREFIX}.2', 'guest_wan_ipv6': 'fd44:2::2',
            'client_namespace': 'openrhp-client', 'client': '10.44.0.20', 'client_ipv6': 'fd44:1::20',
            'wan_namespace': 'openrhp-wan', 'wan_target': '8.8.8.8', 'wan_target_ipv6': '2001:4860:4860::8888',
            'qemu_pid': running_pid(), 'image_sha256': SHA256,
            'reboot_mode': 'guest graceful reboot followed by a fresh QEMU process',
            'kernel': 'Actual OpenWrt guest kernel; QEMU TCG, no hardware'}


def require_owner():
    expected = {'project': 'OpenRHP isolated full-boot lab', 'image_sha256': SHA256}
    if json.loads((STATE / 'owner.json').read_text()) != expected:
        raise RuntimeError('Foreign VM state directory')


def stop_vm():
    pid = running_pid()
    if pid is None:
        return
    try:
        with socket.socket(socket.AF_UNIX) as control:
            control.settimeout(3)
            control.connect(str(SOCKETS / 'qmp.sock'))
            replies = control.makefile('rb')
            replies.readline()
            control.sendall(b'{"execute":"qmp_capabilities"}\n')
            replies.readline()
            control.sendall(b'{"execute":"quit"}\n')
            # Keep the monitor connection alive until QEMU handles the command;
            # immediately closing it can discard an unread quit request.
            while True:
                line = replies.readline()
                if not line or 'return' in json.loads(line):
                    break
    except OSError:
        pass
    graceful_deadline = time.monotonic() + 3
    while running_pid() is not None and time.monotonic() < graceful_deadline:
        time.sleep(0.1)
    if running_pid() is not None:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 15
    while running_pid() is not None and time.monotonic() < deadline:
        time.sleep(0.1)
    if running_pid() is not None:
        raise RuntimeError('QEMU did not stop; refusing to copy an active virtual disk')


def snapshot_pristine(restore=False):
    require_owner()
    saved, metadata = STATE / 'pristine.qcow2', STATE / 'pristine.json'
    identity = {'image_sha256': SHA256,
                'host_identity': hashlib.sha256((STATE / 'known_hosts').read_bytes()).hexdigest(),
                'client_identity': hashlib.sha256((STATE / 'identity.pub').read_bytes()).hexdigest()}
    if restore:
        if saved.is_symlink() or not saved.is_file():
            raise RuntimeError('No regular pristine snapshot exists')
        expected = json.loads(metadata.read_text())
        if any(expected.get(key) != value for key, value in identity.items()):
            raise RuntimeError('Pristine snapshot identity does not match this private lab')
        if expected.get('disk_sha256') != hashlib.sha256(saved.read_bytes()).hexdigest():
            raise RuntimeError('Pristine snapshot hash mismatch')
    elif saved.exists() or metadata.exists():
        raise RuntimeError('Pristine snapshot already exists; refusing to replace it')
    # Sync the guest if it is reachable. Snapshot creation requires this clean
    # point; restore can recover an unreachable guest but still stops QEMU first.
    try:
        synced = guest(b'sync\n', check=False, timeout=5).returncode == 0
    except subprocess.TimeoutExpired:
        synced = False
    if not restore and not synced:
        raise RuntimeError('Pristine capture requires a synced reachable guest')
    stop_vm()
    if running_pid() is not None:
        raise RuntimeError('Refusing an active-disk copy')
    try:
        if restore:
            replacement = STATE / 'router.qcow2.restore'
            with saved.open('rb') as source, replacement.open('xb') as destination:
                shutil.copyfileobj(source, destination)
                destination.flush(); os.fsync(destination.fileno())
            # Retain the pre-restore disk for private diagnosis of the last run.
            previous = STATE / 'before-restore.qcow2'
            os.replace(STATE / 'router.qcow2', previous)
            os.replace(replacement, STATE / 'router.qcow2')
        else:
            run(['qemu-img', 'convert', '-O', 'qcow2', '/state/router.qcow2', '/state/pristine.qcow2'], timeout=90)
            os.chmod(saved, 0o400)
            identity['disk_sha256'] = hashlib.sha256(saved.read_bytes()).hexdigest()
            with saved.open('rb') as disk:
                os.fsync(disk.fileno())
            with metadata.open('x') as document:
                document.write(json.dumps(identity, indent=2) + '\n')
                document.flush(); os.fsync(document.fileno())
        directory = os.open(STATE, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        start()
    boot = wait_ssh()
    print(json.dumps({'snapshot': 'pristine', 'restored': restore, 'boot_id': boot}))


def main():
    require_lab()
    action = sys.argv[1] if len(sys.argv) > 1 else 'info'
    if action == 'up':
        prepare_disk(); network(); start(); bootstrap(); wait_ssh()
        (STATE / 'ready.json').write_text(json.dumps(info(), indent=2) + '\n')
        print(json.dumps(info()))
    elif action in ('snapshot', 'restore-pristine'):
        if len(sys.argv) != 2: raise RuntimeError('Snapshot commands take no paths or names')
        snapshot_pristine(action == 'restore-pristine')
    elif action == 'exec':
        result = guest(sys.stdin.buffer.read(), check=False)
        sys.stdout.buffer.write(result.stdout); sys.stderr.buffer.write(result.stderr)
        return result.returncode
    elif action == 'serial':
        output, code = serial(sys.stdin.buffer.read())
        sys.stdout.buffer.write(output)
        return code
    elif action in ('put', 'get'):
        if len(sys.argv) != 4 or not re.fullmatch(r'/[A-Za-z0-9_./~+-]+', sys.argv[3]):
            raise RuntimeError('Supply a source file and a safe absolute destination path')
        source, dest = sys.argv[2:4]
        if action == 'put':
            dest = 'root@' + GUEST + ':' + dest
        else:
            source = 'root@' + GUEST + ':' + source
        result = run(['scp', '-O', *ssh_args(), source, dest], check=False, timeout=120)
        sys.stderr.buffer.write(result.stderr)
        return result.returncode
    elif action in ('reboot', 'powercut'):
        try:
            observed = guest(b'cat /proc/sys/kernel/random/boot_id\n', check=False, timeout=5)
        except subprocess.TimeoutExpired:
            observed = subprocess.CompletedProcess([], 124, b'', b'')
        before = observed.stdout if observed.returncode == 0 else None
        if before is None and (STATE / 'last-boot-id').exists():
            before = (STATE / 'last-boot-id').read_bytes()
        if action == 'reboot':
            if observed.returncode != 0: raise RuntimeError('Graceful reboot requires reachable pinned SSH; use powercut for recovery')
            pid = running_pid()
            if pid is None or b'-no-reboot' not in pathlib.Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0'):
                raise RuntimeError('Restart the emulator with the current -no-reboot profile before graceful reboot testing')
            guest(b'reboot\n', check=False)
            # ARM-host TCG can stall in GRUB after an in-process x86 reset.
            # Let the real guest complete shutdown and request reboot, then
            # start fresh emulated hardware on the same flushed disk. Never
            # kill a guest here or substitute a forced powercut for shutdown.
            deadline = time.monotonic() + 45
            while running_pid() is not None and time.monotonic() < deadline:
                time.sleep(0.1)
            if running_pid() is not None:
                raise RuntimeError('Guest did not complete graceful reboot; emulator was not killed')
            start()
        else:
            pid = running_pid()
            if pid is None: raise RuntimeError('QEMU is not running')
            os.kill(pid, signal.SIGKILL)
            time.sleep(0.3)
            start()
        print(json.dumps({'boot_id': wait_ssh(before), 'previous_boot_id': before.decode().strip() if before else None,
                          'emulator_restarted_after_guest_reboot': action == 'reboot'}))
    elif action == 'info':
        print(json.dumps(info(), indent=2))
    else:
        raise RuntimeError('Expected up, exec, serial, put, get, reboot, powercut, snapshot, restore-pristine or info')
    return 0


if __name__ == '__main__':
    sys.exit(main())
