#!/usr/bin/env python3
"""Exercise package installation and closed-policy recovery on a booted OpenWrt VM.

Requires the isolated vmctl harness and independently verified package inputs.
This is emulated OpenWrt kernel/boot evidence, never physical-radio acceptance.
"""

import argparse
import atexit
import datetime
import hashlib
import importlib.util
import json
import pathlib
import shlex
import signal
import subprocess
import time
import uuid


class Lab:
    def __init__(self, container):
        self.container = container

    def container_command(self, argv, data=None, check=True, timeout=90):
        result = subprocess.run(
            ["docker", "exec", "-i", self.container, *argv], input=data,
            text=True, capture_output=True, timeout=timeout,
        )
        if check and result.returncode:
            raise RuntimeError(f"Lab command failed: {argv}\n{result.stdout}\n{result.stderr}")
        return result

    def guest(self, script, check=True):
        return self.container_command(["python3", "/lab/vmctl.py", "exec"], "set -eu\n" + script, check)

    def put_host_file(self, source, destination):
        # Read the actual caller-selected file, never an older read-only mount
        # with the same filename. Verify the bytes after transport into the guest.
        staged = "/tmp/openrhp-boot-input-" + uuid.uuid4().hex
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        subprocess.run(["docker", "cp", str(source), self.container + ":" + staged], check=True, capture_output=True)
        try:
            self.container_command(["python3", "/lab/vmctl.py", "put", staged, destination])
            actual = self.guest("sha256sum " + shlex.quote(destination) + "\n").stdout.split()[0]
            assert actual == digest, "Guest package bytes differ from the selected host artifact"
        finally:
            self.container_command(["rm", "-f", staged], check=False)

    def signal(self, pid, value, check=True):
        code = "import os,pathlib,sys; p=int(sys.argv[1]); command=pathlib.Path('/proc/'+str(p)+'/cmdline').read_bytes(); assert b'openrhp-boot-' in command, 'Foreign process'; os.kill(p,int(sys.argv[2]))"
        return self.container_command(['python3', '-c', code, str(pid), str(value)], check=check, timeout=5)

    def api(self, path, method="GET", data=None, revision=None):
        argv = ["/usr/bin/openrhp", "api", "--token-file", "/root/openrhp-lab/admin.token",
                "--path", path, "--method", method]
        if data is not None:
            argv += ["--data", "-", "--idempotency-key", uuid.uuid4().hex]
        if revision is not None:
            argv += ["--revision", str(revision)]
        command = shlex.join(argv)
        if data is not None:
            marker = "OPENRHP_INPUT_" + uuid.uuid4().hex
            command += " <<'" + marker + "'\n" + json.dumps(data) + "\n" + marker
        return json.loads(self.guest(command + "\n").stdout)

    def wait_api(self):
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                status = self.api("/api/v1/status")
                if 'network' in status and status.get('path_initialization_error') != 'helper_unavailable':
                    return status
            except RuntimeError:
                pass
            time.sleep(0.25)
        raise AssertionError("API and privileged network helper did not recover")

    def powercut(self):
        return self.container_command(["python3", "/lab/vmctl.py", "powercut"], timeout=180)

    def reboot(self):
        return self.container_command(["python3", "/lab/vmctl.py", "reboot"], timeout=180)


CLIENT = r'''
import json, socket, struct, sys
phase = sys.argv[1]
result = {}
for version, address in [(4, '8.8.8.8'), (6, '2001:4860:4860::8888')]:
    for kind, port in [('tcp', 18080), ('udp', 18081), ('dns-udp', 53), ('dns-tcp', 53)]:
        family = socket.AF_INET if version == 4 else socket.AF_INET6
        transport = socket.SOCK_STREAM if kind in ['tcp', 'dns-tcp'] else socket.SOCK_DGRAM
        payload = ('OpenRHP-boot-' + phase).encode()
        with socket.socket(family, transport) as connection:
            connection.settimeout(1.5)
            try:
                connection.connect((address, port))
                connection.sendall(payload)
                result[str(version) + '-' + kind] = connection.recv(1024) == payload
            except OSError:
                result[str(version) + '-' + kind] = False
    local = '10.44.0.1' if version == 4 else 'fd44:1::1'
    question = struct.pack('!HHHHHH', 1234, 256, 1, 0, 0, 0) + b'\x07OpenWrt\x03lan\x00\x00\x01\x00\x01'
    for kind in ['udp', 'tcp']:
        with socket.socket(family, socket.SOCK_DGRAM if kind == 'udp' else socket.SOCK_STREAM) as connection:
            connection.settimeout(1.5)
            try:
                connection.connect((local, 53))
                connection.sendall(question if kind == 'udp' else struct.pack('!H', len(question)) + question)
                answer = connection.recv(1024)
                if kind == 'tcp':
                    answer = answer[2:]
                result[str(version) + '-router-dns-' + kind] = len(answer) >= 12 and answer[:2] == question[:2] and bool(answer[2] & 128) and answer[6:8] != b'\x00\x00'
            except OSError:
                result[str(version) + '-router-dns-' + kind] = False
with socket.socket() as management:
    management.settimeout(2)
    try:
        management.connect(('10.44.0.1', 22))
        result['management'] = management.recv(64).startswith(b'SSH-')
    except OSError:
        result['management'] = False
print(json.dumps(result))
'''

SERVER = r'''
import selectors, socket
selector = selectors.DefaultSelector()
for family, address in [(socket.AF_INET, '8.8.8.8'), (socket.AF_INET6, '2001:4860:4860::8888')]:
    for kind, port in [(socket.SOCK_STREAM, 18080), (socket.SOCK_DGRAM, 18081), (socket.SOCK_DGRAM, 53), (socket.SOCK_STREAM, 53)]:
        connection = socket.socket(family, kind)
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            connection.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        connection.bind((address, port))
        if kind == socket.SOCK_STREAM:
            connection.listen(32)
        connection.setblocking(False)
        selector.register(connection, selectors.EVENT_READ, 'listen' if kind == socket.SOCK_STREAM else 'udp')
while True:
    for event, _ in selector.select():
        connection, kind = event.fileobj, event.data
        if kind == 'listen':
            client, _ = connection.accept()
            client.setblocking(False)
            selector.register(client, selectors.EVENT_READ, 'tcp')
        elif kind == 'udp':
            data, address = connection.recvfrom(1024)
            connection.sendto(data, address)
        else:
            try:
                data = connection.recv(1024)
                if data:
                    connection.sendall(data)
            except OSError:
                data = b''
            if not data:
                selector.unregister(connection)
                connection.close()
'''

FLOOD = r'''
import json, pathlib, socket, time
stop = pathlib.Path('/tmp/openrhp-boot-traffic.stop')
status = pathlib.Path('/tmp/openrhp-boot-traffic.json')
udp = []
tcp = []
connections = []
for family, address in [(socket.AF_INET, '8.8.8.8'), (socket.AF_INET6, '2001:4860:4860::8888')]:
    for port in [53, 18081]:
        connection = socket.socket(family, socket.SOCK_DGRAM)
        udp.append((connection, (address, port)))
    for port in [18080, 53]:
        connection = socket.socket(family, socket.SOCK_STREAM)
        connection.settimeout(2)
        connection.connect((address, port))
        connections.append({'local': connection.getsockname(), 'remote': connection.getpeername(), 'family': int(family)})
        connection.setblocking(False)
        tcp.append(connection)
deadline = time.monotonic() + 900
iterations = 0
reported = 0
while time.monotonic() < deadline and not stop.exists():
    for connection, address in udp:
        try:
            connection.sendto(b'OpenRHP-boot-persistent', address)
        except OSError:
            pass
    for connection in tcp:
        try:
            connection.send(b'OpenRHP-boot-established')
            connection.recv(65536)
        except OSError:
            pass
    for family, address in [(socket.AF_INET, '8.8.8.8'), (socket.AF_INET6, '2001:4860:4860::8888')]:
        for port in [18080, 53]:
            with socket.socket(family, socket.SOCK_STREAM) as candidate:
                candidate.setblocking(False)
                candidate.connect_ex((address, port))
    iterations += 1
    if time.monotonic() - reported >= 0.2:
        staging = status.with_suffix('.tmp')
        staging.write_text(json.dumps({'iterations': iterations, 'updated': time.time(), 'connections': connections}))
        staging.replace(status)
        reported = time.monotonic()
    time.sleep(0.02)
'''


def traffic(lab, phase, expected):
    report = lab.container_command(
        ["ip", "netns", "exec", "openrhp-client", "python3", "-c", CLIENT, phase], timeout=30)
    values = json.loads(report.stdout)
    assert values.pop('management'), (phase, 'LAN management unavailable')
    wan = {name: value for name, value in values.items() if '-router-dns-' not in name}
    local_dns = {name: value for name, value in values.items() if '-router-dns-' in name}
    assert len(wan) == 8 and len(local_dns) == 4, (phase, 'Incomplete probe matrix', values)
    assert all(value == expected for value in wan.values()), (phase, values)
    if expected:
        assert all(local_dns.values()), (phase, 'Local DNS baseline unavailable', local_dns)
    # A cached router-local answer is LAN traffic. DNS leakage is tested with
    # unique uncached names and actual upstream WAN capture in the DNS lab.
    print(json.dumps({'phase': phase, 'WAN_TCP_UDP_DNS_8': 'permitted' if expected else 'blocked',
                      'gateway_local_DNS_4': local_dns}), flush=True)
    return values


def start_background(lab, name, namespace, source):
    target = '/tmp/openrhp-boot-' + name + '.py'
    lab.container_command(['python3', '-c', 'import pathlib,sys; pathlib.Path(sys.argv[1]).write_text(sys.stdin.read())', target], source)
    command = shlex.join(['ip', 'netns', 'exec', namespace, 'python3', target])
    return int(lab.container_command(['sh', '-c', command + ' >/tmp/openrhp-boot-' + name + '.log 2>&1 </dev/null & echo $!']).stdout)


def check_flood(lab, pid, previous=0):
    lab.signal(pid, 0)
    report = json.loads(lab.container_command(['cat', '/tmp/openrhp-boot-traffic.json']).stdout)
    assert time.time() - report['updated'] < 3, 'Traffic generator stopped making progress'
    assert report['iterations'] > previous, 'No fresh traffic was generated'
    return report['iterations']


CAPTURE_FILTER = '(dst host 8.8.8.8 or dst host 2001:4860:4860::8888) and (port 18080 or port 18081 or port 53)'


def check_capture(lab, pid):
    state = lab.container_command(['cat', f'/proc/{pid}/stat']).stdout.rsplit(')', 1)[1].split()[0]
    assert state not in ['Z', 'X'], 'WAN capture stopped before the test ended'


def start_capture(lab, path, *, namespace='openrhp-wan', interface='any', expression=None):
    if expression is None:
        expression = CAPTURE_FILTER
    command = shlex.join(['ip', 'netns', 'exec', namespace, 'tcpdump', '--immediate-mode', '-n', '-U', '-i', interface, '-w', path, expression])
    log = path + '.log'
    pid = int(lab.container_command(['sh', '-c', command + ' >' + shlex.quote(log) + ' 2>&1 </dev/null & echo $!']).stdout)
    atexit.register(lab.signal, pid, signal.SIGINT, check=False)
    time.sleep(0.3)
    check_capture(lab, pid)
    assert 'listening on' in lab.container_command(['cat', log]).stdout, 'Capture not ready'
    return pid


def stop_capture(lab, pid, path):
    check_capture(lab, pid)
    lab.signal(pid, signal.SIGINT)
    code = "import pathlib,sys,time; p=pathlib.Path('/proc/'+sys.argv[1]+'/stat'); deadline=time.monotonic()+5\nwhile p.exists() and p.read_text().rsplit(')',1)[1].split()[0] not in ['Z','X']:\n if time.monotonic()>deadline: raise RuntimeError('Capture did not flush and exit')\n time.sleep(0.05)"
    lab.container_command(['python3', '-c', code, str(pid)])
    return lab.container_command(['tcpdump', '-nn', '-r', path]).stdout


def select_dependencies(manifest):
    packages = {item["package"]: item for item in manifest}
    remaining = ["ip-full", "conntrack", "tcpdump", "kmod-nft-tproxy", "kmod-nft-socket", "kmod-nft-queue"]
    selected = {}
    while remaining:
        name = remaining.pop()
        if name in selected or name in {"kernel", "libc", "libgcc1", "libpthread", "librt"}:
            continue
        item = packages[name]
        selected[name] = item
        for dependency in item.get("depends", "").split(","):
            dependency = dependency.strip().split(" ")[0]
            if dependency:
                remaining.append(dependency)
    return list(selected.values())


def validate_captures(metadata_path):
    """Same final assertion for a live run and its immutable retained evidence."""
    module_path = pathlib.Path(__file__).resolve().parent.parent / 'docker/lab-openwrt-vm/capture.py'
    specification = importlib.util.spec_from_file_location('openrhp_capture', module_path)
    checks = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(checks)
    result = checks.verify_files(metadata_path.parent, json.loads(metadata_path.read_text()))
    print(json.dumps({'capture_validation': result}), flush=True)
    print('PASS protected-client WAN packets: 0; separately proven router reset responses: ' +
          str(result['router_generated_resets']), flush=True)
    return result


def retain_and_validate_captures(lab, run_id, confirmed_at, connections, diagnostics, protected):
    directory = pathlib.Path(__file__).resolve().parent.parent / 'test-results' / ('openwrt-boot-' + run_id)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    sources = {'wan': diagnostics[0][1], 'lan': diagnostics[1][1], 'protected': protected}
    metadata = {'confirmed_at': confirmed_at, 'connections': connections, 'logs': {}}
    for key, source in sources.items():
        for suffix in ('', '.log'):
            filename = key + '.pcap' + suffix
            subprocess.run(['docker', 'cp', lab.container + ':' + source + suffix,
                            str(directory / filename)], check=True, capture_output=True)
            if suffix:
                metadata['logs'][key] = filename
            else:
                metadata[key] = filename
    destination = directory / 'metadata.json'
    destination.write_text(json.dumps(metadata, indent=2) + '\n')
    print('RETAINED_CAPTURE_METADATA ' + str(destination), flush=True)
    return validate_captures(destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", default="openrhp-openwrt-boot-lab")
    parser.add_argument("--dependencies", type=pathlib.Path)
    parser.add_argument("--packages", type=pathlib.Path)
    parser.add_argument('--verify-captures', type=pathlib.Path,
                        help='Read-only replay of the same final packet assertion on retained metadata')
    parser.add_argument('--install-only', action='store_true',
                        help='Stop after ordinary package installation/setup with routing still off')
    args = parser.parse_args()
    if args.verify_captures:
        if args.dependencies or args.packages or args.install_only:
            parser.error('Capture replay takes no package inputs')
        validate_captures(args.verify_captures.resolve(strict=True))
        return
    if not args.dependencies or not args.packages:
        parser.error('An actual boot test requires verified --dependencies and --packages')
    lab = Lab(args.container)
    deps = args.dependencies.resolve(strict=True)
    sdk = args.packages.resolve(strict=True)
    release = lab.guest("cat /etc/openwrt_release; uname -r; cat /proc/1/comm\n").stdout
    assert "24.10.7" in release and "6.6.141" in release and "procd" in release, release
    lab.guest("if opkg list-installed | grep -q '^openrhp'; then echo 'Restore the pristine lab checkpoint before this installation test' >&2; exit 1; fi\n")
    print("PASS actual OpenWrt 24.10.7 kernel and PID1 procd", flush=True)
    server_pid = start_background(lab, 'server', 'openrhp-wan', SERVER)
    atexit.register(lab.signal, server_pid, signal.SIGTERM, check=False)
    time.sleep(0.2)
    lab.signal(server_pid, 0)
    calibration = '/tmp/openrhp-boot-baseline.pcap'
    calibration_pid = start_capture(lab, calibration)
    traffic(lab, 'uninstalled-baseline', True)
    observed = stop_capture(lab, calibration_pid, calibration)
    for address in ['8.8.8.8', '2001:4860:4860::8888']:
        for port, tcp in [(18080, True), (18081, False), (53, True), (53, False)]:
            assert any(f'> {address}.{port}:' in line and ('Flags [' in line) == tcp for line in observed.splitlines()), ('Capture did not observe known permitted traffic', address, port, tcp)
    print('PASS positive LAN-to-WAN IPv4/IPv6 TCP/UDP/DNS baseline and LAN management', flush=True)
    lab.guest("mkdir -p /tmp/openrhp-deps /tmp/openrhp-ipks /root/openrhp-lab; chmod 0700 /root/openrhp-lab\n")
    selected = select_dependencies(json.loads((deps / "manifest.json").read_text()))
    for item in selected:
        path = deps / item["file"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"], path.name
        lab.put_host_file(path, "/tmp/openrhp-deps/" + path.name)
    lab.guest("opkg install /tmp/openrhp-deps/*.ipk\n")
    for name in ["openrhp", "openrhp-guard", "openrhp-node", "openrhp-conntrack"]:
        candidates = list(sdk.glob(name + "_*.ipk"))
        assert len(candidates) == 1, name
        path = candidates[0]
        lab.put_host_file(path, "/tmp/openrhp-ipks/" + path.name)
    lab.guest("sha256sum /etc/config/network /etc/config/firewall /etc/config/dhcp > /root/openrhp-lab/network-before.sha\n"
              "opkg install /tmp/openrhp-ipks/*.ipk\n"
              "test \"$(uci -q get openrhp.main.enabled)\" = 0\n"
              "test \"$(uci -q get openrhp-node.main.enabled)\" = 0\n"
              "sha256sum -c /root/openrhp-lab/network-before.sha\n"
              "/usr/libexec/openrhp-setup /root/openrhp-lab/admin.token\n")
    lab.wait_api()
    assert lab.api("/api/v1/capabilities")["platform"]["supported"]
    print("PASS ordinary package installation, disabled defaults and root/service setup", flush=True)
    config = lab.api("/api/v1/config")
    if args.install_only:
        assert not config['network']['enabled'] and config['policy']['mode'] == 'off'
        assert config['sources'] == [] and config['targets'] == []
        lab.guest('sha256sum -c /root/openrhp-lab/network-before.sha\n')
        print('PASS clean manual-setup baseline: routing remains off, no sources or resources', flush=True)
        return
    config["sources"] = [{"id": "direct", "name": "Isolated WAN", "type": "direct", "enabled": True, "auto": True, "settings": {}}]
    config["targets"] = [{"id": "unreachable", "url": "https://8.8.8.8/", "required": True, "status_codes": [200], "max_bytes": 1024}]
    config["policy"].update(mode="auto", fallback="closed", break_existing=False)
    interfaces = lab.api("/api/v1/capabilities")["platform"]["interfaces"]
    wan = next(value["device"] for value in interfaces if value["name"] == "wan")
    lan = next(value["device"] for value in interfaces if value["name"] == "lan")
    config["network"] = {"enabled": True, "lan_interfaces": [lan], "wan_interface": wan,
                         "local_prefixes": ["10.44.0.0/24", "fd44:1::/64"], "ipv6": "block",
                         "dns": "block", "dns_resolver": "8.8.8.8"}
    lab.api("/api/v1/config", "PUT", config, config["revision"])
    revision = lab.api("/api/v1/config")["revision"]
    run_id = str(time.time_ns())
    diagnostic_filter = '(host 8.8.8.8 or host 2001:4860:4860::8888) and (port 18080 or port 18081 or port 53)'
    diagnostics = []
    for label, namespace in [('wan', 'openrhp-wan'), ('lan', 'openrhp-client')]:
        destination = '/tmp/openrhp-boot-' + label + '-duplex-' + run_id + '.pcap'
        diagnostics.append((start_capture(lab, destination, namespace=namespace,
                                          interface='peer0', expression=diagnostic_filter), destination))
        print('DIAGNOSTIC_CAPTURE ' + destination, flush=True)
    print('CLIENT_ADDRESSES ' + lab.container_command(['ip', '-n', 'openrhp-client', '-j', 'address', 'show', 'dev', 'peer0']).stdout.strip(), flush=True)
    lab.container_command(['rm', '-f', '/tmp/openrhp-boot-traffic.stop', '/tmp/openrhp-boot-traffic.json'])
    flood_pid = start_background(lab, 'traffic', 'openrhp-client', FLOOD)
    atexit.register(lab.signal, flood_pid, signal.SIGTERM, check=False)
    time.sleep(0.3)
    iterations = check_flood(lab, flood_pid)
    socket_inventory = json.loads(lab.container_command(['cat', '/tmp/openrhp-boot-traffic.json']).stdout)
    print('PERSISTENT_CLIENT_SOCKETS ' + json.dumps(socket_inventory), flush=True)
    def phase(name, state):
        print(state + ' ' + name + ' ' + datetime.datetime.now(datetime.timezone.utc).isoformat(), flush=True)
    phase('prepare-apply-confirm', 'BEGIN')
    operation = lab.api("/api/v1/transactions", "POST", {"confirm_timeout_seconds": 90}, revision)
    transaction = operation["result"]["id"]
    for action in ["apply", "confirm"]:
        assert lab.api(f"/api/v1/transactions/{transaction}/{action}", "POST", {})["state"] == "succeeded"
    confirmed_at = time.time()
    phase('prepare-apply-confirm', 'READY')
    time.sleep(1)
    capture = '/tmp/openrhp-boot-guard-' + run_id + '.pcap'
    print('PROTECTED_CAPTURE ' + capture, flush=True)
    capture_pid = start_capture(lab, capture)
    traffic(lab, "confirmed", False)
    print('PASS confirmed closed policy and client management', flush=True)
    iterations = check_flood(lab, flood_pid, iterations)
    check_capture(lab, capture_pid)
    phase('reboot', 'BEGIN')
    lab.reboot()
    lab.wait_api()
    phase('reboot', 'READY')
    traffic(lab, "reboot", False)
    print('PASS closed policy and helper recovery after actual reboot', flush=True)
    iterations = check_flood(lab, flood_pid, iterations)
    check_capture(lab, capture_pid)
    phase('firewall-reload', 'BEGIN')
    lab.guest("/etc/init.d/firewall reload\n")
    phase('firewall-reload', 'READY')
    traffic(lab, "reload", False)
    print('PASS closed policy after firewall reload', flush=True)
    iterations = check_flood(lab, flood_pid, iterations)
    check_capture(lab, capture_pid)
    phase('firewall-flush', 'BEGIN')
    lab.guest("fw4 flush\n")
    phase('firewall-flush', 'READY')
    traffic(lab, "flush", False)
    print('PASS closed policy after firewall flush', flush=True)
    iterations = check_flood(lab, flood_pid, iterations)
    check_capture(lab, capture_pid)
    lab.guest("/etc/init.d/firewall restart\n")
    phase('powercut', 'BEGIN')
    lab.powercut()
    lab.wait_api()
    phase('powercut', 'READY')
    traffic(lab, "powercut", False)
    print('PASS closed policy and helper recovery after abrupt power cut', flush=True)
    check_flood(lab, flood_pid, iterations)
    lab.guest("sha256sum -c /root/openrhp-lab/network-before.sha\n")
    lab.container_command(['touch', '/tmp/openrhp-boot-traffic.stop'])
    stop_capture(lab, capture_pid, capture)
    for pid, destination in diagnostics:
        stop_capture(lab, pid, destination)
    retain_and_validate_captures(lab, run_id, confirmed_at, socket_inventory['connections'], diagnostics, capture)
    lab.signal(server_pid, signal.SIGTERM, check=False)
    lab.signal(flood_pid, signal.SIGTERM, check=False)
    print("PASS API closed policy, reboot, fw4 reload/flush, abrupt power cycle and management preservation", flush=True)
    print('PASS continuous duplex capture: no protected IPv4/IPv6 TCP/UDP/DNS was forwarded to WAN during those transitions', flush=True)


if __name__ == "__main__":
    main()
