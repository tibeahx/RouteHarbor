#!/usr/bin/env python3
"""Boot regression on the already installed isolated x86_64 OpenWrt lab.

Requires a confirmed closed policy. It distinguishes forwarded WAN traffic from
gateway-local DNS replies and makes no claim that the latter are WAN leaks.
"""
import atexit
import datetime
import importlib.util
import json
import pathlib
import signal
import time

spec = importlib.util.spec_from_file_location('boot_lab', pathlib.Path(__file__).with_name('lab-openwrt-boot.py'))
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)

FLOOD_CLOSED = r'''
import json, pathlib, socket, time
status = pathlib.Path('/tmp/routeharbor-boot-traffic.json')
sockets = []
for family, address in [(socket.AF_INET,'8.8.8.8'),(socket.AF_INET6,'2001:4860:4860::8888')]:
    for port in [53,18081]:
        sockets.append((socket.socket(family,socket.SOCK_DGRAM),(address,port)))
iterations = 0
deadline = time.monotonic()+900
while time.monotonic()<deadline:
    for connection,address in sockets:
        try: connection.sendto(b'RouteHarbor-boot-recovery',address)
        except OSError: pass
    for family,address in [(socket.AF_INET,'8.8.8.8'),(socket.AF_INET6,'2001:4860:4860::8888')]:
        for port in [18080,53]:
            with socket.socket(family,socket.SOCK_STREAM) as connection:
                connection.setblocking(False)
                connection.connect_ex((address,port))
    iterations += 1
    staging = status.with_suffix('.tmp')
    staging.write_text(json.dumps({'iterations':iterations,'updated':time.time()}))
    staging.replace(status)
    time.sleep(0.02)
'''


def wait_helper(lab):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            lab.wait_api()
            if lab.api('/api/v1/capabilities')['platform']['supported']:
                lab.guest('test -S /var/run/routeharbor/helper.sock\n')
                return
        except (RuntimeError, AssertionError):
            pass
        time.sleep(0.25)
    raise AssertionError('Root helper did not recover after actual OpenWrt boot')


def check_traffic(lab, phase):
    result = lab.container_command(['ip', 'netns', 'exec', 'routeharbor-client', 'python3', '-c', boot.CLIENT, phase], timeout=30)
    values = json.loads(result.stdout)
    assert values.pop('management'), (phase, 'management unavailable')
    local_dns = {key:value for key,value in values.items() if '-router-dns-' in key}
    forwarded = {key:value for key,value in values.items() if '-router-dns-' not in key}
    assert len(forwarded) == 8 and not any(forwarded.values()), (phase, forwarded)
    print(json.dumps({'phase':phase, 'WAN_TCP_UDP_DNS_8':'blocked', 'gateway_local_DNS_4':local_dns}), flush=True)


def main():
    lab = boot.Lab('routeharbor-openwrt-boot-lab')
    wait_helper(lab)
    server = boot.start_background(lab, 'server', 'routeharbor-wan', boot.SERVER)
    atexit.register(lab.signal, server, signal.SIGTERM, check=False)
    lab.container_command(['rm','-f','/tmp/routeharbor-boot-traffic.stop','/tmp/routeharbor-boot-traffic.json'])
    traffic = boot.start_background(lab, 'traffic', 'routeharbor-client', FLOOD_CLOSED)
    atexit.register(lab.signal, traffic, signal.SIGTERM, check=False)
    time.sleep(0.3)
    iterations = boot.check_flood(lab,traffic)
    path = '/tmp/routeharbor-boot-early-guard-'+str(time.time_ns())+'.pcap'
    print('CAPTURE '+path,flush=True)
    capture = boot.start_capture(lab,path)
    check_traffic(lab,'before-reboot')
    for phase, action in [('reboot',lab.reboot), ('fw4-flush',lambda:lab.guest('fw4 flush\n')), ('powercut',lab.powercut)]:
        print('BEGIN '+phase+' '+datetime.datetime.now(datetime.timezone.utc).isoformat(),flush=True)
        action()
        wait_helper(lab)
        print('READY '+phase+' '+datetime.datetime.now(datetime.timezone.utc).isoformat(),flush=True)
        check_traffic(lab,phase)
        iterations = boot.check_flood(lab,traffic,iterations)
        boot.check_capture(lab,capture)
    observed = boot.stop_capture(lab,capture,path)
    assert not observed.strip(), 'WAN traffic escaped during guard recovery:\n' + observed
    print('PASS actual OpenWrt early helper startup, reboot, total nft flush and QEMU powercut; continuous WAN capture is empty',flush=True)


if __name__ == '__main__':
    main()
