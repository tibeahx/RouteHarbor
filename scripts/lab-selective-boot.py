#!/usr/bin/env python3
"""Selective-routing acceptance on the dedicated network-none OpenWrt boot VM.

Requires a fresh vmctl VM whose lab-only WAN is 11.0.0/24 (the original harness
uses the reserved FakeIP range). No host WAN, hardware or other VMs are touched.
"""
import argparse
import atexit
import hashlib
import importlib.util
import json
import pathlib
import signal
import tempfile
import subprocess
import time

spec = importlib.util.spec_from_file_location('boot', pathlib.Path(__file__).with_name('lab-openwrt-boot.py'))
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)
class SelectiveLab(boot.Lab):
    def container_command(self, argv, *args, **kwargs):
        if argv[:2] == ['python3', '/lab/vmctl.py']:
            argv = [argv[0], '/lab/vmctl-selective.py', *argv[2:]]
        return super().container_command(argv, *args, **kwargs)


ENGINE_SHA256 = 'ce3ed8667dd99ff40c85a8b236075e856ea9cb80731b304cedd2a47187828120'

SERVER = r'''
import socket,struct,threading,select,ssl

def read(c,n):
 b=b''
 while len(b)<n:
  v=c.recv(n-len(b))
  if not v: raise EOFError()
  b+=v
 return b

def dns(q):
 i=12
 while q[i]: i+=q[i]+1
 i+=1; typ=struct.unpack('!H',q[i:i+2])[0]; end=i+4
 h=bytearray(q[:end]);h[2:4]=b'\x81\x80';h[6:12]=b'\0'*6
 if typ!=1:return bytes(h)
 h[7]=1
 return bytes(h)+b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04'+socket.inet_aton('8.8.8.8')

def handle(c,role):
 try:
  with c:
   if role=='https':
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain('/tmp/openrhp-selective-tls/cert.pem','/tmp/openrhp-selective-tls/key.pem')
    with context.wrap_socket(c,server_side=True) as tls:
     tls.recv(8192);tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK')
   elif role=='echo':
    while c.recv(1): c.sendall((c.getpeername()[0]+'\n').encode())
   elif role=='dns':
    while True:
     q=read(c,struct.unpack('!H',read(c,2))[0]);a=dns(q);c.sendall(struct.pack('!H',len(a))+a)
   else:
    version,count=read(c,2);assert version==5;read(c,count);c.sendall(b'\x05\x00')
    version,cmd,_,typ=read(c,4);assert version==5 and cmd==1
    if typ==1: host=socket.inet_ntoa(read(c,4))
    elif typ==3: host=read(c,read(c,1)[0]).decode()
    elif typ==4: host=socket.inet_ntop(socket.AF_INET6,read(c,16))
    else: raise ValueError()
    port=struct.unpack('!H',read(c,2))[0]
    with socket.create_connection((host,port),3) as upstream:
     c.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
     while True:
      ready,_,_=select.select([c,upstream],[],[],60)
      if not ready:return
      for source in ready:
       data=source.recv(65536)
       if not data:return
       (upstream if source is c else c).sendall(data)
 except (OSError,EOFError,AssertionError,ValueError):pass

def listener(host,port,role):
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((host,port));s.listen()
 while True:
  c,_=s.accept();threading.Thread(target=handle,args=(c,role),daemon=True).start()
for host,port,role in [('8.8.8.8',443,'https'),('8.8.8.8',18080,'echo'),('8.8.8.8',53,'dns'),('11.0.0.1',19080,'socks')]:threading.Thread(target=listener,args=(host,port,role),daemon=True).start()
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('8.8.8.8',53))
while True:
 q,peer=s.recvfrom(4096)
 try:s.sendto(dns(q),peer)
 except (IndexError,struct.error):pass
'''
CLIENT = r'''
import socket,struct,json,sys,ipaddress
phase=sys.argv[1];expected_bypass=sys.argv[2];expected_direct=sys.argv[3]
results={}
for domain,want in [('allowed.example',expected_direct),('blocked.example',expected_bypass)]:
 q=struct.pack('!HHHHHH',1234,256,1,0,0,0)+b''.join(bytes([len(p)])+p.encode() for p in domain.split('.'))+b'\0\0\1\0\1'
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
  s.settimeout(5);s.sendto(q,('10.44.0.1',53));a=s.recv(4096)
 assert a[6:8]==b'\0\1',a.hex()
 ip=socket.inet_ntoa(a[-4:]);synthetic=ipaddress.ip_address(ip) in ipaddress.ip_network('198.18.0.0/15')
 assert synthetic==(phase=='selective'),(phase,ip)
 try:
  with socket.create_connection((ip,18080),5) as c:
   c.sendall(b'x');actual=c.recv(128).decode().strip()
 except OSError as err: raise AssertionError((domain,ip,str(err))) from err
 assert actual==want,(domain,actual,want)
 results[domain]={'resolved':ip,'egress':actual}
print(json.dumps(results))
'''

def wait_emergency(lab):
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        s = json.loads(lab.guest('cat /etc/openrhp-helper/transaction.json\n').stdout)
        if s.get('selective_emergency') and not s.get('selective_emergency_pending'):
            return s
        time.sleep(.3)
    raise AssertionError('independent watchdog did not complete emergency direct')


def check_rollback(lab, traffic, confirm):
    """Apply a different prepared pool, then prove the prior classifier returns."""
    previous=json.loads(lab.guest('cat /etc/openrhp-helper/transaction.json\n').stdout)['committed']['selective']
    original=lab.api('/api/v1/routing')
    candidate=json.loads(json.dumps(original))
    candidate['exceptions']=[{'action':'direct','domain':'blocked.example'}]
    config=lab.api('/api/v1/config')
    lab.api('/api/v1/routing','PUT',candidate,config['revision'])
    revision=lab.api('/api/v1/config')['revision']
    prepared=lab.api('/api/v1/transactions','POST',{'confirm_timeout_seconds':90},revision)
    transaction=prepared['result']['id']
    selected=prepared['result']['candidate']['selective']
    assert selected['fake_pool']!=previous['fake_pool'], 'Candidate must use a distinct pool'
    result=lab.api('/api/v1/transactions/'+transaction+'/apply','POST',{})
    assert result['state']=='succeeded',result
    traffic('selective','11.0.0.2')
    result=lab.api('/api/v1/transactions/'+transaction+'/rollback','POST',{})
    assert result['state']=='succeeded',result
    restored=json.loads(lab.guest('cat /etc/openrhp-helper/transaction.json\n').stdout)['committed']['selective']
    assert restored==previous, 'Rollback must restore the previous exact classifier intent'
    traffic('selective','8.8.8.8')
    # Save the original requested settings again after the runtime rollback.
    lab.api('/api/v1/routing','PUT',original,lab.api('/api/v1/config')['revision'])
    confirm()
    print('PASS applied transaction rollback restores previous FakeIP pool and selective bypass',flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--container', default='openrhp-selective-boot-lab')
    parser.add_argument('--packages', type=pathlib.Path, required=True)
    parser.add_argument('--dependencies', type=pathlib.Path, required=True)
    parser.add_argument('--engine', type=pathlib.Path, required=True)
    parser.add_argument('--installed', action='store_true', help='Retry the same installed SDK snapshot only')
    args = parser.parse_args()
    assert args.container == 'openrhp-selective-boot-lab'
    meta = json.loads(subprocess.check_output(['docker','inspect',args.container]))[0]
    assert meta['HostConfig']['NetworkMode']=='none' and meta['Config']['Labels']['openrhp.task']=='selective-routing'
    assert hashlib.sha256(args.engine.read_bytes()).hexdigest()==ENGINE_SHA256
    lab = SelectiveLab(args.container)
    if not args.installed:
        lab.container_command(['python3','/lab/vmctl-selective.py','capacity'], timeout=180)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            dns_ready = lab.guest('nslookup OpenWrt.lan 127.0.0.1\n', check=False)
            if dns_ready.returncode == 0 and '10.44.0.1' in dns_ready.stdout:
                break
            time.sleep(.5)
        else:
            raise AssertionError('Baseline dnsmasq did not become ready after boot')
        subprocess.run(['python3',str(pathlib.Path(__file__).with_name('lab-openwrt-boot.py')),'--container',args.container,'--packages',str(args.packages),'--dependencies',str(args.dependencies),'--install-only'],check=True)
    existing_engine=lab.guest('sha256sum /usr/bin/sing-box\n',check=False)
    if existing_engine.returncode != 0 or existing_engine.stdout.split()[0] != ENGINE_SHA256:
        lab.put_host_file(args.engine,'/usr/bin/sing-box')
        lab.guest('chmod 0755 /usr/bin/sing-box\n')
    assert 'sing-box version 1.14.0' in lab.guest('/usr/bin/sing-box version\n').stdout
    package_evidence = json.loads((args.packages/'package-results.json').read_text())
    source = package_evidence['source']['source_sha256']
    for package in package_evidence['packages']:
        if package['package'] not in ['openrhp', 'openrhp-guard', 'openrhp-node']:
            continue
        for binary in package['binaries']:
            actual = lab.guest('sha256sum /' + binary['path'].lstrip('./') + '\n').stdout.split()[0]
            assert actual == binary['sha256'], 'Installed binary differs from selected SDK snapshot'
    # The private namespace CA is trusted only by this disposable VM.
    with tempfile.TemporaryDirectory(prefix='openrhp-selective-tls-') as private:
        cert,key=[pathlib.Path(private)/name for name in ['cert.pem','key.pem']]
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','2','-subj','/CN=OpenRHP isolated VM fixture','-addext','subjectAltName=IP:8.8.8.8','-addext','basicConstraints=critical,CA:TRUE'],check=True,capture_output=True)
        lab.container_command(['mkdir','-p','/tmp/openrhp-selective-tls'])
        for path in [cert,key]:
            subprocess.run(['docker','cp',str(path),args.container+':/tmp/openrhp-selective-tls/'+path.name],check=True,capture_output=True)
        lab.put_host_file(cert,'/tmp/openrhp-selective-ca.pem')
        lab.guest('cat /tmp/openrhp-selective-ca.pem >> /etc/ssl/certs/ca-certificates.crt\n/etc/init.d/openrhp restart\n')
    lab.wait_api()
    server = boot.start_background(lab,'selective-server','openrhp-wan',SERVER)
    atexit.register(lab.signal,server,signal.SIGTERM,check=False)
    time.sleep(.3)
    lab.signal(server,0)
    lab.guest("uci -q delete dhcp.@dnsmasq[0].server || true\nuci add_list dhcp.@dnsmasq[0].server='8.8.8.8'\nuci set dhcp.@dnsmasq[0].noresolv=1\nuci commit dhcp\n/etc/init.d/dnsmasq restart\n")
    config = lab.api('/api/v1/config')
    config['sources']=[{'id':'proxy','name':'Lab SOCKS','type':'socks5','enabled':True,'auto':True,'settings':{'server':'11.0.0.1','server_port':19080}}]
    config['targets']=[{'id':'unreachable','url':'https://8.8.8.8/','required':True,'status_codes':[200],'max_bytes':1024}]
    config['policy'].update(mode='manual',pinned='proxy',fallback='closed',break_existing=False,recovery_confirmations=1)
    config['probes'].update(active_interval_seconds=2,other_interval_seconds=2)
    interfaces=lab.api('/api/v1/capabilities')['platform']['interfaces']
    config['network']={'enabled':True,'lan_interfaces':[next(x['device'] for x in interfaces if x['name']=='lan')],'wan_interface':next(x['device'] for x in interfaces if x['name']=='wan'),'local_prefixes':['10.44.0.0/24','fd44:1::/64'],'ipv6':'block','dns':'block','dns_resolver':'8.8.8.8'}
    config['routing']={'mode':'selective','failure_policy':'direct','registry':{'enabled':False,'provider':'antifilter'},'detection':{'enabled':False,'control_target_ids':[]},'exceptions':[{'action':'bypass','domain':'blocked.example'}]}
    if not lab.api('/api/v1/config')['network']['enabled']:
        lab.api('/api/v1/config','PUT',config,config['revision'])
    report={'source_sha256':source,'sdk_packages':str(args.packages.resolve()),'engine_version':'1.14.0','engine_sha256':ENGINE_SHA256,'engine_abi':'official static linux-amd64-musl','image_sha256':'3caea69f186b2bce80938d265e5e2a3dfd0f8713aed101df35d60b88d7270d1f','evidence_tier':'OpenWrt SDK package running on booted OpenWrt 24.10.7 QEMU VM; no physical qualification','checks':[]}
    def confirm():
        config=lab.api('/api/v1/config')
        operation=lab.api('/api/v1/transactions','POST',{'confirm_timeout_seconds':90},config['revision'])
        identifier=operation['result']['id']
        for action in ['apply','confirm']:
            result=lab.api('/api/v1/transactions/'+identifier+'/'+action,'POST',{})
            assert result['state']=='succeeded',result
    def traffic(phase,bypass,direct='11.0.0.2'):
        value=json.loads(lab.container_command(['ip','netns','exec','openrhp-client','python3','-c',CLIENT,phase,bypass,direct]).stdout)
        report['checks'].append({'phase':phase,'traffic':value});print('PASS '+phase+' '+json.dumps(value),flush=True)
    confirm()
    deadline=time.monotonic()+110
    while time.monotonic()<deadline:
        status=lab.api('/api/v1/status')
        if status.get('decision',{}).get('selected')=='proxy':break
        time.sleep(.5)
    else:raise AssertionError('Pinned fixture failed verified HTTPS readiness: '+json.dumps(status))
    traffic('selective','8.8.8.8')
    check_rollback(lab,traffic,confirm)
    report['checks'].append({'applied_transaction_rollback_restored_previous_classifier':True})
    # Stop the actual unprivileged DNS-front process; its still-live owner cannot
    # substitute a loader or detector error for this serving failure.
    lab.guest("for p in /proc/[0-9]*/cmdline; do if tr '\\000' ' ' < \"$p\" | grep -q '^/usr/libexec/openrhp-helper dns-front'; then pid=${p#/proc/}; pid=${pid%/cmdline}; kill -STOP \"$pid\"; fi; done\n")
    wait_emergency(lab);traffic('emergency','11.0.0.2')
    # Cached virtual destinations remain quarantined even after nft state loss.
    guard=lab.guest('ip -4 route get 198.18.0.2\n',check=False)
    assert guard.returncode!=0
    lab.guest("for p in /proc/[0-9]*/cmdline; do if tr '\\000' ' ' < \"$p\" | grep -q '^/usr/libexec/openrhp-helper dns-front'; then pid=${p#/proc/}; pid=${pid%/cmdline}; kill -CONT \"$pid\"; fi; done\n")
    confirm();traffic('selective','8.8.8.8')
    state=json.loads(lab.guest('cat /etc/openrhp-helper/transaction.json\n').stdout)
    port=state['committed']['selective']['path']['port']
    rows=lab.guest('netstat -lnpt\n').stdout.splitlines()
    matching=[r.split()[-1].split('/')[0] for r in rows if '127.0.0.1:'+str(port)+' ' in r and '/sing-box' in r]
    assert len(matching)==1 and matching[0].isdigit(), 'Cannot identify active native dispatcher listener'
    engine_pid=matching[0]
    lab.guest('kill -STOP '+engine_pid+'\n')
    wait_emergency(lab);traffic('engine-hang','11.0.0.2')
    lab.guest('kill -CONT '+engine_pid+'\n')
    lab.reboot();lab.wait_api();traffic('reboot','11.0.0.2')
    for family,address in [('4','198.18.0.2'),('6','fd66:6f70:656e::2')]:
        assert lab.guest('ip -'+family+' route get '+address+'\n',check=False).returncode!=0
    lab.guest('/etc/init.d/firewall reload\n');traffic('fw4-reload','11.0.0.2')
    # A full fw4 flush also removes its own WAN masquerade. The isolated WAN
    # routes the client subnet, so its original LAN address proves the direct
    # path; OpenRHP must not recreate foreign firewall/NAT rules.
    lab.guest('fw4 flush\n');traffic('fw4-flush','10.44.0.20','10.44.0.20')
    for family,address in [('4','198.18.0.2'),('6','fd66:6f70:656e::2')]:
        assert lab.guest('ip -'+family+' route get '+address+'\n',check=False).returncode!=0
    lab.guest('/etc/init.d/firewall restart\n');traffic('fw4-restored','11.0.0.2')
    report['checks'].append({'virtual_address_quarantine':True,'persistent_emergency_after_reboot':True})
    lab.guest('/usr/libexec/openrhp-helper decommission --state-dir /etc/openrhp-helper --policy restore-direct\n')
    state=json.loads(lab.guest('cat /etc/openrhp-helper/transaction.json\n').stdout)
    assert not state.get('committed') and not state.get('transaction') and not state.get('guarded') and not state.get('maintenance_hold'), state
    lab.guest('nft list table inet fw4 >/dev/null\n')
    traffic('decommissioned','11.0.0.2')
    report['checks'].append({'explicit_restore_direct_decommission':True,'foreign_fw4_preserved':True})
    out=pathlib.Path('test-results/selective-boot');out.mkdir(parents=True,exist_ok=True)
    (out/'results.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS selective SDK install, real DNS/WAN separation, DNS and native-engine outage emergency, reboot and fw4 recovery',flush=True)

if __name__=='__main__':main()
