#!/usr/bin/env python3
"""Diagnose real uncached gateway DNS forwarding in the isolated OpenWrt VM.

Temporarily points only the disposable guest's dnsmasq at the synthetic WAN
resolver. Restores the exact DHCP file and quarantine in a finally block.
It deliberately calibrates permitted DNS only against the private synthetic WAN,
then asserts no TCP/UDP DNS packets escape with the guards active or nft flushed.
Cached local replies are not leak evidence.
"""
import atexit
import importlib.util
import json
import pathlib
import signal
import subprocess
import time
import uuid

spec = importlib.util.spec_from_file_location('boot_lab', pathlib.Path(__file__).with_name('lab-openwrt-boot.py'))
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)

SERVER = r'''
import selectors,socket,struct,threading,time
selector=selectors.DefaultSelector()
def answer(data):
    position=12
    while position<len(data) and data[position]: position+=1+data[position]
    position+=5
    if position>len(data): return b''
    return data[:2]+struct.pack('!HHHHH',0x8180,1,1,0,0)+data[12:position]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+bytes([9,9,9,9])
def reply(connection,data,address):
    try: connection.sendto(answer(data),address)
    except OSError: pass
def tcp(connection):
    with connection:
        connection.settimeout(5)
        def exact(n):
            data=b''
            while len(data)<n:
                chunk=connection.recv(n-len(data))
                if not chunk: raise OSError('closed')
                data+=chunk
            return data
        try:
            data=exact(struct.unpack('!H',exact(2))[0]);time.sleep(1)
            result=answer(data);connection.sendall(struct.pack('!H',len(result))+result)
        except OSError: pass
for family,address in [(socket.AF_INET,'8.8.8.8'),(socket.AF_INET6,'2001:4860:4860::8888')]:
    for transport in [socket.SOCK_DGRAM,socket.SOCK_STREAM]:
        connection=socket.socket(family,transport);connection.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        connection.bind((address,53));connection.setblocking(False)
        if transport==socket.SOCK_STREAM: connection.listen(16)
        selector.register(connection,selectors.EVENT_READ,transport)
while True:
    for key,_ in selector.select():
        connection=key.fileobj
        if key.data==socket.SOCK_STREAM:
            child,_=connection.accept();threading.Thread(target=tcp,args=(child,),daemon=True).start()
        else:
            data,address=connection.recvfrom(4096)
            threading.Timer(1,reply,args=(connection,data,address)).start()
'''

CLIENT = r'''
import concurrent.futures,json,socket,struct,sys
nonce=sys.argv[1]
def query(case):
    family,address,transport,label=case
    name='rh-'+nonce+'-'+label+'.example.com'
    question=struct.pack('!HHHHHH',1234,256,1,0,0,0)+b''.join(bytes([len(part)])+part.encode() for part in name.split('.'))+b'\0\0\1\0\1'
    with socket.socket(family,transport) as connection:
        connection.settimeout(4)
        try:
            connection.connect((address,53))
            connection.sendall(question if transport==socket.SOCK_DGRAM else struct.pack('!H',len(question))+question)
            def exact(n):
                data=b''
                while len(data)<n:
                    chunk=connection.recv(n-len(data))
                    if not chunk: raise OSError('closed')
                    data+=chunk
                return data
            answer=connection.recv(4096) if transport==socket.SOCK_DGRAM else exact(struct.unpack('!H',exact(2))[0])
            success=len(answer)>=12 and answer[:2]==question[:2] and bool(answer[2]&128) and answer[6:8]!=b'\0\0'
        except OSError: success=False
    return label,success
cases=[(family,address,transport,str(version)+'-'+kind) for version,family,address in [(4,socket.AF_INET,'10.44.0.1'),(6,socket.AF_INET6,'fd44:1::1')] for kind,transport in [('udp',socket.SOCK_DGRAM),('tcp',socket.SOCK_STREAM)]]
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    print(json.dumps(dict(pool.map(query,cases))))
'''


def main():
    lab=boot.Lab('routeharbor-openwrt-boot-lab')
    lab.wait_api()
    # A deliberately permissive calibration is bounded to this private synthetic
    # WAN. Only exact rules proven present are removed; quarantine restores them.
    owners=[]
    for family in [4,6]:
        rules=json.loads(lab.guest('ip -'+str(family)+' -j rule show\n').stdout)
        for offset,protocol in [(0,'tcp'),(1,'udp')]:
            matches=[r for r in rules if r.get('priority')==29900+offset]
            assert len(matches)==1,'Missing unique installed DNS guard'
            rule=matches[0]
            assert set(rule)<=set(['priority','src','uid_start','uid_end','ipproto','dport','action','protocol'])
            uid=rule.get('uid_start')
            assert isinstance(uid,int) and 0<uid<2**31 and rule.get('uid_end')==uid
            assert rule.get('src')=='all' and rule.get('ipproto')==protocol and rule.get('dport')==53 and rule.get('action')=='blackhole'
            owners.append((family,offset,uid))
    backup='/root/routeharbor-lab/dhcp-before-uncached-dns'
    lab.guest('test ! -e '+backup+'\ncp /etc/config/dhcp '+backup+'\n')
    try:
        lab.guest("uci set dhcp.@dnsmasq[0].noresolv='1'\n"
                  "uci -q delete dhcp.@dnsmasq[0].server || true\n"
                  "uci add_list dhcp.@dnsmasq[0].server='8.8.8.8'\n"
                  "uci add_list dhcp.@dnsmasq[0].server='2001:4860:4860::8888'\n"
                  "uci set dhcp.@dnsmasq[0].allservers='1'\nuci commit dhcp\n/etc/init.d/dnsmasq restart\n")
        server=boot.start_background(lab,'uncached-dns','routeharbor-wan',SERVER)
        atexit.register(lab.signal,server,signal.SIGTERM,check=False)
        time.sleep(6)
        lab.signal(server,0)
        for phase in ['permissive-calibration','guard-active','nft-flushed']:
            if phase=='permissive-calibration':
                lab.guest('fw4 flush\n'+''.join('ip -'+str(family)+' rule del priority '+str(29900+offset)+' uidrange '+str(uid)+'-'+str(uid)+' ipproto '+('6' if offset==0 else '17')+' dport 53 blackhole\n' for family,offset,uid in owners))
            elif phase=='guard-active': lab.guest('/usr/libexec/routeharbor-helper quarantine --state-dir /etc/routeharbor-helper\n')
            else: lab.guest('fw4 flush\n')
            nonce=uuid.uuid4().hex[:12]
            path='/tmp/routeharbor-boot-uncached-'+phase+'.pcap'
            capture=boot.start_capture(lab,path)
            process=subprocess.Popen(['docker','exec','-i',lab.container,'ip','netns','exec','routeharbor-client','python3','-c',CLIENT,nonce],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            time.sleep(0.7)
            sockets=lab.guest("for pid in $(pidof dnsmasq); do sed -n '/^Name:/p;/^Uid:/p;/^Gid:/p' /proc/$pid/status; done\ncat /proc/net/udp /proc/net/udp6\n").stdout
            stdout,stderr=process.communicate(timeout=20)
            assert process.returncode==0,stderr
            observed=boot.stop_capture(lab,capture,path)
            forwarded=[line for line in observed.splitlines() if '.53:' in line or '.53 ' in line]
            answers=json.loads(stdout)
            print(json.dumps({'phase':phase,'unique_query_nonce':nonce,'client_answers':answers,'WAN_query_count':len(forwarded),'WAN_queries':forwarded,'kernel_socket_ownership':sockets}),flush=True)
            if phase=='permissive-calibration':
                assert len(answers)==4 and all(answers.values()),'Real TCP/UDP gateway DNS calibration failed'
                assert forwarded,'WAN capture missed permitted DNS'
            else:
                assert not forwarded,'Protected DNS emitted WAN packets (including TCP handshakes)'
                assert not any(answers.values()),'Uncached query unexpectedly resolved while protected'
    finally:
        lab.guest('/usr/libexec/routeharbor-helper quarantine --state-dir /etc/routeharbor-helper\n'
                  'cp '+backup+' /etc/config/dhcp\n/etc/init.d/dnsmasq restart\n'
                  'sha256sum /etc/config/dhcp '+backup+'\nrm -f '+backup+'\n')


if __name__=='__main__':
    main()
