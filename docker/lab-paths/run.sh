#!/bin/sh
set -eu
# Destructive operations are restricted to disposable named network namespaces in this lab container.
[ "$(id -u)" = 0 ] || { echo 'This lab requires root inside a disposable Linux container.' >&2; exit 1; }
[ "$(nfqws --version | sed -n '1p')" = 'github version v72.10 (f0b0d89)' ] || { echo 'Unverified nfqws build.' >&2; exit 1; }
mkdir -p /tmp/routeharbor-lab
cleanup() {
  for namespace in rh-gw rh-px rh-srv; do
    ip netns pids "$namespace" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns del "$namespace" 2>/dev/null || true
  done
  ip link del rh-lab-br 2>/dev/null || true
}
trap cleanup EXIT INT TERM
ip link add rh-lab-br type bridge
ip link set rh-lab-br up
for item in gw:2 px:3 srv:4; do
  name=${item%:*}
  addr=${item#*:}
  ip netns add "rh-$name"
  ip link add "rh-$name-v" type veth peer name "rh-$name-n"
  ip link set "rh-$name-v" master rh-lab-br
  ip link set "rh-$name-v" up
  ip link set "rh-$name-n" netns "rh-$name"
  ip -n "rh-$name" link set lo up
  ip -n "rh-$name" link set "rh-$name-n" up
  ip -n "rh-$name" address add "10.210.0.$addr/24" dev "rh-$name-n"
done
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout /tmp/routeharbor-lab/key.pem -out /tmp/routeharbor-lab/cert.pem -subj '/CN=lab.example' -addext 'subjectAltName=DNS:lab.example' >/dev/null 2>&1
ip netns exec rh-srv python3 /lab/lab.py https >/tmp/routeharbor-lab/https.log 2>&1 &
ip netns exec rh-px python3 /lab/lab.py proxy >/tmp/routeharbor-lab/proxy.log 2>&1 &
ip netns exec rh-gw nfqws --qnum=21002 --dpi-desync-fwmark=0x4f028000 --filter-tcp=443 --dpi-desync=multisplit --dpi-desync-split-pos=1,midsld --dpi-desync-repeats=1 --user=nobody --debug=1 >/tmp/routeharbor-lab/dpi-a.log 2>&1 &
echo "$!" >/tmp/routeharbor-lab/dpi-a.pid
ip netns exec rh-gw nfqws --qnum=21003 --dpi-desync-fwmark=0x4f038000 --filter-tcp=443 --dpi-desync=multisplit --dpi-desync-split-pos=1,midsld --dpi-desync-repeats=1 --user=nobody --debug=1 >/tmp/routeharbor-lab/dpi-b.log 2>&1 &
ip netns exec rh-gw nft -f - <<'NFT'
table inet routeharbor_probe_lab {
 counter dpi_a {}
 counter dpi_b {}
 chain output {
  type filter hook output priority mangle; policy accept;
  meta mark & 0x8000 != 0 return
  meta mark & 0xffff0000 == 0x4f020000 tcp dport 443 counter name dpi_a queue num 21002
  meta mark & 0xffff0000 == 0x4f030000 tcp dport 443 counter name dpi_b queue num 21003
 }
}
NFT
sleep 1
ip netns exec rh-gw python3 /lab/lab.py check
# nfqws debug must confirm actual desynchronization, not an NFQUEUE pass-through stand-in.
grep -qi 'multisplit' /tmp/routeharbor-lab/dpi-a.log
grep -qi 'multisplit' /tmp/routeharbor-lab/dpi-b.log
printf '%s\n' 'PASS: direct, real nfqws profiles A/B and CONNECT proxy used independent paths; profile A crash failed closed.'
