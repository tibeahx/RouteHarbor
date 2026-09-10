# OpenWrt boot and network recovery evidence

This checkpoint was measured on 9 September 2026 in an isolated full-system
OpenWrt VM. It is guest-kernel and boot evidence, not physical router, switch or
radio acceptance. The initial correction checkpoint used a locally compiled
helper installed in the disposable guest. The final SDK-package run and its
separate control-packet accounting are recorded below.

## Environment

- Official OpenWrt 24.10.7 x86/64 ext4 combined image, Linux 6.6.141, PID 1 procd.
- Compressed image SHA-256:
  `3caea69f186b2bce80938d265e5e2a3dfd0f8713aed101df35d60b88d7270d1f`.
- QEMU 7.2.22 TCG inside Docker, `--network none`; no physical NIC, host network,
  host disk device, published port or Internet uplink.
- One guest CPU, 512 MiB RAM. A private writable qcow2 disk uses the verified
  image as its immutable base. SSH host identity is pinned from trusted serial.
- The harness uses QEMU `-no-reboot`: the guest performs its actual graceful
  shutdown, QEMU exits, and the harness starts a fresh QEMU process on the same
  disk. This avoids an intermittent emulated GRUB warm-reset stall. Abrupt
  powercut explicitly kills QEMU without guest shutdown before restarting it.
- Guest LAN `br-lan`/`eth0`: `10.44.0.1`, `fd44:1::1`; separate client namespace:
  `10.44.0.20`, `fd44:1::20`. Guest WAN `eth1`: `198.18.0.2`, `fd44:2::2`.
- `8.8.8.8` and `2001:4860:4860::8888` are loopback aliases in a separate synthetic
  WAN namespace, with local test responders. No packets reach those Internet hosts.
- Tested helper SHA-256:
  `3dc3cd30be488d4d90244b21aca98a48d509f9da6215253f8b11f435e51cd3cb`.
  The subsequent private `IngressBound` serialization correction has a focused
  restart regression; the final SDK rebuild must include that correction.

## Findings and reproduced corrections

| Case | Evidence | Outcome |
| --- | --- | --- |
| Helper starts before netifd has addresses | Actual boot failed with `router_addresses_unavailable`; native namespace starts with no interfaces/addresses | Only quarantine accepts empty discovered addresses; normal apply remains strict |
| nft flush with uncached gateway DNS | Actual dnsmasq emitted unique UDP queries over IPv4 and IPv6 | Dedicated verified DNS UID rules block upstream TCP/UDP53 independently of nft |
| Shutdown bridge teardown | Continuous capture saw unNATed IPv4 TCP/UDP; source MAC matched guest WAN | Persisted verified bridge-member ingress guards close the bypass |
| Controlled teardown without reboot | Stop API/helper; LAN and loopback down while WAN stays up; restore after one second | Baseline leaked; temporary rule prototype and production implementation both produced empty capture |
| Graceful reboot, nft flush, abrupt QEMU kill | Continuous fresh IPv4/IPv6 TCP and UDP traffic; live capture and generator progress checked throughout | After production fix, complete capture empty; helper recovered after both boots and LAN management remained available |
| Real DNS transport calibration | Valid framed TCP and UDP DNS responders; four IPv4/IPv6 client-to-gateway queries | All four answered with only the exact DNS guards temporarily removed in this private lab |
| Protected uncached DNS, then total nft flush | Same responders and fresh names; capture checks all WAN destination53 packets, including TCP SYNs | Four queries unanswered and zero WAN DNS packets in each protected phase |

Cached/local gateway DNS replies after nft loss are reported separately. They are
not WAN leakage evidence. The uncached test checks actual upstream transmissions.
The observed dnsmasq2.90 upstream socket UID is 453; root-opened listening sockets
are expected. A root `ujail` process is distinguished from the unprivileged DNS
worker and TCP children. Source inspection and admission restrictions for
preallocated root sockets are recorded in the DNS source review.

The earlier eight-packet capture was not dismissed as a QEMU artifact. A later
capture reproduced the same shutdown failure and a controlled service/interface
teardown reproduced it without reboot. Both before/after traces were retained.

## Reproduction and retained files

- `scripts/lab-openwrt-vm.sh` and `docker/lab-openwrt-vm/vmctl.py`: verified private
  image, transport, graceful shutdown, powercut and stopped-disk pristine restore.
- `scripts/lab-openwrt-early-guard.py`: already-installed, confirmed-closed guest
  transition test with a unique pcap path for each run.
- `scripts/lab-openwrt-dns-egress.py`: explicit synthetic-WAN calibration followed
  by protected DNS assertions. It restores the exact DHCP file and quarantine.
- `scripts/lab-network.sh`: isolated native Linux rules, bridge deletion, DNS
  owner/foreign-owner checks, conntrack, crash rollback and detached watchdogs.
- Local ignored artifacts under `test-results/openwrt-boot-network/`: before/after
  boot and controlled-teardown logs, calibrated DNS log and synthetic pcaps.
- Host-side working logs remain under `/private/tmp/routeharbor-vm/`.

After this checkpoint, `/etc/config/network`, `/etc/config/firewall` and
`/etc/config/dhcp` matched their pre-install hashes. The temporary serial monitor
startup entry was removed. The VM was handed back to the parent acceptance run
with a confirmed closed policy, private DNS ownership and the physical `eth0`
ingress guard. The pristine checkpoint remains available for clean final-package
provisioning. Temporary running monitors disappear at the next VM restart.

## Final SDK package run

The disposable guest was restored from its stopped-disk pristine checkpoint and
provisioned with the final `source-hsdpl8_b` x86/64 SDK artifacts, version
`0.1.0-r1`: controller, guard, node and optional conntrack packages. Package bytes
were copied from the selected host artifacts and checked again in the guest;
the older read-only package mount was not used. This includes the final private
`IngressBound` correction. Installation, trusted setup, confirmed closed routing,
actual guest reboot, firewall reload/flush, QEMU powercut, helper recovery and
LAN management checks passed. Original network, firewall and DHCP hashes matched.

The first strict outgoing-capture assertion correctly reported four unexpected
packets. They were not discarded by TCP flags. A second clean full run reproduced
them while recording simultaneous bidirectional WAN and LAN Ethernet captures,
starting before the four persistent client connections were opened. Socket
addresses/ports and confirmation/recovery timestamps were recorded independently.

**Final result: 0 forwarded protected client packets; 4 router-generated
rejects.** The total outgoing WAN capture is not empty. Each reject is a bare
zero-payload TCP reset responding to a retransmission from the synthetic WAN
server on an already recorded pre-policy connection after the first reboot:

| Family | Client port | Server port | Incoming ACK = reset sequence | Response delay |
| --- | ---: | ---: | ---: | ---: |
| IPv4 | 35152 | 53 | 3625051855 | 1.329 ms |
| IPv4 | 55192 | 18080 | 917762119 | 1.343 ms |
| IPv6 | 39200 | 53 | 805623445 | 0.745 ms |
| IPv6 | 59142 | 18080 | 1431468064 | 0.759 ms |

The resets left the guest WAN MAC with TTL/hop-limit 64. The same initial client
connections were observed on LAN at 64 and forwarded to WAN at 63. Every reset
matches the reverse tuple and exact ACK of an immediately preceding WAN
PSH+ACK. Its payload/sequence/ACK match an earlier captured server retransmission.
There is no matching LAN-origin reset, and the specific triggering copy did not
reach the LAN. Earlier copies of old server data did reach the LAN before reboot;
that is recorded separately from the protected outbound-traffic assertion.
The IPv6 source is the client's observed SLAAC address, not an assumed gateway
address. WAN captured 3,210 packets and LAN 58,796; all three captures reported
zero dropped packets. After confirmation, the only outgoing frames were these
four control replies: no new SYN, UDP or client payload escaped.

`docker/lab-openwrt-vm/capture.py` requires all these proofs for each individual
reset and reports the control-reply count separately. It does not exclude RSTs
from capture. A missing inbound match, wrong sequence, observed LAN reset,
forwarded TTL, SYN/data/UDP, unknown connection, duplicate reset, missing initial
calibration, truncated capture or packet loss fails the assertion. The final
assertion shared by the live harness and read-only evidence replay passed on the
saved full-run captures; 17 capture tests and four checkpoint tests passed using
Python's standard `unittest` without Docker.

The retained local evidence is under `test-results/openwrt-boot-network/`:

- `final-sdk-duplex.log`: real install/boot phases and pre-policy socket inventory.
- `final-sdk-capture-metadata.json`: exact inputs for the shared final assertion.
- `final-sdk-{wan,lan}-duplex.pcap`, `final-sdk-reset-reproduced.pcap` and their
  `.tcpdump.log` count records; the initial unexpected reset capture is retained
  as `final-sdk-reset-before.pcap`.

Replay without accessing a VM:

```sh
python3 scripts/lab-openwrt-boot.py --verify-captures \
  test-results/openwrt-boot-network/final-sdk-capture-metadata.json
python3 -m unittest discover -s docker/lab-openwrt-vm -p 'test_*.py'
```

The actual WAN duplex pcap SHA-256 is
`4d69cd8036371810cb2635caa27eb265b202048baae990d24920ff76ec248696`;
the LAN duplex pcap SHA-256 is
`fbab782224da9d7b877c992e1679caffeac2ced26f4e87a6552c55eec3a71c4c`.
No production change was made in response to these proven router control replies.
After verification, the installed final SDK baseline was handed to the separate
maintenance acceptance run with confirmed closed routing, no maintenance hold or
job, no temporary lab CA, and no remaining synthetic WAN listener.

## Router-recursive DNS limitation

The dedicated dnsmasq UID TCP/UDP53 guard remains installed for every managed
routing plan, including an explicitly selected Direct source. It blocks uncached
upstream DNS requests issued by the router's dnsmasq process; there is currently
no separate selected-path route for that router-originated recursion. Router
applications using that resolver, such as package tools or NTP hostname lookup,
can therefore fail to resolve uncached names. Cached/local DNS answers and local
management remain available. Client DNS intercepted by selected-path rules and
per-source probe DNS are separate paths and do not remove this limitation.

This is an explicit functional limitation of this development PR. The current
change retains the verified closed guard rather than adding an unverified direct
exception. The VM checks above do not claim that ordinary router-recursive DNS
continues to work while managed routing is installed.
