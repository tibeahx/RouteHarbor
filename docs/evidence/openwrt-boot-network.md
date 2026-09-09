# OpenWrt boot and network recovery evidence

This checkpoint was measured on 9 September 2026 in an isolated full-system
OpenWrt VM. It is guest-kernel and boot evidence, not physical router, switch or
radio acceptance. Final SDK-package provisioning is recorded separately; this
checkpoint used a locally compiled helper installed in the disposable guest.

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
- Host-side working logs remain under `/private/tmp/openrhp-vm/`.

After this checkpoint, `/etc/config/network`, `/etc/config/firewall` and
`/etc/config/dhcp` matched their pre-install hashes. The temporary serial monitor
startup entry was removed. The VM was handed back to the parent acceptance run
with a confirmed closed policy, private DNS ownership and the physical `eth0`
ingress guard. The pristine checkpoint remains available for clean final-package
provisioning. Temporary running monitors disappear at the next VM restart.
