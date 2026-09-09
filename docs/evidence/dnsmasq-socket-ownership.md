# DNS socket ownership review

This source review supports the dedicated resolver UID guard. It does not replace
packet capture, prove arbitrary dnsmasq configurations safe, or certify a device.

The reviewed OpenWrt release is **24.10.7**, whose
[dnsmasq recipe](https://github.com/openwrt/openwrt/blob/v24.10.7/package/network/services/dnsmasq/Makefile)
selects upstream **2.90**, package revision 5. The official upstream source archive
has SHA-256
`8e50309bd837bfec9649a812e066c09b6988b73d749b7d293c06c57d46a109e4`.
The archive was checked against the recipe before extraction. All eleven
[release patches](https://github.com/openwrt/openwrt/tree/v24.10.7/package/network/services/dnsmasq/patches)
were inspected. None moves upstream DNS socket allocation across privilege drop.
The ubus patch closes inherited ubus listeners in TCP children.

Upstream source locations refer to the verified, unpatched archive:

| Location | Finding |
| --- | --- |
| `src/dnsmasq.c:463` | Upstream socket preallocation runs before privilege drop. |
| `src/dnsmasq.c:781` | The main process drops to its configured non-root UID. |
| `src/dnsmasq.c:1046` | Server checks and then the normal event loop run after that drop. |
| `src/network.c:1457` | With default randomized source ports, zero-source-port server sockets are deferred. |
| `src/network.c:1519` | Explicit query/source ports can create root-owned upstream UDP sockets during startup. |
| `src/option.c:3438` | Even explicitly setting `query-port=0` selects a different socket allocation mode. |
| `src/forward.c:2561` | Normal randomized UDP forwarding allocates its socket on demand. |
| `src/dnsmasq.c:1955` and `src/forward.c:1965` | TCP forwarding forks after privilege drop and creates new upstream sockets in that child. |

Therefore, the process UID alone is insufficient evidence for a DNS egress guard.
Admission must also inspect the effective configuration, included files/directories,
server source bindings and actual socket ownership. A root-owned listening socket
on port 53 is distinct from an upstream socket sending to port 53. Explicit
`query-port`, including zero, and configurations that preallocate upstream sockets
must not be admitted under the default randomized-port proof.

OpenWrt's
[init script](https://github.com/openwrt/openwrt/blob/v24.10.7/package/network/services/dnsmasq/files/dnsmasq.init)
can generate additional configuration through `queryport`, server lists,
`serversfile`, `confdir` and `extraconftext`, as well as an existing configuration
file. Inspecting only the generated top-level file would miss those inputs.

The configuration reader also uses `fgets(buff, MAXDNAME)` in
`src/option.c:5377`, with `MAXDNAME=1025` in `src/dns-protocol.h:26`. A physical
line can therefore become multiple parser inputs. An isolated `dnsmasq --test`
run on the actual OpenWrt 2.90 package accepted a short comment, but rejected a
comment padded to 1024 bytes followed by an invalid option as an option on line
2. No DNS service or network was started for that test. Admission rejects physical
lines longer than 1023 bytes before skipping comments, so its interpretation cannot
hide options in later `fgets` fragments.

The isolated VM reproduced four distinct uncached client queries reaching its
synthetic WAN through dnsmasq after a total nftables flush. Upstream sockets used
the dedicated non-root resolver UID; listening sockets used root. This establishes
actual forwarding, unlike a cached local-name reply. A corrected implementation
must pass the same real DNS fixture for both IP families and transports, including
resolver restart, before this review can support a successful runtime result.
