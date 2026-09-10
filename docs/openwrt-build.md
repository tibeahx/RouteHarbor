# OpenWrt SDK packages

RouteHarbor uses the OpenWrt SDK to produce packages for the SDK's exact release and
package architecture. A Linux Go architecture is not an OpenWrt package
architecture. A successful package build is not evidence of router compatibility.

The source recipe is `packaging/openwrt/routeharbor/Makefile`. It builds the controller,
privileged helper and node binary with the pinned Go 1.27.1 runtime, no CGO and no
network dependency downloads. It produces these separate packages:

| Package | Responsibility |
| --- | --- |
| `routeharbor` | Unprivileged gateway controller, embedded English UI, setup command and conntrack dependency for selective DNS recovery |
| `routeharbor-guard` | Root helper, detached watchdog and persistent safety policy |
| `routeharbor-node` | Unprivileged paired-node TLS agent and separate root node helper |
| `routeharbor-conntrack` | Compatibility alias for the connection tracking dependency now required by the core gateway package |
| `routeharbor-sing-box` | Optional dependency bundle for the upstream sing-box package and TPROXY modules |
| `routeharbor-xray` | Optional dependency bundle for the upstream Xray package and TPROXY modules |

The engine adapters check their supported versions at runtime. Installing a bundle
does not make an incompatible engine version supported. nfqws v72.10 remains a
separate, administrator-verified engine installation; the project does not ship
an unverified executable download or redistribute that engine in its own package.

Switches preserve established connection marks by default. The optional
`policy.break_existing` field enables a bounded reset of the previous source's
tracking after routing confirmation. Pass both-family privileged preflight before
enabling it. The core gateway now installs conntrack because selective emergency
recovery also removes only the dispatcher slot's DNS NAT state; this restores
normal DNS for applications that reuse an existing UDP socket. A failed reset remains visible while the
new route stays confirmed; see [configuration](configuration.md). The upstream
[conntrack package](https://github.com/openwrt/packages/blob/openwrt-24.10/net/conntrack-tools/Makefile)
installs the fixed `/usr/sbin/conntrack` utility and pulls kernel netlink support
through its library dependencies.

## Build from a verified SDK

Obtain the SDK for the required OpenWrt target/subtarget from the official OpenWrt
release infrastructure. Verify the signed checksum file against independently
trusted OpenWrt signing keys before extracting it. Do the same for Go using the
official Go release digest. `scripts/sdk-build.sh` deliberately downloads nothing
and does not establish trust from an adjacent, unverified checksum file.

Run on Linux with a complete SDK and the verified Linux Go runtime:

```sh
scripts/sdk-build.sh /absolute/path/to/openwrt-sdk /absolute/path/to/go/bin/go
```

The script stages only the owned SDK package directory, preserves other packages,
and invokes the SDK's package machinery. SDK generations using opkg produce IPK
packages; generations using apk produce APK packages. No custom archive writer
renames a tarball into an IPK or APK. Output is under the SDK's `bin/packages` and
`bin/targets` directories.

The script uses the SDK's `NO_DEPS=1` build-graph option because these CGO-free
binaries compile only with the supplied Go toolchain. Runtime `DEPENDS` entries
remain in every package and are enforced by the router's package manager. This
avoids rebuilding firmware kernel modules: the 24.10.7 SDK hardcodes unrelated
kernel packages as enabled, including modules absent from its prebuilt kernel.
It does not disable package installation dependency checks.

The build supports Go targets 386, amd64, arm, arm64, mips, mipsle, mips64,
mips64le and riscv64. It chooses conservative ARM and MIPS floating-point options
for the standard-library, CGO-free binaries. Unsupported SDK architectures fail
before compilation. Engine support, CPU features, endianness and device resources
must also pass the release matrix; see [compatibility](compatibility.md).

Package files from a local SDK run are development artifacts. A stable release
also requires source-commit provenance, hashes, SBOM, release signatures and the
OpenWrt and physical-device acceptance gates in [release/update policy](updates.md).

## Service and state layout

OpenWrt's `/var` is normally backed by temporary storage. Durable state therefore
lives under `/etc`, while engine runtime files remain under `/var/run`.

| Path | Owner and contents |
| --- | --- |
| `/etc/routeharbor` | `routeharbor`, mode 0700; controller configuration and credential store |
| `/etc/routeharbor-helper` | root, mode 0700; durable transaction journal and generated guard |
| `/etc/routeharbor-maintenance` | root, mode 0700; independently supplied trust key, signed offline package cache and durable maintenance jobs |
| `/var/run/routeharbor` | root; helper socket, mode 0600, assigned to the API user |
| `/var/run/routeharbor-engines` | `routeharbor`, mode 0700; temporary engine configuration |
| `/var/run/routeharbor-engine-worker` | root, mode 0700; transient helper-generated engine configuration, unlinked after opening |
| `/etc/routeharbor-node` | `routeharbor-node`, mode 0700; node identity and pairing state |
| `/etc/routeharbor-node-helper` | root, mode 0700; node UCI transaction state |

User/group IDs are allocated by the SDK's package user machinery and resolved at
service start. The root helper authenticates the actual connecting UID with
`SO_PEERCRED`; it does not trust the socket pathname alone.

For managed transparent proxies, the root helper independently validates the
typed source and regenerates its configuration. It launches the pinned engine
under the authenticated API's service UID/GID with empty supplementary groups
and only `CAP_NET_RAW` in the permitted, effective, inheritable and ambient sets.
The API receives no capability. This permits transparent input sockets without
running the engine as root or changing executable file capabilities. A private
connection controls its lifetime; loss of either API or helper stops the engine.

A fresh installation leaves both gateway and node service configuration disabled
and the persistent guard empty. It does not edit WAN, PPPoE, DHCP, SSID or the user's
firewall UCI. Gateway bootstrap is performed through existing administrator access:

```sh
mkdir -p /root/routeharbor-private
chmod 0700 /root/routeharbor-private
/usr/libexec/routeharbor-setup /root/routeharbor-private/admin.token
```

This starts the panel on loopback. Open it through a trusted SSH tunnel, or
explicitly configure an authenticated LAN TLS listener with its exact allowed
Host value. The token is written to a private file, never printed by setup. The
saved traffic configuration remains disabled until a network transaction is
prepared, applied and confirmed. Repeating setup with the existing credential
file preserves the identity and does not overwrite sources.

## Lifecycle controls and validation

Before enabling network routing, the helper verifies fw4 automatic includes and
the installed ruleset-scope guard include. It persists a guard before applying
rules. The guard init script synchronously restores safety at startup order 18,
before the normal OpenWrt firewall order 19 and network startup. The API starts
later as an unprivileged process. On controller/helper stop, the saved policy is
quarantined and LAN management remains reachable.

A strict policy also has independent input-interface routing rules and a
blackhole default route. Explicit per-source marks select the permitted path
before that rule. This prevents a complete nftables flush from releasing
unmarked LAN traffic onto the ordinary WAN; explicitly mapped local LAN routes
remain available. The fw4 include restores the packet guard on firewall reload.
The controller must reapply its confirmed path to clear the guarded state.

The isolated Linux lab executes generated nft rules and policy routes, selected
DNS DNAT, foreign-object refusal, nft-flush protection for IPv4/IPv6, local-LAN
reachability and a real detached watchdog after helper SIGKILL:

The same lab starts the pinned nfqws with its dedicated supervisor, kills its
manager after nfqws drops to the `nobody` account, and verifies the supervisor
terminates and reaps the process. Linux parent-death signals alone are
insufficient because changing credentials [clears that signal](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html).

```sh
scripts/lab-network.sh
scripts/lab-engine-worker.sh
python3 packaging/tests/test_packaging.py
```

The engine-worker lab checks both native engines' service credentials and
capability sets, owned TCP/UDP/IPv6 sockets, API and helper SIGKILL cleanup, and
restoration of the confirmed input ports through a new unprivileged API process.

The separate [OpenWrt SDK/userland lab](evidence/openwrt-sdk.md) built real IPKs
and tested normal opkg installation, packaged procd services, repeat setup,
unprivileged capability discovery through the helper, API transactions, fw4
lifecycle and protected removal. Run it with independently verified inputs:

```sh
python3 scripts/lab-openwrt.py --packages /absolute/current-sdk-ipks
```

The labs use isolated Docker containers with no host or external networking.
The Linux kernel/engine labs do not test procd. The OpenWrt userland lab runs real
procd as a child of the container shell and uses the Docker Linux kernel. Neither
is a full OpenWrt boot, kernel-module ABI, radio or physical-router test. Physical
acceptance status is recorded separately in the release matrix.

The integration follows OpenWrt's [fw4 include discovery](https://github.com/openwrt/firewall4/blob/master/root/usr/share/ucode/fw4.uc)
and [firewall lifecycle](https://github.com/openwrt/firewall4/blob/master/root/etc/init.d/firewall).
`fw4 flush` deletes every nft table; the independent routing guard exists for that
specific lifecycle case.

The optional `routeharbor-continuity` package installs `/usr/libexec/routeharbor-continuity`
for private relay session continuity and depends on gateway plus TPROXY/socket
kernel support. It is separate from the base gateway install, has no independently
enabled procd service, and is started through the authenticated helper. The SDK
recipe now produces seven package variants; historical six-package evidence does
not certify this new worker. `make build` and `scripts/build-matrix.sh` also include
`routeharbor-continuity` and the VPS binary `routeharbor-relay`. Pairing and the VPS service
are described in [session-continuity.md](session-continuity.md).
