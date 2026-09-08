# Compatibility and resource evidence

OpenRHP targets OpenWrt interfaces, not a router brand. **No physical device is
certified yet.** Xiaomi AX3200 is a planned household test device, not the product's
platform definition. The second household router has not been identified.

## Platform contract

- Linux with OpenWrt release/package metadata, procd, UCI/ubus/netifd.
- Implemented firewall backend: fw4/nftables. fw3/iptables is not implemented and
  fails preflight; running nft commands on a fw3 device is not a compatibility layer.
- Protected routing requires installed persistent lifecycle guard, owned RPDB guard
  support, observed interfaces and explicit offload handling. Capabilities are
  checked independently: missing NFQUEUE does not disable proxy source storage.
- TPROXY/UDP/IPv6, packet queues and engines must each pass kernel/native checks.
  A TCP-only proxy explicitly blocks UDP. DNS has an explicit chosen policy/resolver.
- Node Ethernet bridging requires matching discovered management bridge and one
  uplink. Wireless requires a verified encrypted compatible pair and gateway-side
  backhaul setup; generic AP-mode advertising alone is insufficient.
- Package format follows the SDK/OpenWrt generation. 24.10 uses ipk/opkg; 25.12
  packaging uses apk. A compiled Linux binary is not an installable router package.

## Compilation matrix

[Recorded compiler output](evidence/build-matrix.csv) contains byte sizes for the
controller, network helper, node agent and release verifier. `scripts/build-matrix.sh`
uses Go 1.27.1, `CGO_ENABLED=0`, trimpath, stripped symbols and no build ID.
The following have cross-compiled successfully; this is **compilation evidence**.

| Linux variant | Go setting | ABI/instruction boundary |
| --- | --- | --- |
| x86-64 | GOARCH=amd64 | Baseline Go AMD64; not a package-architecture name |
| x86 | GOARCH=386 | Go 386 target; exact OpenWrt CPU requirements still checked |
| ARMv5 | GOARCH=arm, GOARM=5 | Go default soft-float for v5 |
| ARMv6 | GOARCH=arm, GOARM=6 | Go default hardware floating-point requirement |
| ARMv7 | GOARCH=arm, GOARM=7 | Go default hardware floating-point requirement |
| AArch64 | GOARCH=arm64 | Baseline ARM64; includes potential mt7622 package family |
| MIPS big-endian | GOARCH=mips, GOMIPS=softfloat | Explicit endianness/soft-float |
| MIPS little-endian | GOARCH=mipsle, GOMIPS=softfloat | Explicit endianness/soft-float |
| MIPS64 big-endian | GOARCH=mips64, GOMIPS64=softfloat | Explicit endianness/soft-float |
| MIPS64 little-endian | GOARCH=mips64le, GOMIPS64=softfloat | Explicit endianness/soft-float |
| RISC-V 64 | GOARCH=riscv64 | Go RV64 baseline |

Use the [SDK mapping](openwrt-build.md) for the actual OpenWrt package architecture.
Unsupported Go architectures (for example 32-bit PowerPC) are **not** advertised as
supported. If a required target cannot be built, it needs a different implementation
or toolchain decision, not a renamed artifact. No release claims universal hardware
support. No QEMU execution evidence is claimed merely from cross-compilation.

## Measurements

The minimal HTTP-bearing portability prototype compiled to 3.13–3.94 MiB across
this matrix; exact bytes are in [prototype evidence](evidence/minimal-prototype.csv).
The actual controller is larger: approximately 7.9–9.8 MiB stripped at the recorded
snapshot, excluding helpers and engines. Consult exact byte counts and the
working-tree basis in [build validation](evidence/build-validation.md).

One idle local **macOS ARM64 development** controller process was observed at
15,296 KiB RSS. This is not a Linux/OpenWrt memory minimum, a load test, or a promise
for weak routers. The 32 MiB controller RSS objective still needs measurements on
multiple device classes. Engine memory/flash/CPU costs are additional and separate.

Sources remain portable; interface bindings do not. Disabled engines are not started.
On weak devices use fewer active engines, less frequent probes and shorter histories.
The runtime enforces configured response/concurrency/history budgets and at most
250 simultaneous routing slots; the saved-source model has no arbitrary source count.

The current evidence ledger, including real Linux and remaining OpenWrt/physical
acceptance, is [verification.md](verification.md).
