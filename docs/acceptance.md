# Acceptance checklist

This checklist separates explicit user requests, implemented software and the
remaining acceptance evidence in the original implementation plan. A passed
unit test, container test or user-mode emulator is not physical-router acceptance.
The implementation plan is still open until the required end-to-end VM and
hardware gates are satisfied. On 2026-09-09 the user paused further improvements
and lab scenarios, requested publication of the current changes through a PR,
and deferred physical installation until their next message. Outstanding cases
below are an acceptance ledger, not an instruction to keep expanding this PR.

## Explicit user requests

- [x] Project name: **RouteHarbor**, an adaptive routing gateway.
- [x] English UI, following the user's clarification over the original plan's
  initial Russian-language default.
- [x] A public repository under the current `tibeahx` account was created and
  published: [tibeahx/RouteHarbor](https://github.com/tibeahx/RouteHarbor).
- [x] Go **1.27.1**, verified as the latest stable version during implementation,
  is pinned and used by the build and CI.
- [x] golangci-lint **2.13.2**, verified as the latest stable version during
  implementation, is pinned with archive checksums. `scripts/lint.sh` runs locally
  and in CI; its `--fix` mode was actually run on host and Linux targets.
- [x] Built-in Go formatters and pinned Prettier format Go and the embedded web UI.
  Local formatter/check commands and CI checks are present and were executed.
- [x] The observed CI failure was fixed. The published
  [b314ebf](https://github.com/tibeahx/RouteHarbor/commit/b314ebfe2e9463d752799b95ca44e0400838c718)
  checkpoint passed all five CI jobs. The additional implementation in
  [PR #1](https://github.com/tibeahx/RouteHarbor/pull/1) also passed all five required
  checks at `d59dcc4`. The user merged that PR as `88d5b71` on 2026-09-09.
  Later corrections and acceptance additions are on a separate branch and require
  their own PR and CI run; the user retains responsibility for merging it.
- [ ] The complete original implementation plan has met every acceptance gate.

## Executed software evidence

- [x] Required-resource selection, degradation, hysteresis, recovery and bounded
  extra speed probes: deterministic and race tests.
- [x] Independent source paths and native engine/process privilege boundaries:
  real Linux namespace, packet-engine and engine-worker labs.
- [x] API/UI parity, authentication, revision/idempotency, redaction and recovery:
  API tests and real embedded-UI browser tests. Fixture-only UI tests are labelled.
- [x] Node pairing and coordinated gateway/node transactions: real local TLS with
  typed UCI test boundaries; real upstream UCI parser preservation tests; separate
  detached watchdog process tests. These do not prove radio compatibility.
- [x] Ordinary SDK-generated OpenWrt package installation and service lifecycle:
  actual OpenWrt userland in a Docker container, under the Docker Linux kernel.
- [x] All eighteen current SDK IPKs across x86_64, ARM64 and MIPS32:
  exact package/control identities, intact ELF sections and embedded Go metadata.
  [Package evidence](evidence/sdk-package-matrix.md) is separate from execution.
- [x] The recorded pre-removal-fix x86_64 SDK checkpoint on clean booted OpenWrt: ordinary installation,
  API configuration, closed-policy confirmation, reboot, firewall reload/flush
  and abrupt QEMU restart preserved management. Continuous dual-sided capture
  verified zero forwarded protected client packets; four separately proven
  router-generated TCP rejections are recorded in the [boot evidence](evidence/openwrt-boot-network.md).
- [x] Forty-four cross-compiled binaries, ELF/Go build metadata and one independent
  source/cache reproducibility target: [build evidence](evidence/build-validation.md).
- [x] User-mode CPU execution of selection, configuration and offline release CLI
  suites on ARMv5/v6/v7, MIPS32 big/little-endian soft-float and RISC-V64: all
  eighteen target/suite combinations passed. These are Linux syscall/CPU emulations,
  not OpenWrt kernel, package or physical-device acceptance.
- [x] Separate i386 full-system execution: the same standard-library control and
  selection/configuration/release suites passed on booted OpenWrt x86/generic,
  Linux 6.6.141 i686, after failing under user-mode QEMU.
- [x] MIPS64 big/little-endian full-system execution: the stdlib control and all
  three suites passed on booted official OpenWrt Malta be64/le64 kernels. The
  original user-mode failures remain recorded. Kernel alignment emulation explains
  the environment distinction; see [exact results and limits](evidence/abi-execution.md).
- [x] Offline release CLI in a read-only Linux container without network and with
  all capabilities dropped: generated Ed25519 trust/signature, exact architecture,
  downgrade/tamper rejection and executable-looking artifact bytes never executed.
- [x] Interrupted **staging-file states**: empty, partial, truncated and appended
  manifest/signature/package files are rejected without modification; a complete
  trusted replacement verifies on retry. Correctly signed unknown/duplicate/trailing
  manifest fields, wrong project, version overflow, duplicate artifacts and path
  traversal are also rejected. Run `sh scripts/lab-release.sh`.
- [x] Public maintenance API, English UI and durable privileged package jobs:
  strict component/bundle identities, frozen revision/digest/idempotency and
  authoritative root job status. API, helper and UI contract tests passed; UI
  service fixtures do not install packages.
- [x] Actual offline opkg with signed package fixtures: installation, upgrade,
  preflight script non-execution, feed isolation, SIGKILL during postinst, explicit
  authenticated rollback and same-version file repair. The routing gate is injected
  in this userland lab; full SDK/service/boot integration remains a separate gate.

The release-staging tests do not kill opkg, interrupt a filesystem write, emulate
flash power loss or demonstrate atomic package replacement. The current release
utility verifies files only; it never installs them or downloads a trust key.
Package installation and offline recovery use the platform package manager and
trusted local administrator workflow. No production signing trust root or stable
signed release has been issued.

## Prioritized outstanding cases

| Priority | Concrete case | Required pass evidence | Current status |
| --- | --- | --- | --- |
| P0 | Complete `FOR_AGENTS.md` setup from a clean booted compatible OpenWrt VM, then repeat it | No hidden author steps/browser; same final state; ordinary dependency checks; actual LAN client path tests | Full-boot VM work in progress; container-userland installation already passed |
| P0 | Offline upgrade of gateway and guard while a closed policy is committed | Old/new verified packages and recovery files cached before disconnect; no protected client traffic escapes during stop/replacement/start | Not yet demonstrated |
| P0 | Kill package manager at old-package removal, new executable extraction, conffile update and service restart boundaries | Restart/resume or explicit offline rollback preserves management and committed traffic policy | Not yet demonstrated; torn staging files are a different test |
| P0 | Cold boot after guard executable is missing/truncated from interrupted replacement | Boot cannot allow protected LAN traffic directly while the helper is unavailable; offline restoration works | Concrete unverified case; existing process-SIGKILL tests retain the executable |
| P0 | Power loss while persistent network/node journal and configuration are being replaced | Restart reads a complete old/new state or enters a recoverable safe state; client packet capture confirms policy | fsync/atomic-write and recovery unit tests exist; filesystem/boot crash sequence still required |
| P0 | Stable release trust and downgrade/key-rotation operations | Independently distributed real trust root, signed manifest/artifacts, authenticated rotation and demonstrated operator workflow | Release process decision and acceptance pending; no test key is a production trust root |
| P1 integration | Planned API engine installation and project update/removal operations | Narrow authenticated operations with trusted package identity, validation/diff, operation IDs, interruption recovery and the same safe local package workflow | Public API, root jobs, explicit recovery and English UI implemented; actual opkg fixture tests passed. Full-boot SDK package/controller replacement and removal checks remain open. Guard and node replacement are explicitly unsupported by this API |
| P1 | Boot/firewall/network reload, changing WAN and offload with actual LAN clients | DNS/TCP/UDP/IPv6 behavior and WAN capture match explicit direct/closed policy; management stays reachable | Several namespace tests passed; complete booted-device matrix remains open |
| P1 | Exact OpenWrt package CPU variants | SDK-packaged binaries execute with documented CPU and ABI; distinguish emulator userland from OpenWrt kernel/module behavior | Standalone suites passed under user-mode ARMv5/v6/v7, MIPS32 BE/LE and RISC-V64, plus full-system i386 and MIPS64 BE/LE. SDK package/lifecycle evidence remains separately scoped |
| P1 | Physical Ethernet and encrypted WDS/mesh pairs | One DHCP/RA policy, visible client addresses, one uplink, actual throughput, verified management recovery and local receipts | No physical pair has been tested or authorized for changes |
| P1 | Weak-device resources and multiple device classes | Measured controller/engine RAM, flash, CPU and useful throughput against direct baseline | Size matrix and one development RSS observation exist; device minima unconfirmed |
| P2 | Additional OpenWrt generations/package managers/backend combinations | Their own SDK/package install and functional checks; unsupported cases stop before mutation | The tested matrix remains explicitly scoped to documented combinations |

See the [verification ledger](verification.md) for detailed passed scopes,
[update and recovery guide](updates.md) for current operator steps, and
[hardware lab guide](home-lab.md) for the remaining device tests.
