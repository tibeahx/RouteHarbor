# Verification ledger

Status: development preview, 2026-09-09. Source publication is not a stable router
release. This ledger separates compiled code, deterministic tests, real Linux
network execution, SDK packaging and hardware acceptance. Full product acceptance
requires the remaining device/client tests from the implementation plan.

## Executed checks

| Area | Evidence | Scope |
| --- | --- | --- |
| Configuration | Go tests and race suite | Strict schema/import, safe persistence, cross-process revision conflicts, permissions, symlinks/hardlinks, bounded input |
| Configuration snapshots | Config/API race suites and `tests/browser/backups.spec.js` | Private bounded snapshots, masked previews, revision-conflict refusal, credential-preserving draft restore and real browser flow; restoring a snapshot does not apply routing |
| Selection | Go tests and race suite | Freshness, required resources, sustained advantage, dwell/cooldown, total/partial failure, recovery, manual/excluded paths, unknown metrics |
| Probe/adapters | Go tests and race suite | Per-source transport, SSRF/public-IP pinning, redirects, proxy numeric destinations, limits, hostile imports |
| Degradation-triggered probes | Control race suite | Fresh failure, latency baseline and actual loss telemetry can trigger a bounded extra speed check; cooldown, concurrency and byte limits remain enforced |
| Path prototype | `scripts/lab-paths.sh` | Real Linux: 32 concurrent direct, two actual nfqws queues and CONNECT requests; queue independence; one nfqws killed while others remain usable |
| Engine schemas | `scripts/lab-engines.sh` | Native pinned sing-box/Xray validators for six supported configuration examples with DNS/UDP/IPv6 listener generation |
| Engine privilege/lifecycle | `scripts/lab-engine-worker.sh` | Actual sing-box/Xray run as the API peer UID/GID with only CAP_NET_RAW; API remains without capabilities; listener ownership, API/helper SIGKILL cleanup and committed-port restoration |
| Network helper | `scripts/lab-network.sh` | Real nftables, owned routes, direct/TPROXY/interface paths, DNS DNAT, foreign-object rejection and independent rollback after helper SIGKILL |
| Optional connection tracking reset | Helper/control race suites and real Linux network lab | Default-off retention, exact previous-source connmark deletion for IPv4/IPv6 TCP/UDP, current/foreign/unmarked preservation, durable failure and safe retry |
| Firewall flush safety | Linux helper lab | RPDB closed guards keep unmarked LAN IPv4/IPv6 blocked after nft ruleset flush; explicit LAN-local routing remains |
| API | Go tests, race suite and bounded fuzzing | Auth/ACL/Host/Origin, all supported credential formats redacted in ordinary reads/diagnostics/SSE, revision/idempotency, request and SSE saturation/release, durable journal byte reservations and write-failure recovery, agent workflow |
| Node protocol | Node Go tests | Real loopback pinned TLS/mTLS enrollment and lifecycle; wrong peer/code/replay rejection; UCI boundary and transaction recovery |
| UCI secret handling | `scripts/lab-uci.sh` | Pinned real OpenWrt parser round-trips adversarial Wi-Fi keys through stdin without argument/output disclosure |
| Gateway Wi-Fi coordinator | Coverage/node race suites and UCI lab | Real pinned loopback TLS with injected gateway/node UCI effects: paired prepare/apply/confirmation recovery, secret erasure and narrow gateway rollback. Separate real-parser checks verify UCI syntax, not a live radio change |
| Wireless verification storage | `scripts/lab-wireless.sh` and Go tests | Actual isolated root-owned receipt storage; expiry, platform/identity changes, wrong peer/radio/mode, symlink/hardlink and ownership rejection; no hardware receipt generated |
| Node link telemetry | `scripts/lab-node-link.sh` | Real Linux veth carrier up/down and actual transmitted-frame counters; unavailable radio measurements remain unknown |
| Service-user administration | `scripts/lab-admin.sh` | Real Linux UID/GID drop; issued token accepted then revoked by the live API; strict ownership and root-only output rejection; actual age secret backup round trip |
| Browser | `scripts/test-browser.sh` | Actual embedded UI adds/checks/selects/removes sources; desktop/mobile screenshots; untrusted name rendered as text; no persistent browser token storage |
| Wi-Fi browser contract | `tests/browser/coverage-ui.spec.js` | Explicit UI-only response fixtures check detected main AP selection, no password request field and pending confirmation; not real router evidence |
| Maintenance browser contract | `tests/browser/maintenance-ui.spec.js` | Explicit UI-only package-service fixtures: frozen revision/digest/key retry, direct-removal consent, failed/interrupted state retention, authoritative completion and status resume after reload; no package installation evidence |
| Package maintenance contract | API/helper/maintenance race suites | Narrow component/bundle identities, strict auth/revision/idempotency, distinct dispatch and root job status, durable routing gate, explicit recovery and no old-confirmation replay |
| Offline package execution | `scripts/lab-maintenance.sh` | Real OpenWrt opkg in a network-isolated rootfs with signed package fixtures: install/upgrade, noaction script non-execution, system-feed exclusion, opkg SIGKILL during postinst, explicit signed rollback and same-version payload repair. Routing gate is injected; separate actual worker-parent SIGKILL test proves process lifetime, not a complete router update |
| Routing browser contract | `tests/browser/routing-ui.spec.js` | Explicit response fixtures distinguish confirmed routing from failed/pending optional cleanup and allow a retry; actual conntrack execution is covered by Linux tests |
| OpenWrt packages and services | `scripts/lab-openwrt.py`; [SDK evidence](evidence/openwrt-sdk.md) | Real SDK-generated IPKs, ordinary opkg, actual OpenWrt procd/netifd/fw4 userland, disabled defaults, repeat setup, service identities, API transaction, restart/reload and protected removal in an isolated container using the Docker Linux kernel; no full OpenWrt boot |
| Cross compilation | `scripts/build-matrix.sh` | Four binaries across 11 Linux variants; exact byte counts in evidence CSV |
| Offline release verifier | `scripts/lab-release.sh` | Actual keygen/sign/verify CLI paths in an offline read-only Linux container; 12 torn staging states, 8 correctly signed malformed manifests, retry with complete trusted files, no artifact execution. This does not interrupt opkg or filesystem power |
| ABI execution | `scripts/lab-abi.sh`; [recorded results](evidence/abi-execution.md) | Eighteen passing user-mode target/suite combinations across ARMv5/v6/v7, MIPS32 BE/LE and RISC-V64; nine original MIPS64 BE/LE/i386 failures remain recorded. Separate actual OpenWrt x86/generic and Malta be64/le64 guest kernels pass the stdlib control plus all three suites. No physical CPU or package-lifecycle claim |

Unit tests using injected UCI runners do not imply a real OpenWrt AP was reconfigured.
The path prototype's isolated private-address test harness is not a production SSRF
exception. Native engine config validation does not prove end-to-end VPN service from
real user credentials. Browser selection changes are not proof of LAN interception.
The OpenWrt userland lab starts procd under the container shell and uses dummy
interfaces. Its actual service and firewall execution does not establish bootloader,
OpenWrt kernel/module ABI, hardware offload, radio or physical-client behavior.

The official Go vulnerability scan (`govulncheck` v1.7.0) returned **No vulnerabilities found** for the inspected source/toolchain snapshot. Gitleaks v8.30.1 found no secrets in the staged source changes. These scans are not a proof that the implementation has no vulnerabilities. Four parser/telemetry fuzz targets passed five-second campaigns with two workers each. The later resource-exhaustion review ran fifteen-second campaigns with two workers for the actual API handler (8,626 executions) and the expanded seven-type source importer (412,500 executions). Longer campaigns remain a release activity.

## Release gates still requiring specific evidence

- Interrupted package updates/power-loss recovery and a complete manual/agent setup
  on booted OpenWrt devices; container userland installation does not prove a full boot.
- procd/netifd/fw4 ordering on OpenWrt boot and reload, dynamic WAN, hardware/software
  offload, real DNS/UDP/IPv6 client traffic and WAN packet-capture leak assertions.
- Physical encrypted WDS/mesh pair qualification, including current per-device
  verification receipts; generic advertisements keep unverified wireless modes disabled.
- Physical Ethernet and Wi-Fi coverage with one DHCP/RA policy, preserved client
  addresses/visibility, uplink degradation isolated from WAN decisions and management
  recovery after node/helper failure. No hardware pair is currently available.
- Several hardware classes/endian/float-ABI targets, emulated execution where supported,
  controller/engine memory and throughput against each device's direct baseline.
- Production release signing trust root, verified release artifacts and policy for
  key rotation/downgrade; no stable signed release has been issued.

Known unimplemented/unsupported behavior is surfaced before network changes. It is
not labelled healthy to complete a demonstration. See [security review](security-review.md)
for findings fixed during independent review, and [home-lab.md](home-lab.md) for the
concrete next hardware setup steps.
