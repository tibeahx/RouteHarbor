# Verification ledger

Status: development preview, 2026-09-08. Source publication is not a stable router
release. This ledger separates compiled code, deterministic tests, real Linux
network execution, SDK packaging and hardware acceptance. Full product acceptance
requires the remaining device/client tests from the implementation plan.

## Executed checks

| Area | Evidence | Scope |
| --- | --- | --- |
| Configuration | Go tests and race suite | Strict schema/import, safe persistence, cross-process revision conflicts, permissions, symlinks/hardlinks, bounded input |
| Selection | Go tests and race suite | Freshness, required resources, sustained advantage, dwell/cooldown, total/partial failure, recovery, manual/excluded paths, unknown metrics |
| Probe/adapters | Go tests and race suite | Per-source transport, SSRF/public-IP pinning, redirects, proxy numeric destinations, limits, hostile imports |
| Path prototype | `scripts/lab-paths.sh` | Real Linux: 32 concurrent direct, two actual nfqws queues and CONNECT requests; queue independence; one nfqws killed while others remain usable |
| Engine schemas | `scripts/lab-engines.sh` | Native pinned sing-box/Xray validators for six supported configuration examples with DNS/UDP/IPv6 listener generation |
| Engine privilege/lifecycle | `scripts/lab-engine-worker.sh` | Actual sing-box/Xray run as the API peer UID/GID with only CAP_NET_RAW; API remains without capabilities; listener ownership, API/helper SIGKILL cleanup and committed-port restoration |
| Network helper | `scripts/lab-network.sh` | Real nftables, owned routes, direct/TPROXY/interface paths, DNS DNAT, foreign-object rejection and independent rollback after helper SIGKILL |
| Firewall flush safety | Linux helper lab | RPDB closed guards keep unmarked LAN IPv4/IPv6 blocked after nft ruleset flush; explicit LAN-local routing remains |
| API | Go tests and race suite | Auth/ACL/Host/Origin, secret redaction/export, revision/idempotency, bounded requests, interrupted-operation recovery, agent workflow |
| Node protocol | Node Go tests | Real loopback pinned TLS/mTLS enrollment and lifecycle; wrong peer/code/replay rejection; UCI boundary and transaction recovery |
| UCI secret handling | `scripts/lab-uci.sh` | Pinned real OpenWrt parser round-trips adversarial Wi-Fi keys through stdin without argument/output disclosure |
| Node link telemetry | `scripts/lab-node-link.sh` | Real Linux veth carrier up/down and actual transmitted-frame counters; unavailable radio measurements remain unknown |
| Service-user administration | `scripts/lab-admin.sh` | Real Linux UID/GID drop; issued token accepted then revoked by the live API; strict ownership and root-only output rejection; actual age secret backup round trip |
| Browser | `scripts/test-browser.sh` | Actual embedded UI adds/checks/selects/removes sources; desktop/mobile screenshots; untrusted name rendered as text; no persistent browser token storage |
| Cross compilation | `scripts/build-matrix.sh` | Four binaries across 11 Linux variants; exact byte counts in evidence CSV |

Unit tests using injected UCI runners do not imply a real OpenWrt AP was reconfigured.
The path prototype's isolated private-address test harness is not a production SSRF
exception. Native engine config validation does not prove end-to-end VPN service from
real user credentials. Browser selection changes are not proof of LAN interception.

The official Go vulnerability scan (`govulncheck` v1.7.0) returned **No vulnerabilities found** for the inspected source/toolchain snapshot. Gitleaks v8.30.1 found no secrets in the staged initial source import. This is a known-vulnerability database check, not a proof that the implementation has no vulnerabilities. Four parser/telemetry fuzz targets also passed five-second campaigns with two workers each; longer campaigns remain a release activity.

## Release gates still requiring specific evidence

- Complete clean OpenWrt installation/agent-only setup and manual setup on the
  actual SDK/package generation; interrupted install/update/removal recovery.
- procd/netifd/fw4 ordering on OpenWrt boot and reload, dynamic WAN, hardware/software
  offload, real DNS/UDP/IPv6 client traffic and WAN packet-capture leak assertions.
- Full Wi-Fi gateway counterpart and encrypted WDS/mesh pair capability validation;
  generic discovery currently keeps unverified wireless modes disabled.
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
