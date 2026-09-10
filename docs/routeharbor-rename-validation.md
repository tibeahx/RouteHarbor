# RouteHarbor rename validation

This change is based on `main` commit
`c12c14e8d828a96c39ce158a254617f8f5b635e5`. It changes the current project identity
and keeps Git history intact. No physical router, active WAN or production relay
is a test target.

The rename covers the Go module/imports, six CLI entry points, OpenWrt packages
and service users, systemd relay unit, state/socket paths, owned network objects,
release manifests, environment variables, API/UI, examples, lab tooling and
documentation. No compatibility aliases retain the previous identity.

The health query now derives DNS label lengths from the canonical health name.
The existing strict socket/DNS regression reproduced a failure after the simple
name replacement and passed after this correction. Short `rh` names keep lab
interfaces within Linux name limits; opaque numeric mark and FakeIP allocations
remain unchanged.

The README has original vector wordmarks for light and dark backgrounds. The UI
header and favicon use the same harbor/route mark. The artwork has no external
font or network dependency. Light/dark, mobile and small-icon renderings were
visually inspected.

## Checks

| Check | Result |
| --- | --- |
| Focused helper/routing/node/release/adapter tests, followed by `go test -race ./...` | Passed |
| `go vet ./...`, pinned lint on Darwin and Linux | Passed; zero lint findings |
| Canonical Go and web formatting, documentation links/OpenAPI operations, secret scan, diff whitespace | Passed |
| Cross-build matrix | 66 Linux executables: six commands on eleven targets |
| Reproducibility | Linux amd64 controller byte-identical across independent paths and empty build caches |
| Packaging and VM harness unit tests | 10 packaging and 21 VM harness tests passed |
| Actual-server Chromium suite | 23 passed; one existing paired-device scenario requires a separate device fixture and was not executed |
| Current tracked paths/content scan | No previous full-name or abbreviated-brand identifiers |

The browser run exposed an in-flight response handler being disposed during
fixture teardown. The continuity test now awaits pending route handlers before
closing its context. The complete suite passed after this test-only fix; no
application exception was suppressed.

## Native Linux

Real network namespace tests passed for network rules (15 scenarios), selective
routing (five scenarios), node link telemetry, release verification and the
unprivileged administrative service. The path lab passed 32 parallel requests
through direct, two actual nfqws profiles and CONNECT, with one DPI process's
failure isolated to its own traffic.

The native dispatcher matrix passed interface, SOCKS5, HTTP CONNECT, sing-box,
Xray and DPI paths with IPv4/IPv6 and TCP/UDP coverage. Its production worker
passed strict DNS health, hot rules, process hang recovery, UID/private-FD
isolation and owner cleanup. Recorded worker peak memory was 157,020,160 bytes,
with zero OOM kills.

## OpenWrt artifacts and boot

The real x86-64 OpenWrt SDK built and inspected all seven RouteHarbor IPKs using
Go 1.27.1 in 79.2 seconds. ELF architecture, package names and renamed Go
module/command metadata were checked. The immutable snapshot contains 308
inputs; every input matches the final source bytes. Its SHA-256 is
`e91ccde8d5199cd4522cd6cf0102372c2c3489ea27cf39c2229aea59aab3b71d`.

A fresh OpenWrt 24.10.7 QEMU VM installed these packages and verified the exact
installed binary hashes. Service accounts, socket paths and inactive defaults
were checked. The completed scenario recorded 14 checks, including:

- Two names on the same real IP: `allowed.example` received `198.18.0.2` and
  exited through WAN `11.0.0.2`; `blocked.example` received `198.18.0.3` and
  exited through the bypass at `8.8.8.8`.
- Applied transaction rollback restored the previous FakeIP pool and routing.
- DNS frontend and native sing-box hangs restored real DNS and emergency direct;
  recovery restored selective routing.
- Graceful reboot and fw4 reload/flush/recovery preserved the authorized policy;
  IPv4/IPv6 virtual-address quarantine remained enforced.
- Explicit restore-direct decommission preserved foreign fw4 state.

The first final-artifact attempt stalled during EXT4 journal recovery before
userspace on reboot, after installation and binary checks had passed. An
explicit power cycle recovered this isolated VM. The successful rerun rechecked
the installed bytes and completed the whole scenario, including another
graceful reboot. No product code or fixture was changed to obtain this result.

[Machine-readable artifact hashes and VM results](evidence/routeharbor-rename-artifacts.json)
record the final evidence. Only the dedicated test VM was stopped; existing VMs
were left untouched. Current SDK/boot evidence is x86-64 only. Historical
ARM/MIPS and other reports keep their original scope and do not qualify the
renamed runtime. No physical-device or active-WAN qualification is claimed.
