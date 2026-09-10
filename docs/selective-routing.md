# Selective routing

New installations use a selective routing profile with network interception still
disabled. Ordinary external destinations leave through the configured WAN. Registry
domains, explicit blocked IP prefixes and confirmed temporary restrictions use the
selected bypass method. A direct source is excluded from that bypass pool; with
private relay continuity it may still carry encrypted traffic **to the relay**.

Old files without `routing` (or with `routing:null`) preserve legacy all-traffic
behavior. Saving a selective profile is an explicit migration of configuration,
not activation: inspect preflight, prepare, apply with the rollback timer, verify
connectivity and confirm. The previously confirmed journal keeps its own routing
semantics until a replacement is confirmed. Maintenance holds retain their meaning.

## Pinned engine on OpenWrt

The dispatcher requires sing-box 1.14.0. OpenWrt uses musl: the generic official
Linux archive is glibc-linked and cannot run there. Use the corresponding official
musl release archive, verify its SHA-256, and provision the extracted engine through
the documented engine installation path. These hashes pin archives, not the
extracted executable.

| Target | Official archive | SHA-256 |
| --- | --- | --- |
| x86-64 | `sing-box-1.14.0-linux-amd64-musl.tar.gz` | `d2d6b4543d850269214ced70ffe41b13b1595baa1b6f9c016466abfba162c4d4` |
| ARM64 | `sing-box-1.14.0-linux-arm64-musl.tar.gz` | `1811c446a4957edee1b62ed2363607f8e99e1f7b6d88179719251d7ed5f30169` |
| MIPS little-endian softfloat | `sing-box-1.14.0-linux-mipsle-softfloat-musl.tar.gz` | `2f71d969cf4cf2181a6497bbb147fd38a1aaea101caf48cbbf8e29a2ca4a415e` |

Archives are published in the official [sing-box 1.14.0 release](https://github.com/SagerNet/sing-box/releases/tag/v1.14.0).
Architecture and available memory still require separate qualification; see the
[validation report](selective-routing-validation.md).

## DNS and path selection

The helper generates the local sing-box dispatcher's typed configuration. Arbitrary
engine configuration import is not accepted. A bounded unprivileged DNS proxy keeps
local dnsmasq answers local and passes external queries to managed FakeIP DNS.
Different domain names can consequently select different paths even when their real
IP is shared. Real destination resolution does not recurse through FakeIP DNS.
External HTTPS/SVCB queries receive NODATA to suppress real-address hints. Synthetic
answers do not support strict client-side DNSSEC validation.

Rule precedence is local destinations, manual direct exceptions, manual bypass
exceptions, registry/temporary rules, then direct WAN. Domain rules are exact;
`include_subdomains:true` is explicit and matches label boundaries. Public numeric
IP prefixes match independently. FakeIP addresses are intercepted before local
address exclusions, checked against configured LAN/tunnel ranges, and never sent to
WAN. Apps using encrypted DNS outside this service cannot receive domain-specific
routing when the domain is unknown; explicit destination IP rules still apply.

Proxy methods use prepared local SOCKS ingress. Tunnel and DPI methods use reserved
marks and the verified interface. A failed bypass path must not fall back to WAN.
Switching the prepared bypass source does not restart the dispatcher or deliberately
interrupt ordinary direct connections. With continuity, only bypass destinations
use the private relay, through the worker's restricted TCP/UDP SOCKS ingress.

A policy transaction stages a second dispatcher with a disjoint FakeIP pool before
moving ingress; the previous instance remains available for rollback. FakeIP
mapping caches are private and reused only for their original pool. After a policy
replacement or rollback, a cached address whose mapping is unavailable can fail;
refreshing the application's DNS cache obtains a current mapping. Such addresses
never fall through to WAN. The pinned engine advertises a 600-second synthetic
DNS TTL. Its persistent mapping store is independent of that TTL: allocations
remain until replaced, and a pool wrapping under high domain churn can reuse an
old address for a different domain. Applications must respect DNS TTLs and refresh
cached answers; indefinite mapping identity after pool exhaustion is not guaranteed.
This behavior follows the pinned [FakeIP allocator](https://github.com/SagerNet/sing-box/blob/v1.14.0/dns/transport/fakeip/store.go)
and [DNS TTL constant](https://github.com/SagerNet/sing-box/blob/v1.14.0/constant/dns.go).

## Registry and detection

Antifilter is a **third-party publication of registry data**, not an official RKN
verification service. Only its domain list and explicit subnet list are used.
Resolved domain IP lists and aggregated `/24` lists are not imported: they would
route unrelated CDN tenants through bypass. Updates are attempted every 30 minutes;
validation and atomic publication preserve the last good snapshot on failure. A
snapshot older than 24 hours is stale. Generation files live separately from config
and transaction records; helper RPC carries a bounded hash/generation reference.
Publication and observed application by the engine are distinct states.

Detection defaults off. Enabling requires explicit IDs of existing HTTPS control
resources on port 443; RouteHarbor does not choose an external control service for you. Only recently
observed unknown external domains enter bounded in-memory work queues. DNS query
history is not persisted or exposed in ordinary diagnostics. Global probe concurrency
and work budgets also apply to these comparisons.

A comparison uses identical public IP, address family, SNI and certificate validation
for direct TCP/TLS on port 443 and the actual bypass exit. Continuity probes go
through the relay. Three failed direct comparisons with successful bypass, spaced
at least 10 seconds apart, and a fresh successful independent WAN control are
required for a temporary rule. Any working direct address, incomplete address
coverage, uncertain DNS, certificate error or general WAN failure makes the result
indeterminate. WAN or selected-source changes reset accumulated evidence.

The resulting exact-domain rule is called **Detected restriction**, not a proven
RKN block. It lasts one hour; direct is reconsidered every ten minutes. Three direct
successes remove the rule early, and extension requires new confirmation. It never
expands to a shared IP or CDN. An initial connection may fail and the next connection
may use bypass. User requests and bodies are never replayed. URL-specific blocks,
slowdowns and QUIC-only restrictions are not diagnosed by this version.

## Failures and recovery

A bypass method, worker or relay failing affects bypass traffic. A registry download
or detector failure only disables that function; it is not a classifier failure.
The independent watchdog responds to dispatcher or managed DNS failure by restoring
ordinary WAN and DNS, removing only RouteHarbor-owned restrictions including its separate
DNS guard. This **emergency direct** policy is explicit in the routing profile and
confirmed journal. It can interrupt connections; stale FakeIP answers may require an
application DNS-cache refresh. FakeIP destinations themselves are never leaked to WAN.

This availability choice means destinations previously using bypass can attempt
direct access during classifier failure. It does not change an explicit maintenance
hold. Emergency direct is separate from `policy.fallback`, which remains `closed`
for selective bypass selection, including continuity.

## API and verification

`GET /api/v1/routing` returns public settings or null and an ETag. Admin-only
`PUT /routing` saves the complete profile or null with quoted `If-Match` and
`Idempotency-Key`, preserving source secrets. See
[`examples/routing-settings.json`](../examples/routing-settings.json).
`GET /routing/status` exposes state, selected method, list provenance/freshness,
counts and generations; unavailable measurements stay unknown.

Admin-only `POST /routing/refresh` takes `{}`; `POST /routing/check` takes
`{"domain":"example.org"}`. Both require CAS and idempotency headers and return an
operation ID. Poll `/operations/{id}`; duplicate submissions replay the original
operation. A destination check reports the currently applied action, reason and
route. If detection is enabled, an unknown domain also enters the same bounded
comparison queue as observed DNS queries; the response does not claim a completed
TLS comparison. These operations do not fetch arbitrary URLs or expose a DNS query
log.

Validation must separately record focused unit/API/browser behavior, real Linux
TCP/UDP and IPv4/IPv6 paths, OpenWrt SDK output, booted OpenWrt VM behavior, and any
explicitly authorized physical device test. Browser response fixtures do not prove
packet routing. Earlier boot or continuity evidence does not qualify this feature.
See [selective-routing-validation.md](selective-routing-validation.md) for the
current evidence matrix and reproduction commands.
