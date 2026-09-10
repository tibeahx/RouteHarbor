# Security policy

RouteHarbor controls potentially sensitive home traffic. Its development preview is not
a security-certified product; no physical router is presently approved for a stable
release. See [threat model](docs/threat-model.md), [independent review](docs/security-review.md)
and [verification status](docs/verification.md).

## Report privately

Use [GitHub private vulnerability reporting](https://github.com/tibeahx/RouteHarbor/security/advisories/new).
Include affected commit/version, prerequisites, a minimal reproduction and the
security impact. Use synthetic credentials and redacted diagnostics. Do not post VPN,
Wi-Fi, API or PPPoE secrets, packet payloads or private endpoint addresses publicly.

The current development branch receives fixes. No stable support lifetime is
promised before a stable release exists. High/critical unresolved findings block a
stable release. Fixes receive regression tests and an advisory when appropriate;
there is no claim of absolute security or blanket OWASP compliance.

API credentials are unique, revocable and local. LAN is untrusted. Remote management
requires authenticated TLS. Imported names/configs/responses cannot execute shell,
load arbitrary listeners/files/scripts, enroll arbitrary devices or expand privileges.
Protected traffic does not silently fall back to direct. The real boot/firewall,
DNS/IPv6 and client packet-capture checks remain part of platform acceptance.

There is no mandatory cloud telemetry, TLS interception, developer access tunnel,
default password, universal recovery key or automatic firmware update.
