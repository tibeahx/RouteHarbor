<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/routeharbor-logo-dark.svg">
    <img src="docs/assets/routeharbor-logo-light.svg" alt="RouteHarbor" width="800">
  </picture>
</p>

**Adaptive routing for your home network.**

When an access method slows down or stops reaching the sites you need, switching
VPNs, adjusting DPI tools and configuring every device becomes a recurring job.
RouteHarbor is an OpenWrt service that checks each configured path independently,
selects a usable path for the LAN, and helps extend coverage with another router.
A paid VPN is optional. Your configurations and credentials stay on your devices;
there is no required cloud account or hardware vendor lock-in.

**[Install and configure with an agent → FOR_AGENTS.md](FOR_AGENTS.md)**

**[Set up manually → docs/quick-setup.md](docs/quick-setup.md)**

> Development preview. The controller, adapters, public API, English UI, network
> helper and node agent are implemented. Automated tests and isolated Linux labs
> are reproducible. **No physical router is certified and no stable installation
> release has been published.** Read [verification status](docs/verification.md)
> and [compatibility](docs/compatibility.md) before changing a working gateway.

## What it does

- Stores direct, SOCKS5, HTTP CONNECT, safe sing-box/Xray outbounds, existing
  tunnel interfaces and a pinned nfqws packet strategy as independent sources.
- Checks required HTTPS resources, response time and bounded download throughput.
  Unknown packet-loss measurements stay unknown. It does not perform TLS MITM.
- Uses freshness, recovery checks, sustained improvement, dwell time and cooldown
  to avoid oscillation. New configurations route ordinary destinations directly and send blocked
  destinations through the selected bypass. Classifier failure has an explicit
  emergency-direct policy; old profiles retain legacy behavior until migration.
- Separates saved configuration, read-only plans and confirmed network changes.
  Existing TCP connections are not promised to survive a change of external IP.
- Offers optional [session continuity through your own relay](docs/session-continuity.md),
  with bounded TCP replay and short UDP replay over prepared access methods. Relay
  restart and resource limits can still interrupt sessions; no fixed switch latency
  has been qualified for a physical device.
- Uses a small privileged helper for owned nftables/routes, with local peer
  authentication, a durable journal and a separate rollback process.
- Pairs an OpenWrt access-point agent using verified device fingerprints and mutual
  TLS. Coordinates both routers' Wi-Fi changes with independent recovery. Wi-Fi
  requires [verification of the exact pair](docs/wireless-verification.md); Ethernet is supported.
  Discovery alone grants no authority. Uplink quality stays separate from WAN quality.

The control daemon is Go with the standard library. It embeds a small HTML/CSS/JS
panel and does not forward packets in Go. Third-party engines remain separate
processes with separate licenses and resource budgets.

## Try the control panel locally

Use the pinned Go version in [go.mod](go.mod). These commands run as your ordinary
user and do not modify the host network:

```sh
mkdir -p .local
chmod 700 .local
go build -trimpath -o .local/routeharbor ./cmd/routeharbor
.local/routeharbor bootstrap --state .local/state --token-file .local/admin.token
.local/routeharbor serve --state .local/state --runtime .local/runtime --listen 127.0.0.1:8787
```

Open `http://127.0.0.1:8787` and enter the key from the private file. Retrieve it
locally; do not paste it into issue reports or chats. `bootstrap` is repeatable
with its original credential file. The initial configuration has no external
probe targets, no sources, selection off and traffic routing disabled.

Use **Access methods → Add access method**, then **Overview → Add resource**.
The panel and CLI use the same [public API](api/openapi.yaml). OpenWrt-only features
explain their missing capabilities when running on a development computer.

## Documentation

| Topic | Guide |
| --- | --- |
| Supported platforms, architectures and resource measurements | [Compatibility](docs/compatibility.md) |
| Exact implemented/tested boundaries | [Verification status](docs/verification.md) |
| Architecture and versioned configuration | [Architecture](docs/architecture.md), [configuration](docs/configuration.md) |
| Adapter settings and independent probe paths | [Adapters and probes](docs/probe-paths.md) |
| API, retries and agent operation | [API guide](docs/api.md), [OpenAPI](api/openapi.yaml) |
| Wi-Fi/Ethernet coverage | [Coverage](docs/coverage.md) |
| Preparing your physical test setup | [Home lab guide](docs/home-lab.md) |
| Building OpenWrt packages | [SDK builds](docs/openwrt-build.md) |
| Data handling and security boundaries | [Threat model](docs/threat-model.md), [security policy](SECURITY.md), [control matrix](docs/security-controls.md) |
| Updates, trust and backups | [Updates](docs/updates.md) |
| Removal and recovery | [Uninstall](docs/uninstall.md) |
| Common failures | [Troubleshooting](docs/troubleshooting.md) |
| Development and independent review | [Contributing](CONTRIBUTING.md), [security review](docs/security-review.md) |
| Project identity, logo and installation transition | [Branding](docs/branding.md) |

## Develop and verify

```sh
go test -race ./...
go vet ./...
sh scripts/build-matrix.sh
sh scripts/lab-paths.sh
sh scripts/lab-network.sh
```

Linux labs use disposable containers with their own network namespaces. They need
Docker and privileged operations **inside the disposable container**; they never
join the host network or configure a physical router. Browser tests have separate
pinned development dependencies under `tests/browser`; Node.js is not needed on
routers. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full verification commands.

Licensed under [Apache-2.0](LICENSE). See [third-party notices](THIRD_PARTY.md)
for separately installed engines. RouteHarbor does not automatically update OpenWrt,
flash devices or promise to bypass every present or future restriction.

Selective routing, managed FakeIP DNS, registry provenance, detector limits and
emergency recovery are documented in [selective-routing.md](docs/selective-routing.md).
