# Troubleshooting

| Symptom | Meaning and next action |
| --- | --- |
| 401 after connecting | Key invalid/revoked; retrieve or rotate through trusted local access. No LAN ownership shortcut. |
| 403 Host/Origin | Use the configured exact management host and trusted scheme; do not enable arbitrary CORS. |
| Revision conflict (409) | Another writer changed the config. Read current config and reconcile before a new logical operation. |
| Idempotency conflict (409) | Same key used for different request bytes/path/revision. Inspect the original operation. |
| 429 | Bounded rate, request, job or journal capacity. Wait/read outstanding operations; do not flood retries. |
| Engine missing/version rejected | Install the supported package/version; source import does not install arbitrary programs. |
| Target DNS rejected | Resolver returned private/special-use address or failed. Check the explicit resource, without bypassing SSRF. |
| Redirect rejected | Configure the actual intended HTTPS endpoint; probes do not follow redirects into internal services. |
| No path selected | No complete fresh usable candidate, selection off, or required recovery checks not yet passed. Inspect resources. |
| Speed/packet loss is absent | No valid measurement exists. It is not a measured zero. |
| Traffic routing is not applied | Configuration/probes exist but a network transaction has not been applied/confirmed. |
| Helper unavailable | Check root helper procd instance/socket ownership/peer identity and platform report. Do not run the API as root. |
| HTTP CONNECT cannot carry UDP | Capability is explicit; UDP is blocked for this TCP-only path. Choose a UDP-capable source if needed. |
| Controller interrupted during apply | Inspect helper transaction and independent rollback deadline via preserved local management. |
| Source cannot be edited while active | Stage removal in a new confirmed network plan before replacing its live engine settings. |
| Wireless not offered | Advertised radio modes alone do not prove compatible encrypted bridging. Inspect both devices; use Ethernet meanwhile. |
| Weak second-router uplink | Treat as a coverage problem; compare separately with gateway path health. |
| Removal leaves protected traffic blocked | Closed guard is preserved intentionally until an explicit post-removal direct policy is chosen. |

Use the panel's **Download diagnostics**, or `GET /api/v1/diagnostics`, for a redacted
report. Capture only minimal counters/metadata unless packet capture is expressly part
of an isolated authorized test. Never upload live secrets or user packet contents.
