# Developing OpenRHP

This file applies to repository development. FOR_AGENTS.md is the separate
operational guide for agents administering routers.

- Product name: OpenRHP, expansion OpenReverseHomeProxy; English UI.
- Go standard library; embed offline HTML/CSS/JS. No cloud/CDN/runtime Node dependency.
- Read docs/architecture.md and docs/threat-model.md before changing network/import code.
- Preserve separate unprivileged control and typed privileged helper boundaries.
- Tests and docs distinguish unit, real Linux, OpenWrt SDK, OpenWrt boot and physical
  device evidence. Never turn a missing capability into a fabricated success.
- Keep settings, OpenAPI, examples, UI and guides consistent. All ordinary source
  reads/diagnostics redact secrets by allowlist. No credentials in arguments/logs.
- Physical routers, flash/bootloaders and a user's active WAN are not development
  test targets unless the user explicitly authorizes those concrete devices/actions.
- Run focused tests first, then relevant race/integration/contract checks. Code
  reviews must verify source and reproduce significant findings before acting.
