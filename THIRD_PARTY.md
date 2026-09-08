# Third-party components

The OpenRHP controller and helpers use Go's standard library. The official Go
runtime/toolchain has its own BSD-style license. No external Go modules are linked.

Network engines are separate, optional installed packages and are not copied into
OpenRHP's source or core package:

| Component | Pinned integration version | Upstream license |
| --- | --- | --- |
| sing-box | 1.14.0 | GPL-3.0-or-later with an additional naming restriction; see [upstream LICENSE](https://github.com/SagerNet/sing-box/blob/v1.14.0/LICENSE) |
| Xray-core | 26.3.27 | MPL-2.0 |
| zapret/nfqws | v72.10 | [MIT](https://github.com/bol-van/zapret/blob/v72.10/docs/LICENSE.txt) |
| age (optional encrypted backup CLI) | target's trusted supported package | BSD-3-Clause |

See [adapter pins and validation](docs/probe-paths.md). Distributing any combined
image requires checking the complete licenses and source obligations of all included
OpenWrt packages; the core project's license does not relicense an engine.

Browser development tests pin Playwright in their own package lock (Apache-2.0).
Playwright/Chromium and Linux lab tools are development dependencies, not router
runtime dependencies. Build/SBOM reports distinguish controller from optional engines.
