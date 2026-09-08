# Contributing

Use the Go toolchain pinned by `go.mod`; the controller has no third-party Go module
dependencies. Keep engines separate. Read [architecture](docs/architecture.md),
[threat model](docs/threat-model.md), [API](api/openapi.yaml) and [verification](docs/verification.md).

```sh
go test -race ./...
go vet ./...
make lint
make fmt-check
sh scripts/build-matrix.sh
sh scripts/check-reproducible.sh
python3 scripts/check-docs.py
```

Tests using localhost need permission to bind a loopback port. An environment
restriction is not a failing network assertion; rerun in a permitted test environment.
Linux-only integration tests are opt-in through the isolated scripts:

```sh
sh scripts/lab-paths.sh
sh scripts/lab-network.sh
sh scripts/lab-uci.sh
sh scripts/lab-node-link.sh
sh scripts/lab-wireless.sh
sh scripts/lab-admin.sh
```

The native engine fixture check uses exact pinned sing-box/Xray builds; consult
`scripts/lab-engines.sh` (Docker amd64 or arm64). These tests don't certify OpenWrt kernel,
fw4/procd lifecycle, hardware offload, Wi-Fi interoperability or power-loss behavior.

`make lint` and CI run the same `scripts/lint.sh`: golangci-lint v2.13.2,
the current stable release selected on 2026-09-08, with the standard linters plus
`bodyclose` and `nolintlint`. The installer verifies the pinned official SHA-256
before extraction or execution. Both host and Linux build-tagged source and tests
are analyzed. The verified release archive is cached under `.local/tools`; set
`OPENRHP_TOOLS_DIR` to choose another local cache. Set `GO=/path/to/go` for the
pinned toolchain. Fix findings rather than adding broad exclusions; any necessary
local suppression must name its linter and explain the reason.
Run `sh scripts/lint.sh --fix` to apply the linters' supported automatic fixes,
then inspect the changes and rerun `make lint` for the remaining findings.

Run `make fmt` to format all Go code with the same pinned tool: `gofumpt` applies
consistent declaration spacing, `gci` groups standard-library and project imports,
and `golines` wraps long expressions at 100 columns. CI runs `make fmt-check` to
reject formatting drift without rewriting files. The frontend has separate
`make fmt-web` and `make fmt-web-check` commands after its development dependencies
are installed with `npm ci --prefix tests/browser --ignore-scripts`.

For the browser, bootstrap and start a **separate empty development state** as shown
in README, then:

```sh
npm ci --prefix tests/browser --ignore-scripts
npx --prefix tests/browser playwright install chromium
OPENRHP_TEST_TOKEN_FILE="$PWD/.local/admin.token" \
  npm --prefix tests/browser test
```

Tests use the public API via the real embedded UI; the test credential is read from
a private file and never printed. Screenshots go under `test-results`, ignored by Git.
Do not enable traces containing credentials. Router installation requires no Node.js.

Add meaningful regression tests for auth/ACL, import/SSRF, source-path independence,
selection degradation and rollback changes. Use canary secrets and assert their
absence from responses, errors, SSE and diagnostics. Fuzz parser inputs. Do not
substitute mocked network success for Linux/OpenWrt/client acceptance.

Changes to public schemas include OpenAPI/examples/UI/docs together. API mutations
need revision/idempotency semantics; unavailable capabilities fail explicitly. No
arbitrary shell/helper commands, downloads/execution from imported configs, silent
root fallback, implicit direct fallback or undocumented external requests.

All code is Apache-2.0. Contributions must be legally distributable under this license;
keep upstream engine code/licenses separate. Report suspected vulnerabilities using
[SECURITY.md](SECURITY.md), not public secret-bearing bug reports.

CI also runs `govulncheck` v1.7.0 and gitleaks v8.30.1 with its verified release digest. For local gitleaks checks, use `gitleaks git --redact`; staged initial imports use `gitleaks git --pre-commit --staged --redact`. Keep reports redacted. The smaller offline `scripts/check-secrets.py` guard complements this scan.
