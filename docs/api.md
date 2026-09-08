# Public API

[OpenAPI](../api/openapi.yaml) is also served at authenticated `GET /api/v1/openapi`.
The `.yaml` file uses JSON syntax, which is valid YAML 1.2. UI, CLI and agents share
these operations. API responses are JSON except SSE at `/events`.

Use `Authorization: Bearer …`; no query-string credentials or CORS. Plain HTTP is
allowed only on loopback. Non-loopback management requires trusted TLS plus exact
Host allowlisting. An Origin, when present, must match the request's scheme and
host. The read credential can inspect state and plans; writes, credential management
and secret export require admin. Tokens can be issued/revoked through trusted
local access with `openrhp token`; revocation also terminates subsequent event reads.

For a configuration write, read `/config` and send the quoted `If-Match` revision.
Every mutation sends an `Idempotency-Key` (8–128 visible ASCII characters). Retain
the same key, method, path, revision and body when retrying one logical request.
A changed request with the same key returns 409. Keys are scoped to credentials and
retained for 24 hours. A bounded journal rejects new work when full; it does not
evict still-live retry guarantees. At most 16 control operations run concurrently.

Successful mutations return an operation. Probes return 202 and continue without
the original HTTP connection; poll `/operations/{id}`. A process interrupted before
recording completion is reported as `interrupted_check_current_state`; inspect the
current configuration revision and helper transaction before deciding on new work.
Do not blindly replay an uncertain action under a new key. SSE is supplementary:
GET status, operation and transaction reads are authoritative after reconnecting.

Read-only `/config/validate` and `/config/plan` do not apply rules or launch an
engine. A saved configuration and a successful HTTP response are not evidence of
LAN connectivity. Network flow: save → prepare `/transactions` → apply → inspect
client traffic/management → confirm, or rollback. Node transactions use the same
principle through `/nodes/{id}/{prepare,apply,confirm,rollback}` and `/status`.

Errors contain `error.code`, `error.message` and `error.retryable`. Expected failures
include 401 auth, 403 scope/origin, 409 revision/idempotency, 422 validation,
428 missing revision, 429 bounded queue/rate, and 503 absent capability/helper.
Error messages never include engine stdout, arbitrary import content or credentials.

The CLI reads credentials from private files and accepts request bodies from files
or stdin. For example, with the service already bootstrapped:

```sh
openrhp api --token-file /private/path/admin.token --path /api/v1/capabilities
openrhp api --token-file /private/path/admin.token --path /api/v1/config
openrhp api --token-file /private/path/admin.token --method POST \
  --path /api/v1/sources --data source.json --revision 1 \
  --idempotency-key add-direct-20260908
```

The revision in this example is only correct for a fresh state. Always read the
actual revision. Private file paths and token values belong on the administrator's
device, not in shared logs, screenshots, pull requests or agent conversation text.
