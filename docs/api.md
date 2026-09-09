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
evict still-live retry guarantees. Its 2 MiB durable limit reserves up to 256 KiB
per unfinished result before admitting a mutation. At most 16 control operations
run concurrently; the byte budget can impose a lower limit.

Successful mutations return an operation. Probes return 202 and continue without
the original HTTP connection; poll `/operations/{id}`. A process interrupted before
recording completion is reported as `interrupted_check_current_state`; inspect the
current configuration revision and helper transaction before deciding on new work.
Do not blindly replay an uncertain action under a new key. SSE is supplementary:
GET status, operation and transaction reads are authoritative after reconnecting.

If an unexpected result exceeds its storage contract, the completed operation
retains its ID, state, revision and request identity. Its result instead contains
`result_unavailable: true`, a `reason`, and available canonical object or transaction
IDs in `references`. Inspect those authoritative objects and current state; this
marker does not authorize repeating the mutation under a new key. A failed durable
completion write is never presented as a successfully recorded completion.

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

## Configuration snapshots and restore

In the browser, open **Overview → Gateway setup and diagnostics → Configuration
backups** to create a snapshot, preview its masked settings, restore it or delete
it. Restore is available from the preview and remains bound to the revision that
was current when that preview opened; a concurrent edit requires a new preview.

The API manages private snapshots on this device without accepting filesystem
paths or uploaded archives. Up to eight snapshots may occupy at most 2 MiB total.
They retain source credentials inside the same private, mode-0600 configuration
store. These local recovery snapshots are not portable encrypted backups; use the
existing trusted-local `openrhp backup` command with an age recipient for that.

| Operation | Behavior |
| --- | --- |
| `GET /config/backups` | List IDs, creation times, saved revisions, counts and byte sizes; read credential allowed. |
| `GET /config/backups/{id}` | Preview metadata and configuration with all source settings redacted. |
| `POST /config/backups` with `{}` | Snapshot the current revision. The backup ID equals the returned operation ID. |
| `POST /config/backups/{id}/restore` with `{}` | Validate and save the private snapshot at a new configuration revision. |
| `DELETE /config/backups/{id}` without a body | Explicitly remove one snapshot; current configuration is unchanged. |

All three writes require an administrator credential, current quoted `If-Match`
revision and idempotency key. Creation and deletion leave the configuration
revision unchanged. A full backup store rejects creation before writing anything;
it never silently evicts a retained snapshot. Reuse the same logical request when
retrying, including its original revision. If creation was interrupted after the
snapshot reached disk, inspect `/config/backups/{operation_id}`; its operation
remains marked interrupted rather than being run again.

Restore uses the ordinary active-path and pending-transaction guard. It restores
sources, targets, selection policy, probe settings and network configuration,
including private source settings. It does not restore management credentials,
node enrollment, installed packages or privileged helper journals. Its result
contains `configuration_saved: true` and `network_changes_applied: false`. Inspect
the new configuration and explicitly prepare/apply/confirm the network afterward.
Saving a snapshot from a moved device does not establish interface compatibility;
actual platform checks still apply. A blocked active-path change must follow the
normal removal and transaction workflow while preserving management access.

For example, after reading the current revision:

```sh
printf '{}\n' | openrhp api --token-file /private/path/admin.token \
  --method POST --path /api/v1/config/backups --data - \
  --revision 3 --idempotency-key snapshot-before-edit
openrhp api --token-file /private/path/read.token --path /api/v1/config/backups
```

Use the returned backup ID for preview and restore. Keep separate encrypted
recovery material off the device when protection against device/storage loss is
required; an on-device snapshot cannot survive loss of its own storage.


## Software maintenance

Open **Overview → Gateway setup and diagnostics → Software maintenance** to inspect
availability and staged signed bundles. The supported components are `openrhp`,
`openrhp-sing-box`, `openrhp-xray` and `openrhp-conntrack`. Bundle staging requires
trusted local administration; the browser accepts no package URLs, filesystem
paths or verification-key uploads.

`GET /maintenance/capabilities` and `GET /maintenance/bundles` are read-only.
`POST /maintenance/plan` reviews an install, upgrade or removal request without
starting a package worker. The browser freezes that request, its returned
`expected_installed_digest`, the configuration revision and one idempotency key
before administrator-only `POST /maintenance/operations`. Form changes invalidate
the review. An uncertain retry reuses the frozen body, revision and key, even if
the background configuration refresh has observed a newer revision.

Track the returned ID through `GET /maintenance/operations/{id}`. This is the
privileged package service's durable operation; the general `/operations/{id}`
journal only records dispatch. `prepared`, `running` and `verifying` are pending;
only `completed` confirms success. `failed` and `interrupted` retain the operation
ID and require inspection. An interrupted package-manager invocation requires
trusted local reconciliation; resending a dispatch key is not permission to run
that worker again.

Removal defaults to `preserve-closed`. Selecting `restore-direct` requires explicit
consent in the browser and restores normal direct routing. `guard_retained`
means the safety **package** remains installed, not that protected traffic is
currently blocked. Removing the controller can disconnect the API. Keep the
operation ID; the browser includes it in the page URL for status recovery after
sign-in and displays this trusted local command:

```sh
/usr/libexec/openrhp-helper maintenance-status --operation OPERATION_ID
```

Keep the page open until an ID is known if the dispatch response is uncertain.
A lost connection is never displayed as successful package installation.
