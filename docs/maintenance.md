# Verified offline package maintenance

The controller and privileged service must both support maintenance. The public
API exposes package planning, installation, controller updates and managed removal.
The privileged service accepts fixed component identities and signed local bundle
IDs. It accepts no download URL, executable command, filesystem path or trust key
from the API. Network rules and package jobs have separate durable journals.

This is development functionality. No production signing key or stable signed
release has been issued. Test keys used by a lab do not establish release trust.
Guard replacement and node package updates are currently unavailable through this
API. They require their own validated recovery workflow.

## Prepare through trusted local access

Retain wired management access and a separate encrypted configuration backup.
Keep both the installed and replacement package sets available offline, including
their signed manifests. The previous signed package set is required for recovery
of changed installed components. A filename or an installed version number alone
does not verify the executable bytes.

An administrator supplies the trusted Ed25519 public key independently of the
package download, as a base64 value in the root-owned mode-0600 file
`/etc/routeharbor-maintenance/trust.pub`. Its parent directory must be root-owned and
private. Never copy a new trust key from an unverified bundle. See
[release trust and encrypted backups](updates.md).

Place a verified release's `manifest.json`, base64 `manifest.sig` and exact IPK
files in a root-owned directory that other users cannot modify. The staging
command verifies the signature, target package architecture, every selected
artifact's length and hash, package metadata and bounded archive contents. It
copies verified bytes into private storage and returns a bundle ID:

```sh
/usr/libexec/routeharbor-helper maintenance-stage --source /root/private-bundle-dir
```

Stage both the previous and replacement bundles. Staging neither installs packages
nor changes routing. The public API lists metadata for these bundles; it does not
expose source configurations, signing material or private paths.

## Review and start the same operation from UI, CLI or agent

The English panel provides **Software maintenance** under advanced settings. Use
its preview before confirming an operation. The same operations are available
through the CLI and the live [OpenAPI contract](../api/openapi.yaml):

| Operation | Purpose |
| --- | --- |
| `GET /maintenance/capabilities` | Supported components, installed inventory digest and maintenance availability |
| `GET /maintenance/bundles` | Verified locally staged package sets |
| `POST /maintenance/plan` | Resolve and validate a proposed action without applying it |
| `POST /maintenance/operations` | Start one durable package job |
| `GET /maintenance/operations/{id}` | Read authoritative progress, completion or required recovery |

All paths are under `/api/v1`. Only an administrator can start a job. Reads and
planning are available to a read-only credential. Supported component identities
are `routeharbor`, `routeharbor-sing-box`, `routeharbor-xray`, `routeharbor-conntrack` and `routeharbor-continuity`.

For planning, supply `action` (`install`, `upgrade` or `remove`) and `components`.
Install and upgrade additionally require a `bundle_id`. The returned plan includes
the exact package changes, warnings and `installed_digest`. Removal requires an
explicit `removal_policy`:

- `preserve-closed` retains the independent guard and keeps protected forwarding
  closed. Removing the controller does not restore automatic path selection.
- `restore-direct` explicitly authorizes direct access and decommissions RouteHarbor's
  routing rules. Review that consequence before submitting the operation.

Before starting, copy the plan's inventory digest to `expected_installed_digest`.
Send the current quoted configuration revision in `If-Match`, and a new
`Idempotency-Key`. The CLI supplies these with `--revision` and `--idempotency-key`;
use `--token-file` and `--data -` so credentials stay out of process arguments.
Do not refresh the revision silently after the operator has reviewed a plan.

The start response contains the root job's ID and state. Its `Location` header
identifies the status endpoint. Retain both the job ID and the idempotency key.
The generic `/operations` journal records dispatch acceptance; package completion
is reported by `/maintenance/operations/{id}`. A lost response is not permission
to create another installation. Repeat the identical request and key to retrieve
the same job. A prepared job whose worker could not start may be safely rearmed;
an uncertain package-manager invocation is never blindly repeated.

## Interruption and routing recovery

Package planning uses a private offline package-manager configuration with no
feeds. Missing dependencies or unsupported package formats stop before installation.
The worker acquires a durable routing gate, rejects concurrent network or coverage
transactions, and quarantines protected traffic before changing packages. The
worker runs independently of the API request and controller service.

After installation or upgrade, routing remains guarded until a fresh explicit
prepare/apply/test/confirm sequence succeeds. A scheduler restart or a replay of
an old confirmation does not remove this hold. A failed recovery transaction
returns to closed forwarding, including when the earlier configuration used a
direct fallback. User configuration and physical interface choices remain subject
to normal validation and revision checks.

Controller removal can close the API connection. The retained privileged service
and local administrator status command provide the recovery path:

```sh
/usr/libexec/routeharbor-helper maintenance-status --operation JOB_ID
/usr/libexec/routeharbor-helper maintenance-resume
```

Replace `JOB_ID` with the returned 32-character identifier. Resume only rearms a
safe durable state or reconciles a completed package invocation. If the result is
`interrupted`, retain the guard, cached signed packages and management connection;
inspect the reported phase before an explicit offline recovery. Through trusted
local root access, choose one of these actions for that same job:

```sh
# Repair the originally requested package state from its authenticated cache.
/usr/libexec/routeharbor-helper maintenance-recover --operation JOB_ID --mode retry
# Restore the authenticated package versions retained before the operation.
/usr/libexec/routeharbor-helper maintenance-recover --operation JOB_ID --mode rollback
```

Recovery records that explicit choice before starting its worker. It removes and
reinstalls only the supported managed package set, using ordinary dependency
checks and cached signed bytes. It checks configured package state and immutable
installed files before releasing the package gate. An interrupted same-version
installation cannot pass merely because opkg still reports the old version.
Successful rollback reports the original job as `failed`, phase
`recovery_rolled_back`; it does not report the requested upgrade as
successful. Routing still requires a fresh tested transaction and confirmation.

This recovery covers the controller, adapter wrappers and supported native engine
packages. Repairing shared system libraries, replacing the guard, or resolving a
dependency that prevents ordinary removal is outside its supported recovery set.
Those cases retain the interruption and guard for trusted local repair. Do not
delete the journals, replace the trust key, force dependencies or remove the guard
to make an error disappear. Stable-release acceptance requires the actual package
and power-loss tests recorded in [the acceptance checklist](acceptance.md).

`routeharbor-continuity` is an optional authenticated maintenance component. The same
signed-package inventory, exact installed-payload verification, guarded maintenance,
and offline rollback requirements apply. Removing the gateway includes this dependent
worker package. Private pairing identity is retained separately in gateway state;
package install/upgrade never imports a private key or enables a relay profile.
