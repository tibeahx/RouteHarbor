# Offline maintenance evidence

These checks cover the current development working tree. They do not establish a
stable signed release, a clean release commit, physical-router acceptance, or
package installation across a real loss of device power. Production release trust
is separate from the ephemeral signing keys used by these tests.

| Layer | Result and scope |
| --- | --- |
| Manager and archive unit tests | Race detector passed for signature/hash/identity checks, bounded archive parsing, malformed signed packages, symlink refusal, concurrent starts, worker-start retry, uncertain execution, installed-byte verification, explicit retry/rollback, and lost gate-release acknowledgement. |
| Crash regressions | A resumed `releasing_gate` state verifies installed payload again. Truncated or empty staged artifacts can be repaired from the exact authenticated source, including an already completed bundle. Unsigned cached payload metadata is rebuilt from signed archive bytes. Damaged incoming bytes are rejected even when a valid cache exists. |
| Immutable guard boundary | Correctly signed non-guard packages cannot claim reserved guard files/state, replace their ancestor directories, alias them through links, or declare that they replace/conflict with the guard. Guard IPKs can be staged but cannot be selected for replacement. Maintainer scripts remain part of trusted publisher code. |
| Actual OpenWrt opkg | The production staging/manager/backend installed and upgraded signed **generated test IPKs** using the actual OpenWrt 24.10.7 package manager. This verifies opkg behavior, not the final SDK package service lifecycle. |
| Offline resolution | An actual `--noaction` plan did not execute its candidate maintainer script. Verbose opkg inspection confirmed that production `OPKG_CONF_DIR` plus a private empty lists directory excludes system feeds. `--conf` by itself does not provide that isolation. |
| Package-process interruption | SIGKILL of the real opkg process group during a test postinst left an interrupted job with its gate held. Explicit local rollback restored the authenticated previous version. Explicit same-version retry restored a truncated executable even though opkg already reported that version. This is process interruption, not physical power loss. |
| Dependent package removal | A real opkg regression keeps a controller-dependent wrapper installed during interrupted upgrade rollback and same-version repair. The shared preview/execution/recovery path removes the wrapper before its dependency, then verifies controller/wrapper absence and guard retention. No force options are used. |
| Detached worker | A real detached worker survived parent/controller SIGKILL. Duplicate arms of one durable job executed exactly once and recorded completion. Its backend used private marker files; it did not claim to test opkg, radio or network changes. |
| SDK input compatibility | A read-only optional test accepted all six x86_64 SDK 0.1.0 baseline IPKs and all six 0.1.1 upgrade-fixture IPKs from `source-hsdpl8_b` through the archive parser and reserved-path checks. That snapshot predates the subsequently discovered removal-order fix; rebuilt package acceptance remains pending. |
| Full boot maintenance — partial | Actual SDK controller upgrade to 0.1.1 through the public API completed, same-key replay resolved its authoritative root operation, the guard executable stayed unchanged, and a fresh routing confirmation cleared the maintenance hold. The continuous monitored WAN capture across upgrade and confirmation contained zero packets, with zero kernel capture drops. Removal preflight then exposed the dependent-wrapper ordering bug before any removal. Both removal policies still require a clean rerun using rebuilt SDK packages containing the fix. |

Reproduce the bounded native userland and worker checks:

```sh
GO=/absolute/path/to/go GOCACHE=/absolute/private/cache sh scripts/lab-maintenance.sh
```

The script verifies the official
[OpenWrt 24.10.7 x86/64 root filesystem](https://downloads.openwrt.org/releases/24.10.7/targets/x86/64/)
against SHA-256
`862c25809a12356bdc051d144f53a4ebb6494bd0239a19e8c54cd9160db89b21`
before building the lab image. Each test uses a separate disposable container with
networking disabled and no host network access. Reports are written to
`test-results/maintenance/opkg.log` and `worker.log`. CI calls this same script.
OpenWrt userland executes on the Docker Linux kernel; this test is not a boot of
the OpenWrt firmware kernel.

The standard Go race suite also runs the unit regressions and bounded fuzz seeds.
A separate local two-worker parser fuzz run completed 313,975 executions in about
six seconds without a failure (`-fuzztime=5s -parallel=2`).
An optional read-only check can inspect the final SDK outputs independently:

```sh
ROUTEHARBOR_SDK_IPK_DIR=/absolute/sdk/packages go test ./internal/maintenance \
  -run '^TestActualSDKPackageFormatAndGuardBoundary$' -count=1 -v
```

The separate full-boot script checks the public API, discarded-response replay,
authoritative root progress after controller removal, retained guard executable,
fresh routing confirmation, management access and continuous external WAN
capture for each explicit removal policy. It requires a previously provisioned,
feature-compatible baseline; it never substitutes an older incompatible helper
for rollback proof. Its `--execute` flag is used only after the isolated VM owner
releases the test window. No physical device action is part of either script.
Incoming lab copies are deleted after successful authenticated staging to avoid
consuming the small guest filesystem twice. A preflight-only rerun may use
`--reuse-staged`; it accepts an existing authenticated bundle only when its complete
package hash set matches the exact supplied SDK files. Temporary journal lock
contention causes a bounded status-read retry and never replays package execution.
