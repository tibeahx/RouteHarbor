# User-mode ABI execution evidence

Date: 2026-09-08 UTC. Basis: working tree after published commit
`b314ebfe2e9463d752799b95ca44e0400838c718`, including the new offline release CLI
regressions. This is execution evidence for the listed test suites, not a release
certification, a full OpenWrt boot or a physical-router claim.

## Environment and command

- Official, unmodified Go 1.27.1; `CGO_ENABLED=0`, Linux targets.
- Docker Linux ARM64 host; isolated read-only containers without networking and
  with all capabilities dropped; bounded tmpfs and external process deadlines.
- Debian `qemu-user-static` **1:7.2+dfsg-7+deb12u18+b3**, pinned in
  `docker/lab-abi/Dockerfile` and obtained through signed Debian APT metadata.
- Explicit CPU selection and MIPS soft-float. No binfmt registration is required.

```sh
GO=/path/to/go1.27.1/bin/go sh scripts/lab-abi.sh
```

A bounded follow-up accepts explicit target names, for example:

```sh
GO=/path/to/go1.27.1/bin/go sh scripts/lab-abi.sh armv6
```

Filtered runs write their own `test-results/abi-TARGET` directory. They do not
overwrite the baseline run or rerun unrelated targets. Standard-library failure
controls run only when the corresponding MIPS64 big-endian or i386 target is
selected. The default unfiltered target set now includes ARMv6.

The script records environment details, every target/suite result, and individual
logs under `test-results/abi`. It continues collecting results after a failure and
returns nonzero if any test or standard-library control fails. The observed run
returned **1**; none of the failed rows is waived or hidden.

## Results

Each row runs all tests in `internal/selection`, `internal/config` and
`cmd/routeharbor-release` in separate cross-compiled test executables.

| Target | CPU | Selection | Configuration | Offline release CLI |
| --- | --- | --- | --- | --- |
| ARMv5, GOARM=5 | arm926 | PASS | PASS | PASS |
| ARMv6, GOARM=6 | arm1176 | PASS | PASS | PASS |
| ARMv7, GOARM=7 | cortex-a9 | PASS | PASS | PASS |
| MIPS32 big-endian, soft-float | 24Kc | PASS | PASS | PASS |
| MIPS32 little-endian, soft-float | 24Kc | PASS | PASS | PASS |
| MIPS64 big-endian, soft-float | 5Kc | FAIL | FAIL | FAIL |
| MIPS64 little-endian, soft-float | 5Kc | FAIL | FAIL | FAIL |
| i386 | qemu32 | FAIL | FAIL | FAIL |
| RISC-V64 | rv64 | PASS | PASS | PASS |

The [recorded CSV](abi-execution.csv) contains 27 observations: the original 24
plus a focused ARMv6 follow-up on 2026-09-08 UTC with the same Go/QEMU versions.
All three actual `GOARM=6` executables passed on `arm1176`; logs and current source
state are recorded separately under `test-results/abi-armv6`. OpenWrt CPU/package
variants beyond these CPU choices, real kernel modules and wireless hardware were
not tested here. ARM64 native container and x86 full-system
VM evidence, when available, are separate lab scopes.

## Failure controls

MIPS64 big/little-endian test executables fail with `SIGBUS`, `sigcode=1`, inside
Go 1.27.1 `runtime.netpoll`, `runtime/netpoll_epoll.go:140`. The faulting address is
only four-byte aligned. This matches the official
[Go runtime alignment issue #80978](https://github.com/golang/go/issues/80978).
Its discussion links the upstream change and notes that native MIPS64 Linux can
emulate unaligned access, unlike the user-mode emulator. Thus these observations
establish a failure in this execution environment, not a universal native-device
failure. No toolchain patch, downgrade or unsupported runtime flag was applied.

The standalone `scripts/testdata/abi-netpoll/main.go` uses only standard-library
pipes, timers and goroutines. It reproduces the MIPS64 failure on both `5Kc` and
`MIPS64R2-generic`. It also reproduces the i386 `SIGSEGV` in `runtime.runqput` during
runtime initialization on both `qemu32` and `max`; that failure's cause remains
unresolved. Neither control imports RouteHarbor packages. They rule out a requirement
for project code in reproducing the crash, but do not distinguish every possible
emulator/runtime interaction.

The four [standard-library control results](abi-stdlib.csv) are recorded separately
from the 27 application test-suite results.

An additional check used the booted OpenWrt 24.10.7 `x86/64` image, revision
`r29197-ab4c7d6af7`, Linux 6.6.141. That kernel rejected the i386 executable with
`exec format error` before its runtime could start. A native AMD64 `syscall.Exec`
launcher confirmed the error, avoiding the shell's attempt to interpret rejected
ELF bytes as a script. Only temporary guest files were used and removed; no
packages, services, routes or kernel configuration were changed. This x86-64
image therefore cannot validate i386 behavior; an actual 32-bit kernel or a
kernel with the required compatibility support remains necessary.

## Separate successful i386 full-system execution

A second, separate VM booted the official OpenWrt 24.10.7 **x86/generic** image:
Linux 6.6.141 `i686`, package architecture `i386_pentium4`, real PID 1 `procd`.
QEMU system 7.2.22 TCG used `qemu32` and one CPU. The image's verified SHA-256 is
`394014a15bfb1efd0cd47242897d72493f6a2b3be81b7099a340490384457b82`.
The same Go 1.27.1 standard-library control and all three unchanged i386 test
executables **passed** with `-test.timeout 90s -test.v`. No user-mode QEMU ran
inside the guest. The separate harness is `scripts/lab-openwrt-i386.py`.

This clears the listed i386 execution suites on that actual guest kernel and
shows the earlier user-mode failure is specific to that environment. It does
not certify packages, physical CPUs or every 32-bit x86 variant. The original
user-mode CSV remains unchanged because its failures were real observations.

## Separate successful MIPS64 full-system execution

On 2026-09-09 UTC, a focused follow-up booted the official OpenWrt 24.10.7 **malta/be64** and
**malta/le64** kernel images with their embedded initramfs. Both reported Linux
6.6.141 `mips64`, release revision `r29197-ab4c7d6af7`, and real PID 1 `procd`.
Their package architectures were `mips64_mips64r2` and `mips64el_mips64r2`.

Both checksum manifests passed `usign` verification using the independently
verified OpenWrt release keys, and both full image hashes matched those signed
manifests. Image pins, verifier provenance and exact commands are documented in
the [separate Malta lab](../../docker/lab-malta/README.md). The runner uses native
host QEMU system 7.2.22, `MIPS64R2-generic`, one CPU and 512 MiB RAM. It does not
run a user-mode emulator inside either guest.

| Actual guest | Stdlib netpoll control | Selection | Configuration | Offline release CLI |
| --- | --- | --- | --- | --- |
| OpenWrt malta/be64 | PASS | PASS | PASS | PASS |
| OpenWrt malta/le64 | PASS | PASS | PASS | PASS |

All binaries used unmodified Go 1.27.1 and `GOMIPS64=softfloat`. The three suites
ran all their tests with `-test.timeout 120s -test.v`; the stdlib-only program was
unchanged. The [eight recorded results](abi-mips64-fullsystem.csv) include binary
and kernel-image hashes. Environment, signature checks and individual logs are
under `test-results/openwrt-mips64`.

The guest debugfs `mips/unaligned_instructions` counter increased from 254 to
12324 on be64 and from 250 to 12306 on le64 during these runs. This establishes
that guest-kernel unaligned-instruction handling was active; the counter also
includes unrelated guest activity, so it does not attribute every increment to
Go. Together with the passing stdlib control, the results distinguish these
full-system kernels from the failing user-mode environment. No runtime patch,
compiler downgrade or unsupported runtime option was used.

These observations clear the listed execution suites for the tested Malta guest
kernels. They do not validate physical MIPS64 routers, every CPU variant, IPK
installation, persistent-storage recovery or radio behavior. The initramfs guests
were disposable and terminated after the checks. Original MIPS64 and i386
user-mode failures remain visible above and in their original result rows.
