# Separate OpenWrt Malta MIPS64 ABI lab

This lab boots the actual OpenWrt kernel and embedded initramfs with the native
host `qemu-system-mips64` or `qemu-system-mips64el` executable. It runs the Go
standard-library netpoll control plus the selection, configuration and offline
release CLI suites. It does not run QEMU user-mode inside the guest, install
packages, create a persistent guest disk or access physical devices.

The fixed image inputs are from the official OpenWrt 24.10.7 release directories:

| Profile | Official image | SHA-256 |
| --- | --- | --- |
| be64 | [vmlinux-initramfs.elf](https://downloads.openwrt.org/releases/24.10.7/targets/malta/be64/openwrt-24.10.7-malta-be64-vmlinux-initramfs.elf) | `2ad942f521fa5faf97377ad9f1830c584bfe069fd1d270a187885b674ad95ce5` |
| le64 | [vmlinux-initramfs.elf](https://downloads.openwrt.org/releases/24.10.7/targets/malta/le64/openwrt-24.10.7-malta-le64-vmlinux-initramfs.elf) | `2e3560c8a9fbac2d5f0d89f62b9a206159baa7332e8f37786e6a1759bc9e656a` |

Place each image, `sha256sums` and `sha256sums.sig` inside its `be64` or `le64`
subdirectory of an absolute private input directory. The runner downloads
nothing. It verifies each manifest with `usign`, checks the image against that
manifest and then enforces the fixed whole-image digest above before booting.

The verifier is the already independently verified
`openrhp-openwrt-deps:24.10.7` image, using `/etc/opkg/keys`. Its official 24.10.7
x86/64 base rootfs SHA-256 is
`862c25809a12356bdc051d144f53a4ebb6494bd0239a19e8c54cd9160db89b21`;
see the [SDK provenance](../../docs/evidence/openwrt-sdk.md). The verification
container is read-only and has no network. The execution container uses native
Debian host tools, with QEMU system pinned to
`1:7.2+dfsg-7+deb12u18+b3` through signed Debian APT metadata.

```sh
docker build -t openrhp-malta-lab:24.10.7 docker/lab-malta
mkdir -p /absolute/private-malta-state
chmod 0700 /absolute/private-malta-state
GO=/absolute/go1.27.1/bin/go python3 scripts/lab-openwrt-mips64.py /absolute/verified-malta-inputs /absolute/private-malta-state
# Run only one endian profile without rerunning the other:
GO=/absolute/go1.27.1/bin/go python3 scripts/lab-openwrt-mips64.py /absolute/verified-malta-inputs /absolute/private-malta-state le64
```

Each profile gets its own disposable Docker container with `--network none`,
all capabilities dropped, a read-only root filesystem and bounded temporary
storage. QEMU uses `MIPS64R2-generic`, one CPU, 512 MiB guest RAM and single-threaded
TCG. Its restricted SLIRP network forwards SSH only to `127.0.0.1:10022` **inside
that container**. There are no published Docker ports, TAP devices, host network
interfaces or block devices. The x86 acceptance VMs are separate and untouched.

The trusted serial console installs an ephemeral client public key and a lab
address in the guest's initramfs. The SSH host key is read from that console and
pinned; both SSH and SCP require the pinned key. Private keys and serial logs
remain in the mode-0700 local state directory and must not be committed. Only the
public environment, image/test hashes, bounded test logs and result summaries
are copied to `test-results/openwrt-mips64`. The guest is terminated after tests;
this is not shutdown, upgrade or power-loss acceptance.

When available, the guest's debugfs MIPS unaligned-instruction counter is recorded
before and after the suites. This is an observation of guest-kernel handling, not
a claim that every counter increment came from Go or a universal compatibility
claim. Missing counters remain explicitly unavailable. Original QEMU user-mode
failures stay recorded in the [ABI evidence](../../docs/evidence/abi-execution.md).
