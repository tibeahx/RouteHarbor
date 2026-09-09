# Full-boot OpenWrt VM harness

This boots the actual OpenWrt 24.10.7 x86_64 kernel and root filesystem with QEMU
TCG. The first verified boot reports Linux 6.6.141 and `procd` as PID 1. It uses a
Docker container with `--network none`, private TAP bridges and network namespaces.
There are no published ports, host network interfaces, physical NICs or physical
disk devices. The container needs privileges to create only its private TAP and
namespace topology. TCG works without KVM or host architecture compatibility. The tested configuration
uses one virtual CPU and single-threaded TCG. In-process x86 warm resets sometimes
stalled in GRUB before kernel entry, including with one virtual CPU. The harness
therefore uses QEMU's `-no-reboot`: the actual guest completes its graceful
shutdown and requests reboot, QEMU exits, and the harness starts a fresh emulator
process on the same disk. This tests actual OpenWrt shutdown and boot while
explicitly excluding the unstable in-process emulator reset from the evidence.

Download the official BIOS ext4 combined image from the
[24.10.7 x86/64 release directory](https://downloads.openwrt.org/releases/24.10.7/targets/x86/64/),
verify the signed `sha256sums` manifest with independently trusted OpenWrt keys,
and place it in a private input directory as `openwrt.img.gz`. The harness also
requires the independently published whole-file SHA-256:

```text
3caea69f186b2bce80938d265e5e2a3dfd0f8713aed101df35d60b88d7270d1f
```

The checked image is `openwrt-24.10.7-x86-64-generic-ext4-combined.img.gz`.
This run verified `sha256sums.sig` using `usign` and the 24.10 release keys inside
the separately verified OpenWrt root filesystem. The immutable source image and
its appended sysupgrade metadata remain unchanged. Writes go to a private qcow2
overlay backed by the decompressed raw image. No image is flashed onto hardware.

Build the native QEMU tool container and start the lab with already verified input
packages/dependencies (the start script downloads nothing):

```sh
docker build -t openrhp-openwrt-vm:24.10.7 docker/lab-openwrt-vm
mkdir -p /absolute/private-vm-state
chmod 0700 /absolute/private-vm-state
scripts/lab-openwrt-vm.sh /absolute/verified-image-inputs /absolute/private-vm-state /absolute/sdk-ipks /absolute/verified-dependencies
```

The fresh-guest bootstrap waits for OpenWrt to generate its default network
configuration and SSH host keys. It installs an ephemeral client public key,
configures only this lab's network, and obtains the host public key from the
trusted serial console. SSH and SCP always enforce that pinned host key. Reusing
the state directory starts the existing disk without rewriting guest configuration.
Keep the state directory private: the overlay, client private key and serial
recovery log are local lab artifacts and must not be committed or published.

The fixed transport contract is:

```sh
# A script supplied on stdin runs through pinned SSH as guest root.
printf '%s\n' 'uname -a' 'cat /proc/1/comm' | docker exec -i openrhp-openwrt-boot-lab python3 /lab/vmctl.py exec
# Transfer a package from a read-only input mount.
docker exec openrhp-openwrt-boot-lab python3 /lab/vmctl.py put /packages/openrhp_0.1.0-r1_x86_64.ipk /tmp/openrhp.ipk
# Trusted serial recovery; use SSH stdin for credentials and ordinary operations.
printf '%s\n' 'ubus call system board' | docker exec -i openrhp-openwrt-boot-lab python3 /lab/vmctl.py serial
# Both wait for a changed guest boot ID and pinned SSH readiness. Graceful reboot
# requires a guest-requested QEMU exit; it never kills a guest to force success.
docker exec openrhp-openwrt-boot-lab python3 /lab/vmctl.py reboot
docker exec openrhp-openwrt-boot-lab python3 /lab/vmctl.py powercut
# Capture a clean checkpoint once, before installation; restore it for a fresh run.
docker exec openrhp-openwrt-boot-lab python3 /lab/vmctl.py snapshot
docker exec openrhp-openwrt-boot-lab python3 /lab/vmctl.py restore-pristine
```

`powercut` kills only the checked QEMU process for this private disk and starts it
again; it does not shut down or power-cycle Docker or the host. Coordinate reboot
commands with any in-progress installer or other lab agent.

The checkpoint commands accept no names or paths. They require the private lab
ownership marker, preserve pinned SSH identities, stop QEMU before copying a disk,
and verify the saved disk's SHA-256 before restoration. A snapshot requires a
reachable guest that completes `sync`; restoration also works after a failed boot.
The last disk before restoration is retained privately as `before-restore.qcow2`.
These are disposable lab checkpoints, not a router backup or update mechanism.

The separate `x86-generic` profile boots the official 32-bit kernel for i386 ABI
execution. Download and signature-verify
[`openwrt-24.10.7-x86-generic-generic-ext4-combined.img.gz`](https://downloads.openwrt.org/releases/24.10.7/targets/x86/generic/),
with SHA-256 `394014a15bfb1efd0cd47242897d72493f6a2b3be81b7099a340490384457b82`,
into a distinct input directory and use a distinct private state directory:

```sh
OPENRHP_VM_PROFILE=x86-generic scripts/lab-openwrt-vm.sh /absolute/verified-i386-inputs /absolute/private-i386-state /absolute/sdk-ipks /absolute/verified-dependencies
printf '%s\n' 'uname -a' | docker exec -i openrhp-openwrt-i386-lab python3 /lab/vmctl-i386.py exec
# Build and execute the stdlib control plus selection, config and release suites.
GO=/absolute/pinned-go-1.27.1/bin/go python3 scripts/lab-openwrt-i386.py
```

This profile uses `qemu32` and the separate `openrhp-openwrt-i386-lab` container.
Its identically named private interfaces and addresses exist in that container's
own namespace; it cannot reach or modify the x86_64 acceptance VM. Do not install
x86_64 SDK packages into the 32-bit guest merely because they are mounted read-only.
The execution wrapper writes environment details, binary hashes and bounded test
logs under `test-results/openwrt-i386`. The first actual guest run passed all four
suites, including the stdlib diagnostic that failed under QEMU user-mode i386.

| Surface | IPv4 | IPv6 |
| --- | --- | --- |
| Guest LAN (`br-lan`) | `10.44.0.1/24` | `fd44:1::1/64` |
| Container management bridge | `10.44.0.2/24` | `fd44:1::2/64` |
| Client namespace `openrhp-client` | `10.44.0.20/24` | `fd44:1::20/64` |
| Guest WAN (`eth1`) | `198.18.0.2/24` | `fd44:2::2/64` |
| WAN namespace `openrhp-wan` | `198.18.0.1/24` | `fd44:2::1/64` |
| Isolated WAN test target aliases | `8.8.8.8/32` | `2001:4860:4860::8888/128` |

The public-looking target addresses exist only as local aliases in the WAN
namespace; the container cannot reach the actual Internet. Run client or target
commands with `docker exec ... ip netns exec openrhp-client ...` or
`openrhp-wan`. `/state/ready.json` describes the active topology and image digest.

The QEMU [system invocation documentation](https://www.qemu.org/docs/master/system/invocation.html)
describes the TCG, TAP and serial socket options used here. This is full guest-kernel
and boot evidence, separate from earlier OpenWrt-userland-only container tests.
It remains virtual-machine evidence; it does not prove physical radios, device
flash resilience, hardware offload, or other CPU/firmware combinations.

Stop the disposable lab with `docker stop openrhp-openwrt-boot-lab`. Its private
state directory is retained for inspection or another controlled start.
