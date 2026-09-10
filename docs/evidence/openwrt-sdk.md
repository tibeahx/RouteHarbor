# OpenWrt SDK and userland evidence

The OpenWrt 24.10.7 x86/64 SDK produced real development IPKs for `routeharbor`,
`routeharbor-guard`, `routeharbor-node`, `routeharbor-conntrack`, `routeharbor-sing-box` and
`routeharbor-xray` (six packages). The SDK build
ran on Linux in an isolated Docker volume using the verified Go 1.27.1 toolchain.
The Go compiler used no CGO or network dependency downloads. Package runtime
`DEPENDS` metadata remained intact; ordinary `opkg install` accepted the gateway,
guard and node packages against the OpenWrt root filesystem.

Input artifacts:

| Input | SHA-256 |
| --- | --- |
| `openwrt-sdk-24.10.7-x86-64_gcc-13.3.0_musl.Linux-x86_64.tar.zst` | `996d71f9eab7df2e8acb0bb2c9726426f05c10d419e5f9600d59b14d871f2acb` |
| `openwrt-24.10.7-x86-64-rootfs.tar.gz` | `862c25809a12356bdc051d144f53a4ebb6494bd0239a19e8c54cd9160db89b21` |
| Go 1.27.1 Linux amd64 archive | `63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445` |

The OpenWrt SDK and root filesystem came from the official
[24.10.7 x86/64 release directory](https://downloads.openwrt.org/releases/24.10.7/targets/x86/64/).
Their whole-file hashes were checked before extraction/import. The base package
index was verified with `usign` using the signing keys inside that verified root
filesystem. Each supplied dependency IPK was checked against the signed index.
These public hashes document the tested inputs; they are not project release
signatures or a replacement for an independently trusted OpenWrt signing key.

To reproduce the container image, obtain and verify these inputs first. Place the
rootfs archive in a private build directory as `rootfs.tar.gz`; place `Packages`,
`Packages.sig`, `ip-full`, `libbpf1`, `libelf1` and `zlib` IPKs from the release's
x86_64 base repository in its `dependencies` directory. Copy the repository's
`docker/lab-openwrt/Dockerfile` there, then build without network access:

```sh
docker build --platform linux/amd64 --network none -t routeharbor-openwrt-deps:24.10.7 /absolute/verified-openwrt-lab-inputs
python3 scripts/lab-openwrt.py --packages /absolute/current-sdk-ipks
```

The laboratory starts actual `ubusd`, `procd` and `netifd`, creates dummy LAN/WAN
interfaces inside the container, installs real IPKs with normal dependency
checks, and invokes the packaged service/setup scripts. It never joins the host
network, uses no physical interface and downloads nothing. The image contains
OpenWrt userland but executes the Docker Linux kernel; procd runs as a child of
the container shell. This is not a full OpenWrt boot, firmware/kernel ABI, radio,
wireless backhaul or physical-router acceptance result. Optional native engine
packages are verified by separate engine labs and are not installed in this
userland test. The optional connection tracking package is built but not installed
in this userland fixture. Its absence is checked explicitly; real IPv4/IPv6
TCP/UDP mark-scoped reset is covered by the separate Linux network lab. That test
verifies default-off retention, old-source-only deletion, low-bit mark masking,
current/foreign/unmarked entry preservation and idempotent empty deletion.

The initial real-userland run exposed and fixed the OpenWrt `/bin/ubus` executable
location, creation of the private service runtime directory under root-owned
`/var/run`, and privileged capability reporting for an unprivileged controller.
The complete reproducible lifecycle run passed:

- ordinary dependency-checked IPK installation and fresh disabled defaults;
- repeated gateway/node setup, distinct service UIDs and zero API capabilities;
- helper platform discovery, credential issuance and procd restarts;
- packaged node TLS pairing, helper-derived capabilities, status and revocation;
- refusal to issue a wireless verification receipt without live hardware, even
  when all administrator checklist flags are supplied;
- explicit unavailable optional conntrack capability and opt-in refusal before
  creating a routing transaction, followed by successful default-off operation;
- API prepare/apply/confirm of protected traffic;
- procd stop and actual fw4 flush/start/reload while IPv4/IPv6 external traffic
  remains blocked and local LAN routing remains available;
- refusal to uninstall an active guard, explicit direct-routing decommission,
  and ordinary package removal;
- byte-for-byte preservation of network/DHCP/firewall files and identity files.
