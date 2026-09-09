# Current SDK package matrix

On 2026-09-09 the official OpenWrt 24.10.7 SDK built all six OpenRHP packages
for each of three targets. These are development artifacts from frozen sources,
not a signed release or physical-device compatibility claim.

| SDK target | Package architecture | Packages | Total compressed bytes | Result |
| --- | --- | ---: | ---: | --- |
| x86/64 | x86_64 | 6 | 9,654,805 | Pass |
| mediatek/mt7622 | aarch64_cortex-a53 | 6 | 8,669,941 | Pass |
| ramips/mt7621 | mipsel_24kc | 6 | 9,057,900 | Pass |

Each build used the independently verified official SDK archive, pinned Go
1.27.1 and a read-only source snapshot in a container without network access.
`scripts/sdk-build.sh` performed a clean package build, then checked exactly the
six current outputs against the recipe version/release and SDK architecture.
All nine executable payloads passed ELF section/segment bounds, static-loader,
permission and Go build-metadata checks. The nine dependency-only packages contain
no executable payload. MIPS32 metadata specifies soft-float.

An earlier frozen x86_64 snapshot (`source-hsdpl8_b`, before the removal-order
and status-read corrections) passed clean installation, client reachability,
management, reboot, firewall reload/flush and abrupt-restart assertions. The first outgoing-only capture
contained four TCP Reset packets and was not sufficient to prove their origin.
A repeated full run captured both directions at WAN and LAN. The shared final
assertion verified **zero forwarded protected client packets** and separately
proved **four router-generated rejections** of old server retransmissions. All
captures reported zero dropped packets; this is not a claim of zero total WAN
traffic. [Exact boot evidence](openwrt-boot-network.md) records that distinction.

The [exact identities, sizes and hashes](sdk-package-matrix.json) include both
compressed IPKs and their executable payloads. Source files were hashed before
copying, after copying, and within the private snapshot; all three inventories
matched. The snapshot includes `go.mod`, `LICENSE`, `api`, `cmd`, `internal`,
`packaging` and `scripts/sdk-build.sh`, excluding Python cache files. Its inventory
SHA-256 is computed from the sorted compact JSON mapping of paths to file hashes:

```text
ad805e08453b39f2a24a62ca81799be897f1e48e2285309e4da4f07dde447e3e
```

The source base is `88d5b71e890b25306a8e2e97bc504749ad95970d` with the current
uncommitted implementation additions; these artifacts are not attributed to that
base commit alone. The previous snapshot also supplied an isolated `0.1.1`
maintenance upgrade fixture. The newly built packages above contain the removal
and status-read fixes; they have not had a new full-boot run. Additional VM runs
and physical installation were deferred by the user on 2026-09-09. Neither
development version is a signed release.

The verified SDK archive SHA-256 values are:

| Target | Archive SHA-256 |
| --- | --- |
| x86/64 | `996d71f9eab7df2e8acb0bb2c9726426f05c10d419e5f9600d59b14d871f2acb` |
| mediatek/mt7622 | `326064cd8da2b6c9dd254748a6130d2c48a10efb9624d6457ee6c394e9ad62dd` |
| ramips/mt7621 | `014cd0f69b2b28088fd89e5b00e4f4d5087e2fe6da52cbaa48cd521087ebf10d` |

Checksums were verified against signed release manifests using independently
trusted OpenWrt release keys. A package build does not test target kernel modules,
radio drivers, package installation or runtime resource budgets. The
[earlier ELF defect and regression](package-elf.md),
[full-system ABI execution](abi-execution.md) and
[OpenWrt boot network tests](openwrt-boot-network.md) have separate evidence scopes.
