# SDK package ELF metadata verification

Date: 2026-09-09 UTC. Scope: the actual OpenWrt 24.10.7 SDK IPK outputs and the
Go 1.27.1 executables they contain. This is package-content inspection, not another
router installation or boot claim.

The SDK's `include/package-pack.mk` invokes `RSTRIP` after the recipe installs
files into the package directory. Its `rules.mk` selected host `sstrip -z`; the
actual build log confirmed that command. Applying it to a private copy of the
real pre-strip SDK controller output reproduced the defect:

| Artifact | Bytes | `file` / Go metadata inspection |
| --- | --- | --- |
| Original Go output, already built with `-s -w` | 9,441,404 | Valid stripped ELF; `go version -m` reads Go 1.27.1 and module/build settings |
| The same bytes after SDK `sstrip -z` | 9,436,418 | Section-name table at offset 9,441,280 extends beyond EOF; Go buildinfo reader rejects the ELF |
| Controller extracted from the corrected SDK IPK | 9,441,404 | Valid ELF; byte-identical to the original Go output |

The surviving `.go.buildinfo` bytes alone were insufficient: the ELF section
headers still referred to the removed string table. This prevented standard Go
metadata inspection even though the runtime could still execute loaded segments.
All nine executable-bearing original IPKs across x86_64, ARM64 and MIPS32 were
rejected by the new section-bounds check. Those old packages need regeneration;
their successful compilation is not evidence that their inspection metadata was
valid.

The [recipe](../../packaging/openwrt/routeharbor/Makefile) now sets package-local
`RSTRIP:=:` after including the SDK package definitions. It bundles only the
three Go executables and scripts; the Go linker already removes symbols and
DWARF with `-s -w`. Runtime dependencies and SDK package generation are unchanged.
This prevents the destructive second strip without adding debug information.

A fresh, genuine SDK clean/compile run rebuilt the six x86_64 IPKs using the same
source snapshot and the corrected recipe. The controller's packaged SHA-256 is
`8ea3c41c78b5f70ef0892c48fbea196d357f0a2458b55d7d9c940c40e5aefdb7`, matching the
pre-strip SDK output exactly. All six packages passed the
[recorded check](package-elf.json): three expected executable payloads have valid
ELF tables/segments and readable Go build metadata; three dependency-only packages
correctly contain no executable payload. ARM64/MIPS32 corrected packages were not
rebuilt during this bounded check. A later final-source
[three-target rebuild](sdk-package-matrix.md) regenerated and validated all
eighteen packages, including ARM64 and MIPS32.

The [validator](../../packaging/tests/check_ipk_elf.py) reads the real IPK payloads
without extracting archive-controlled paths or executing target code. It checks
ELF table and segment bounds, static executable format, the expected binary path,
permissions, Go version/module identity, Linux/CGO-disabled settings and agreement
between the ELF machine, Go architecture and OpenWrt package architecture. MIPS
build metadata must declare the intended soft-float ABI.

`scripts/sdk-build.sh` now runs this check after compilation. It selects exactly
six current artifacts using the recipe's literal version/release and the SDK's
package architecture. Missing or duplicate current outputs fail; stale versions
or another architecture cannot supply a successful check. Package control metadata
must agree with those identities.

To inspect an existing set before signing or binary vulnerability analysis:

```sh
GO=/absolute/go1.27.1/bin/go python3 packaging/tests/check_ipk_elf.py /absolute/sdk-packages/routeharbor*.ipk
```

The check deliberately rejects malformed or unreadable build metadata. It does
not infer success from finding a build-info string somewhere in the file or from
inspecting a separate build output outside the IPK.
