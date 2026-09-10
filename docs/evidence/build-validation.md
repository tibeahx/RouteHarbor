# Build validation evidence

Executed on 2026-09-09 with Go 1.27.1 from the **uncommitted working tree**
based on `b314ebfe2e9463d752799b95ca44e0400838c718`. These results do not describe that base commit alone.
The frozen production sources passed the complete race suite and `go vet` before
these build checks. The build-input inventory covers `go.mod`, `api`, `cmd` and
`internal`, excluding Go test files. Its SHA-256 is:

```text
f71d399adac194eada907f70dc7c73deb0c5accf024e701717b9dba4dc28ed44
```

All 44 binaries compiled: four programs for 11 Linux architecture/ABI variants.
ELF class, endianness and machine identifiers matched every target. Embedded Go
build metadata confirmed Go 1.27.1, Linux, CGO disabled, ARMv5/v6/v7 selections
and MIPS/MIPS64 soft-float settings. This is compilation evidence, not execution
on every architecture or physical-router compatibility.

| Binary | Linux amd64 bytes | Matrix minimum bytes | Matrix maximum bytes |
| --- | ---: | ---: | ---: |
| `routeharbor` | 9,441,404 | 8,388,732 | 10,420,379 |
| `routeharbor-helper` | 5,918,844 | 5,308,540 | 6,684,827 |
| `routeharbor-node` | 7,954,556 | 7,012,476 | 8,847,515 |
| `routeharbor-release` | 3,379,324 | 3,080,316 | 3,866,748 |

Exact target rows are in [build-matrix.csv](build-matrix.csv). Sizes use stripped
binaries with `-trimpath`, `-buildvcs=false` and `-ldflags='-s -w -buildid='`.
They exclude separately installed engines and do not measure RAM usage.

The Linux amd64 controller was also built twice from different absolute source
paths, each with a separate empty Go build cache. `cmp` verified identical bytes.
This reproducibility check covers that controller target; it does not assert
independent-cache reproducibility for every matrix entry or the SDK packages.

The generated SBOM passed the [official SPDX 2.3 JSON schema](https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json)
and additional inventory checks: 44 binary files, two packages, 47 unique SPDX
identifiers, 90 relationships, no dangling references, and matching SHA-256 for
every binary. Each artifact is independently described and `GENERATED_FROM` the
source package. The validator used Python jsonschema 4.22.0 and the schema snapshot
with SHA-256 `239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b`.

For a dirty checkout, `scripts/sbom.py` records the working-tree input digest,
uses `NOASSERTION` for the source download location, and does not attribute local
changes to the base commit alone. Clean CI builds retain their exact Git commit
reference. The SBOM inventories the core and linked Go runtime; optional engines
remain separately installed.

To repeat the build checks from the repository root with the pinned toolchain:

```sh
GO=/absolute/path/to/go1.27.1/bin/go sh scripts/build-matrix.sh
GO=/absolute/path/to/go1.27.1/bin/go sh scripts/check-reproducible.sh
python3 scripts/sbom.py > dist/sbom.spdx.json
```

`OUT` selects the artifact directory for both the matrix and SBOM scripts.
