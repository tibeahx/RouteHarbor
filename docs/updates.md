# Updates, release trust and backups

No stable installation release or production signing trust root is published yet.
Do not install files merely because their names match an example. The repository
ships an offline `openrhp-release` utility for the release process.

A schema-1 manifest binds `project:OpenRHP`, stable numeric `version`, full source
`commit`, and artifacts with exact `name`, OpenWrt `architecture`, `sha256`, `bytes`.
The detached signature is standard Ed25519 over the manifest's bytes. The trusted
public key is supplied by the administrator independently of the downloaded archive.

```sh
go build -o openrhp-release ./cmd/openrhp-release
openrhp-release verify --manifest manifest.json --signature manifest.sig \
  --key /trusted/location/openrhp.pub --arch EXACT_OPENWRT_PACKAGE_ARCH \
  --current-version INSTALLED_VERSION --artifact DOWNLOADED_PACKAGE
```

Replace the uppercase placeholders with collected facts. Architecture is the package
architecture, not `arm64` inferred from Linux. Omit current-version only for a fresh
install. The verifier rejects signature/data tampering, mismatched size/hash/name/arch,
nonregular artifacts and version downgrades. Verification does not execute/install
anything. Keep the verified files in an administrator-owned private staging directory
until the package manager consumes them; do not allow another process to replace them.

Release signing keys are not checked in. Maintainers generate/store them offline with
`openrhp-release keygen`. Future key rotation must be authenticated by the previously
trusted key and an independently confirmed new fingerprint; downloading a new key
beside a new package is not rotation approval. Manifest/package association must match
the tagged source commit and published build/SBOM evidence.

## Backup and recovery

On the installed router, use existing root administrator access and run
`openrhp as-service backup --state /etc/openrhp --recipient age1... --out /etc/openrhp/admin/NEW_BACKUP.age`.
The command re-executes only the trusted installed `/usr/bin/openrhp` as the actual
non-root service UID/GID, with no supplementary groups, before opening service
state or writing the private output. Root does not follow a service-writable
state tree or change its ownership. Output must be a new path writable by the
service user. The command supports only `token` and `backup` administration.

For a development state directory, invoke
`openrhp backup --state STATE --recipient age1... --out NEW_PRIVATE_FILE.age`
directly as that directory's owner. The backup command uses
the standard age tool to encrypt the full source configuration for a recipient chosen
by the administrator. The private decryption identity is kept separately. No bespoke
password encryption or cloud upload is used. A backup excludes physical device
mapping validation, installed packages and firmware: retain these recovery materials
separately and securely.

`scripts/lab-admin.sh` verifies this boundary with a real Linux service account:
root issues and revokes a token through the privilege drop, the live service API
accepts then rejects that token, service-owned files retain their owner, a root-only
output path remains inaccessible, and a real age encryption/decryption round trip
retains the private source settings without printing them. This does not replace
installed OpenWrt package and lifecycle validation.

For a planned restore, decrypt locally through age into a 0600 file, validate schema
and reselect physical interfaces on the destination. Use the ordinary authenticated
configuration API with current revision, then independent path checks and a new
confirmed network transaction. Never apply a copied interface mapping blindly.

Before an update retain old/new verified packages offline, backup, rollback instructions
and a working management path. Update only OpenRHP and explicitly selected dependencies.
OpenWrt upgrades, bootloader operations and node firmware flashing are separate work.
A failed update must preserve the user's traffic policy; do not remove closed guards
as an automatic repair. Use [removal/recovery](uninstall.md) for decommissioning.
