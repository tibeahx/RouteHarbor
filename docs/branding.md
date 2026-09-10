# RouteHarbor identity

RouteHarbor is an adaptive routing gateway. The name is a brand, not an acronym.
Use `RouteHarbor` in prose and `routeharbor` for commands, package names, service
accounts, state paths and machine identifiers. Environment variables use
`ROUTEHARBOR_`. The Go module is `github.com/tibeahx/RouteHarbor`.

The logo combines an open harbor with an incoming route ending in sheltered
water. Its wordmark is original vector geometry, with no font files, remote
resources or runtime dependencies. The artwork is covered by the repository's
[Apache-2.0 license](../LICENSE).

- [Light-background wordmark](assets/routeharbor-logo-light.svg)
- [Dark-background wordmark](assets/routeharbor-logo-dark.svg)
- [Standalone mark](assets/routeharbor-mark.svg)

The README selects the appropriate wordmark for the reader's color scheme. The
offline control panel uses the same mark and the descriptor “Adaptive routing
gateway”; its favicon is simplified for small sizes.

## Installation identity

RouteHarbor packages, service accounts, private state directories, Unix sockets,
owned firewall objects and release manifests use the current identity. Builds
installed under an earlier project identity are separate installations; this
change does not provide an automatic in-place package or state migration.

Before replacing an earlier installation, retain a verified private backup and a
working management path. Use that installation's own trusted commands and guard
to decommission its routing with an explicit policy and remove its packages.
Then install RouteHarbor into fresh private directories and validate imported
configuration through prepare → apply → confirm. Recheck interface mappings and
node/relay pairing. Renaming an existing private state tree does not constitute
a validated migration, and the new helper does not claim another installation's
network objects.

Signed manifests are bound to their exact bytes and project identity. Generate
new manifests for new packages; changing an old manifest's name invalidates its
signature. User-provided certificates and secrets are not silently rewritten or
rotated by a branding change.

## Recorded evidence

Git history is retained. Earlier verification reports describe their recorded
commits, hashes and environments; readable terminology follows the current
project name. Their historical results are not new validation of renamed
packages. See [rename validation](routeharbor-rename-validation.md) for checks of
the current identity.
