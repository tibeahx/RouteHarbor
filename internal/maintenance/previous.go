package maintenance

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/release"
)

// Existing versions must remain available as authenticated offline recovery files.
func (m *Manager) previousPayloads(ctx context.Context, plan Plan) ([]PackagePayload, error) {
	desired := map[string]string{}
	if plan.Request.Action == "remove" {
		for _, p := range plan.Packages {
			desired[p.Name] = p.Version
		}
	} else {
		inventory, err := m.backend.Inventory(ctx)
		if err != nil {
			return nil, err
		}
		for _, p := range plan.Packages {
			if version := inventory.Packages[p.Name]; version != "" {
				desired[p.Name] = version
			}
			if p.Name == "openrhp" {
				for _, wrapper := range []string{"openrhp-sing-box", "openrhp-xray", "openrhp-conntrack", "openrhp-continuity"} {
					if version := inventory.Packages[wrapper]; version != "" {
						desired[wrapper] = version
					}
				}
			}
		}
	}
	if len(desired) == 0 {
		return nil, nil
	}
	entries, err := stateEntries(m.root)
	if err != nil {
		return nil, err
	}
	found := map[string]PackagePayload{}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "bundle-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		record, err := readBundle(
			m.root,
			strings.TrimSuffix(strings.TrimPrefix(name, "bundle-"), ".json"),
		)
		if err != nil {
			return nil, err
		}
		var manifest release.Manifest
		if adapter.StrictDecode(record.Manifest, &manifest) != nil {
			return nil, errors.New("maintenance_manifest_rejected")
		}
		for _, p := range record.Metadata {
			if desired[p.Name] == "" || desired[p.Name] != p.Version {
				continue
			}
			for _, artifact := range manifest.Artifacts {
				if artifact.SHA256 != p.SHA256 {
					continue
				}
				actual, err := inspectArtifact(m.root, artifact)
				if err != nil {
					return nil, err
				}
				if actual.Name != p.Name || actual.Version != p.Version {
					return nil, errors.New("maintenance_previous_identity_rejected")
				}
				found[p.Name] = PackagePayload{
					Package:   actual.Package,
					Files:     actual.Files,
					Conffiles: actual.Conffiles,
				}
			}
		}
	}
	if len(found) != len(desired) {
		return nil, errors.New("maintenance_previous_package_not_staged")
	}
	out := []PackagePayload{}
	for _, prior := range found {
		out = append(out, prior)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Package.Name < out[j].Package.Name })
	return out, nil
}
