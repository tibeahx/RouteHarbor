package maintenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
)

type Inventory struct {
	Architecture   string
	Packages       map[string]string
	AvailableBytes int64
}

type Backend interface {
	Inventory(context.Context) (Inventory, error)
	Compare(context.Context, string, string, string) (bool, error)
	Check(context.Context, Plan, []string) error
	Acquire(context.Context, string) error
	Release(string) error
	Decommission(context.Context, string, string) error
	Execute(context.Context, Plan, []string) error
	Verify(context.Context, Plan, []PackagePayload) error
}

type Worker interface{ Arm(string) error }

var dependencyPattern = regexp.MustCompile(
	`^([a-z0-9][a-z0-9+.-]{0,79})(?:\s*\((=|>=|<=|>>|<<|>|<)\s*([A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127})\))?$`,
)

type dependency struct{ Name, Operator, Version string }

func dependencies(raw string) ([]dependency, error) {
	if raw == "" {
		return nil, nil
	}
	if len(raw) > 8192 {
		return nil, errors.New("maintenance_dependency_limit")
	}
	var result []dependency
	for entry := range strings.SplitSeq(raw, ",") {
		parts := dependencyPattern.FindStringSubmatch(strings.TrimSpace(entry))
		if parts == nil || len(result) >= 64 {
			return nil, errors.New("maintenance_dependency_format_unsupported")
		}
		result = append(result, dependency{parts[1], parts[2], parts[3]})
	}
	return result, nil
}

func inventoryDigest(inventory Inventory) (string, error) {
	if !packageArchitecture.MatchString(inventory.Architecture) || len(inventory.Packages) > 4096 {
		return "", errors.New("maintenance_inventory_invalid")
	}
	for name, version := range inventory.Packages {
		if !packageName.MatchString(name) || !packageVersion.MatchString(version) {
			return "", errors.New("maintenance_inventory_invalid")
		}
	}
	raw, err := json.Marshal(struct {
		Architecture string
		Packages     map[string]string
	}{inventory.Architecture, inventory.Packages})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func makePlan(
	ctx context.Context,
	backend Backend,
	request Request,
	record bundleRecord,
) (Plan, error) {
	var plan Plan
	if err := ValidateRequest(request, false); err != nil {
		return plan, err
	}
	inventory, err := backend.Inventory(ctx)
	if err != nil {
		return plan, err
	}
	digest, err := inventoryDigest(inventory)
	if err != nil {
		return plan, err
	}
	if request.ExpectedInstalledDigest != "" && request.ExpectedInstalledDigest != digest {
		return plan, errors.New("maintenance_installed_state_conflict")
	}
	request.Components = append([]string(nil), request.Components...)
	sort.Strings(request.Components)
	request.ExpectedInstalledDigest = digest
	plan = Plan{
		Request:         request,
		InstalledDigest: digest,
		Warnings: []string{
			"Routing remains guarded until a fresh network transaction is confirmed.",
			"The guard package and existing native engines are retained on controller removal.",
		},
	}
	if request.Action == "remove" && request.RemovalPolicy == "restore-direct" {
		plan.Warnings[0] = "Explicit removal policy restores ordinary direct routing; the guard package remains installed."
	}
	if inventory.Packages["openrhp-guard"] == "" {
		return plan, errors.New("maintenance_guard_required")
	}
	if request.Action == "remove" {
		selected := map[string]bool{}
		for _, name := range request.Components {
			selected[name] = true
		}
		if selected["openrhp"] {
			for _, name := range []string{"openrhp-sing-box", "openrhp-xray", "openrhp-conntrack"} {
				if inventory.Packages[name] != "" {
					selected[name] = true
				}
			}
		}
		for name := range selected {
			if version := inventory.Packages[name]; version != "" {
				plan.Packages = append(
					plan.Packages,
					Package{Name: name, Version: version, Architecture: inventory.Architecture},
				)
			}
		}
	} else {
		if record.Summary.Architecture != inventory.Architecture {
			return plan, errors.New("maintenance_architecture_mismatch")
		}
		candidates := map[string]packageMetadata{}
		for _, p := range record.Metadata {
			candidates[p.Name] = p
		}
		selected := map[string]bool{}
		visiting := map[string]bool{}
		var add func(string) error
		add = func(name string) error {
			if selected[name] {
				return nil
			}
			if visiting[name] {
				return errors.New("maintenance_dependency_cycle")
			}
			candidate, ok := candidates[name]
			if !ok {
				return errors.New("maintenance_dependency_not_staged")
			}
			if name == "openrhp-guard" || name == "openrhp-node" {
				return errors.New("maintenance_guard_or_node_replacement_unsupported")
			}
			if name == "openrhp" &&
				strings.SplitN(candidate.Version, "-", 2)[0] != record.Summary.Version {
				return errors.New("maintenance_source_version_mismatch")
			}
			if current := inventory.Packages[name]; current != "" {
				acceptable, err := backend.Compare(ctx, candidate.Version, ">=", current)
				if err != nil {
					return err
				}
				if !acceptable {
					return errors.New("maintenance_downgrade_rejected")
				}
			}
			visiting[name] = true
			deps, err := dependencies(candidate.Depends)
			if err != nil {
				return err
			}
			for _, dep := range deps {
				satisfied := false
				if installed := inventory.Packages[dep.Name]; installed != "" {
					satisfied = dep.Operator == ""
					if dep.Operator != "" {
						satisfied, err = backend.Compare(ctx, installed, dep.Operator, dep.Version)
						if err != nil {
							return err
						}
					}
				}
				if satisfied {
					continue
				}
				if err = add(dep.Name); err != nil {
					return err
				}
				if dep.Operator != "" {
					satisfied, err = backend.Compare(
						ctx,
						candidates[dep.Name].Version,
						dep.Operator,
						dep.Version,
					)
					if err != nil {
						return err
					}
					if !satisfied {
						return errors.New("maintenance_dependency_version_mismatch")
					}
				}
			}
			visiting[name] = false
			selected[name] = true
			plan.Packages = append(plan.Packages, candidate.Package)
			return nil
		}
		for _, component := range request.Components {
			if request.Action == "upgrade" && inventory.Packages[component] == "" {
				return plan, errors.New("maintenance_upgrade_requires_installed_component")
			}
			if err = add(component); err != nil {
				return plan, err
			}
		}
		var required int64
		for name := range selected {
			required += candidates[name].ExpandedBytes + candidates[name].Bytes
		}
		if required > inventory.AvailableBytes {
			return plan, errors.New("maintenance_insufficient_storage")
		}
	}
	sort.Slice(
		plan.Packages,
		func(i, j int) bool { return plan.Packages[i].Name < plan.Packages[j].Name },
	)
	raw, err := json.Marshal(plan)
	if err != nil {
		return plan, err
	}
	hash := sha256.Sum256(raw)
	plan.Digest = hex.EncodeToString(hash[:])
	return plan, nil
}
