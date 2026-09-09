package maintenance

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

type recoveryRecord struct {
	Mode   string    `json:"mode"`
	Target []Package `json:"target"`
	Remove []Package `json:"remove"`
}

type recoveryBackend interface {
	Recover(context.Context, Plan, []Package, []string) error
}

func recoverablePackage(name string) bool {
	switch name {
	case "openrhp",
		"openrhp-sing-box",
		"openrhp-xray",
		"openrhp-conntrack",
		"sing-box",
		"xray-core",
		"conntrack":
		return true
	}
	return false
}

// Recover is trusted-local administration only. It records explicit intent before
// starting a detached worker; uncertain commands are never automatically retried.
func (m *Manager) Recover(ctx context.Context, id, mode string) (Operation, error) {
	if mode != "retry" && mode != "rollback" {
		return Operation{}, errors.New("maintenance_recovery_mode_invalid")
	}
	if _, ok := m.backend.(recoveryBackend); !ok {
		return Operation{}, errors.New("maintenance_recovery_unsupported")
	}
	workerLock, err := stateLock(m.root, ".worker-lock")
	if err != nil {
		return Operation{}, err
	}
	lock, err := stateLock(m.root, ".lock")
	if err != nil {
		stateUnlock(workerLock)
		return Operation{}, err
	}
	job, err := m.readJob(id)
	if err != nil {
		stateUnlock(lock)
		stateUnlock(workerLock)
		return Operation{}, err
	}
	if job.Operation.State != "interrupted" {
		stateUnlock(lock)
		stateUnlock(workerLock)
		return Operation{}, errors.New("maintenance_recovery_requires_interrupted_job")
	}
	recovery, err := m.recoveryPlan(job, mode)
	if err == nil {
		job.Recovery = &recovery
		job.Operation.State, job.Operation.Phase, job.Operation.ErrorCode = "prepared", "recovery_requested", ""
		job.Operation.Retryable = false
		err = m.saveJob(job)
	}
	stateUnlock(lock)
	stateUnlock(workerLock)
	if err != nil {
		return Operation{}, err
	}
	if m.worker == nil {
		return m.workerUnavailable(id)
	}
	if err = m.worker.Arm(id); err != nil {
		return m.workerUnavailable(id)
	}
	return m.Status(ctx, id)
}

func (m *Manager) recoveryPlan(job jobRecord, mode string) (recoveryRecord, error) {
	r := recoveryRecord{Mode: mode}
	selected := map[string]Package{}
	for _, p := range job.Previous {
		selected[p.Name] = p
	}
	for _, p := range job.Plan.Packages {
		if p.SHA256 != "" || selected[p.Name].Name == "" {
			selected[p.Name] = p
		}
	}
	for _, p := range selected {
		if !recoverablePackage(p.Name) {
			return r, errors.New("maintenance_system_dependency_recovery_unsupported")
		}
		r.Remove = append(r.Remove, p)
	}
	if mode == "rollback" {
		r.Target = append(r.Target, job.Previous...)
	} else if job.Plan.Request.Action != "remove" {
		r.Target = append(r.Target, job.Plan.Packages...)
		// Preserve installed wrappers temporarily removed with their controller.
		for _, p := range job.Previous {
			present := false
			for _, current := range r.Target {
				present = present || current.Name == p.Name
			}
			if !present {
				r.Target = append(r.Target, p)
			}
		}
	}
	sort.Slice(r.Target, func(i, j int) bool { return r.Target[i].Name < r.Target[j].Name })
	sort.Slice(r.Remove, func(i, j int) bool { return r.Remove[i].Name < r.Remove[j].Name })
	if _, err := m.packagePayloads(r.Target); err != nil {
		return r, err
	}
	if _, err := m.packagePayloads(r.Remove); err != nil {
		return r, err
	}
	return r, nil
}

func (m *Manager) packagePayloads(packages []Package) ([]PackagePayload, error) {
	if len(packages) == 0 {
		return nil, nil
	}
	entries, err := stateEntries(m.root)
	if err != nil {
		return nil, err
	}
	var bundles []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "bundle-") && strings.HasSuffix(name, ".json") {
			bundles = append(
				bundles,
				strings.TrimSuffix(strings.TrimPrefix(name, "bundle-"), ".json"),
			)
		}
	}
	out := make([]PackagePayload, 0, len(packages))
	for _, expected := range packages {
		found := false
		for _, bundle := range bundles {
			record, err := readBundle(m.root, bundle)
			if err != nil {
				return nil, err
			}
			for _, actual := range record.Metadata {
				if reflect.DeepEqual(actual.Package, expected) {
					out = append(
						out,
						PackagePayload{
							Package:   actual.Package,
							Files:     actual.Files,
							Conffiles: actual.Conffiles,
						},
					)
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return nil, errors.New("maintenance_recovery_package_not_authenticated")
		}
	}
	return out, nil
}

func recoveryTarget(job jobRecord) Plan {
	plan := job.Plan
	plan.Request.Action = "install"
	plan.Packages = job.Recovery.Target
	if len(plan.Packages) == 0 {
		plan.Request.Action = "remove"
		plan.Packages = job.Recovery.Remove
	}
	return plan
}

func (m *Manager) verifiedJob(ctx context.Context, job jobRecord) bool {
	if job.Recovery == nil {
		return m.installed(ctx, job.Plan)
	}
	plan := recoveryTarget(job)
	payloads, err := m.packagePayloads(job.Recovery.Target)
	if err != nil || m.backend.Verify(ctx, plan, payloads) != nil {
		return false
	}
	// A rollback also removes newly introduced managed packages.
	for _, removed := range job.Recovery.Remove {
		present := false
		for _, target := range job.Recovery.Target {
			present = present || removed.Name == target.Name
		}
		if !present {
			absence := Plan{Request: Request{Action: "remove"}, Packages: []Package{removed}}
			payloads, err := m.packagePayloads([]Package{removed})
			if err != nil || m.backend.Verify(ctx, absence, payloads) != nil {
				return false
			}
		}
	}
	return true
}

func (m *Manager) runRecovery(ctx context.Context, job jobRecord) error {
	backend, ok := m.backend.(recoveryBackend)
	if !ok {
		return m.update(
			job.Operation.ID,
			"interrupted",
			"recovery_unavailable",
			"maintenance_recovery_unsupported",
		)
	}
	if _, err := m.packagePayloads(job.Recovery.Target); err != nil {
		return m.update(
			job.Operation.ID,
			"interrupted",
			"verification_failed",
			"maintenance_recovery_package_not_authenticated",
		)
	}
	paths := []string{}
	for _, p := range job.Recovery.Target {
		paths = append(paths, filepath.Join(m.dir, "artifact-"+p.SHA256+".ipk"))
	}
	if err := m.update(job.Operation.ID, "running", "recovery_package_manager", ""); err != nil {
		return err
	}
	if err := backend.Recover(ctx, recoveryTarget(job), job.Recovery.Remove, paths); err != nil {
		return m.update(
			job.Operation.ID,
			"interrupted",
			"package_recovery_required",
			"maintenance_recovery_failed",
		)
	}
	if err := m.update(job.Operation.ID, "verifying", "recovery_installed_state", ""); err != nil {
		return err
	}
	if !m.verifiedJob(ctx, job) {
		return m.update(
			job.Operation.ID,
			"interrupted",
			"package_recovery_required",
			"maintenance_installed_state_mismatch",
		)
	}
	return m.complete(job.Operation.ID)
}
