package maintenance

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/release"
)

type jobRecord struct {
	Schema    int             `json:"schema"`
	Operation Operation       `json:"operation"`
	Plan      Plan            `json:"plan"`
	Previous  []Package       `json:"previous"`
	Recovery  *recoveryRecord `json:"recovery,omitempty"`
}

type Manager struct {
	root    *os.Root
	dir     string
	backend Backend
	worker  Worker
}

func NewManager(dir string, backend Backend, worker Worker) (*Manager, error) {
	if backend == nil {
		return nil, errors.New("maintenance_backend_required")
	}
	root, err := openStateRoot(dir)
	if err != nil {
		return nil, err
	}
	return &Manager{root: root, dir: dir, backend: backend, worker: worker}, nil
}

func (m *Manager) Close() error { return m.root.Close() }

func (m *Manager) Capabilities(ctx context.Context) (map[string]any, error) {
	lock, err := stateLock(m.root, ".lock")
	if err != nil {
		return nil, err
	}
	activeID, _, err := m.activeLocked()
	stateUnlock(lock)
	if err != nil {
		return nil, err
	}
	result := map[string]any{
		"available":           false,
		"guard_replacement":   false,
		"node_update":         false,
		"active":              activeID != "",
		"active_operation_id": activeID,
		"components": []string{
			"openrhp",
			"openrhp-sing-box",
			"openrhp-xray",
			"openrhp-conntrack", "openrhp-continuity",
		},
		"actions": []string{"install", "upgrade", "remove"},
	}
	_, _, trustErr := trustedKey(m.root)
	result["trusted_key_available"] = trustErr == nil
	inventory, err := m.backend.Inventory(ctx)
	if err != nil {
		result["reason"] = "maintenance_platform_or_inventory_unavailable"
		return result, nil
	}
	digest, err := inventoryDigest(inventory)
	if err != nil {
		return nil, err
	}
	result["available"] = inventory.Packages["openrhp-guard"] != "" && m.worker != nil
	result["architecture"], result["installed_digest"] = inventory.Architecture, digest
	return result, nil
}

func (m *Manager) Bundles(context.Context) ([]BundleSummary, error) {
	lock, err := stateLock(m.root, ".lock")
	if err != nil {
		return nil, err
	}
	defer stateUnlock(lock)
	entries, err := stateEntries(m.root)
	if err != nil {
		return nil, err
	}
	out := []BundleSummary{}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "bundle-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(name, "bundle-"), ".json")
		record, err := readBundle(m.root, id)
		if err != nil {
			return nil, err
		}
		out = append(out, record.Summary)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Manager) Plan(ctx context.Context, request Request) (Plan, error) {
	lock, err := stateLock(m.root, ".lock")
	if err != nil {
		return Plan{}, err
	}
	defer stateUnlock(lock)
	return m.planLocked(ctx, request)
}

func (m *Manager) planLocked(ctx context.Context, request Request) (Plan, error) {
	var record bundleRecord
	if err := ValidateRequest(request, false); err != nil {
		return Plan{}, err
	}
	if request.Action != "remove" {
		var err error
		record, err = readBundle(m.root, request.BundleID)
		if err != nil {
			return Plan{}, err
		}
	}
	plan, err := makePlan(ctx, m.backend, request, record)
	if err != nil {
		return plan, err
	}
	if _, err = m.previousPayloads(ctx, plan); err != nil {
		return plan, err
	}
	paths, err := m.artifacts(plan, record)
	if err != nil {
		return plan, err
	}
	if err = m.backend.Check(ctx, plan, paths); err != nil {
		return plan, err
	}
	return plan, nil
}

func (m *Manager) artifacts(plan Plan, record bundleRecord) ([]string, error) {
	paths := []string{}
	if plan.Request.Action == "remove" {
		return paths, nil
	}
	var manifest release.Manifest
	if err := adapter.StrictDecode(record.Manifest, &manifest); err != nil {
		return nil, errors.New("maintenance_manifest_rejected")
	}
	signed := map[string]release.Artifact{}
	for _, artifact := range manifest.Artifacts {
		signed[artifact.SHA256] = artifact
	}
	for _, p := range plan.Packages {
		artifact, ok := signed[p.SHA256]
		if !ok || artifact.Bytes != p.Bytes || artifact.Architecture != p.Architecture {
			return nil, errors.New("maintenance_package_not_signed")
		}
		metadata, err := inspectArtifact(m.root, artifact)
		if err != nil {
			return nil, err
		}
		if !reflect.DeepEqual(metadata.Package, p) {
			return nil, errors.New("maintenance_package_identity_changed")
		}
		paths = append(paths, filepath.Join(m.dir, "artifact-"+p.SHA256+".ipk"))
	}
	return paths, nil
}

func (m *Manager) readJob(id string) (jobRecord, error) {
	var job jobRecord
	if !hexID.MatchString(id) {
		return job, errors.New("maintenance_operation_id_invalid")
	}
	raw, err := readPrivate(m.root, "job-"+id+".json")
	if err != nil {
		return job, err
	}
	if len(raw) > 128<<10 || adapter.StrictDecode(raw, &job) != nil || job.Schema != 1 ||
		job.Operation.ID != id ||
		ValidateRequest(job.Plan.Request, true) != nil ||
		!hashID.MatchString(job.Plan.Digest) {
		return job, errors.New("maintenance_job_rejected")
	}
	switch job.Operation.State {
	case "prepared", "running", "verifying", "completed", "failed", "interrupted":
	default:
		return job, errors.New("maintenance_job_rejected")
	}
	return job, nil
}

func (m *Manager) saveJob(job jobRecord) error {
	job.Operation.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	raw, err := json.Marshal(job)
	if err != nil {
		return err
	}
	if len(raw) > 128<<10 {
		return errors.New("maintenance_job_limit")
	}
	return writePrivate(m.root, "job-"+job.Operation.ID+".json", raw)
}

func terminal(job jobRecord) bool {
	return job.Operation.State == "completed" || job.Operation.State == "failed"
}

func (m *Manager) activeLocked() (string, int, error) {
	entries, err := stateEntries(m.root)
	if err != nil {
		return "", 0, err
	}
	active, count := "", 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "job-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		count++
		job, err := m.readJob(strings.TrimSuffix(strings.TrimPrefix(name, "job-"), ".json"))
		if err != nil {
			return "", count, err
		}
		if !terminal(job) {
			if active != "" {
				return "", count, errors.New("maintenance_multiple_active_jobs")
			}
			active = job.Operation.ID
		}
	}
	return active, count, nil
}

func (m *Manager) Active() (bool, error) {
	lock, err := stateLock(m.root, ".lock")
	if err != nil {
		return false, err
	}
	defer stateUnlock(lock)
	id, _, err := m.activeLocked()
	return id != "", err
}

func (m *Manager) Start(ctx context.Context, id string, request Request) (Operation, error) {
	if !hexID.MatchString(id) {
		return Operation{}, errors.New("maintenance_operation_id_invalid")
	}
	if err := ValidateRequest(request, true); err != nil {
		return Operation{}, err
	}
	lock, err := stateLock(m.root, ".lock")
	if err != nil {
		return Operation{}, err
	}
	var job jobRecord
	existing, readErr := m.readJob(id)
	if readErr == nil {
		desired := request
		desired.Components = append([]string(nil), request.Components...)
		sort.Strings(desired.Components)
		if !reflect.DeepEqual(existing.Plan.Request, desired) {
			stateUnlock(lock)
			return Operation{}, errors.New("maintenance_operation_identity_conflict")
		}
		job = existing
	} else if !errors.Is(readErr, os.ErrNotExist) {
		stateUnlock(lock)
		return Operation{}, readErr
	} else {
		active, count, err := m.activeLocked()
		if err != nil {
			stateUnlock(lock)
			return Operation{}, err
		}
		if active != "" {
			stateUnlock(lock)
			return Operation{}, errors.New("maintenance_active")
		}
		if count >= 64 {
			stateUnlock(lock)
			return Operation{}, errors.New("maintenance_job_history_full")
		}
		plan, err := m.planLocked(ctx, request)
		if err != nil {
			stateUnlock(lock)
			return Operation{}, err
		}
		previous, err := m.previousPayloads(ctx, plan)
		if err != nil {
			stateUnlock(lock)
			return Operation{}, err
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		job = jobRecord{
			Schema: 1,
			Plan:   plan,
			Operation: Operation{
				ID:            id,
				State:         "prepared",
				Phase:         "waiting_for_worker",
				Action:        request.Action,
				Components:    plan.Request.Components,
				CreatedAt:     now,
				UpdatedAt:     now,
				GuardRetained: true,
			},
		}
		for _, payload := range previous {
			job.Previous = append(job.Previous, payload.Package)
		}
		if err = m.saveJob(job); err != nil {
			stateUnlock(lock)
			return Operation{}, err
		}
	}
	stateUnlock(lock)
	if job.Operation.State == "prepared" {
		if m.worker == nil {
			return m.workerUnavailable(id)
		}
		if err = m.worker.Arm(id); err != nil {
			return m.workerUnavailable(id)
		}
	}
	return m.Status(ctx, id)
}

func (m *Manager) Status(_ context.Context, id string) (Operation, error) {
	lock, err := stateLock(m.root, ".lock")
	if err != nil {
		return Operation{}, err
	}
	defer stateUnlock(lock)
	job, err := m.readJob(id)
	return job.Operation, err
}

func (m *Manager) Resume(ctx context.Context) error {
	lock, err := stateLock(m.root, ".lock")
	if err != nil {
		return err
	}
	id, _, err := m.activeLocked()
	stateUnlock(lock)
	if err != nil || id == "" {
		return err
	}
	if m.worker == nil {
		return errors.New("maintenance_worker_unavailable")
	}
	return m.worker.Arm(id)
}

func (m *Manager) update(id, state, phase, code string) error {
	lock, err := stateLock(m.root, ".lock")
	if err != nil {
		return err
	}
	defer stateUnlock(lock)
	job, err := m.readJob(id)
	if err != nil {
		return err
	}
	job.Operation.State, job.Operation.Phase, job.Operation.ErrorCode = state, phase, code
	job.Operation.Retryable = false
	return m.saveJob(job)
}

// Run executes only in a detached root worker. On restart an uncertain package
// command is reconciled, never blindly replayed with force flags.
func (m *Manager) Run(ctx context.Context, id string) error {
	workerLock, err := stateLock(m.root, ".worker-lock")
	if err != nil {
		return err
	}
	defer stateUnlock(workerLock)
	lock, err := stateLock(m.root, ".lock")
	if err != nil {
		return err
	}
	job, err := m.readJob(id)
	stateUnlock(lock)
	if err != nil {
		return err
	}
	if terminal(job) {
		return nil
	}
	if job.Operation.Phase == "release_failed_job" {
		return m.failBeforeExecution(id, job.Operation.ErrorCode)
	}
	if job.Operation.Phase == "releasing_gate" {
		if !m.verifiedJob(ctx, job) {
			return m.update(
				id,
				"interrupted",
				"package_recovery_required",
				"maintenance_installed_state_mismatch",
			)
		}
		return m.complete(id)
	}
	if job.Recovery != nil {
		if recovery, ok := m.backend.(interface {
			AcquireRecovery(context.Context, string) error
		}); ok {
			err = recovery.AcquireRecovery(ctx, id)
		} else {
			err = errors.New("maintenance_recovery_unsupported")
		}
	} else {
		err = m.backend.Acquire(ctx, id)
	}
	if err != nil {
		return m.update(id, "interrupted", "guard_failed", "maintenance_guard_failed")
	}
	if job.Operation.State == "interrupted" {
		return nil
	}
	if job.Operation.State == "running" {
		return m.update(
			id,
			"interrupted",
			"package_recovery_required",
			"maintenance_interrupted_package_operation",
		)
	}
	if job.Operation.State == "verifying" {
		if !m.verifiedJob(ctx, job) {
			return m.update(
				id,
				"interrupted",
				"package_recovery_required",
				"maintenance_interrupted_package_operation",
			)
		}
		return m.complete(id)
	}
	if job.Recovery != nil {
		return m.runRecovery(ctx, job)
	}
	plan, err := m.Plan(ctx, job.Plan.Request)
	if err != nil {
		return m.failBeforeExecution(id, "maintenance_preflight_failed")
	}
	if plan.Digest != job.Plan.Digest {
		return m.failBeforeExecution(id, "maintenance_preflight_changed")
	}
	var record bundleRecord
	if plan.Request.Action != "remove" {
		record, err = readBundle(m.root, plan.Request.BundleID)
		if err != nil {
			return m.update(id, "interrupted", "verification_failed", "maintenance_bundle_rejected")
		}
	}
	paths, err := m.artifacts(plan, record)
	if err != nil {
		return m.update(id, "interrupted", "verification_failed", "maintenance_artifact_rejected")
	}
	if plan.Request.Action == "remove" {
		if err = m.backend.Decommission(ctx, id, plan.Request.RemovalPolicy); err != nil {
			return m.update(
				id,
				"interrupted",
				"decommission_failed",
				"maintenance_decommission_failed",
			)
		}
	}
	if err = m.update(id, "running", "package_manager", ""); err != nil {
		return err
	}
	if err = m.backend.Execute(ctx, plan, paths); err != nil {
		return m.update(
			id,
			"interrupted",
			"package_recovery_required",
			"maintenance_package_manager_failed",
		)
	}
	if err = m.update(id, "verifying", "installed_state", ""); err != nil {
		return err
	}
	if !m.installed(ctx, plan) {
		return m.update(
			id,
			"interrupted",
			"package_recovery_required",
			"maintenance_installed_state_mismatch",
		)
	}
	return m.complete(id)
}

func (m *Manager) installed(ctx context.Context, plan Plan) bool {
	payloads, err := m.payloads(plan)
	return err == nil && m.backend.Verify(ctx, plan, payloads) == nil
}

func (m *Manager) payloads(plan Plan) ([]PackagePayload, error) {
	if plan.Request.Action == "remove" {
		return m.previousPayloads(context.Background(), plan)
	}
	record, err := readBundle(m.root, plan.Request.BundleID)
	if err != nil {
		return nil, err
	}
	if _, err = m.artifacts(plan, record); err != nil {
		return nil, err
	}
	selected := map[string]bool{}
	for _, p := range plan.Packages {
		selected[p.Name] = true
	}
	out := []PackagePayload{}
	for _, p := range record.Metadata {
		if selected[p.Name] {
			out = append(
				out,
				PackagePayload{Package: p.Package, Files: p.Files, Conffiles: p.Conffiles},
			)
		}
	}
	return out, nil
}

func (m *Manager) complete(id string) error {
	// Keep the independent gate until the durable terminal record exists. If the
	// reply/save is lost, the worker verifies the installed payload again.
	if err := m.update(id, "verifying", "releasing_gate", ""); err != nil {
		return err
	}
	if err := m.backend.Release(id); err != nil {
		return err
	}
	job, err := m.readJob(id)
	if err != nil {
		return err
	}
	if job.Recovery != nil && job.Recovery.Mode == "rollback" {
		return m.update(
			id,
			"failed",
			"recovery_rolled_back",
			"maintenance_original_operation_rolled_back",
		)
	}
	return m.update(id, "completed", "complete", "")
}

func (m *Manager) workerUnavailable(id string) (Operation, error) {
	lock, err := stateLock(m.root, ".lock")
	if err != nil {
		return Operation{}, err
	}
	defer stateUnlock(lock)
	job, err := m.readJob(id)
	if err != nil {
		return Operation{}, err
	}
	if job.Operation.State == "prepared" {
		job.Operation.Phase = "worker_unavailable"
		job.Operation.ErrorCode = "maintenance_worker_unavailable"
		job.Operation.Retryable = true
		if err = m.saveJob(job); err != nil {
			return Operation{}, err
		}
	}
	return job.Operation, errors.New("maintenance_worker_unavailable")
}

func (m *Manager) failBeforeExecution(id, code string) error {
	if err := m.update(id, "verifying", "release_failed_job", code); err != nil {
		return err
	}
	if err := m.backend.Release(id); err != nil {
		return err
	}
	return m.update(id, "failed", "preflight_failed", code)
}
