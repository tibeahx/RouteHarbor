package helper

import (
	"context"
	"errors"
)

var ErrMaintenanceActive = errors.New(
	"maintenance_active: routing awaits package recovery and a new confirmed transaction",
)

// AcquireMaintenance commits a gate before installing quarantine. The same
// cross-process routing lock serializes engine startup and coverage mutations.
// check must not call this Manager again; it verifies other privileged journals.
func (m *Manager) AcquireMaintenance(ctx context.Context, id string, check func() error) error {
	return m.acquireMaintenance(ctx, id, check, false)
}

// ReacquireMaintenance is reserved for an explicitly requested, durable local
// package recovery. A lost release acknowledgement can be repaired only while
// its routing hold remains; a new network confirmation ends that permission.
func (m *Manager) ReacquireMaintenance(ctx context.Context, id string, check func() error) error {
	return m.acquireMaintenance(ctx, id, check, true)
}

func (m *Manager) acquireMaintenance(
	ctx context.Context,
	id string,
	check func() error,
	recovery bool,
) error {
	if !validTransactionID(id) {
		return errors.New("invalid_maintenance_identity")
	}
	return m.locked(func(s *State) error {
		if s.MaintenanceJob == "" && s.MaintenanceLastJob == id &&
			(!recovery || !s.MaintenanceHold) {
			return errors.New("maintenance_already_released")
		}
		if s.MaintenanceJob != "" && s.MaintenanceJob != id {
			return ErrMaintenanceActive
		}
		if active(s.Transaction) {
			return ErrBusy
		}
		if check != nil {
			if err := check(); err != nil {
				return err
			}
		}
		if s.MaintenanceJob == "" {
			s.MaintenanceJob, s.MaintenanceHold = id, true
			if err := m.save(s); err != nil {
				return err
			}
		}
		// A failed quarantine leaves the durable gate closed. Only the same job
		// may retry; a package worker must not continue after this error.
		return m.quarantineLocked(ctx, s)
	})
}

// ReleaseMaintenance permits a fresh explicit prepare/apply/confirm sequence.
// It never authorizes the scheduler to restore the pre-update selected path.
func (m *Manager) ReleaseMaintenance(id string) error {
	if !validTransactionID(id) {
		return errors.New("invalid_maintenance_identity")
	}
	return m.locked(func(s *State) error {
		if s.MaintenanceJob == "" && s.MaintenanceLastJob == id {
			return nil
		}
		if s.MaintenanceJob != id {
			return errors.New("maintenance_identity_conflict")
		}
		s.MaintenanceJob = ""
		s.MaintenanceLastJob = id
		return m.save(s)
	})
}

// WithRuntime holds the gate only for a bounded mutation, never for the lifetime
// of an engine or connection. fn must not acquire the routing journal lock.
func (m *Manager) WithRuntime(fn func() error) error {
	return m.locked(func(s *State) error {
		if s.MaintenanceJob != "" {
			return ErrMaintenanceActive
		}
		return fn()
	})
}

// DecommissionMaintenance is used only by the already-authorized package job.
// The ordinary local command cannot race a package worker's explicit policy.
func (m *Manager) DecommissionMaintenance(ctx context.Context, id, policy string) error {
	if !validTransactionID(id) {
		return errors.New("invalid_maintenance_identity")
	}
	return m.locked(func(s *State) error {
		if s.MaintenanceJob != id {
			return errors.New("maintenance_identity_conflict")
		}
		if policy == "preserve-closed" {
			return m.quarantineLocked(ctx, s)
		}
		if policy != "restore-direct" {
			return errors.New("decommission_policy_required")
		}
		return m.decommissionLocked(ctx, s)
	})
}
