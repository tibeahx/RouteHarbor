package helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
)

const PersistentGuardPath = "/etc/openrhp-helper/guard.nft"

func (b *NetworkBackend) saveGuard(p dataplane.Plan) error {
	return writePrivateAtomic(PersistentGuardPath, []byte(p.GuardNFT))
}

func writePrivateAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 ||
		!ownedByCurrentUID(info) {
		return errors.New("persistent_guard_untrusted")
	}
	f, err := os.CreateTemp(dir, ".guard-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }()
	if err = f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// CheckQuarantine verifies ownership before the manager journals a new guard
// intent. This read-only phase must precede every first quarantine mutation.
func (b *NetworkBackend) CheckQuarantine(ctx context.Context, p dataplane.Plan) error {
	_, err := b.quarantinePlan(ctx, p)
	return err
}

func (b *NetworkBackend) quarantinePlan(
	ctx context.Context,
	p dataplane.Plan,
) (dataplane.Plan, error) {
	if err := b.checkTables(ctx); err != nil {
		return dataplane.Plan{}, err
	}
	safe := dataplane.SafeRollback(p.Desired, nil)
	guard, err := dataplane.Compile(safe)
	if err != nil {
		return guard, err
	}
	guard.DNSGuardUID = p.DNSGuardUID
	guard.IngressDevices = p.IngressDevices
	guard, err = dataplane.WithIngressDevices(guard)
	if err != nil {
		return guard, err
	}
	addresses, err := localAddresses()
	if err != nil {
		return guard, err
	}
	guard, err = dataplane.WithQuarantineRouterAddresses(guard, addresses)
	if err != nil {
		return guard, err
	}
	if err = b.checkRoutes(ctx, guard, &p); err != nil {
		return guard, err
	}
	if err = b.checkSafety(ctx, guard, &p); err != nil {
		return guard, err
	}
	if _, err = b.Runner.Run(
		ctx,
		b.NFTBinary,
		[]string{"--check", "--file", "-"},
		[]byte(guard.GuardNFT),
	); err != nil {
		return guard, errors.New("guard_check_failed")
	}
	return guard, nil
}

func (b *NetworkBackend) Quarantine(ctx context.Context, p dataplane.Plan) error {
	guard, err := b.quarantinePlan(ctx, p)
	if err != nil {
		return err
	}
	if err = b.applyDNSGuard(ctx, guard, &p); err != nil {
		return err
	}
	if err = b.applySafety(ctx, guard, &p); err != nil {
		return err
	}
	if err = b.saveGuard(guard); err != nil {
		return err
	}
	if _, err = b.Runner.Run(
		ctx,
		b.NFTBinary,
		[]string{"--file", "-"},
		[]byte(guard.GuardNFT),
	); err != nil {
		return errors.New("guard_apply_failed")
	}
	return nil
}

// Remove is available only through the trusted local decommission command. It
// requires an explicit restore-direct policy; normal API imports cannot invoke it.
func (b *NetworkBackend) Remove(ctx context.Context, p dataplane.Plan) error {
	if err := b.Quarantine(ctx, p); err != nil {
		return err
	}
	owner := p
	owner.Desired.Fallback = "closed"
	if err := b.checkRoutes(ctx, p, &owner); err != nil {
		return err
	}
	for _, route := range p.Routes {
		if err := b.removeRoute(ctx, route); err != nil {
			return err
		}
	}
	if err := b.removeDNSGuard(ctx, p); err != nil {
		return err
	}
	// Empty owned tables have no packet-handling effect and remain recognizable.
	for _, table := range []string{dataplane.Table, dataplane.ProbeTable} {
		if _, err := b.Runner.Run(
			ctx,
			b.NFTBinary,
			[]string{"list", "table", "inet", table},
			nil,
		); err == nil {
			if _, err = b.Runner.Run(
				ctx,
				b.NFTBinary,
				[]string{"flush", "table", "inet", table},
				nil,
			); err != nil {
				return errors.New("decommission_failed")
			}
		}
	}
	disabled := p
	disabled.Desired.Fallback = "direct"
	disabled.Desired.Paths = nil
	disabled.Routes = nil
	if err := b.cleanupSafety(ctx, disabled, &owner); err != nil {
		return err
	}
	if err := writePrivateAtomic(
		PersistentGuardPath,
		[]byte("# OpenRHP routing explicitly decommissioned; direct access was authorized.\n"),
	); err != nil {
		return err
	}
	if _, err := b.Runner.Run(
		ctx,
		b.NFTBinary,
		[]string{"delete", "table", "inet", dataplane.GuardTable},
		nil,
	); err != nil {
		return errors.New("decommission_failed")
	}
	return nil
}

func (m *Manager) BootGuard(ctx context.Context) error {
	return m.locked(func(s *State) error { return m.quarantineLocked(ctx, s) })
}

func (m *Manager) quarantineLocked(ctx context.Context, s *State) error {
	d := s.Committed
	if s.Transaction != nil && active(s.Transaction) && s.Transaction.State != "prepared" {
		d = &s.Transaction.Candidate
	}
	if d == nil {
		return nil
	}
	b, ok := m.backend.(interface {
		CheckQuarantine(context.Context, dataplane.Plan) error
		Quarantine(context.Context, dataplane.Plan) error
	})
	if !ok {
		return errors.New("lifecycle_guard_unavailable")
	}
	p, err := dataplane.Compile(*d)
	if err != nil {
		return err
	}
	attachDNSGuard(&p, s)
	if s.Guarded {
		addSafetyOwner(&p, p.Desired.Network)
	}
	// A power loss can leave objects from either side of an applying transaction.
	// The root-owned, validated journal proves both prior allocations.
	if s.Transaction != nil && active(s.Transaction) && s.Transaction.State != "prepared" &&
		s.Transaction.Previous != nil {
		previous, err := dataplane.Compile(*s.Transaction.Previous)
		if err != nil {
			return err
		}
		if previous.Desired.Fallback == "closed" || s.Guarded {
			addSafetyOwner(&p, previous.Desired.Network)
		}
		for _, route := range previous.Routes {
			if !containsRoute(p.Routes, route) {
				p.Routes = append(p.Routes, route)
			}
		}
	}
	if err = b.CheckQuarantine(ctx, p); err != nil {
		return err
	}
	if !s.Guarded {
		// Persist intent before routes or guard files. A subsequent boot may replay
		// this intent after any partial mutation without treating our rules as foreign.
		s.Guarded = true
		if err = m.save(s); err != nil {
			return err
		}
	}
	addSafetyOwner(&p, p.Desired.Network)
	return b.Quarantine(ctx, p)
}

func (m *Manager) CanRemove() error {
	return m.locked(func(s *State) error {
		if s.MaintenanceJob != "" {
			return ErrMaintenanceActive
		}
		if s.Committed != nil || active(s.Transaction) {
			return errors.New(
				"protected_configuration_exists: decommission explicitly before removing the guard package",
			)
		}
		return nil
	})
}

func (m *Manager) Decommission(ctx context.Context, policy string) error {
	if policy == "preserve-closed" {
		return m.BootGuard(ctx)
	}
	if policy != "restore-direct" {
		return errors.New("decommission_policy_required: choose preserve-closed or restore-direct")
	}
	return m.locked(func(s *State) error {
		if s.MaintenanceJob != "" {
			return ErrMaintenanceActive
		}
		return m.decommissionLocked(ctx, s)
	})
}

func (m *Manager) decommissionLocked(ctx context.Context, s *State) error {
	if active(s.Transaction) {
		return ErrBusy
	}
	if s.Committed == nil {
		return nil
	}
	if err := m.quarantineLocked(ctx, s); err != nil {
		return err
	}
	p, err := dataplane.Compile(*s.Committed)
	if err != nil {
		return err
	}
	attachDNSGuard(&p, s)
	if s.Guarded {
		addSafetyOwner(&p, p.Desired.Network)
	}
	b, ok := m.backend.(interface {
		Remove(context.Context, dataplane.Plan) error
	})
	if !ok {
		return errors.New("decommission_unavailable")
	}
	if err = b.Remove(ctx, p); err != nil {
		return err
	}
	s.Committed = nil
	s.DNSGuard = nil
	s.Ingress = nil
	s.IngressBound = false
	s.Transaction = nil
	s.Guarded = false
	return m.save(s)
}
