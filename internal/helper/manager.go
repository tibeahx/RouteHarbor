// Package helper implements the small, typed privileged boundary. All durable
// intent is revalidated, and watchdog recovery uses the same transaction journal.
package helper

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
)

const (
	MaxRequestBytes = 256 << 10
	JournalVersion  = 1
)

var ErrBusy = errors.New("transaction_busy: confirm or roll back the active transaction first")

type Backend interface {
	Check(context.Context, dataplane.Plan) error
	Apply(context.Context, dataplane.Plan, *dataplane.Plan) error
}
type (
	Watchdog    interface{ Arm(string) error }
	Transaction struct {
		ID              string             `json:"id"`
		State           string             `json:"state"`
		CreatedAt       time.Time          `json:"created_at"`
		Deadline        time.Time          `json:"deadline,omitempty"`
		Candidate       dataplane.Desired  `json:"candidate"`
		Rollback        dataplane.Desired  `json:"rollback"`
		Previous        *dataplane.Desired `json:"previous,omitempty"`
		ErrorCode       string             `json:"error_code,omitempty"`
		FlowTermination string             `json:"flow_termination,omitempty"`
	}
)

type State struct {
	IngressBound       bool               `json:"ingress_bound,omitempty"`
	Ingress            []string           `json:"ingress_devices,omitempty"`
	DNSGuard           *DNSGuardIdentity  `json:"dns_guard,omitempty"`
	MaintenanceJob     string             `json:"maintenance_job,omitempty"`
	MaintenanceLastJob string             `json:"maintenance_last_job,omitempty"`
	MaintenanceHold    bool               `json:"maintenance_hold,omitempty"`
	Guarded            bool               `json:"guarded"`
	Version            int                `json:"version"`
	Committed          *dataplane.Desired `json:"committed,omitempty"`
	Transaction        *Transaction       `json:"transaction,omitempty"`
}
type Manager struct {
	dir      string
	backend  Backend
	watchdog Watchdog
	mu       sync.Mutex
	now      func() time.Time
}

func NewManager(dir string, b Backend, w Watchdog) (*Manager, error) {
	if !filepath.IsAbs(dir) || b == nil {
		return nil, errors.New("state directory must be absolute and backend must be configured")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("state directory must be a private real directory (0700)")
	}
	if !ownedByCurrentUID(info) {
		return nil, errors.New("state directory must belong to the helper user")
	}
	return &Manager{dir: dir, backend: b, watchdog: w, now: time.Now}, nil
}

func (m *Manager) locked(fn func(*State) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	lock, err := openPrivate(filepath.Join(m.dir, "transaction.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	if err = lockFile(lock); err != nil {
		return err
	}
	defer unlockFile(lock)
	state, err := m.read()
	if err != nil {
		return err
	}
	return fn(&state)
}

func (m *Manager) read() (State, error) {
	s := State{Version: JournalVersion}
	f, e := openPrivate(filepath.Join(m.dir, "transaction.json"), os.O_RDONLY, 0o600)
	if os.IsNotExist(e) {
		return s, nil
	}
	if e != nil {
		return s, e
	}
	defer func() { _ = f.Close() }()
	data, e := io.ReadAll(io.LimitReader(f, MaxRequestBytes+1))
	if e != nil {
		return s, e
	}
	if len(data) > MaxRequestBytes {
		return s, errors.New("journal_size: journal exceeds limit")
	}
	if e = DecodeStrict(data, &s); e != nil {
		return s, errors.New("journal_invalid: durable state failed validation")
	}
	if !validIngress(s.Ingress) {
		return s, errors.New("journal_invalid: invalid ingress ownership")
	}
	if s.DNSGuard != nil && !s.DNSGuard.valid() {
		return s, errors.New("journal_invalid: invalid DNS guard identity")
	}
	if s.Version != JournalVersion {
		return s, errors.New("journal_version: unknown journal version")
	}
	if s.MaintenanceJob != "" && (!validTransactionID(s.MaintenanceJob) || !s.MaintenanceHold) {
		return s, errors.New("journal_invalid: invalid maintenance gate")
	}
	if s.MaintenanceLastJob != "" && !validTransactionID(s.MaintenanceLastJob) {
		return s, errors.New("journal_invalid: invalid completed maintenance identity")
	}
	if s.Committed != nil {
		if _, e = dataplane.Compile(*s.Committed); e != nil {
			return s, errors.New("journal_invalid: committed network intent is invalid")
		}
	}
	if t := s.Transaction; t != nil {
		if !validTransactionID(t.ID) {
			return s, errors.New("journal_invalid: invalid transaction identity")
		}
		if _, e = dataplane.Compile(t.Candidate); e != nil {
			return s, errors.New("journal_invalid: candidate is invalid")
		}
		if _, e = dataplane.Compile(t.Rollback); e != nil {
			return s, errors.New("journal_invalid: rollback policy is invalid")
		}
		if t.Previous != nil {
			if _, e = dataplane.Compile(*t.Previous); e != nil {
				return s, errors.New("journal_invalid: previous policy is invalid")
			}
		}
		if t.FlowTermination != "" {
			if t.State != "confirmed" || previousResetSlot(t) == 0 ||
				(t.FlowTermination != "pending" && t.FlowTermination != "completed" && t.FlowTermination != "failed") {
				return s, errors.New("journal_invalid: invalid connection tracking reset state")
			}
		}
		switch t.State {
		case "prepared",
			"applying",
			"applied",
			"confirmed",
			"rolling-back",
			"rolled-back",
			"failed":
		default:
			return s, errors.New("journal_invalid: unknown transaction state")
		}
	}
	return s, nil
}

func (m *Manager) save(s *State) error {
	data, e := json.Marshal(s)
	if e != nil {
		return e
	}
	if len(data) > MaxRequestBytes {
		return errors.New("journal_size: state exceeds limit")
	}
	f, e := os.CreateTemp(m.dir, ".transaction-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }()
	if e = f.Chmod(0o600); e != nil {
		_ = f.Close()
		return e
	}
	if _, e = f.Write(data); e != nil {
		_ = f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		_ = f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(name, filepath.Join(m.dir, "transaction.json")); e != nil {
		return e
	}
	d, e := os.Open(m.dir)
	if e != nil {
		return e
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

func (m *Manager) Status() (State, error) {
	var out State
	err := m.locked(func(s *State) error { out = *s; return nil })
	return out, err
}

func active(t *Transaction) bool {
	return t != nil &&
		(t.State == "prepared" || t.State == "applying" || t.State == "applied" || t.State == "rolling-back")
}

func (m *Manager) Prepare(ctx context.Context, d dataplane.Desired) (Transaction, error) {
	return m.prepare(ctx, d, false)
}

func (m *Manager) prepare(
	ctx context.Context,
	d dataplane.Desired,
	automatic bool,
) (Transaction, error) {
	var out Transaction
	plan, err := dataplane.Compile(d)
	if err != nil {
		return out, err
	}
	err = m.locked(func(s *State) error {
		if s.MaintenanceJob != "" || automatic && s.MaintenanceHold {
			return ErrMaintenanceActive
		}
		if s.Transaction != nil && s.Transaction.State == "confirmed" &&
			s.Transaction.FlowTermination == "pending" {
			if err := m.finishFlowReset(ctx, s); err != nil {
				return err
			}
		}
		if active(s.Transaction) {
			return ErrBusy
		}
		if s.Committed != nil {
			if !slices.Equal(s.Committed.Network.LANInterfaces, d.Network.LANInterfaces) {
				return errors.New(
					"active_lan_change: explicitly decommission routing before changing LAN devices or their guard priority order",
				)
			}
			for _, old := range s.Committed.Paths {
				for _, next := range d.Paths {
					if old.Slot == next.Slot &&
						(old.SourceID != next.SourceID || old.Kind != next.Kind || old.Interface != next.Interface || old.Port != next.Port) {
						return errors.New(
							"allocation_conflict: active slots cannot be reassigned to a different source or listener",
						)
					}
					if old.SourceID == next.SourceID && old.Slot != next.Slot {
						return errors.New(
							"allocation_conflict: retained sources must preserve their connection marks",
						)
					}
				}
			}
		}
		if d.BreakExisting {
			resetter, ok := m.backend.(flowResetBackend)
			if !ok {
				return errors.New(
					"capability_unavailable: scoped connection tracking reset is unavailable",
				)
			}
			if err := resetter.CheckFlowReset(ctx); err != nil {
				return err
			}
		}
		if err := m.prepareIngress(ctx, s, d); err != nil {
			return err
		}
		if err := m.prepareDNSIdentity(ctx, s); err != nil {
			return err
		}
		attachDNSGuard(&plan, s)
		if err := m.backend.Check(ctx, plan); err != nil {
			return err
		}
		id := make([]byte, 16)
		if _, err := rand.Read(id); err != nil {
			return err
		}
		out = Transaction{
			ID:        hex.EncodeToString(id),
			State:     "prepared",
			CreatedAt: m.now().UTC(),
			Candidate: d,
			Rollback:  dataplane.SafeRollback(d, s.Committed),
			Previous:  s.Committed,
		}
		if s.MaintenanceHold {
			out.Rollback.Selected = ""
			out.Rollback.Fallback = "closed"
		}
		s.Transaction = &out
		return m.save(s)
	})
	return out, err
}

func (m *Manager) Apply(
	ctx context.Context,
	id string,
	confirmTimeout time.Duration,
) (Transaction, error) {
	var out Transaction
	if confirmTimeout < 30*time.Second || confirmTimeout > 180*time.Second {
		return out, errors.New("invalid_timeout: confirmation window must be 30 to 180 seconds")
	}
	err := m.locked(func(s *State) error {
		if s.MaintenanceJob != "" {
			return ErrMaintenanceActive
		}
		t := s.Transaction
		if t == nil || t.ID != id {
			return errors.New("not_found: transaction does not exist")
		}
		out = *t
		if t.State == "applied" || t.State == "confirmed" {
			return nil
		}
		if t.State != "prepared" {
			return errors.New("invalid_state: only a prepared transaction can be applied")
		}
		plan, err := dataplane.Compile(t.Candidate)
		if err != nil {
			return err
		}
		if err = m.prepareIngress(ctx, s, t.Candidate); err != nil {
			return err
		}
		if err = m.prepareDNSIdentity(ctx, s); err != nil {
			return err
		}
		attachDNSGuard(&plan, s)
		if err = m.backend.Check(ctx, plan); err != nil {
			return err
		}
		if m.watchdog == nil {
			return errors.New("watchdog_unavailable: independent rollback process is required")
		}
		t.State = "applying"
		t.Deadline = m.now().Add(confirmTimeout).UTC()
		if err = m.save(s); err != nil {
			return err
		}
		if err = m.watchdog.Arm(id); err != nil {
			t.State = "failed"
			t.ErrorCode = "watchdog_unavailable"
			_ = m.save(s)
			out = *t
			return errors.New("watchdog_unavailable: network was not changed")
		}
		var old *dataplane.Plan
		if s.Committed != nil {
			p, e := dataplane.Compile(*s.Committed)
			if e != nil {
				return e
			}
			if s.Guarded {
				addSafetyOwner(&p, p.Desired.Network)
			}
			attachDNSGuard(&p, s)
			old = &p
		}
		applyCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err = m.backend.Apply(applyCtx, plan, old)
		cancel()
		if err != nil {
			t.ErrorCode = "apply_failed"
			rollbackErr := m.rollbackLocked(context.Background(), s)
			out = *t
			if rollbackErr != nil {
				return fmt.Errorf("apply_failed: rollback remains pending: %w", rollbackErr)
			}
			return errors.New("apply_failed: safe rollback completed")
		}
		t.State = "applied"
		s.Guarded = false
		if err = m.save(s); err != nil {
			return err
		}
		out = *t
		return nil
	})
	return out, err
}

func (m *Manager) Confirm(id string) (Transaction, error) {
	var out Transaction
	err := m.locked(func(s *State) error {
		if s.MaintenanceJob != "" {
			return ErrMaintenanceActive
		}
		t := s.Transaction
		if t == nil || t.ID != id {
			return errors.New("not_found: transaction does not exist")
		}
		out = *t
		if t.State == "confirmed" {
			err := m.finishFlowReset(context.Background(), s)
			out = *t
			return err
		}
		if t.State != "applied" {
			return errors.New("invalid_state: only an applied transaction can be confirmed")
		}
		if !m.now().Before(t.Deadline) {
			return errors.New("confirmation_expired: safe rollback is due")
		}
		t.State = "confirmed"
		d := t.Candidate
		s.Committed = &d
		s.MaintenanceHold = false
		if previousResetSlot(t) != 0 {
			t.FlowTermination = "pending"
		}
		if err := m.save(s); err != nil {
			return err
		}
		if err := m.finishFlowReset(context.Background(), s); err != nil {
			return err
		}
		out = *t
		return nil
	})
	return out, err
}

func (m *Manager) Rollback(ctx context.Context, id string) (Transaction, error) {
	var out Transaction
	err := m.locked(func(s *State) error {
		t := s.Transaction
		if t == nil || t.ID != id {
			return errors.New("not_found: transaction does not exist")
		}
		if t.State == "rolled-back" {
			out = *t
			return nil
		}
		if t.State == "prepared" {
			t.State = "rolled-back"
			out = *t
			return m.save(s)
		}
		if t.State == "confirmed" || t.State == "failed" {
			return errors.New("invalid_state: transaction is terminal")
		}
		err := m.rollbackLocked(ctx, s)
		out = *t
		return err
	})
	return out, err
}

func (m *Manager) rollbackLocked(ctx context.Context, s *State) error {
	t := s.Transaction
	t.State = "rolling-back"
	if err := m.save(s); err != nil {
		return err
	}
	safe, err := dataplane.Compile(t.Rollback)
	if err != nil {
		return err
	}
	candidate, err := dataplane.Compile(t.Candidate)
	if err != nil {
		return err
	}
	if s.Guarded {
		addSafetyOwner(&candidate, t.Candidate.Network)
	}
	if t.Previous != nil {
		if t.Previous.Fallback == "closed" || s.Guarded {
			addSafetyOwner(&candidate, t.Previous.Network)
		}
		old, e := dataplane.Compile(*t.Previous)
		if e != nil {
			return e
		}
		for _, r := range old.Routes {
			if !containsRoute(candidate.Routes, r) {
				candidate.Routes = append(candidate.Routes, r)
			}
		}
	}
	attachDNSGuard(&safe, s)
	attachDNSGuard(&candidate, s)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err = m.backend.Apply(ctx, safe, &candidate); err != nil {
		t.ErrorCode = "rollback_pending"
		_ = m.save(s)
		return errors.New("rollback_pending: independent watchdog will retry")
	}
	t.State = "rolled-back"
	s.Guarded = t.Rollback.Selected == ""
	d := t.Rollback
	s.Committed = &d
	return m.save(s)
}

// Recover can be called by another process after the API/helper has exited.
// It retries incomplete rollbacks and expired applying/applied transactions.
func (m *Manager) Recover(ctx context.Context) (bool, error) {
	done := true
	err := m.locked(func(s *State) error {
		t := s.Transaction
		if t != nil && t.State == "confirmed" && t.FlowTermination == "pending" {
			return m.finishFlowReset(ctx, s)
		}
		if t == nil || !active(t) || t.State == "prepared" {
			return nil
		}
		done = false
		if t.State == "rolling-back" || !m.now().Before(t.Deadline) {
			err := m.rollbackLocked(ctx, s)
			done = err == nil
			return err
		}
		return nil
	})
	return done, err
}

// Resume arms a fresh watchdog for an interrupted, still-pending transaction.
func (m *Manager) Resume(ctx context.Context) error {
	done, err := m.Recover(ctx)
	if err != nil {
		return err
	}
	if done {
		return nil
	}
	s, err := m.Status()
	if err != nil {
		return err
	}
	if m.watchdog == nil {
		return errors.New("watchdog_unavailable")
	}
	return m.watchdog.Arm(s.Transaction.ID)
}

func validTransactionID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}
