package node

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
)

type (
	Watchdog    interface{ Arm(string) error }
	Transaction struct {
		ID        string    `json:"id"`
		State     string    `json:"state"`
		CreatedAt time.Time `json:"created_at"`
		Deadline  time.Time `json:"deadline,omitempty"`
		Plan      Plan      `json:"plan"`
		ErrorCode string    `json:"error_code,omitempty"`
	}
)

type journal struct {
	Version     int          `json:"version"`
	Transaction *Transaction `json:"transaction,omitempty"`
	Snapshot    Snapshot     `json:"snapshot,omitempty"`
	RequestKey  string       `json:"request_key,omitempty"`
	RequestHash string       `json:"request_hash,omitempty"`
}
type Manager struct {
	mu       sync.Mutex
	root     *os.Root
	backend  Backend
	watchdog Watchdog
	now      func() time.Time
}

var (
	transactionID = regexp.MustCompile(`^[a-f0-9]{32}$`)
	requestKey    = regexp.MustCompile(`^[a-zA-Z0-9_.-]{16,128}$`)
)

func NewManager(dir string, b Backend, w Watchdog) (*Manager, error) {
	if b == nil {
		return nil, errors.New("node backend required")
	}
	r, e := openStateRoot(dir)
	if e != nil {
		return nil, e
	}
	return &Manager{root: r, backend: b, watchdog: w, now: time.Now}, nil
}

func (m *Manager) Close() error {
	return m.root.Close()
}

func (m *Manager) locked(fn func(*journal) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	lock, e := stateLock(m.root, "transaction.lock")
	if e != nil {
		return e
	}
	defer stateUnlock(lock)
	s := journal{Version: 1}
	data, e := readPrivate(m.root, "transaction.json")
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e == nil {
		if e = adapter.StrictDecode(data, &s); e != nil || s.Version != 1 {
			return errors.New("invalid_node_journal")
		}
		if s.Transaction != nil && !transactionID.MatchString(s.Transaction.ID) {
			return errors.New("invalid_node_transaction_identity")
		}
		if t := s.Transaction; t != nil {
			switch t.State {
			case "prepared",
				"applying",
				"applied",
				"confirmed",
				"rolling-back",
				"rolled-back",
				"failed":
			default:
				return errors.New("invalid_node_transaction_state")
			}
			if (t.State == "applying" || t.State == "applied") && t.Deadline.IsZero() {
				return errors.New("invalid_node_transaction_deadline")
			}
			if active(t) {
				if len(s.Snapshot) != len(packages) {
					return errors.New("invalid_node_snapshot")
				}
				for _, name := range packages {
					if len(s.Snapshot[name]) == 0 || len(s.Snapshot[name]) > 256<<10 {
						return errors.New("invalid_node_snapshot")
					}
				}
			}
		}
	}
	return fn(&s)
}

func (m *Manager) save(s *journal) error {
	data, e := json.Marshal(s)
	if e != nil {
		return e
	}
	return writePrivate(m.root, "transaction.json", data)
}

func publicTransaction(t *Transaction) *Transaction {
	if t == nil {
		return nil
	}
	out := *t
	out.Plan = RedactPlan(out.Plan)
	out.Plan.LANPorts = append([]string(nil), out.Plan.LANPorts...)
	return &out
}

func active(t *Transaction) bool {
	return t != nil &&
		(t.State == "prepared" || t.State == "applying" || t.State == "applied" || t.State == "rolling-back")
}

func (m *Manager) Status() (map[string]any, error) {
	var out map[string]any
	e := m.locked(func(s *journal) error {
		out = map[string]any{"transaction": publicTransaction(s.Transaction)}
		return nil
	})
	return out, e
}

func (m *Manager) Prepare(ctx context.Context, key string, p Plan) (Transaction, error) {
	var out Transaction
	if !requestKey.MatchString(key) {
		return out, errors.New("idempotency_key_required")
	}
	data, e := json.Marshal(p)
	if e != nil {
		return out, e
	}
	hash := sha256.Sum256(data)
	e = m.locked(func(s *journal) error {
		if s.RequestKey == key {
			if s.RequestHash != hex.EncodeToString(hash[:]) {
				return errors.New("idempotency_conflict")
			}
			if s.Transaction == nil {
				return errors.New("invalid_node_journal")
			}
			out = *publicTransaction(s.Transaction)
			return nil
		}
		if active(s.Transaction) {
			return errors.New("node_transaction_busy")
		}
		if e := m.backend.Check(ctx, p); e != nil {
			return e
		}
		snapshot, e := m.backend.Snapshot(ctx)
		if e != nil {
			return e
		}
		if len(snapshot) != len(packages) {
			return errors.New("invalid_node_snapshot")
		}
		for _, name := range packages {
			if len(snapshot[name]) == 0 || len(snapshot[name]) > 256<<10 {
				return errors.New("invalid_node_snapshot")
			}
		}
		var nonce [16]byte
		if _, e = rand.Read(nonce[:]); e != nil {
			return e
		}
		t := Transaction{
			ID:        hex.EncodeToString(nonce[:]),
			State:     "prepared",
			CreatedAt: m.now().UTC(),
			Plan:      p,
		}
		s.Transaction = &t
		s.Snapshot = snapshot
		s.RequestKey = key
		s.RequestHash = hex.EncodeToString(hash[:])
		if e = m.save(s); e != nil {
			return e
		}
		out = *publicTransaction(&t)
		return nil
	})
	return out, e
}

func (m *Manager) Validate(ctx context.Context, id string) (Transaction, error) {
	var out Transaction
	e := m.locked(func(s *journal) error {
		if s.Transaction == nil || s.Transaction.ID != id {
			return errors.New("node_transaction_not_found")
		}
		if e := m.backend.Check(ctx, s.Transaction.Plan); e != nil {
			return e
		}
		out = *publicTransaction(s.Transaction)
		return nil
	})
	return out, e
}

func (m *Manager) Apply(
	ctx context.Context,
	id string,
	timeout time.Duration,
) (Transaction, error) {
	var out Transaction
	if timeout < 30*time.Second || timeout > 180*time.Second {
		return out, errors.New("confirmation_window_must_be_30_to_180_seconds")
	}
	e := m.locked(func(s *journal) error {
		t := s.Transaction
		if t == nil || t.ID != id {
			return errors.New("node_transaction_not_found")
		}
		if t.State == "applied" || t.State == "confirmed" {
			out = *publicTransaction(t)
			return nil
		}
		if t.State != "prepared" {
			return errors.New("node_transaction_invalid_state")
		}
		if e := m.backend.Check(ctx, t.Plan); e != nil {
			return e
		}
		if m.watchdog == nil {
			return errors.New("independent_node_watchdog_required")
		}
		t.State = "applying"
		t.Deadline = m.now().Add(timeout).UTC()
		if e := m.save(s); e != nil {
			return e
		}
		if e := m.watchdog.Arm(t.ID); e != nil {
			t.State = "failed"
			t.ErrorCode = "watchdog_unavailable"
			if err := m.save(s); err != nil {
				return errors.New("node_watchdog_unavailable_and_journal_write_failed")
			}
			return errors.New("node_watchdog_unavailable")
		}
		if e := m.backend.Apply(ctx, t.Plan); e != nil {
			t.ErrorCode = "apply_failed"
			if rollbackErr := m.rollback(ctx, s); rollbackErr != nil {
				return rollbackErr
			}
			out = *publicTransaction(t)
			return errors.New("node_apply_failed_and_rolled_back")
		}
		t.State = "applied"
		if e := m.save(s); e != nil {
			return e
		}
		out = *publicTransaction(t)
		return nil
	})
	return out, e
}

func (m *Manager) Confirm(ctx context.Context, id string) (Transaction, error) {
	var out Transaction
	e := m.locked(func(s *journal) error {
		t := s.Transaction
		if t == nil || t.ID != id {
			return errors.New("node_transaction_not_found")
		}
		if t.State == "confirmed" {
			out = *publicTransaction(t)
			return nil
		}
		if t.State != "applied" {
			return errors.New("node_transaction_invalid_state")
		}
		if !m.now().Before(t.Deadline) {
			if e := m.rollback(ctx, s); e != nil {
				return e
			}
			return errors.New("node_confirmation_expired")
		}
		if e := m.backend.Check(ctx, t.Plan); e != nil {
			return e
		}
		t.State = "confirmed"
		t.Deadline = time.Time{}
		s.Snapshot = nil
		t.Plan.Passphrase = ""
		if e := m.save(s); e != nil {
			return e
		}
		out = *publicTransaction(t)
		return nil
	})
	return out, e
}

func (m *Manager) rollback(ctx context.Context, s *journal) error {
	t := s.Transaction
	if t == nil {
		return errors.New("node_transaction_not_found")
	}
	t.State = "rolling-back"
	if e := m.save(s); e != nil {
		return e
	}
	if e := m.backend.Restore(ctx, s.Snapshot, t.Plan); e != nil {
		t.ErrorCode = "rollback_failed"
		if err := m.save(s); err != nil {
			return errors.New("node_rollback_failed_and_journal_write_failed")
		}
		return errors.New("node_rollback_failed")
	}
	t.State = "rolled-back"
	t.Deadline = time.Time{}
	t.Plan.Passphrase = ""
	s.Snapshot = nil
	return m.save(s)
}

func (m *Manager) Rollback(ctx context.Context, id string) (Transaction, error) {
	var out Transaction
	e := m.locked(func(s *journal) error {
		if s.Transaction == nil || s.Transaction.ID != id {
			return errors.New("node_transaction_not_found")
		}
		if s.Transaction.State == "rolled-back" {
			out = *publicTransaction(s.Transaction)
			return nil
		}
		if s.Transaction.State == "confirmed" || s.Transaction.State == "failed" {
			return errors.New("node_transaction_invalid_state")
		}
		if s.Transaction.State == "prepared" {
			s.Transaction.State = "rolled-back"
			s.Transaction.Plan.Passphrase = ""
			s.Snapshot = nil
			if e := m.save(s); e != nil {
				return e
			}
		} else if e := m.rollback(ctx, s); e != nil {
			return e
		}
		out = *publicTransaction(s.Transaction)
		return nil
	})
	return out, e
}

// Recover is called by a separate watchdog process and at helper startup. It
// reads durable intent every time; losing the agent, browser, gateway, or WAN
// cannot cancel an armed rollback. Interrupted rollback is retried on restart.
func (m *Manager) Recover(ctx context.Context) (bool, error) {
	done := false
	e := m.locked(func(s *journal) error {
		t := s.Transaction
		if t == nil || !active(t) || t.State == "prepared" {
			done = true
			return nil
		}
		if t.State == "rolling-back" || (!t.Deadline.IsZero() && !m.now().Before(t.Deadline)) {
			if e := m.rollback(ctx, s); e != nil {
				return e
			}
			done = true
		}
		return nil
	})
	return done, e
}
