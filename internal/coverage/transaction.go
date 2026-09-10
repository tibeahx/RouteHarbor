package coverage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/adapter"
)

type Watchdog interface{ Arm(string) error }

type journal struct {
	Version     int          `json:"version"`
	Role        string       `json:"role"`
	PrivateWiFi *WiFi        `json:"gateway_wifi,omitempty"`
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

func NewManager(dir string, b Backend, w Watchdog) (*Manager, error) {
	if b == nil {
		return nil, errors.New("gateway backend required")
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
	s := journal{Version: 1, Role: "gateway-backhaul"}
	data, e := readPrivate(m.root, "transaction.json")
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e == nil {
		if e = adapter.StrictDecode(
			data,
			&s,
		); e != nil || s.Version != 1 ||
			s.Role != "gateway-backhaul" {
			return errors.New("invalid_gateway_journal")
		}
		if s.Transaction != nil && !transactionID.MatchString(s.Transaction.ID) {
			return errors.New("invalid_gateway_transaction_identity")
		}
		if t := s.Transaction; t != nil {
			if ValidatePlan(t.Plan) != nil || t.CreatedAt.IsZero() ||
				!requestKey.MatchString(s.RequestKey) ||
				!fingerprint.MatchString(s.RequestHash) {
				return errors.New("invalid_gateway_journal")
			}
			switch t.State {
			case "prepared",
				"applying",
				"applied",
				"confirmed",
				"finalized",
				"rolling-back",
				"rolled-back",
				"failed":
			default:
				return errors.New("invalid_gateway_transaction_state")
			}
			if (t.State == "applying" || t.State == "applied") && t.Deadline.IsZero() {
				return errors.New("invalid_gateway_transaction_deadline")
			}
			if active(t) || t.State == "confirmed" {
				if err := validatePrepared(s.Snapshot, t.Plan, s.PrivateWiFi); err != nil {
					return err
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
	if err := ValidatePlan(p); err != nil {
		return out, err
	}
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
				return errors.New("invalid_gateway_journal")
			}
			out = *publicTransaction(s.Transaction)
			return nil
		}
		if active(s.Transaction) || (s.Transaction != nil && s.Transaction.State == "confirmed") {
			return errors.New("gateway_transaction_busy")
		}
		wifi, e := m.backend.Check(ctx, p)
		if e != nil {
			return e
		}
		snapshot, e := m.backend.Snapshot(ctx, p)
		if e != nil {
			return e
		}
		if err := validatePrepared(snapshot, p, &wifi); err != nil {
			return err
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
		s.PrivateWiFi = &wifi
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
			return errors.New("gateway_transaction_not_found")
		}
		if e := m.checkCurrent(ctx, s); e != nil {
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
			return errors.New("gateway_transaction_not_found")
		}
		if t.State == "applied" || t.State == "confirmed" {
			out = *publicTransaction(t)
			return nil
		}
		if t.State != "prepared" {
			return errors.New("gateway_transaction_invalid_state")
		}
		if e := m.checkCurrent(ctx, s); e != nil {
			return e
		}
		if m.watchdog == nil {
			return errors.New("independent_gateway_watchdog_required")
		}
		t.State = "applying"
		t.Deadline = m.now().Add(timeout).UTC()
		if e := m.save(s); e != nil {
			return e
		}
		if e := m.watchdog.Arm(t.ID); e != nil {
			t.State = "failed"
			t.ErrorCode = "watchdog_unavailable"
			s.Snapshot = nil
			s.PrivateWiFi = nil
			if err := m.save(s); err != nil {
				return errors.New("gateway_watchdog_unavailable_and_journal_write_failed")
			}
			return errors.New("gateway_watchdog_unavailable")
		}
		if e := m.backend.Apply(ctx, t.Plan); e != nil {
			t.ErrorCode = "apply_failed"
			if rollbackErr := m.rollback(ctx, s); rollbackErr != nil {
				return rollbackErr
			}
			out = *publicTransaction(t)
			return errors.New("gateway_apply_failed_and_rolled_back")
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
			return errors.New("gateway_transaction_not_found")
		}
		if t.State == "confirmed" || t.State == "finalized" {
			out = *publicTransaction(t)
			return nil
		}
		if t.State != "applied" {
			return errors.New("gateway_transaction_invalid_state")
		}
		if !m.now().Before(t.Deadline) {
			if e := m.rollback(ctx, s); e != nil {
				return e
			}
			return errors.New("gateway_confirmation_expired")
		}
		if e := m.checkCurrent(ctx, s); e != nil {
			return e
		}
		t.State = "confirmed"
		t.Deadline = time.Time{}
		if e := m.save(s); e != nil {
			return e
		}
		out = *publicTransaction(t)
		return nil
	})
	return out, e
}

func validatePrepared(snapshot Snapshot, p Plan, wifi *WiFi) error {
	if len(snapshot) != 1 || len(snapshot["wireless"]) == 0 || len(snapshot["wireless"]) > 256<<10 {
		return errors.New("invalid_gateway_snapshot")
	}
	var s wirelessSnapshot
	if adapter.StrictDecode(snapshot["wireless"], &s) != nil || validateSnapshot(s) != nil ||
		s.APSection != p.APSection {
		return errors.New("invalid_gateway_snapshot")
	}
	if wifi == nil || !cleanText(wifi.SSID, 1, 32) || !cleanText(wifi.Passphrase, 8, 63) ||
		wifi.Channel < 1 ||
		wifi.Channel > 233 {
		return errors.New("invalid_gateway_private_wifi")
	}
	return nil
}

func (m *Manager) rollback(ctx context.Context, s *journal) error {
	t := s.Transaction
	if t == nil {
		return errors.New("gateway_transaction_not_found")
	}
	t.State = "rolling-back"
	if e := m.save(s); e != nil {
		return e
	}
	if e := m.backend.Restore(ctx, s.Snapshot); e != nil {
		t.ErrorCode = "rollback_failed"
		if err := m.save(s); err != nil {
			return errors.New("gateway_rollback_failed_and_journal_write_failed")
		}
		return errors.New("gateway_rollback_failed")
	}
	t.State = "rolled-back"
	t.Deadline = time.Time{}
	s.PrivateWiFi = nil
	s.Snapshot = nil
	return m.save(s)
}

func (m *Manager) Rollback(ctx context.Context, id string) (Transaction, error) {
	var out Transaction
	e := m.locked(func(s *journal) error {
		if s.Transaction == nil || s.Transaction.ID != id {
			return errors.New("gateway_transaction_not_found")
		}
		if s.Transaction.State == "rolled-back" {
			out = *publicTransaction(s.Transaction)
			return nil
		}
		if s.Transaction.State == "finalized" || s.Transaction.State == "failed" {
			return errors.New("gateway_transaction_invalid_state")
		}
		if s.Transaction.State == "prepared" {
			s.Transaction.State = "rolled-back"
			s.PrivateWiFi = nil
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

func (m *Manager) checkCurrent(ctx context.Context, s *journal) error {
	if s.Transaction == nil || s.PrivateWiFi == nil {
		return errors.New("gateway_private_plan_missing")
	}
	wifi, err := m.backend.Check(ctx, s.Transaction.Plan)
	if err != nil {
		return err
	}
	if wifi != *s.PrivateWiFi {
		return errors.New("gateway_ap_settings_changed")
	}
	return nil
}

func (m *Manager) Finalize(id string) (Transaction, error) {
	var out Transaction
	err := m.locked(func(s *journal) error {
		t := s.Transaction
		if t == nil || t.ID != id {
			return errors.New("gateway_transaction_not_found")
		}
		if t.State == "finalized" {
			out = *publicTransaction(t)
			return nil
		}
		if t.State != "confirmed" {
			return errors.New("gateway_transaction_invalid_state")
		}
		t.State = "finalized"
		s.Snapshot = nil
		s.PrivateWiFi = nil
		if err := m.save(s); err != nil {
			return err
		}
		out = *publicTransaction(t)
		return nil
	})
	return out, err
}

func (m *Manager) Resume() error {
	return m.locked(func(s *journal) error {
		t := s.Transaction
		if t == nil || !active(t) || t.State == "prepared" {
			return nil
		}
		if m.watchdog == nil {
			return errors.New("independent_gateway_watchdog_required")
		}
		return m.watchdog.Arm(t.ID)
	})
}

func (m *Manager) CanRemove() error {
	return m.locked(func(s *journal) error {
		if active(s.Transaction) || (s.Transaction != nil && s.Transaction.State == "confirmed") {
			return errors.New("gateway_transaction_requires_resolution")
		}
		return nil
	})
}

func (m *Manager) material(id string) (WiFi, error) {
	var out WiFi
	err := m.locked(func(s *journal) error {
		if s.Transaction == nil || s.Transaction.ID != id || s.PrivateWiFi == nil {
			return errors.New("gateway_private_plan_missing")
		}
		out = *s.PrivateWiFi
		return nil
	})
	return out, err
}

func (m *Manager) Do(ctx context.Context, o Operation) (map[string]any, error) {
	if err := ValidateOperation(o); err != nil {
		return nil, err
	}
	var t Transaction
	var err error
	switch o.Action {
	case "inspect":
		setup, err := m.backend.Inspect(ctx)
		if err != nil {
			return nil, err
		}
		return map[string]any{"gateway_setup": setup}, nil
	case "status":
		return m.Status()
	case "prepare":
		t, err = m.Prepare(ctx, o.Key, *o.Plan)
		if err != nil {
			return nil, err
		}
		wifi, err := m.material(t.ID)
		if err != nil {
			return nil, err
		}
		return map[string]any{"transaction": t, "node_wifi": wifi}, nil
	case "validate":
		if o.Plan != nil {
			wifi, err := m.backend.Check(ctx, *o.Plan)
			if err != nil {
				return nil, err
			}
			return map[string]any{"plan": *o.Plan, "node_wifi": wifi}, nil
		}
		t, err = m.Validate(ctx, o.ID)
	case "apply":
		t, err = m.Apply(ctx, o.ID, time.Duration(o.TimeoutSeconds)*time.Second)
	case "confirm":
		t, err = m.Confirm(ctx, o.ID)
	case "rollback":
		t, err = m.Rollback(ctx, o.ID)
	case "finalize":
		t, err = m.Finalize(o.ID)
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"transaction": t}, nil
}
