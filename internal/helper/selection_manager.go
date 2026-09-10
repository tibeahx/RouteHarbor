package helper

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
)

// switchSelection holds the durable journal lock from snapshot through commit.
// The RPC layer additionally holds the source registry lock around this method.
func (m *Manager) switchSelection(
	ctx context.Context,
	sourceID string,
) (out Transaction, handled bool, err error) {
	b, ok := m.backend.(selectionBackend)
	if !ok {
		return out, false, nil
	}
	handled = true
	err = m.locked(func(s *State) error {
		if s.Committed == nil {
			return errors.New("network_unconfigured: confirm network configuration first")
		}
		if s.MaintenanceJob != "" || s.MaintenanceHold {
			return ErrMaintenanceActive
		}
		if active(s.Transaction) {
			return ErrBusy
		}
		if s.Committed.Continuity != nil {
			return errors.New("continuity_runtime_selection_required")
		}
		if s.Committed.BreakExisting || s.Guarded {
			handled = false
			return nil
		}
		if s.Transaction != nil && s.Transaction.State == "confirmed" &&
			s.Transaction.FlowTermination == "pending" {
			if err := m.finishFlowReset(ctx, s); err != nil {
				return err
			}
		}
		d := *s.Committed
		d.Selected = sourceID
		if d.Selected == s.Committed.Selected && s.Transaction != nil {
			out = *s.Transaction
			return nil
		}
		previous, err := dataplane.Compile(*s.Committed)
		if err != nil {
			return err
		}
		next, err := dataplane.Compile(d)
		if err != nil {
			return err
		}
		attachDNSGuard(&previous, s)
		attachDNSGuard(&next, s)
		if err = b.CheckSelection(ctx, next, previous); err != nil {
			if errors.Is(err, errSelectionFullApply) {
				handled = false
				return nil
			}
			return err
		}
		if m.watchdog == nil {
			return errors.New("watchdog_unavailable")
		}
		id := make([]byte, 16)
		if _, err = rand.Read(id); err != nil {
			return err
		}
		t := &Transaction{
			ID: hex.EncodeToString(id), Kind: "selection", State: "applying",
			CreatedAt: m.now().UTC(), Deadline: m.now().Add(30 * time.Second).UTC(),
			Candidate: d, Previous: s.Committed,
			Rollback: dataplane.SafeRollback(d, s.Committed),
		}
		s.Transaction = t
		if err = m.save(s); err != nil {
			return err
		}
		out = *t
		if err = m.watchdog.Arm(t.ID); err != nil {
			t.State, t.ErrorCode = "failed", "watchdog_unavailable"
			if saveErr := m.save(s); saveErr != nil {
				return saveErr
			}
			out = *t
			return errors.New("watchdog_unavailable: network was not changed")
		}
		applyCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err = b.ApplySelection(applyCtx, next, previous)
		cancel()
		if err != nil {
			t.ErrorCode = "selection_commit_ambiguous"
			if rollbackErr := m.rollbackLocked(context.Background(), s); rollbackErr != nil {
				out = *t
				return fmt.Errorf(
					"selection_commit_ambiguous: rollback remains pending: %w",
					rollbackErr,
				)
			}
			out = *t
			return errors.New("selection_apply_failed: safe rollback completed")
		}
		t.State = "confirmed"
		s.Committed = &d
		if err = m.save(s); err != nil {
			// Keep the response at applying: a successful nft call is not a
			// durable confirmation, and the independent watchdog still owns it.
			return errors.New("selection_commit_ambiguous: durable confirmation failed")
		}
		out = *t
		return nil
	})
	return out, handled, err
}

func (s *Server) switchRegistered(ctx context.Context, sourceID string) (Transaction, error) {
	s.probeMu.Lock()
	defer s.probeMu.Unlock()
	state, err := s.Manager.Status()
	if err != nil {
		return Transaction{}, err
	}
	if state.Committed != nil && sourceID != "" {
		found := false
		for _, path := range state.Committed.Paths {
			if path.SourceID != sourceID {
				continue
			}
			found = true
			if err = s.validateProbeAllocationLocked(path); err != nil {
				return Transaction{}, err
			}
			if err = s.validateManagedPlanPathLocked(path); err != nil {
				return Transaction{}, err
			}
		}
		if !found {
			return Transaction{}, errors.New("invalid_path: selected source is not prepared")
		}
	}
	return s.Manager.Switch(ctx, sourceID)
}
