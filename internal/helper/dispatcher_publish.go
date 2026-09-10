package helper

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
	"github.com/tibeahx/OpenRHP/internal/routing"
)

// Runtime list changes serialize with prepare/apply/maintenance. Their bounded
// reference is durable, but the list itself never enters the transaction log.
func (s *Server) publishDispatcher(
	ctx context.Context,
	record *dispatcherRegistration,
	ref routing.SnapshotRef,
	file string,
	data []byte,
) error {
	return s.Manager.locked(func(state *State) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if state.MaintenanceHold || state.MaintenanceJob != "" || state.Guarded ||
			state.SelectiveEmergency ||
			state.SelectiveEmergencyPending {
			return errors.New("dispatcher_publication_suspended")
		}
		if t := state.Transaction; t != nil {
			switch t.State {
			case "prepared", "applying", "applied", "rolling-back":
				return ErrBusy
			}
		}
		d := state.Committed
		if d == nil || d.Selective == nil || d.Selective.Path != dispatcherPath(record.spec) {
			return errors.New("dispatcher_not_committed")
		}
		if ref.Generation < d.Selective.Snapshot.Generation ||
			ref.Generation == d.Selective.Snapshot.Generation &&
				ref.SHA256 != d.Selective.Snapshot.SHA256 {
			return errors.New("dispatcher_snapshot_generation_regressed")
		}
		old, e := os.ReadFile(file)
		if e != nil {
			return errors.New("dispatcher_rules_unavailable")
		}
		if e = replaceDispatcherRuleFile(file, data); e != nil {
			return e
		}
		previous := d.Selective.Snapshot
		d.Selective.Snapshot = dataplane.SelectiveSnapshotRef{
			Generation: ref.Generation,
			SHA256:     ref.SHA256,
		}
		// Confirmed candidate describes the same live policy. Keep both references
		// consistent so recovery and offline integrity checks cannot disagree.
		var candidate *dataplane.SelectiveIntent
		if state.Transaction != nil && state.Transaction.State == "confirmed" &&
			state.Transaction.Candidate.Selective != nil &&
			state.Transaction.Candidate.Selective.Path == d.Selective.Path {
			candidate = state.Transaction.Candidate.Selective
			candidate.Snapshot = d.Selective.Snapshot
		}
		if e = s.Manager.save(state); e != nil {
			d.Selective.Snapshot = previous
			if candidate != nil {
				candidate.Snapshot = previous
			}
			_ = replaceDispatcherRuleFile(file, old)
			return errors.New("dispatcher_publication_journal_failed")
		}
		return nil
	})
}

// Keep live/staged and every journal rollback reference, plus the two newest
// validated blobs. Unfinished uploads are bounded separately to one file.
func (s *Server) pruneDispatcherSnapshots(uploaded routing.SnapshotRef) {
	keep := map[string]bool{filepath.Base(s.snapshotName(uploaded)): true}
	s.probeMu.Lock()
	for _, record := range s.dispatchers {
		keep[filepath.Base(s.snapshotName(record.ref))] = true
	}
	s.probeMu.Unlock()
	state, e := s.Manager.Status()
	if e != nil {
		return
	}
	add := func(d *dataplane.Desired) {
		if d == nil || d.Selective == nil {
			return
		}
		r := d.Selective.Snapshot
		keep[strings.Join([]string{formatGeneration(r.Generation), r.SHA256}, "-")+".json"] = true
	}
	add(state.Committed)
	if t := state.Transaction; t != nil {
		add(&t.Candidate)
		add(&t.Rollback)
		add(t.Previous)
	}
	entries, e := os.ReadDir(s.snapshotDir())
	if e != nil {
		return
	}
	type blob struct {
		name       string
		generation uint64
	}
	var blobs []blob
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), ".json") {
			var g uint64
			var hash string
			if _, e := parseDispatcherBlob(entry.Name(), &g, &hash); e == nil {
				blobs = append(blobs, blob{entry.Name(), g})
			}
		}
	}
	sort.Slice(blobs, func(i, j int) bool { return blobs[i].generation > blobs[j].generation })
	for index, b := range blobs {
		if index < 2 || keep[b.name] {
			continue
		}
		_ = os.Remove(filepath.Join(s.snapshotDir(), b.name))
	}
}

func formatGeneration(g uint64) string { return strconv.FormatUint(g, 10) }
func parseDispatcherBlob(name string, g *uint64, hash *string) (bool, error) {
	parts := strings.Split(strings.TrimSuffix(name, ".json"), "-")
	if len(parts) != 2 {
		return false, errors.New("invalid blob")
	}
	n, e := strconv.ParseUint(parts[0], 10, 64)
	if e != nil {
		return false, e
	}
	v, e := hex.DecodeString(parts[1])
	if e != nil || len(v) != 32 {
		return false, errors.New("invalid blob")
	}
	*g = n
	*hash = parts[1]
	return true, nil
}
