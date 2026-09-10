package helper

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/dispatch"
	"github.com/tibeahx/OpenRHP/internal/routing"
)

func TestDispatcherSnapshotChunkIntegrityAndRecovery(t *testing.T) {
	s := &Server{Manager: testManager(t, &memoryBackend{}, nil)}
	snapshot := routing.Snapshot{
		Generation: 7,
		CreatedAt:  time.Now().UTC(),
		Domains:    []string{"restricted.example"},
		CIDRs:      []string{"8.8.8.0/24"},
	}
	data, e := routing.EncodeSnapshot(snapshot)
	if e != nil {
		t.Fatal(e)
	}
	ref := routing.Reference(snapshot, data)
	call := func(r DispatcherRequest) error {
		t.Helper()
		if e := validateDispatcherRequest(r); e != nil {
			return e
		}
		_, e := s.dispatcherAction(context.Background(), r)
		return e
	}
	if e = call(DispatcherRequest{Action: "snapshot-begin", Snapshot: &ref}); e != nil {
		t.Fatal(e)
	}
	if e = call(
		DispatcherRequest{Action: "snapshot-chunk", Snapshot: &ref, Offset: 1, Data: data},
	); e == nil {
		t.Fatal("accepted out of sequence chunk")
	}
	if e = call(DispatcherRequest{Action: "snapshot-commit", Snapshot: &ref}); e == nil {
		t.Fatal("accepted incomplete upload")
	}
	if e = call(DispatcherRequest{Action: "snapshot-begin", Snapshot: &ref}); e != nil {
		t.Fatal(e)
	}
	for off := 0; off < len(data); off += 17 {
		if e = call(
			DispatcherRequest{
				Action:   "snapshot-chunk",
				Snapshot: &ref,
				Offset:   int64(off),
				Data:     data[off:min(off+17, len(data))],
			},
		); e != nil {
			t.Fatal(e)
		}
	}
	if e = call(DispatcherRequest{Action: "snapshot-commit", Snapshot: &ref}); e != nil {
		t.Fatal(e)
	}
	query := ref
	query.Size = 0
	info, e := s.dispatcherSnapshotRead(
		DispatcherRequest{Action: "snapshot-info", Snapshot: &query},
	)
	if e != nil || info.Snapshot == nil || *info.Snapshot != ref {
		t.Fatal("snapshot recovery reference", info, e)
	}
	chunk, e := s.dispatcherSnapshotRead(DispatcherRequest{Action: "snapshot-read", Snapshot: &ref})
	if e != nil || !bytes.Equal(chunk.Data, data) {
		t.Fatal("snapshot recovery bytes", e)
	}
	bad := append([]byte{}, data...)
	bad[len(bad)-1] = '!'
	if e = os.WriteFile(s.snapshotName(ref), bad, 0o600); e != nil {
		t.Fatal(e)
	}
	if _, e = s.dispatcherSnapshotRead(
		DispatcherRequest{Action: "snapshot-info", Snapshot: &query},
	); e == nil {
		t.Fatal("corrupt snapshot passed integrity check")
	}
}

func TestDispatcherPublicationJournalAndPendingIsolation(t *testing.T) {
	ctx := context.Background()
	m := testManager(t, &memoryBackend{}, &testWatchdog{})
	s := &Server{Manager: m}
	desired := selectiveDesired()
	tx, e := m.Prepare(ctx, desired)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.Apply(ctx, tx.ID, 30*time.Second); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Confirm(tx.ID); e != nil {
		t.Fatal(e)
	}
	p := adapter.AllocatePath(
		adapter.DispatcherSourceID,
		"dispatcher",
		int(desired.Selective.Path.Slot),
	)
	p.TransparentPort = int(desired.Selective.Path.Port)
	p.IPv6 = true
	p.UDP = true
	record := &dispatcherRegistration{
		spec: dispatch.Spec{Allocation: adapter.DispatcherAllocation{Path: p}},
	}
	file := filepath.Join(t.TempDir(), "rules.json")
	old := []byte(`{"version":4,"rules":[]}`)
	if e = os.WriteFile(file, old, 0o600); e != nil {
		t.Fatal(e)
	}
	data := []byte(`{"version":4,"rules":[{"domain":["blocked.example"]}]}`)
	ref := routing.SnapshotRef{Generation: 2, SHA256: strings.Repeat("b", 64), Size: 123}
	if e = s.publishDispatcher(ctx, record, ref, file, data); e != nil {
		t.Fatal(e)
	}
	state, e := m.Status()
	if e != nil || state.Committed.Selective.Snapshot.SHA256 != ref.SHA256 ||
		state.Transaction.Candidate.Selective.Snapshot.SHA256 != ref.SHA256 {
		t.Fatal("reference not durable", state, e)
	}
	previous, e := os.ReadFile(file + ".previous")
	if e != nil || !bytes.Equal(previous, old) {
		t.Fatal("previous compiled rules lost", e)
	}
	if _, e = m.Prepare(ctx, *state.Committed); e != nil {
		t.Fatal(e)
	}
	if e = s.publishDispatcher(ctx, record, ref, file, old); e == nil {
		t.Fatal("publication changed pending transaction")
	}
	retained, _ := os.ReadFile(file)
	if !bytes.Equal(retained, data) {
		t.Fatal("pending publication changed active rules")
	}
}

func TestDispatcherRPCRejectsWideningAndMixedPayloads(t *testing.T) {
	ref := routing.SnapshotRef{Generation: 1, SHA256: strings.Repeat("a", 64), Size: 1}
	for _, r := range []DispatcherRequest{
		{Action: "publish", Snapshot: &ref, Learned: []string{"*.example.com"}},
		{Action: "publish", Snapshot: &ref, Learned: []string{"router.lan"}},
		{Action: "publish", Snapshot: &ref, Learned: []string{"http://public.example"}},
		{Action: "select", Selected: "x", Data: []byte("injection")},
		{Action: "status", Slot: 251},
		{Action: "snapshot-chunk", Snapshot: &ref, Data: make([]byte, (48<<10)+1)},
		{Action: "reload-config", Data: []byte(`{}`)},
	} {
		if validateDispatcherRequest(r) == nil {
			t.Fatalf("accepted unsafe RPC: %s", r.Action)
		}
	}
	d := selectiveDesired()
	a, b := d.Selective.Path, d.Selective.Path
	b.Slot--
	b.Port--
	if probeAllocationConflict(a, b) {
		t.Fatal("staging blocked by internal logical name")
	}
	b.SourceID = "ordinary"
	b.Slot = a.Slot
	if !probeAllocationConflict(a, b) {
		t.Fatal("ordinary source may steal dispatcher slot")
	}
}
