package control

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
	"github.com/tibeahx/OpenRHP/internal/helper"
	"github.com/tibeahx/OpenRHP/internal/model"
)

func largeRoutingResult(t *testing.T) map[string]any {
	t.Helper()
	d := dataplane.Desired{
		Network: model.Network{
			Enabled: true, LANInterfaces: []string{"home0"}, WANInterface: "uplink0",
			LocalPrefixes: []string{"192.168.20.0/24"}, DNS: "block", IPv6: "block",
		},
		Fallback: "closed",
	}
	for i := range 250 {
		id := fmt.Sprintf("source-%03d-%s", i, strings.Repeat("x", 50))
		d.Paths = append(d.Paths, dataplane.Path{SourceID: id, Kind: "direct", Slot: uint16(i + 1)})
	}
	d.Selected = d.Paths[0].SourceID
	if _, err := dataplane.Compile(d); err != nil {
		t.Fatal(err)
	}
	return toMap(helper.Transaction{
		ID: strings.Repeat("a", 32), State: "confirmed", Candidate: d, Rollback: d, Previous: &d,
	})
}

func TestJournalCannotWriteHistoryThatItsOwnRestartRejects(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "operations")
	j, err := NewJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	result := largeRoutingResult(t)
	for i := range 64 {
		op, _, err := j.Begin("POST /api/v1/transactions", fmt.Sprint("request-", i), "hash")
		if err == ErrQueueFull {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err = j.Finish(op.ID, 1, result, ""); err != nil {
			t.Fatal("reserved completion failed", err)
		}
	}
	info, err := os.Stat(filepath.Join(dir, "operations.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewJournal(dir); err != nil {
		t.Fatalf("successful writes produced unreadable %d-byte history: %v", info.Size(), err)
	}
}

func TestJournalReservesEveryUnfinishedCompletionBeforeMutation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "operations")
	j, err := NewJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	var accepted []Operation
	for i := range 16 {
		op, _, err := j.Begin("probe", fmt.Sprint("key-", i), "hash")
		if err == ErrQueueFull {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		accepted = append(accepted, op)
	}
	if len(accepted) == 0 || len(accepted) >= 16 {
		t.Fatal("unfinished operations did not reserve their byte budgets", len(accepted))
	}
	result := map[string]any{"value": strings.Repeat("x", maxResultBytes-12)}
	data, err := json.Marshal(result)
	if err != nil || len(data) > maxResultBytes {
		t.Fatal("invalid boundary fixture", err)
	}
	for _, op := range accepted {
		if _, err := j.Finish(op.ID, ^uint64(0), result, strings.Repeat("e", 128)); err != nil {
			t.Fatal("admitted completion exceeded its reserved space", err)
		}
	}
	reopened, err := NewJournal(dir)
	if err != nil || len(reopened.List()) != len(accepted) {
		t.Fatal("reservation lost durable operations", err)
	}
	for i, op := range accepted {
		retry, existing, err := reopened.Begin("probe", fmt.Sprint("key-", i), "hash")
		if err != nil || !existing || retry.ID != op.ID {
			t.Fatal("full storage discarded idempotency", err)
		}
	}
	if _, _, err = reopened.Begin("probe", "additional-key", "hash"); err != ErrQueueFull {
		t.Fatal("full history admitted an unreserved mutation", err)
	}
}

func TestUnexpectedLargeResultPreservesIdentityWithoutReplay(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "operations")
	j, err := NewJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := j.Begin("node-prepare", "original-key", "original-hash")
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	result := map[string]any{
		"transaction": map[string]any{"id": id},
		"oversized":   strings.Repeat("x", maxResultBytes),
		"private":     "DO-NOT-RETAIN-OVERSIZED-CANARY",
	}
	completed, err := j.Finish(op.ID, 1, result, "")
	if err != nil || completed.State != "succeeded" ||
		completed.Result["result_unavailable"] != true {
		t.Fatal("executed mutation lost its durable completion", err)
	}
	refs := completed.Result["references"].(map[string]any)
	if refs["transaction"] != id {
		t.Fatal("authoritative transaction reference was discarded")
	}
	if _, err = j.Finish(op.ID, 9, map[string]any{"changed": true}, "later_error"); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	retry, existing, err := reopened.Begin("node-prepare", "original-key", "original-hash")
	if err != nil || !existing || retry.ID != op.ID || retry.State != "succeeded" ||
		retry.Result["result_unavailable"] != true {
		t.Fatal("completed unavailable result could replay a mutation", err)
	}
	if _, _, err = reopened.Begin(
		"node-prepare",
		"original-key",
		"different-hash",
	); err != ErrIdempotency {
		t.Fatal("compaction discarded request identity", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "operations.json"))
	if err != nil || strings.Contains(string(data), "DO-NOT-RETAIN-OVERSIZED-CANARY") {
		t.Fatal("unavailable provider payload was retained", err)
	}
}

func TestFailedCompletionWriteRemainsRetryableAndDoesNotClaimDurability(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "operations")
	j, err := NewJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := j.Begin("prepare", "write-failure-key", "hash")
	if err != nil {
		t.Fatal(err)
	}
	// A missing private directory forces an actual filesystem write failure,
	// independently of the test runner's user or chmod privileges.
	displaced := dir + "-temporarily-unavailable"
	if err = os.Rename(dir, displaced); err != nil {
		t.Fatal(err)
	}
	if _, err = j.Finish(op.ID, 2, map[string]any{"id": "transaction-id"}, ""); err == nil {
		t.Fatal("completion unexpectedly survived unavailable storage")
	}
	interrupted, found, err := j.Begin("prepare", "write-failure-key", "hash")
	if err != nil || !found || interrupted.ID != op.ID || interrupted.State != "running" {
		t.Fatal("failed write either claimed completion or admitted a repeated mutation", err)
	}
	if err = os.Rename(displaced, dir); err != nil {
		t.Fatal(err)
	}
	completed, err := j.Finish(op.ID, 2, map[string]any{"id": "transaction-id"}, "")
	if err != nil || completed.State != "succeeded" {
		t.Fatal("completion could not retry its durable write", err)
	}
	reopened, err := NewJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	stored, found := reopened.Get(op.ID)
	if !found || stored.State != "succeeded" || stored.Result["id"] != "transaction-id" {
		t.Fatal("retry reported success without durable completion")
	}
}

func TestLargeNumericResultsPreserveBudgetAndPrecisionAcrossRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "operations")
	j, err := NewJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	values := make([]uint64, 13000)
	for i := range values {
		values[i] = 9999999999999999999
	}
	result := map[string]any{"values": values}
	original, err := json.Marshal(result)
	if err != nil || len(original) > maxResultBytes {
		t.Fatal("invalid numeric boundary fixture", err)
	}
	op, _, err := j.Begin("numeric-result", "numeric-key", "hash")
	if err != nil {
		t.Fatal(err)
	}
	completed, err := j.Finish(op.ID, 1, result, "")
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := NewJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	recovered, ok := reopened.Get(op.ID)
	if !ok {
		t.Fatal("operation disappeared")
	}
	for _, operation := range []Operation{completed, recovered} {
		data, err := json.Marshal(operation.Result)
		if err != nil || string(data) != string(original) {
			t.Fatal("numeric result changed precision or expanded past its reservation", err)
		}
	}
}
