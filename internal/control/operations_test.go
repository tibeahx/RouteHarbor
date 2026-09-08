package control

import (
	"path/filepath"
	"testing"
)

func TestJournalCrashRetryAndSecretFreeRecord(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	j, e := NewJournal(dir)
	if e != nil {
		t.Fatal(e)
	}
	op, old, e := j.Begin("source-add", "same-key", "hash-only")
	if e != nil || old {
		t.Fatal(e)
	}
	j, e = NewJournal(dir)
	if e != nil {
		t.Fatal(e)
	}
	retry, old, e := j.Begin("source-add", "same-key", "hash-only")
	if e != nil || !old || retry.ID != op.ID || retry.State != "failed" ||
		retry.ErrorCode != "interrupted_check_current_state" {
		t.Fatal("unsafe crash replay", retry, e)
	}
	if _, _, e = j.Begin("source-add", "same-key", "different-body-hash"); e != ErrIdempotency {
		t.Fatal("collision accepted")
	}
}
