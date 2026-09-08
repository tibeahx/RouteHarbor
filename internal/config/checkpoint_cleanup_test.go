package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckpointPruningKeepsOnlyCurrentCandidateAndUnrelatedFiles(t *testing.T) {
	dir := t.TempDir()
	store, e := NewStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = store.Close() }()
	keep := strings.Repeat("ab", 16)
	for i := range 12 {
		if e = store.SaveCheckpoint(fmt.Sprintf("%032x", i), store.Get()); e != nil {
			t.Fatal(e)
		}
	}
	if e = store.SaveCheckpoint(keep, store.Get()); e != nil {
		t.Fatal(e)
	}
	unrelated := filepath.Join(dir, "checkpoint-not-a-transaction.json")
	if e = os.WriteFile(unrelated, []byte("unrelated"), 0o600); e != nil {
		t.Fatal(e)
	}
	if e = store.SaveConfirmed(store.Get()); e != nil {
		t.Fatal(e)
	}
	if e = store.PruneCheckpoints([]string{keep}); e != nil {
		t.Fatal(e)
	}
	entries, e := os.ReadDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "checkpoint-") {
			count++
		}
	}
	if count != 2 {
		t.Fatal("unbounded or overbroad checkpoint pruning", count)
	}
	if _, found, e := store.Checkpoint(keep); e != nil || !found {
		t.Fatal("active checkpoint lost", e)
	}
	if _, found, e := store.Confirmed(); e != nil || !found {
		t.Fatal("confirmed snapshot lost", e)
	}
	if b, e := os.ReadFile(unrelated); e != nil || string(b) != "unrelated" {
		t.Fatal("unrelated file touched", e)
	}
	if e = store.PruneCheckpoints([]string{"../config"}); e == nil {
		t.Fatal("unsafe keep ID accepted")
	}
}
