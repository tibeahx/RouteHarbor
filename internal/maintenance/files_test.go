package maintenance

import (
	"errors"
	"testing"
)

func TestPrivateJournalContentionHasExactRetryableCode(t *testing.T) {
	root, err := openStateRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	held, err := stateLock(root, ".lock")
	if err != nil {
		t.Fatal(err)
	}
	defer stateUnlock(held)
	unexpected, err := stateLock(root, ".lock")
	if unexpected != nil {
		stateUnlock(unexpected)
		t.Fatal("held journal lock acquired twice")
	}
	if !errors.Is(err, ErrStateBusy) {
		t.Fatal("journal contention did not preserve the busy code", err)
	}
}
