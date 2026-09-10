package dataplane

import (
	"errors"
	"fmt"
	"reflect"
)

// SelectionNFT changes only the new-connection classifier. Both sides must
// describe the same already-confirmed resources; topology and policy changes
// still require the full guarded network transaction.
func SelectionNFT(previous, candidate Desired) (string, error) {
	if previous.BreakExisting || candidate.BreakExisting || previous.Continuity != nil ||
		candidate.Continuity != nil || previous.Selective != nil || candidate.Selective != nil {
		return "", errors.New("selection_requires_full_apply")
	}
	if _, err := Compile(previous); err != nil {
		return "", err
	}
	if _, err := Compile(candidate); err != nil {
		return "", err
	}
	normalized := candidate
	normalized.Selected = previous.Selected
	if !reflect.DeepEqual(previous, normalized) {
		return "", errors.New("selection_requires_full_apply")
	}
	return "flush chain inet " + Table + " select_flow\n" + selectionAddRules(candidate), nil
}

func selectionRules(d Desired) string {
	for _, path := range d.Paths {
		if path.SourceID == d.Selected {
			return fmt.Sprintf(
				"  ct mark & 0xff000000 != 0x4f000000 ct mark set (ct mark & 0x0000ffff) | %s\n",
				markHex(Mark(path.Slot)),
			)
		}
	}
	return ""
}

func selectionAddRules(d Desired) string {
	rules := selectionRules(d)
	if rules == "" {
		return ""
	}
	return "add rule inet " + Table + " select_flow " + rules[2:]
}
