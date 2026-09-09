package helper

import (
	"encoding/json"
	"testing"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
)

func TestDetachedInterfaceMetadataDoesNotBlessForeignSelectors(t *testing.T) {
	p, err := dataplane.Compile(testDesired())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name        string
		value       string
		allowed     bool
		decodeError bool
	}{
		{"detached owned interface", `{"priority":30000,"src":"all","iif":"home0","iif_detached":null,"table":"20999"}`, true, false},
		{"foreign interface", `{"priority":30000,"src":"all","iif":"foreign0","iif_detached":null,"table":"20999"}`, false, false},
		{"invalid detached metadata", `{"priority":30000,"src":"all","iif":"home0","iif_detached":true,"table":"20999"}`, false, false},
		{"foreign protocol selector", `{"priority":30000,"src":"all","iif":"home0","iif_detached":null,"table":"20999","ipproto":"udp"}`, false, false},
		{"invalid protocol field type", `{"priority":30000,"src":"all","iif":"home0","iif_detached":null,"table":"20999","ipproto":17}`, false, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			var rule ipRule
			err := json.Unmarshal([]byte(row.value), &rule)
			if row.decodeError {
				if err == nil {
					t.Fatal("malformed selector was not rejected during decoding")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if safetyRuleAllowed(rule, &p) != row.allowed {
				t.Fatal("unexpected detached rule ownership")
			}
		})
	}
}
