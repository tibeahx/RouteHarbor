package helper

import (
	"encoding/json"
	"testing"
)

func TestDefaultRuleRequiresExactKernelSemantics(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		allowed bool
	}{
		{`{"priority":0,"src":"all","table":"local"}`, true},
		{`{"priority":32766,"src":"all","table":"main"}`, true},
		{`{"priority":32767,"src":"all","table":"default","protocol":"kernel"}`, true},
		{`{"priority":0,"src":"all","table":"main"}`, false},
		{`{"priority":32766,"src":"all","table":20999}`, false},
		{`{"priority":0,"src":"all","table":"local","fwmark":"0x0"}`, false},
		{`{"priority":0,"src":"all","table":"local","not":true}`, false},
		{`{"priority":0,"src":"10.0.0.0/8","table":"local"}`, false},
		{`{"priority":0,"src":"all","table":"local","goto":32766}`, false},
		{`{"priority":0,"src":"all","table":"local","suppress_prefixlength":0}`, false},
		{`{"priority":0,"src":"all","table":"local","flags":["not"]}`, false},
	} {
		var rule ipRule
		if err := json.Unmarshal([]byte(tc.raw), &rule); err != nil {
			t.Fatal(err)
		}
		if actual := defaultRule(rule); actual != tc.allowed {
			t.Fatalf("%s: allowed=%v", tc.raw, actual)
		}
	}
}
