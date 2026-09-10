package routing

import (
	"net/netip"
	"testing"
)

func TestDNSHealthRequiresSyntheticAnswerFromExpectedPool(t *testing.T) {
	query := dnsRequest(DNSHealthName, 1)
	q, err := parseDNSQuestion(query, false)
	if err != nil {
		t.Fatal(err)
	}
	valid := dnsEmpty(query, q, 0)
	valid[7] = 1
	valid = append(valid, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 18, 0, 1)
	pool := netip.MustParsePrefix("198.18.0.0/16")
	if !ValidDNSHealthResponse(query, valid, pool) {
		t.Fatal("real synthetic answer rejected")
	}
	for n := 0; n < len(valid); n++ {
		if ValidDNSHealthResponse(query, valid[:n], pool) {
			t.Fatalf("truncated answer accepted at %d", n)
		}
	}
	for _, tc := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{"frontend-only", func(b []byte) []byte { return dnsEmpty(query, q, 0) }},
		{"servfail", func(b []byte) []byte { b[3] |= 2; return b }},
		{"truncated-flag", func(b []byte) []byte { b[2] |= 2; return b }},
		{"wrong-id", func(b []byte) []byte { b[0]++; return b }},
		{"other-pool", func(b []byte) []byte { b[len(b)-3] = 19; return b }},
		{"real-address", func(b []byte) []byte { copy(b[len(b)-4:], []byte{8, 8, 8, 8}); return b }},
		{"wrong-question", func(b []byte) []byte { b[13] = 'x'; return b }},
		{"multiple-answers", func(b []byte) []byte { b[7] = 2; return b }},
		{"alias", func(b []byte) []byte { b[len(query)+3] = 5; return b }},
		{"trailing-data", func(b []byte) []byte { return append(b, 0) }},
		{"pointer-loop", func(b []byte) []byte { b[len(query)+1] = byte(len(query)); return b }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if ValidDNSHealthResponse(query, tc.edit(append([]byte{}, valid...)), pool) {
				t.Fatal("non-serving classifier accepted as healthy")
			}
		})
	}
}
