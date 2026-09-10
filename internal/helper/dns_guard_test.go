package helper

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/tibeahx/RouteHarbor/internal/dataplane"
)

func TestDNSGuardOwnershipRejectsExtraSelectors(t *testing.T) {
	owner := dataplane.Plan{DNSGuardUID: 453}
	good := `{"priority":29900,"src":"all","uid_start":453,"uid_end":453,"ipproto":"tcp","dport":53,"action":"blackhole"}`
	var rule ipRule
	if err := json.Unmarshal([]byte(good), &rule); err != nil || !dnsRuleAllowed(rule, &owner) {
		t.Fatal(rule, err)
	}
	if defaultRule(rule) || safetyRuleAllowed(rule, &owner) {
		t.Fatal("DNS rule confused with another ownership class")
	}
	cases := []string{
		strings.Replace(good, `"uid_end":453`, `"uid_end":454`, 1),
		strings.Replace(good, `"uid_start":453`, `"uid_start":0`, 1),
		strings.Replace(good, `"priority":29900`, `"priority":0`, 1),
		strings.Replace(good, `"dport":53`, `"dport":443`, 1),
		strings.Replace(good, `"action":"blackhole"`, `"action":"unreachable"`, 1),
		strings.Replace(good, `"src":"all"`, `"src":"10.0.0.0/8"`, 1),
		strings.Replace(good, `"src":"all"`, `"src":"all","sport":53`, 1),
		strings.Replace(good, `"src":"all"`, `"src":"all","fwmark":"0x0"`, 1),
		strings.Replace(good, `"src":"all"`, `"src":"all","table":254`, 1),
	}
	for _, raw := range cases {
		var r ipRule
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			continue
		}
		if dnsRuleAllowed(r, &owner) {
			t.Fatalf("foreign rule accepted: %s", raw)
		}
	}
	if dnsRuleAllowed(rule, nil) || dnsRuleAllowed(rule, &dataplane.Plan{DNSGuardUID: 454}) {
		t.Fatal("rule accepted without trusted prior owner")
	}
}

func TestDNSGuardIdentityDurableAndImmutable(t *testing.T) {
	identity := DNSGuardIdentity{
		UID:          453,
		GID:          453,
		BinarySHA256: strings.Repeat("a", 64),
		InitSHA256:   strings.Repeat("b", 64),
	}
	backend := &NetworkBackend{
		DNSIdentity: func(context.Context) (DNSGuardIdentity, error) { return identity, nil },
	}
	m := testManager(t, backend, nil)
	err := m.locked(func(s *State) error { return m.prepareDNSIdentity(context.Background(), s) })
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewManager(m.dir, backend, nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := restarted.Status()
	if err != nil || state.DNSGuard == nil || *state.DNSGuard != identity {
		t.Fatal(state, err)
	}
	identity.UID = 454
	if err = restarted.locked(
		func(s *State) error { return restarted.prepareDNSIdentity(context.Background(), s) },
	); err == nil {
		t.Fatal("account reassigned")
	}
	backend.DNSIdentity = func(context.Context) (DNSGuardIdentity, error) {
		return DNSGuardIdentity{}, errors.New("process unverified")
	}
	if err = restarted.locked(
		func(s *State) error { return restarted.prepareDNSIdentity(context.Background(), s) },
	); err == nil {
		t.Fatal("unverified identity accepted")
	}
	state, err = restarted.Status()
	if err != nil || state.DNSGuard.UID != 453 {
		t.Fatal("old owner lost", state, err)
	}
}
