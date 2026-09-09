package dataplane

import (
	"net/netip"
	"strings"
	"testing"
)

func TestEarlyQuarantineAllowsNoAddressesWithoutWeakeningApply(t *testing.T) {
	p, err := Compile(Desired{Network: testNetwork(), Fallback: "closed"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = WithRouterAddresses(p, nil); err == nil {
		t.Fatal("ordinary apply accepted an empty address set")
	}
	guard, err := WithQuarantineRouterAddresses(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{"hook prerouting priority -160", "th dport 53 drop", "ip daddr 10.44.0.0/24 return", "ip6 daddr fe80::/10 return", "  drop\n"} {
		if !strings.Contains(guard.GuardNFT, rule) {
			t.Fatal("early quarantine lost protection or management exception", rule)
		}
	}
	if strings.Contains(guard.GuardNFT, "helper injects") {
		t.Fatal("address placeholder was not resolved")
	}
	for _, addresses := range [][]netip.Addr{{{}}, make([]netip.Addr, 513)} {
		if _, err = WithQuarantineRouterAddresses(p, addresses); err == nil {
			t.Fatal("invalid address discovery was ignored")
		}
	}
	direct := p
	direct.Desired.Paths = []Path{{SourceID: "direct", Kind: "direct", Slot: 1}}
	if _, err = WithQuarantineRouterAddresses(direct, nil); err == nil {
		t.Fatal("non-quarantine intent used relaxed discovery")
	}
}
