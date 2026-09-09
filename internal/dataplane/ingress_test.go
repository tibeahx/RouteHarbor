package dataplane

import (
	"strings"
	"testing"
)

func TestIngressAliasesRemainPrivateAndBounded(t *testing.T) {
	p, err := Build(testNetwork(), nil, "", "closed")
	if err != nil {
		t.Fatal(err)
	}
	original := p.Desired.Network.LANInterfaces[0]
	p.IngressDevices = []string{"port0"}
	protected, err := WithIngressDevices(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(protected.Desired.Network.LANInterfaces) != 1 ||
		protected.Desired.Network.LANInterfaces[0] != original {
		t.Fatal("public intent changed")
	}
	for _, rules := range []string{protected.NFT, protected.GuardNFT} {
		if !strings.Contains(rules, `"port0"`) {
			t.Fatal("physical ingress not guarded")
		}
	}
	for _, aliases := range [][]string{{p.Desired.Network.WANInterface}, {original}, {"lo"}, {"port0", "port0"}, {"bad;device"}} {
		p.IngressDevices = aliases
		if _, err := WithIngressDevices(p); err == nil {
			t.Fatal("invalid aliases accepted", aliases)
		}
	}
}
