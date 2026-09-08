package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

const (
	packetTable     = "openrhp_probe"
	packetOwnership = "OpenRHP service-owned v1"
)

// refreshPacketRules is called with the lifecycle mutex held. It replaces only the owned output probe table atomically.
func (m *PacketManager) refreshPacketRules(ctx context.Context) error {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	inspect := exec.CommandContext(
		bounded,
		"/usr/sbin/nft",
		"-j",
		"list",
		"table",
		"inet",
		packetTable,
	)
	var output cappedRuleOutput
	inspect.Stdout = &output
	inspect.Stderr = nil
	err := inspect.Run()
	exists := err == nil
	if exists {
		var listing struct {
			NFTables []struct {
				Table *struct {
					Family  string `json:"family"`
					Name    string `json:"name"`
					Comment string `json:"comment"`
				} `json:"table"`
			} `json:"nftables"`
		}
		if json.Unmarshal(output.Bytes(), &listing) != nil {
			return errors.New("packet_rules_invalid: cannot inspect existing probe table")
		}
		owned := false
		for _, o := range listing.NFTables {
			if o.Table != nil && o.Table.Family == "inet" && o.Table.Name == packetTable &&
				o.Table.Comment == packetOwnership {
				owned = true
			}
		}
		if !owned {
			textCmd := exec.CommandContext(
				bounded,
				"/usr/sbin/nft",
				"list",
				"table",
				"inet",
				packetTable,
			)
			var plain cappedRuleOutput
			textCmd.Stdout = &plain
			textCmd.Stderr = nil
			if textCmd.Run() == nil {
				owned = nftTableOwnedText(plain.Bytes(), packetTable)
			}
		}
		if !owned {
			return errors.New("packet_rules_conflict: probe table is not owned by OpenRHP")
		}
	}
	var script strings.Builder
	if exists {
		fmt.Fprintf(&script, "delete table inet %s\n", packetTable)
	}
	fmt.Fprintf(
		&script,
		"table inet %s {\n comment \"%s\"\n chain probes {\n type filter hook output priority -150; policy accept;\n meta mark & 0x8000 != 0 return\n",
		packetTable,
		packetOwnership,
	)
	slots := make([]int, 0, len(m.processes))
	for _, p := range m.processes {
		slots = append(slots, p.slot)
	}
	sort.Ints(slots)
	for _, slot := range slots {
		fmt.Fprintf(
			&script,
			" meta mark & 0xffff0000 == 0x%x meta l4proto { tcp, udp } meta mark set meta mark | 0x4000 queue num %d\n",
			uint32(0x4f000000)|uint32(slot)<<16,
			21000+slot,
		)
	}
	script.WriteString(" }\n}\n")
	check := exec.CommandContext(bounded, "/usr/sbin/nft", "--check", "--file", "-")
	check.Stdin = strings.NewReader(script.String())
	check.Stdout = nil
	check.Stderr = nil
	if check.Run() != nil {
		return errors.New("packet_rules_rejected: kernel rejected independent probe queue rules")
	}
	apply := exec.CommandContext(bounded, "/usr/sbin/nft", "--file", "-")
	apply.Stdin = strings.NewReader(script.String())
	apply.Stdout = nil
	apply.Stderr = nil
	if apply.Run() != nil {
		return errors.New("packet_rules_failed: independent probe queue rules were not installed")
	}
	return nil
}

type cappedRuleOutput struct{ data []byte }

func (b *cappedRuleOutput) Write(p []byte) (int, error) {
	if len(b.data)+len(p) > 256<<10 {
		return 0, errors.New("rule inspection exceeds limit")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *cappedRuleOutput) Bytes() []byte {
	return b.data
}

func (m *PacketManager) Path(id string) (int, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.processes[id]
	if p == nil || !p.running || !p.rulesReady {
		return 0, false
	}
	return p.slot, true
}
