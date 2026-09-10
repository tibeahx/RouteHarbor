//go:build linux

package helper

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/dataplane"
)

func TestLinuxSelectiveCompletedEmergencyRepairsPolicyReset(t *testing.T) {
	prepareLab(t)
	ctx := context.Background()
	labCommand(t, "/sbin/ip", "-6", "addr", "add", "2001:db8:44::1/64", "dev", "outside0")
	labCommand(t, "/sbin/ip", "-6", "route", "add", "default", "dev", "outside0")
	b := labBackend()
	dir := filepath.Join(t.TempDir(), "state")
	m, err := NewManager(dir, b, &testWatchdog{})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := m.Prepare(ctx, selectiveDesired())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Apply(ctx, tx.ID, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Confirm(tx.ID); err != nil {
		t.Fatal(err)
	}
	if err = m.SelectiveEmergency(ctx); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewManager(dir, b, ProcessWatchdog{
		Binary: "/usr/libexec/routeharbor-helper", StateDir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if state, err := restarted.Status(); err == nil && active(state.Transaction) {
			if _, err := restarted.Rollback(ctx, state.Transaction.ID); err != nil {
				t.Error("prepared monitor fixture cleanup", err)
			}
		}
		if err := restarted.Decommission(ctx, "restore-direct"); err != nil {
			t.Error("monitor fixture cleanup", err)
		}
	}()
	// A service restart must rearm the completed journal and a second restart
	// must acknowledge the existing detached lease without blocking readiness.
	for attempt := 0; attempt < 2; attempt++ {
		if err = restarted.Resume(ctx); err != nil {
			t.Fatal("completed emergency watchdog was not resumed", err)
		}
	}
	p, err := dataplane.Compile(selectiveDesired())
	if err != nil {
		t.Fatal(err)
	}
	conntrack, err := conntrackBinary()
	if err != nil {
		t.Fatal(err)
	}
	// Even a dispatcher-marked UDP entry created after completed recovery must
	// survive guard repair: replaying EmergencyDirect would delete this entry.
	labCommand(t, conntrack, "--create", "--proto", "udp", "--orig-src", "10.44.0.2",
		"--orig-dst", "10.44.0.1", "--sport", "40553", "--dport", "53", "--timeout", "120",
		"--mark", "0x4ffa0000")
	defer func() {
		_ = exec.Command(conntrack, "--delete", "--proto", "udp", "--sport", "40553").Run()
	}()
	journalPath := filepath.Join(dir, "transaction.json")
	journal, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	journalInfo, err := os.Stat(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	assertGuardRepair := func() {
		t.Helper()
		for _, guard := range selectiveGuardRules(&p) {
			if guard.destination != "" {
				labCommand(t, "/sbin/ip", guard.args("del")...)
			}
		}
		deadline := time.Now().Add(6 * time.Second)
		for {
			found := 0
			for _, guard := range selectiveGuardRules(&p) {
				if guard.destination == "" {
					continue
				}
				rules, err := b.rules(ctx, guard.family)
				if err != nil {
					t.Fatal(err)
				}
				for _, rule := range rules {
					if guard.matches(rule) {
						found++
					}
				}
			}
			if found == 2 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("detached watchdog did not restore both synthetic policy rules", found)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	assertPaths := func() {
		t.Helper()
		for _, target := range []struct{ family, fake, real string }{
			{"-4", "198.18.0.1", "1.1.1.1"},
			{"-6", "fd66:6f70:656e::1", "2001:4860:4860::8888"},
		} {
			if out, err := exec.Command("/sbin/ip", target.family, "route", "get", target.fake).
				CombinedOutput(); err == nil {
				t.Fatal("synthetic destination reached WAN", target.fake, string(out))
			}
			out := labCommand(t, "/sbin/ip", target.family, "route", "get", target.real)
			if !strings.Contains(string(out), "outside0") {
				t.Fatal("ordinary direct was not preserved", string(out))
			}
		}
	}
	assertGuardRepair()
	assertPaths()
	// Simulate fw4 replacement after netifd reset. The repaired policy rules
	// remain effective independently of any nft table or classifier process.
	labCommand(t, "/usr/sbin/nft", "flush", "ruleset")
	assertPaths()
	assertGuardRepair()
	assertPaths()
	for _, family := range []int{4, 6} {
		rules, err := b.rules(ctx, family)
		if err != nil {
			t.Fatal(err)
		}
		for _, rule := range rules {
			if rule.Priority >= selectiveInterfacePriority &&
				rule.Priority <= selectiveInterfacePriority+250 {
				t.Fatal("completed guard repair reinstalled bypass protection", rule)
			}
		}
	}
	after, err := os.ReadFile(journalPath)
	if err != nil || string(journal) != string(after) {
		t.Fatal("steady emergency repair rewrote the journal", err)
	}
	afterInfo, err := os.Stat(journalPath)
	if err != nil || !journalInfo.ModTime().Equal(afterInfo.ModTime()) {
		t.Fatal("steady emergency repair replaced the journal file", err)
	}
	if present, err := runConntrack(
		ctx,
		conntrack,
		"--dump",
		"ipv4",
		dataplane.Mark(250),
	); err != nil ||
		!present {
		t.Fatal("guard-only repair reset existing DNS connection state", err)
	}
	// Preparing another policy hands monitoring to its new fenced transaction
	// while the current completed emergency remains the active network policy.
	if _, err = restarted.Prepare(ctx, selectiveDesired()); err != nil {
		t.Fatal("emergency prepared monitor handoff", err)
	}
	assertGuardRepair()
	assertPaths()
}
