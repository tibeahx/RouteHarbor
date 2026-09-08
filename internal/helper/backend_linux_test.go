//go:build linux

package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
	"github.com/tibeahx/OpenRHP/internal/platform"
)

func requireNetLab(t *testing.T) {
	t.Helper()
	if os.Getenv("OPENRHP_NET_LAB") != "1" {
		t.Skip("set OPENRHP_NET_LAB=1 inside the isolated Docker lab")
	}
	if _, e := os.Stat("/.dockerenv"); e != nil {
		t.Fatal("network lab refuses to modify a non-container host")
	}
	if os.Geteuid() != 0 {
		t.Fatal("network lab needs container root")
	}
}

func labCommand(t *testing.T, binary string, args ...string) []byte {
	t.Helper()
	out, e := exec.Command(binary, args...).CombinedOutput()
	if e != nil {
		t.Fatalf("%s %v: %v: %s", binary, args, e, out)
	}
	return out
}

type labRunner struct{}

func (labRunner) Run(
	ctx context.Context,
	binary string,
	args []string,
	input []byte,
) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	out, e := cmd.CombinedOutput()
	if e != nil {
		fmt.Fprintf(os.Stderr, "lab command %s %v failed: %s\n", binary, args, out)
	}
	return out, e
}

func labBackend() *NetworkBackend {
	b := NewNetworkBackend()
	b.Runner = labRunner{}
	b.Detect = func(context.Context) platform.Report {
		return platform.Report{
			Supported: true,
			OS:        "Linux integration fixture",
			Firewall:  "fw4/nftables",
			Interfaces: []platform.Interface{
				{Device: "home0", Role: "local", Up: true, Prefixes: []string{"10.44.0.0/24"}},
				{Device: "outside0", Role: "uplink", Up: true},
				{Device: "tunnel0", Protocol: "wireguard", Up: true},
			},
			Capabilities: map[string]platform.Capability{
				"lifecycle_guard":   {Available: true},
				"flow_offload_safe": {Available: true},
				"tproxy":            {Available: true},
				"ipv6":              {Available: true},
				"nfqueue":           {Available: true},
			},
		}
	}
	return b
}

func prepareLab(t *testing.T) {
	t.Helper()
	requireNetLab(t)
	for _, family := range []string{"-4", "-6"} {
		data := labCommand(t, "/sbin/ip", family, "-j", "rule", "show")
		var rules []ipRule
		if err := json.Unmarshal(data, &rules); err != nil {
			t.Fatal(err)
		}
		for _, r := range rules {
			if r.Priority >= 22001 && r.Priority <= 22250 ||
				r.Priority >= 30000 && r.Priority <= 30031 {
				_ = exec.Command("/sbin/ip", family, "rule", "del", "priority", strconv.Itoa(r.Priority)).
					Run()
			}
		}
		for _, table := range []string{"20999", "20003", "20004", "20010"} {
			_ = exec.Command("/sbin/ip", family, "route", "flush", "table", table).Run()
		}
	}
	for _, table := range []string{dataplane.Table, dataplane.GuardTable, dataplane.ProbeTable} {
		_ = exec.Command("/usr/sbin/nft", "delete", "table", "inet", table).Run()
	}
	for _, dev := range []string{"home0", "outside0", "tunnel0"} {
		_ = exec.Command("/sbin/ip", "link", "del", dev).Run()
		labCommand(t, "/sbin/ip", "link", "add", dev, "type", "dummy")
		labCommand(t, "/sbin/ip", "link", "set", dev, "up")
	}
	labCommand(t, "/sbin/ip", "addr", "add", "10.44.0.1/24", "dev", "home0")
	labCommand(t, "/sbin/ip", "addr", "add", "192.0.2.1/24", "dev", "outside0")
	labCommand(t, "/sbin/ip", "route", "add", "default", "dev", "outside0")
}

func TestLinuxRealNFTAndRoutes(t *testing.T) {
	prepareLab(t)
	ctx := context.Background()
	b := labBackend()
	d := testDesired()
	d.Paths = append(
		d.Paths,
		dataplane.Path{SourceID: "transparent", Kind: "tproxy", Slot: 3, Port: 12003, UDP: true},
		dataplane.Path{
			SourceID:  "tunnel",
			Kind:      "interface",
			Slot:      4,
			Interface: "tunnel0",
			UDP:       true,
		},
	)
	d.Selected = "transparent"
	p, e := dataplane.Compile(d)
	if e != nil {
		t.Fatal(e)
	}
	if e = b.Check(ctx, p); e != nil {
		t.Fatalf("real nft preflight: %v", e)
	}
	if e = b.Apply(ctx, p, nil); e != nil {
		t.Fatalf("real nft/route apply: %v", e)
	}
	table := labCommand(t, "/usr/sbin/nft", "list", "table", "inet", dataplane.Table)
	if !strings.Contains(string(table), "tproxy to :12003") {
		t.Fatal(string(table))
	}

	routes := labCommand(t, "/sbin/ip", "-j", "route", "show", "table", "20003")
	if !strings.Contains(string(routes), `"type":"local"`) {
		t.Fatal(string(routes))
	}
	lookup := labCommand(t, "/sbin/ip", "-4", "route", "get", "8.8.8.8", "mark", "0x4f040000")
	if !strings.Contains(string(lookup), "tunnel0") {
		t.Fatal(string(lookup))
	}
	// A selected-path DNS NAT compiles and applies against the real Linux kernel.
	dns := d
	dns.Network.DNS = "selected-path"
	dns.Network.DNSResolver = "8.8.8.8"
	dns.Paths = []dataplane.Path{{SourceID: "wan", Kind: "direct", Slot: 5}}
	dns.Selected = "wan"
	dnsPlan, e := dataplane.Compile(dns)
	if e != nil {
		t.Fatal(e)
	}
	if e = b.Check(ctx, dnsPlan); e != nil {
		t.Fatal(e)
	}
	if e = b.Apply(ctx, dnsPlan, &p); e != nil {
		t.Fatal(e)
	}
	// The RPDB safety policy survives complete nft removal. Unmarked LAN
	// forwarding is blackholed while local LAN destinations remain routed.
	labCommand(t, "/usr/sbin/nft", "flush", "ruleset")
	if out, err := exec.Command("/sbin/ip", "-4", "route", "get", "8.8.4.4", "from", "10.44.0.2", "iif", "home0").
		CombinedOutput(); err == nil {
		t.Fatalf("nft flush leaked unmarked IPv4: %s", out)
	}
	if out, err := exec.Command("/sbin/ip", "-6", "route", "get", "2001:4860:4860::8888", "from", "2001:db8::2", "iif", "home0").
		CombinedOutput(); err == nil {
		t.Fatalf("nft flush leaked unmarked IPv6: %s", out)
	}
	local := labCommand(
		t,
		"/sbin/ip",
		"-4",
		"route",
		"get",
		"10.44.0.3",
		"from",
		"10.44.0.2",
		"iif",
		"home0",
	)
	if !strings.Contains(string(local), "home0") {
		t.Fatal(string(local))
	}
	// Foreign service objects are refused without replacing the ruleset.
	labCommand(t, "/usr/sbin/nft", "add", "table", "inet", dataplane.Table)
	if e = b.Check(ctx, p); e == nil || !strings.Contains(e.Error(), "ownership_conflict") {
		t.Fatalf("foreign table accepted: %v", e)
	}
}

func TestLinuxForeignDefaultPriorityRefused(t *testing.T) {
	prepareLab(t)
	ctx := context.Background()
	b := labBackend()
	p, err := dataplane.Compile(testDesired())
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"-4", "-6"} {
		labCommand(t, "/sbin/ip", family, "rule", "add", "priority", "0", "lookup", "main")
		if err = b.Apply(
			ctx,
			p,
			nil,
		); err == nil ||
			!strings.Contains(err.Error(), "ownership_conflict") {
			t.Fatalf("foreign %s priority-zero main rule accepted: %v", family, err)
		}
		// The rejection must preserve the foreign rule for its actual owner.
		labCommand(t, "/sbin/ip", family, "rule", "del", "priority", "0", "lookup", "main")
	}
}

type failPolicyOnce struct {
	actual platform.Runner
	failed bool
}

func (r *failPolicyOnce) Run(
	ctx context.Context,
	binary string,
	args []string,
	input []byte,
) ([]byte, error) {
	if !r.failed && binary == "/usr/sbin/nft" && len(args) == 2 && args[0] == "--file" &&
		bytes.HasPrefix(input, []byte("add table inet openrhp {")) {
		r.failed = true
		return nil, errors.New("injected policy install failure after routes and guard")
	}
	return r.actual.Run(ctx, binary, args, input)
}

func TestLinuxRollbackRetainsGuardOwnership(t *testing.T) {
	for _, bootGuarded := range []bool{false, true} {
		t.Run(fmt.Sprintf("boot_guarded_%t", bootGuarded), func(t *testing.T) {
			prepareLab(t)
			ctx := context.Background()
			b := labBackend()
			m := testManager(t, b, &testWatchdog{})
			d := testDesired()
			if bootGuarded {
				d.Fallback = "direct"
			}
			tx, err := m.Prepare(ctx, d)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = m.Apply(ctx, tx.ID, 30*time.Second); err != nil {
				t.Fatal(err)
			}
			if _, err = m.Confirm(tx.ID); err != nil {
				t.Fatal(err)
			}
			if bootGuarded {
				if err = m.BootGuard(ctx); err != nil {
					t.Fatal(err)
				}
			}
			d.Fallback = "direct"
			d.Selected = "b"
			tx, err = m.Prepare(ctx, d)
			if err != nil {
				t.Fatal(err)
			}
			fault := &failPolicyOnce{actual: b.Runner}
			b.Runner = fault
			tx, err = m.Apply(ctx, tx.ID, 30*time.Second)
			if err == nil || tx.State != "rolled-back" || !fault.failed {
				t.Fatalf(
					"rollback could not recognize surviving guard: state=%s error=%v",
					tx.State,
					err,
				)
			}
			s, err := m.Status()
			if err != nil || s.Committed == nil || s.Committed.Selected != "a" {
				t.Fatalf("previous policy not restored: %+v %v", s, err)
			}
			if done, err := m.Recover(ctx); err != nil || !done {
				t.Fatalf("recovery remained pending: %t %v", done, err)
			}
			if _, err := exec.Command("/usr/sbin/nft", "list", "table", "inet", dataplane.GuardTable).
				Output(); err == nil {
				t.Fatal("temporary quarantine left installed after completed rollback")
			}
		})
	}
}

type crashRunner struct {
	ready  string
	actual platform.Runner
}

func (r crashRunner) Run(
	ctx context.Context,
	binary string,
	args []string,
	input []byte,
) ([]byte, error) {
	if len(args) == 2 && args[0] == "--file" &&
		strings.Contains(string(input), "table inet openrhp {") {
		if e := os.WriteFile(r.ready, []byte("ready"), 0o600); e != nil {
			return nil, e
		}
		select {}
	}
	return r.actual.Run(ctx, binary, args, input)
}

func TestLinuxCrashChild(t *testing.T) {
	if os.Getenv("OPENRHP_CRASH_CHILD") != "1" {
		t.Skip("subprocess only")
	}
	requireNetLab(t)
	b := labBackend()
	b.Runner = crashRunner{os.Getenv("OPENRHP_CRASH_READY"), labRunner{}}
	m, e := NewManager(
		os.Getenv("OPENRHP_CRASH_STATE"),
		b,
		ProcessWatchdog{
			Binary:   "/usr/libexec/openrhp-helper",
			StateDir: os.Getenv("OPENRHP_CRASH_STATE"),
		},
	)
	if e != nil {
		t.Fatal(e)
	}
	m.now = func() time.Time { return time.Now().Add(-28 * time.Second) }
	d := testDesired()
	d.Paths = []dataplane.Path{
		{SourceID: "proxy", Kind: "tproxy", Slot: 10, Port: 12010, UDP: true},
	}
	d.Selected = "proxy"
	tx, e := m.Prepare(context.Background(), d)
	if e != nil {
		t.Fatal(e)
	}
	_, e = m.Apply(context.Background(), tx.ID, 30*time.Second)
	if e != nil {
		t.Fatal(e)
	}
}

func TestLinuxIndependentWatchdogAfterHelperSIGKILL(t *testing.T) {
	prepareLab(t)
	dir := filepath.Join(t.TempDir(), "state")
	ready := filepath.Join(t.TempDir(), "ready")
	child := exec.Command(os.Args[0], "-test.run=^TestLinuxCrashChild$", "-test.v")
	child.Env = append(
		os.Environ(),
		"OPENRHP_CRASH_CHILD=1",
		"OPENRHP_CRASH_STATE="+dir,
		"OPENRHP_CRASH_READY="+ready,
	)
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	if e := child.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = child.Process.Kill() }()
	deadline := time.Now().Add(8 * time.Second)
	for {
		if _, e := os.Stat(ready); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("applying subprocess did not reach guarded crash point")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if e := child.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	_ = child.Wait()
	// The detached production watchdog now recovers without the applying process.
	deadline = time.Now().Add(10 * time.Second)
	for {
		data, e := os.ReadFile(filepath.Join(dir, "transaction.json"))
		var state State
		if e == nil && json.Unmarshal(data, &state) == nil && state.Transaction != nil &&
			state.Transaction.State == "rolled-back" {
			if state.Committed == nil || state.Committed.Selected != "" ||
				state.Committed.Fallback != "closed" {
				t.Fatal("unsafe durable rollback")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("independent watchdog did not recover: %s", data)
		}
		time.Sleep(100 * time.Millisecond)
	}
	table := labCommand(t, "/usr/sbin/nft", "list", "table", "inet", dataplane.Table)
	if strings.Contains(string(table), "tproxy") {
		t.Fatal("candidate rules survived rollback")
	}
	if !strings.Contains(string(table), "drop") {
		t.Fatal("safe policy does not block external traffic")
	}
	rules := labCommand(t, "/sbin/ip", "-4", "-j", "rule", "show")
	if strings.Contains(string(rules), "22010") {
		t.Fatal("candidate policy rule survived rollback")
	}
}

func TestLinuxLifecyclePersistedGuardAndRemoval(t *testing.T) {
	prepareLab(t)
	ctx := context.Background()
	stateDir := filepath.Join(t.TempDir(), "state")
	backend := labBackend()
	manager, err := NewManager(
		stateDir,
		backend,
		ProcessWatchdog{Binary: "/usr/libexec/openrhp-helper", StateDir: stateDir},
	)
	if err != nil {
		t.Fatal(err)
	}
	d := testDesired()
	tx, err := manager.Prepare(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.Apply(ctx, tx.ID, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err = manager.Confirm(tx.ID); err != nil {
		t.Fatal(err)
	}
	if err = manager.CanRemove(); err == nil {
		t.Fatal("guard package removal accepted while protecting traffic")
	}
	if err = manager.BootGuard(ctx); err != nil {
		t.Fatal(err)
	}
	state, err := manager.Status()
	if err != nil || !state.Guarded {
		t.Fatal(state, err)
	}
	data, err := os.ReadFile(PersistentGuardPath)
	if err != nil || !strings.Contains(string(data), "table inet openrhp_guard") {
		t.Fatalf("persistent boot guard missing: %v", err)
	}
	// A real fw4-style include can recreate the owned guard after its table is lost.
	labCommand(t, "/usr/sbin/nft", "delete", "table", "inet", dataplane.GuardTable)
	labCommand(t, "/usr/sbin/nft", "--file", PersistentGuardPath)
	if err = manager.Decommission(ctx, "preserve-closed"); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/sbin/ip", "-4", "route", "get", "8.8.4.4", "from", "10.44.0.2", "iif", "home0").
		CombinedOutput(); err == nil {
		t.Fatalf("preserve-closed leaked traffic: %s", out)
	}
	if err = manager.Decommission(ctx, "restore-direct"); err != nil {
		t.Fatal(err)
	}
	if err = manager.Decommission(ctx, "restore-direct"); err != nil {
		t.Fatal("decommission is not retryable", err)
	}
	if err = manager.CanRemove(); err != nil {
		t.Fatal(err)
	}
	direct := labCommand(
		t,
		"/sbin/ip",
		"-4",
		"route",
		"get",
		"8.8.4.4",
		"from",
		"10.44.0.2",
		"iif",
		"home0",
	)
	if !strings.Contains(string(direct), "outside0") {
		t.Fatalf("ordinary direct route was not restored: %s", direct)
	}
	data, err = os.ReadFile(PersistentGuardPath)
	if err != nil || strings.Contains(string(data), "table inet") {
		t.Fatal("persistent guard was not retired", err)
	}
}

type failQuarantineOnce struct {
	actual platform.Runner
	failed bool
}

func (r *failQuarantineOnce) Run(
	ctx context.Context,
	binary string,
	args []string,
	input []byte,
) ([]byte, error) {
	if !r.failed && binary == "/usr/sbin/nft" && len(args) == 2 && args[0] == "--file" &&
		bytes.HasPrefix(input, []byte("add table inet openrhp_guard {")) {
		r.failed = true
		return nil, errors.New("injected interruption after quarantine routes and persistent guard")
	}
	return r.actual.Run(ctx, binary, args, input)
}

func TestLinuxBootGuardCrashRecovery(t *testing.T) {
	for _, scenario := range []string{"partial-quarantine", "previous-closed-candidate-direct", "foreign-safety-table"} {
		t.Run(scenario, func(t *testing.T) {
			prepareLab(t)
			ctx := context.Background()
			b := labBackend()
			m := testManager(t, b, &testWatchdog{})
			d := testDesired()
			d.Fallback = "direct"
			if scenario == "previous-closed-candidate-direct" {
				d.Fallback = "closed"
			}
			tx, err := m.Prepare(ctx, d)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = m.Apply(ctx, tx.ID, 30*time.Second); err != nil {
				t.Fatal(err)
			}
			if _, err = m.Confirm(tx.ID); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "partial-quarantine":
				fault := &failQuarantineOnce{actual: b.Runner}
				b.Runner = fault
				if err = m.BootGuard(ctx); err == nil || !fault.failed {
					t.Fatalf("fault not reached: %v", err)
				}
				s, err := m.Status()
				if err != nil || !s.Guarded {
					t.Fatalf("quarantine intent was not durable before mutation: %+v %v", s, err)
				}
				b.Runner = labRunner{}
				restarted, err := NewManager(m.dir, b, &testWatchdog{})
				if err != nil {
					t.Fatal(err)
				}
				if err = restarted.BootGuard(ctx); err != nil {
					t.Fatalf("partial quarantine replay: %v", err)
				}
			case "previous-closed-candidate-direct":
				d.Fallback = "direct"
				d.Paths = d.Paths[1:]
				d.Selected = "b"
				tx, err = m.Prepare(ctx, d)
				if err != nil {
					t.Fatal(err)
				}
				// Reproduce power loss after writing applying, before candidate mutation;
				// no watchdog process survives a power cycle to repair missing ownership.
				if err = m.locked(func(s *State) error {
					s.Transaction.State = "applying"
					s.Transaction.Deadline = time.Now().Add(time.Minute)
					return m.save(s)
				}); err != nil {
					t.Fatal(err)
				}
				if err = m.BootGuard(ctx); err != nil {
					t.Fatalf("previous guards and removed old marks rejected at boot: %v", err)
				}
			case "foreign-safety-table":
				labCommand(
					t,
					"/sbin/ip",
					"-4",
					"route",
					"add",
					"blackhole",
					"default",
					"table",
					"20999",
				)
				if err = m.BootGuard(
					ctx,
				); err == nil ||
					!strings.Contains(err.Error(), "ownership_conflict") {
					t.Fatalf("foreign safety table accepted: %v", err)
				}
				s, err := m.Status()
				if err != nil || s.Guarded {
					t.Fatalf("foreign table was blessed by durable intent: %+v %v", s, err)
				}
				return
			}
			if out, err := exec.Command("/sbin/ip", "-4", "route", "get", "8.8.4.4", "from", "10.44.0.2", "iif", "home0").
				CombinedOutput(); err == nil {
				t.Fatalf("replayed boot guard released ordinary WAN traffic: %s", out)
			}
		})
	}
}
