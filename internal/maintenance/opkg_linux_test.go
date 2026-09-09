//go:build linux

package maintenance

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fixtureGate struct {
	active   string
	released int
}

func (g *fixtureGate) AcquireMaintenance(_ context.Context, id string, check func() error) error {
	g.active = id
	if check != nil {
		return check()
	}
	return nil
}

func (g *fixtureGate) ReleaseMaintenance(
	string,
) error {
	g.active = ""
	g.released++
	return nil
}
func (*fixtureGate) DecommissionMaintenance(context.Context, string, string) error { return nil }

func opkgFixture(t *testing.T, name, version, depends, postinst string) []byte {
	t.Helper()
	control := "Package: " + name + "\nVersion: " + version + "\nArchitecture: x86_64\nDescription: isolated offline package fixture\n"
	if depends != "" {
		control += "Depends: " + depends + "\n"
	}
	controls := []member{{"control", []byte(control), 0, ""}}
	if postinst != "" {
		controls = append(
			controls,
			member{"postinst", []byte("#!/bin/sh\n" + postinst + "\n"), 0, ""},
		)
	}
	filename := "usr/bin/" + name
	if name == "openrhp-guard" {
		filename = "usr/share/openrhp-guard-fixture"
	}
	return archive(
		t,
		[]member{
			{"debian-binary", []byte("2.0\n"), 0, ""},
			{"control.tar.gz", archive(t, controls), 0, ""},
			{
				"data.tar.gz",
				archive(
					t,
					[]member{
						{
							filename,
							[]byte("#!/bin/sh\nprintf 'fixture " + version + "\\n'\n"),
							0,
							"",
						},
					},
				),
				0,
				"",
			},
		},
	)
}

func TestOpenWrtOpkgOffline(t *testing.T) {
	if os.Getenv("OPENRHP_OPKG_LAB") != "1" {
		t.Skip("requires dedicated disposable OpenWrt rootfs lab")
	}
	if os.Geteuid() != 0 {
		t.Fatal("lab requires isolated root")
	}
	if err := os.MkdirAll("/var/lock", 0o755); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	f := newFixture(t)
	gate := &fixtureGate{}
	backend := &OpkgBackend{StateDir: f.state, Gate: gate}
	guard := filepath.Join(t.TempDir(), "guard.ipk")
	if err := os.WriteFile(
		guard,
		opkgFixture(t, "openrhp-guard", "0.1.0-r1", "", ""),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/opkg", "install", guard)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("fixture guard: %v %s", err, output)
	}
	baseline := opkgFixture(
		t,
		"openrhp",
		"0.1.0-r1",
		"openrhp-guard",
		"echo baseline >/tmp/maintenance-postinst-baseline",
	)
	candidate := opkgFixture(
		t,
		"openrhp",
		"0.1.1-r1",
		"openrhp-guard",
		"echo candidate >/tmp/maintenance-postinst-candidate",
	)
	old, err := f.stage(t, "0.1.0", baseline)
	if err != nil {
		t.Fatal(err)
	}
	next, err := f.stage(t, "0.1.1", candidate)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(f.state, backend, &fakeWorker{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	for index, bundle := range []BundleSummary{old, next} {
		action := "install"
		if index > 0 {
			action = "upgrade"
		}
		plan, err := manager.Plan(
			ctx,
			Request{Action: action, BundleID: bundle.ID, Components: []string{"openrhp"}},
		)
		if err != nil {
			t.Fatal("plan", err)
		}
		if index > 0 {
			if _, err := os.Stat("/tmp/maintenance-postinst-candidate"); !os.IsNotExist(err) {
				t.Fatal("--noaction executed postinst", err)
			}
		}
		id := strings.Repeat(string(rune('1'+index)), 32)
		if _, err := manager.Start(ctx, id, plan.Request); err != nil {
			t.Fatal("start", err)
		}
		if err := manager.Run(ctx, id); err != nil {
			t.Fatal("run", err)
		}
		status, err := manager.Status(ctx, id)
		if err != nil || status.State != "completed" {
			t.Fatal(status, err)
		}
	}
	if _, err := os.Stat("/tmp/maintenance-postinst-candidate"); err != nil {
		t.Fatal("actual postinst missing", err)
	}
	// Real SDK wrappers depend on the controller. Keep one installed through
	// interrupted upgrades and explicit recovery, then remove both together.
	wrapper, err := f.stage(
		t,
		"0.1.0",
		opkgFixture(t, "openrhp-conntrack", "0.1.0-r1", "openrhp", ""),
	)
	if err != nil {
		t.Fatal(err)
	}
	wrapperPlan, err := manager.Plan(
		ctx,
		Request{Action: "install", BundleID: wrapper.ID, Components: []string{"openrhp-conntrack"}},
	)
	if err != nil {
		t.Fatal("dependent wrapper plan", err)
	}
	wrapperID := strings.Repeat("6", 32)
	if _, err = manager.Start(ctx, wrapperID, wrapperPlan.Request); err != nil {
		t.Fatal(err)
	}
	if err = manager.Run(ctx, wrapperID); err != nil {
		t.Fatal(err)
	}
	// The system feed exists, but the production environment must not load it.
	if err := os.WriteFile(
		"/etc/opkg/openrhp-poison.conf",
		[]byte("src poison file:///tmp/forbidden-feed\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	args, err := backend.arguments(Plan{Request: Request{Action: "remove"}}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	inspect := exec.Command("/bin/opkg", args[0], args[1], "-V4", "print-architecture")
	inspect.Env = backend.environment()
	output, err := inspect.CombinedOutput()
	if err != nil {
		t.Fatal(err, string(output))
	}
	if strings.Contains(string(output), "/etc/opkg/") ||
		strings.Contains(string(output), "poison") {
		t.Fatal("system feeds loaded", string(output))
	}
	// Kill a real opkg process while its signed postinst is running. The next
	// worker must retain an interrupted job, then require explicit root recovery.
	broken := opkgFixture(
		t,
		"openrhp",
		"0.1.2-r1",
		"openrhp-guard",
		"if [ ! -e /tmp/maintenance-kill-once ]; then touch /tmp/maintenance-kill-once; echo $PPID >/tmp/maintenance-opkg.pid; sleep 60; fi",
	)
	bad, err := f.stage(t, "0.1.2", broken)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := manager.Plan(
		ctx,
		Request{Action: "upgrade", BundleID: bad.ID, Components: []string{"openrhp"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("3", 32)
	if _, err = manager.Start(ctx, id, plan.Request); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- manager.Run(ctx, id) }()
	deadline := time.Now().Add(10 * time.Second)
	pid := 0
	for time.Now().Before(deadline) {
		raw, readErr := os.ReadFile("/tmp/maintenance-opkg.pid")
		if readErr == nil {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(raw)))
			if pid > 1 {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if pid <= 1 {
		t.Fatal("postinst did not reach kill point")
	}
	if err = syscall.Kill(-pid, syscall.SIGKILL); err != nil {
		t.Fatal("kill opkg process group", pid, err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	status, err := manager.Status(ctx, id)
	if err != nil || status.State != "interrupted" || gate.active != id {
		t.Fatal(status, err)
	}
	if _, err = manager.Recover(ctx, id, "rollback"); err != nil {
		t.Fatal("request rollback", err)
	}
	if err = manager.Run(ctx, id); err != nil {
		t.Fatal("rollback", err)
	}
	status, err = manager.Status(ctx, id)
	if err != nil || status.State != "failed" || status.Phase != "recovery_rolled_back" {
		t.Fatal(status, err)
	}
	inventory, err := backend.Inventory(ctx)
	if err != nil || inventory.Packages["openrhp"] != "0.1.1-r1" {
		t.Fatal("previous signed version not restored", inventory, err)
	}
	// Same-version repair must restore bytes, even if opkg already says installed.
	plan, err = manager.Plan(
		ctx,
		Request{Action: "upgrade", BundleID: next.ID, Components: []string{"openrhp"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	id = strings.Repeat("4", 32)
	if _, err = manager.Start(ctx, id, plan.Request); err != nil {
		t.Fatal(err)
	}
	if err = manager.update(id, "running", "package_manager", ""); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile("/usr/bin/openrhp", []byte("partial"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err = manager.Run(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err = manager.Recover(ctx, id, "retry"); err != nil {
		t.Fatal("request same-version repair", err)
	}
	if err = manager.Run(ctx, id); err != nil {
		t.Fatal("repair", err)
	}
	status, err = manager.Status(ctx, id)
	if err != nil || status.State != "completed" {
		t.Fatal(status, err)
	}
	removal, err := manager.Plan(
		ctx,
		Request{
			Action:        "remove",
			Components:    []string{"openrhp"},
			RemovalPolicy: "preserve-closed",
		},
	)
	if err != nil {
		t.Fatal("controller and dependent wrapper removal preflight", err)
	}
	inventory, err = backend.Inventory(ctx)
	if err != nil || inventory.Packages["openrhp"] != "0.1.1-r1" ||
		inventory.Packages["openrhp-conntrack"] != "0.1.0-r1" {
		t.Fatal(
			"removal preview changed installed packages or recovery lost the wrapper",
			inventory,
			err,
		)
	}
	id = strings.Repeat("5", 32)
	if _, err = manager.Start(ctx, id, removal.Request); err != nil {
		t.Fatal(err)
	}
	if err = manager.Run(ctx, id); err != nil {
		t.Fatal("remove controller and wrapper", err)
	}
	status, err = manager.Status(ctx, id)
	if err != nil || status.State != "completed" {
		t.Fatal(status, err)
	}
	inventory, err = backend.Inventory(ctx)
	if err != nil || inventory.Packages["openrhp"] != "" ||
		inventory.Packages["openrhp-conntrack"] != "" ||
		inventory.Packages["openrhp-guard"] == "" {
		t.Fatal("removal did not retain only the guard", inventory, err)
	}
	t.Log(
		"real opkg signed install/upgrade; noaction scripts; system-feed isolation; SIGKILL interruption; explicit offline rollback and same-version payload repair with a dependent wrapper; controller/wrapper removal retaining guard PASS",
	)
}

func (g *fixtureGate) ReacquireMaintenance(
	ctx context.Context,
	id string,
	check func() error,
) error {
	return g.AcquireMaintenance(ctx, id, check)
}
