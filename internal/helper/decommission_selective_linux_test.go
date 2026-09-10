//go:build linux

package helper

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
)

func TestLinuxSelectiveDecommissionPreservesClosedAcrossBoot(t *testing.T) {
	prepareLab(t)
	ctx := context.Background()
	backend := labBackend()
	manager, err := NewManager(filepath.Join(t.TempDir(), "state"), backend, &testWatchdog{})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := manager.Prepare(ctx, selectiveDesired())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.Apply(ctx, tx.ID, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err = manager.Confirm(tx.ID); err != nil {
		t.Fatal(err)
	}
	if err = manager.Decommission(ctx, "preserve-closed"); err != nil {
		t.Fatal(err)
	}
	assertClosed := func() {
		t.Helper()
		if output, err := exec.Command("/sbin/ip", "-4", "route", "get", "8.8.4.4", "from", "10.44.0.2", "iif", "home0").
			CombinedOutput(); err == nil {
			t.Fatalf("explicit selective preserve-closed leaked WAN: %s", output)
		}
	}
	assertClosed()
	restarted, err := NewManager(manager.dir, backend, &testWatchdog{})
	if err != nil {
		t.Fatal(err)
	}
	if watch, err := restarted.WatchSelectiveOnce(ctx); err != nil || watch {
		t.Fatal("watchdog ignored explicit hold", watch, err)
	}
	if err = restarted.SelectiveEmergencyFor(ctx, tx.ID); !errors.Is(err, ErrMaintenanceActive) {
		t.Fatal("watchdog reopened WAN", err)
	}
	labCommand(t, "/usr/sbin/nft", "flush", "ruleset")
	assertClosed()
	if err = restarted.BootGuard(ctx); err != nil {
		t.Fatal(err)
	}
	assertClosed()
	guard := labCommand(t, "/usr/sbin/nft", "list", "table", "inet", dataplane.GuardTable)
	if !strings.Contains(string(guard), "drop") {
		t.Fatal("boot did not restore closed guard")
	}
	state, err := restarted.Status()
	if err != nil || !state.MaintenanceHold || !state.Guarded {
		t.Fatal("boot lost explicit hold", state, err)
	}
	if err = restarted.Decommission(ctx, "restore-direct"); err != nil {
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
		t.Fatal("explicit direct restore did not restore WAN", string(direct))
	}
	state, err = restarted.Status()
	if err != nil || state.MaintenanceHold || state.Guarded || state.Committed != nil {
		t.Fatal("direct restore did not release ordinary hold", state, err)
	}
}
