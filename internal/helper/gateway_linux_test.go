//go:build linux

package helper

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/coverage"
)

// This subprocess fixture verifies detached process and journal behavior only.
// Its backend changes a private marker file, never UCI, radio or network state.
type gatewayFileBackend struct{ dir string }

func (b gatewayFileBackend) Inspect(context.Context) (coverage.Setup, error) {
	return coverage.Setup{}, nil
}

func (b gatewayFileBackend) Check(context.Context, coverage.Plan) (coverage.WiFi, error) {
	return coverage.WiFi{SSID: "fixture", Passphrase: "fixture-passphrase", Channel: 6}, nil
}

func (b gatewayFileBackend) Snapshot(context.Context, coverage.Plan) (coverage.Snapshot, error) {
	return coverage.Snapshot{"wireless": []byte(`{"ap_section":"existing_ap"}`)}, nil
}

func (b gatewayFileBackend) Apply(context.Context, coverage.Plan) error {
	return os.WriteFile(filepath.Join(b.dir, "backend-marker"), []byte("after"), 0o600)
}

func (b gatewayFileBackend) Restore(_ context.Context, s coverage.Snapshot) error {
	return os.WriteFile(filepath.Join(b.dir, "backend-marker"), s["wireless"], 0o600)
}

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "maintenance-worker" {
		if err := maintenanceWorkerFixture(os.Args[2:]); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if len(os.Args) > 1 && os.Args[1] == "gateway-watchdog" {
		if err := gatewayWatchdogFixture(os.Args[2:]); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func gatewayWatchdogFixture(args []string) error {
	if _, err := os.Stat("/.dockerenv"); err != nil || os.Geteuid() != 0 {
		return fmt.Errorf("fixture requires container root")
	}
	flags := flag.NewFlagSet("gateway-watchdog", flag.ContinueOnError)
	dir := flags.String("state-dir", "", "private fixture journal")
	id := flags.String("transaction", "", "transaction")
	fd := flags.Int("ready-fd", -1, "ready")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !validTransactionID(*id) || *fd != 3 ||
		!strings.HasPrefix(*dir, "/tmp/TestLinuxGatewayWatchdog") {
		return fmt.Errorf("invalid fixture arguments")
	}
	manager, err := coverage.NewManager(*dir, gatewayFileBackend{*dir}, nil)
	if err != nil {
		return err
	}
	defer func() { _ = manager.Close() }()
	if err = os.WriteFile(
		filepath.Join(*dir, "watchdog.pid"),
		[]byte(strconv.Itoa(os.Getpid())),
		0o600,
	); err != nil {
		return err
	}
	ready := os.NewFile(uintptr(*fd), "ready")
	if _, err = ready.Write([]byte("ready\n")); err != nil {
		_ = ready.Close()
		return err
	}
	_ = ready.Close()
	for {
		done, err := manager.Recover(context.Background())
		if done && err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestLinuxGatewayApplyCrashChild(t *testing.T) {
	if os.Getenv("OPENRHP_GATEWAY_CRASH_CHILD") != "1" {
		t.Skip("subprocess only")
	}
	requireNetLab(t)
	dir := os.Getenv("OPENRHP_GATEWAY_CRASH_DIR")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	manager, err := coverage.NewManager(
		dir,
		gatewayFileBackend{dir},
		GatewayWatchdog{Binary: executable, StateDir: dir},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	plan := coverage.Plan{
		Mode:                   "wds",
		APSection:              "existing_ap",
		Network:                "family",
		PeerFingerprint:        strings.Repeat("a", 64),
		AdoptExistingAP:        true,
		PreserveManagementPath: true,
	}
	transaction, err := manager.Prepare(context.Background(), "fixture-operation-key", plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.Apply(context.Background(), transaction.ID, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(
		filepath.Join(dir, "applied.signal"),
		[]byte("ready"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestLinuxGatewayWatchdogAfterManagerSIGKILL(t *testing.T) {
	requireNetLab(t)
	dir := filepath.Join(t.TempDir(), "state")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestLinuxGatewayApplyCrashChild$", "-test.v")
	child.Env = append(
		os.Environ(),
		"OPENRHP_GATEWAY_CRASH_CHILD=1",
		"OPENRHP_GATEWAY_CRASH_DIR="+dir,
	)
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err = os.Stat(filepath.Join(dir, "applied.signal")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("gateway apply fixture did not become ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	before, err := os.ReadFile(filepath.Join(dir, "backend-marker"))
	if err != nil || string(before) != "after" {
		t.Fatal(string(before), err)
	}
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	pidBytes, err := os.ReadFile(filepath.Join(dir, "watchdog.pid"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(pidBytes))
	if err != nil || pid == child.Process.Pid {
		t.Fatal("watchdog was not independent")
	}
	deadline = time.Now().Add(35 * time.Second)
	for {
		restored, err := os.ReadFile(filepath.Join(dir, "backend-marker"))
		if err == nil && string(restored) == `{"ap_section":"existing_ap"}` {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("detached gateway watchdog did not restore after manager SIGKILL")
		}
		time.Sleep(50 * time.Millisecond)
	}
	manager, err := coverage.NewManager(dir, gatewayFileBackend{dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	if err = manager.CanRemove(); err != nil {
		t.Fatal(err)
	}
}
