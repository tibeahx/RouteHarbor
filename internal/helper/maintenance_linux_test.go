//go:build linux

package helper

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/maintenance"
)

// This backend proves detached-process/journal behavior. It never runs opkg or
// mutates network state; actual opkg is covered by the separate OpenWrt lab.
type maintenanceFileBackend struct{ dir string }

func (maintenanceFileBackend) Inventory(context.Context) (maintenance.Inventory, error) {
	return maintenance.Inventory{
		Architecture:   "x86_64",
		Packages:       map[string]string{"routeharbor-guard": "0.1.0-r1"},
		AvailableBytes: 1 << 30,
	}, nil
}

func (maintenanceFileBackend) Compare(context.Context, string, string, string) (bool, error) {
	return true, nil
}

func (maintenanceFileBackend) Check(
	context.Context,
	maintenance.Plan,
	[]string,
) error {
	return nil
}

func (b maintenanceFileBackend) Acquire(context.Context, string) error {
	return os.WriteFile(filepath.Join(b.dir, "guard-held"), []byte("held"), 0o600)
}

func (b maintenanceFileBackend) Release(string) error {
	return os.WriteFile(filepath.Join(b.dir, "guard-released"), []byte("released"), 0o600)
}
func (maintenanceFileBackend) Decommission(context.Context, string, string) error { return nil }
func (b maintenanceFileBackend) Execute(ctx context.Context, _ maintenance.Plan, _ []string) error {
	count, err := os.OpenFile(
		filepath.Join(b.dir, "execution-count"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return err
	}
	_, err = count.Write([]byte("execution\n"))
	closeErr := count.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}

	if err := os.WriteFile(
		filepath.Join(b.dir, "execution-started"),
		[]byte("started"),
		0o600,
	); err != nil {
		return err
	}
	for {
		if _, err := os.Stat(filepath.Join(b.dir, "continue")); err == nil {
			return os.WriteFile(
				filepath.Join(b.dir, "execution-finished"),
				[]byte("finished"),
				0o600,
			)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (b maintenanceFileBackend) Verify(
	context.Context,
	maintenance.Plan,
	[]maintenance.PackagePayload,
) error {
	_, err := os.Stat(filepath.Join(b.dir, "execution-finished"))
	return err
}

func maintenanceWorkerFixture(args []string) error {
	if _, err := os.Stat("/.dockerenv"); err != nil || os.Geteuid() != 0 {
		return errors.New("fixture requires isolated container root")
	}
	flags := flag.NewFlagSet("maintenance-worker", flag.ContinueOnError)
	dir := flags.String("state-dir", "", "private fixture journal")
	routing := flags.String("routing-state-dir", "", "private fixture routing path")
	id := flags.String("operation", "", "job")
	fd := flags.Int("ready-fd", -1, "ready")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !strings.HasPrefix(*dir, "/tmp/TestLinuxMaintenance") || *routing != *dir ||
		!validTransactionID(*id) ||
		*fd != 3 {
		return errors.New("invalid maintenance fixture arguments")
	}
	manager, err := maintenance.NewManager(*dir, maintenanceFileBackend{*dir}, nil)
	if err != nil {
		return err
	}
	defer func() { _ = manager.Close() }()
	if _, err = manager.Status(context.Background(), *id); err != nil {
		return err
	}
	ready := os.NewFile(uintptr(*fd), "ready")
	if _, err = ready.Write([]byte("ready\n")); err != nil {
		_ = ready.Close()
		return err
	}
	if err = ready.Close(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return manager.Run(ctx, *id)
}

func TestLinuxMaintenanceParentChild(t *testing.T) {
	if os.Getenv("ROUTEHARBOR_MAINTENANCE_CHILD") != "1" {
		t.Skip("subprocess fixture only")
	}
	dir := os.Getenv("ROUTEHARBOR_MAINTENANCE_DIR")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	manager, err := maintenance.NewManager(
		dir,
		maintenanceFileBackend{dir},
		MaintenanceWorker{Binary: binary, StateDir: dir, RoutingDir: dir},
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := manager.Plan(
		context.Background(),
		maintenance.Request{
			Action:        "remove",
			Components:    []string{"routeharbor"},
			RemovalPolicy: "preserve-closed",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.Start(
		context.Background(),
		strings.Repeat("a", 32),
		plan.Request,
	); err != nil {
		t.Fatal(err)
	}
	// A lost acknowledgement may arm a second worker for the same durable job.
	if _, err = manager.Start(
		context.Background(),
		strings.Repeat("a", 32),
		plan.Request,
	); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "accepted"), []byte("accepted"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Second)
}

func TestLinuxMaintenanceWorkerSurvivesControllerKill(t *testing.T) {
	if os.Getenv("ROUTEHARBOR_MAINTENANCE_LAB") != "1" {
		t.Skip("requires dedicated isolated root worker lab")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil || os.Geteuid() != 0 {
		t.Fatal("requires isolated container root")
	}
	dir := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(
		executable,
		"-test.run=^TestLinuxMaintenanceParentChild$",
		"-test.timeout=20s",
	)
	child.Env = append(
		os.Environ(),
		"ROUTEHARBOR_MAINTENANCE_CHILD=1",
		"ROUTEHARBOR_MAINTENANCE_DIR="+dir,
	)
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		_, accepted := os.Stat(filepath.Join(dir, "accepted"))
		_, started := os.Stat(filepath.Join(dir, "execution-started"))
		if accepted == nil && started == nil {
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("detached worker did not reach durable execution")
	}
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err = child.Wait(); err == nil {
		t.Fatal("parent was not killed")
	}
	if err = os.WriteFile(filepath.Join(dir, "continue"), []byte("continue"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := maintenance.NewManager(dir, maintenanceFileBackend{dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		operation, err := manager.Status(context.Background(), strings.Repeat("a", 32))
		if err == nil && operation.State == "completed" {
			if _, err = os.Stat(filepath.Join(dir, "guard-released")); err != nil {
				t.Fatal(err)
			}
			count, err := os.ReadFile(filepath.Join(dir, "execution-count"))
			if err != nil || string(count) != "execution\n" {
				t.Fatal("duplicate workers repeated execution", err)
			}
			t.Log(
				"detached workers survived parent SIGKILL; duplicate arms executed once; durable completion and release verified with marker backend",
			)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("detached worker did not complete after parent kill")
}
