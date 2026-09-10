package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/coverage"
	"github.com/tibeahx/RouteHarbor/internal/helper"
	"github.com/tibeahx/RouteHarbor/internal/maintenance"
	"github.com/tibeahx/RouteHarbor/internal/platform"
)

func maintenanceManager(
	dir, routingDir, binary string,
	routing *helper.Manager,
	gateway *coverage.Manager,
) (*maintenance.Manager, error) {
	backend := &maintenance.OpkgBackend{
		StateDir:     dir,
		Gate:         routing,
		CheckPending: gateway.CanRemove,
	}
	return maintenance.NewManager(
		dir,
		backend,
		helper.MaintenanceWorker{Binary: binary, StateDir: dir, RoutingDir: routingDir},
	)
}

func runMaintenanceCommand(action string, args []string) error {
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	dir := flags.String("state-dir", "/etc/routeharbor-maintenance", "root-owned maintenance state")
	routingDir := flags.String(
		"routing-state-dir",
		"/etc/routeharbor-helper",
		"root-owned routing journal",
	)
	source := flags.String("source", "", "private verified release bundle directory")
	operation := flags.String("operation", "", "durable maintenance operation ID")
	mode := flags.String("mode", "", "explicit local recovery: retry or rollback")
	readyFD := flags.Int("ready-fd", -1, "internal detached-worker readiness descriptor")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if action != "maintenance-recover" && *mode != "" {
		return errors.New("maintenance_unexpected_recovery_mode")
	}
	if flags.NArg() != 0 {
		return errors.New("maintenance_unexpected_argument")
	}
	if action == "maintenance-stage" {
		if *source == "" || *operation != "" || *readyFD != -1 {
			return errors.New("maintenance_stage_source_required")
		}
		report := platform.Detect(context.Background())
		if report.Version == "" || report.PackageArch == "" {
			return errors.New("maintenance_openwrt_required")
		}
		summary, err := maintenance.Stage(*dir, *source, report.PackageArch)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(summary)
	}
	if *source != "" {
		return errors.New("maintenance_unexpected_source")
	}
	if action != "maintenance-worker" && *readyFD != -1 {
		return errors.New("maintenance_unexpected_readiness_descriptor")
	}
	if action == "maintenance-resume" && *operation != "" {
		return errors.New("maintenance_resume_uses_durable_active_job")
	}
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		return err
	}
	routing, err := helper.NewManager(*routingDir, helper.NewNetworkBackend(), nil)
	if err != nil {
		return err
	}
	gateway, err := coverage.NewManager(
		filepath.Join(*routingDir, "gateway"),
		coverage.NewUCIBackend(nil),
		nil,
	)
	if err != nil {
		return err
	}
	defer func() { _ = gateway.Close() }()
	manager, err := maintenanceManager(*dir, *routingDir, binary, routing, gateway)
	if err != nil {
		return err
	}
	defer func() { _ = manager.Close() }()
	switch action {
	case "maintenance-status":
		status, err := manager.Status(context.Background(), *operation)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(status)
	case "maintenance-recover":
		status, err := manager.Recover(context.Background(), *operation, *mode)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(status)
	case "maintenance-resume":
		if err = manager.Resume(context.Background()); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]bool{"resume_requested": true})
	case "maintenance-worker":
		if *readyFD < 3 {
			return errors.New("maintenance_worker_readiness_required")
		}
		if _, err = manager.Status(context.Background(), *operation); err != nil {
			return err
		}
		ready := os.NewFile(uintptr(*readyFD), "maintenance-ready")
		if ready == nil {
			return errors.New("maintenance_invalid_readiness_descriptor")
		}
		_, err = ready.Write([]byte("ready\n"))
		closeErr := ready.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		bounded, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		return manager.Run(bounded, *operation)
	default:
		return errors.New("maintenance_action_invalid")
	}
}
