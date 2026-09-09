// openrhp-helper is an explicitly installed privileged service. The unprivileged
// UI cannot choose executable paths, commands, journal paths or socket users.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/tibeahx/OpenRHP/internal/helper"
	"github.com/tibeahx/OpenRHP/internal/platform"
	"github.com/tibeahx/OpenRHP/internal/wireless"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: openrhp-helper serve|watchdog|recover [options]")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New(
			"privileged helper requires Linux and root; network mutation is unavailable on this host",
		)
	}
	if strings.HasPrefix(os.Args[1], "maintenance-") {
		return runMaintenanceCommand(os.Args[1], os.Args[2:])
	}
	if os.Args[1] == "verify-wireless" {
		return wireless.NewVerifier("/etc/openrhp-helper", "gateway", "/etc/openrhp/nodes").
			RecordCommand(context.Background(), os.Args[2:], os.Stdout)
	}
	if os.Args[1] == "packet-worker" {
		workerFlags := flag.NewFlagSet("packet-worker", flag.ContinueOnError)
		slot := workerFlags.Int("slot", 0, "fixed packet engine allocation")
		if err := workerFlags.Parse(os.Args[2:]); err != nil {
			return err
		}
		if workerFlags.NArg() != 0 {
			return errors.New("unexpected packet worker argument")
		}
		return helper.RunPacketWorker(*slot)
	}
	if os.Args[1] == "engine-worker" {
		workerFlags := flag.NewFlagSet("engine-worker", flag.ContinueOnError)
		uid := workerFlags.Uint("uid", 0, "service UID")
		gid := workerFlags.Uint("gid", 0, "service GID")
		if err := workerFlags.Parse(os.Args[2:]); err != nil {
			return err
		}
		if workerFlags.NArg() != 0 || *uid > uint(^uint32(0)) || *gid > uint(^uint32(0)) {
			return errors.New("invalid engine identity")
		}
		return helper.RunEngineWorker(uint32(*uid), uint32(*gid))
	}
	fs := flag.NewFlagSet("openrhp-helper "+os.Args[1], flag.ContinueOnError)
	dir := fs.String("state-dir", "/etc/openrhp-helper", "private durable journal directory")
	maintenanceDir := fs.String(
		"maintenance-dir",
		"/etc/openrhp-maintenance",
		"root-owned package maintenance journal",
	)
	identityDir := fs.String(
		"identity-dir",
		"/etc/openrhp/nodes",
		"gateway paired-node identity directory",
	)
	socket := fs.String("socket", "/var/run/openrhp/helper.sock", "local helper socket")
	uid := fs.Uint("uid", 65534, "UID permitted to connect to the local helper")
	transaction := fs.String("transaction", "", "watchdog transaction identity")
	policy := fs.String("policy", "", "decommission policy: preserve-closed or restore-direct")
	readyFD := fs.Int("ready-fd", -1, "watchdog readiness descriptor")
	if err := fs.Parse(os.Args[2:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional argument")
	}
	if os.Args[1] == "gateway-watchdog" {
		return runGatewayWatchdog(*dir, *transaction, *readyFD)
	}
	backend := helper.NewNetworkBackend()
	verifier := wireless.NewVerifier(*dir, "gateway", *identityDir)
	backend.Detect = func(ctx context.Context) platform.Report { return helper.VerifiedPlatform(ctx, verifier) }
	packet := helper.NewPacketManager()
	backend.Packet = packet
	defer func() { _ = packet.Close() }()
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	var watchdog helper.Watchdog = helper.ProcessWatchdog{Binary: exe, StateDir: *dir}
	manager, err := helper.NewManager(*dir, backend, watchdog)
	if err != nil {
		return err
	}
	switch os.Args[1] {
	case "serve":
		if *uid == 0 || *uid > uint(^uint32(0)) {
			return errors.New("serve requires a dedicated non-root client UID")
		}
		if err = os.MkdirAll(filepath.Dir(*socket), 0o755); err != nil {
			return err
		}
		if err = manager.BootGuard(context.Background()); err != nil {
			return err
		}
		if err = manager.Resume(context.Background()); err != nil {
			return err
		}
		gateway, e := gatewayManager(filepath.Join(*dir, "gateway"), exe, verifier)
		if e != nil {
			return e
		}
		defer func() { _ = gateway.Close() }()
		if e = gateway.Resume(); e != nil {
			return e
		}
		packageManager, e := maintenanceManager(*maintenanceDir, *dir, exe, manager, gateway)
		if e != nil {
			return e
		}
		defer func() { _ = packageManager.Close() }()
		if e = packageManager.Resume(context.Background()); e != nil {
			return e
		}
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		return (&helper.Server{Maintenance: packageManager, Manager: manager, Gateway: gateway, AllowedUID: uint32(*uid), SocketPath: *socket, Packet: packet}).Serve(
			ctx,
		)
	case "quarantine":
		return manager.BootGuard(context.Background())
	case "can-remove":
		if err = manager.CanRemove(); err != nil {
			return err
		}
		gateway, e := gatewayManager(filepath.Join(*dir, "gateway"), exe, verifier)
		if e != nil {
			return e
		}
		defer func() { _ = gateway.Close() }()
		return gateway.CanRemove()
	case "decommission":
		return manager.Decommission(context.Background(), *policy)
	case "recover":
		_, err = manager.Recover(context.Background())
		return err
	case "watchdog":
		// Readiness must not acquire the journal lock held by the applying parent.
		// NewManager has checked the state directory; Recover takes the shared lock.
		if len(*transaction) != 32 {
			return errors.New("watchdog requires a transaction identity")
		}
		if *readyFD >= 3 {
			f := os.NewFile(uintptr(*readyFD), "watchdog-ready")
			if f == nil {
				return errors.New("invalid readiness descriptor")
			}
			_, err = f.Write([]byte("ready\n"))
			_ = f.Close()
			if err != nil {
				return err
			}
		}
		for {
			state, statusErr := manager.Status()
			if statusErr == nil &&
				(state.Transaction == nil || state.Transaction.ID != *transaction) {
				return nil
			}
			done, recoverErr := manager.Recover(context.Background())
			if done && recoverErr == nil {
				return nil
			}
			time.Sleep(time.Second)
		}
	default:
		return errors.New("unknown helper operation")
	}
}
