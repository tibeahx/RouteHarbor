package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/tibeahx/OpenRHP/internal/helper"
	"github.com/tibeahx/OpenRHP/internal/node"
	"github.com/tibeahx/OpenRHP/internal/wireless"
)

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New(
			"usage: openrhp-node bootstrap|serve|helper|watchdog|verify-wireless [options]",
		)
	}
	if args[0] == "verify-wireless" {
		return wireless.NewVerifier("/etc/openrhp-node-helper", "node", "/etc/openrhp-node").
			RecordCommand(context.Background(), args[1:], os.Stdout)
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	state := flags.String("state-dir", "/etc/openrhp-node", "private persistent state directory")
	listen := flags.String("listen", "127.0.0.1:9844", "explicit LAN or loopback HTTPS listener")
	socket := flags.String(
		"helper-socket",
		"/var/run/openrhp-node-helper.sock",
		"root helper Unix socket",
	)
	uid := flags.Uint("uid", 0, "unprivileged node agent UID permitted by root helper")
	codeFile := flags.String("enrollment-file", "", "new private file receiving the one-use code")
	transaction := flags.String("transaction", "", "watchdog transaction ID")
	readyFD := flags.Int("ready-fd", -1, "watchdog readiness descriptor")
	if e := flags.Parse(args[1:]); e != nil {
		return e
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	dir, e := filepath.Abs(*state)
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	switch args[0] {
	case "bootstrap":
		if *codeFile == "" || !filepath.IsAbs(*codeFile) {
			return errors.New("--enrollment-file must name a new absolute private file")
		}
		identity, e := node.LoadIdentity(dir)
		if e != nil {
			return e
		}
		pairing, e := node.NewPairing(dir)
		if e != nil {
			return e
		}
		defer func() { _ = pairing.Close() }()
		// Reserve the private output before replacing the bootstrap challenge.
		f, e := os.OpenFile(*codeFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if e != nil {
			return errors.New("cannot create enrollment output safely")
		}
		written := false
		defer func() {
			_ = f.Close()
			if !written {
				_ = os.Remove(*codeFile)
			}
		}()
		code, e := pairing.Bootstrap(10 * time.Minute)
		if e != nil {
			return e
		}
		if _, e = f.WriteString(code + "\n"); e != nil {
			return e
		}
		if e = f.Sync(); e != nil {
			return e
		}
		if e = f.Close(); e != nil {
			return e
		}
		written = true
		return json.NewEncoder(os.Stdout).
			Encode(map[string]any{"id": identity.ID, "fingerprint": identity.Fingerprint, "enrollment_file": *codeFile, "expires_in_seconds": 600, "note": "Transfer the code through existing trusted administrator access. Verify this fingerprint before pairing."})
	case "serve":
		if os.Geteuid() == 0 {
			return errors.New(
				"run the node TLS agent as an unprivileged service user; use the separate root helper for UCI",
			)
		}
		host, _, e := net.SplitHostPort(*listen)
		if e != nil {
			return errors.New("invalid listener address")
		}
		address, e := netip.ParseAddr(host)
		if e != nil || address.IsUnspecified() || (!address.IsPrivate() && !address.IsLoopback()) {
			return errors.New("node management must bind an explicit LAN or loopback IP")
		}
		identity, e := node.LoadIdentity(dir)
		if e != nil {
			return e
		}
		pairing, e := node.NewPairing(dir)
		if e != nil {
			return e
		}
		defer func() { _ = pairing.Close() }()
		agent := &node.Agent{
			Identity: identity,
			Pairing:  pairing,
			Capabilities: func(ctx context.Context) node.Capabilities {
				caps, err := (node.HelperClient{Socket: *socket}).Capabilities(ctx)
				if err != nil {
					return node.Capabilities{
						Reason: "The local privileged helper could not read platform capabilities.",
					}
				}
				return caps
			},
			Operator: node.HelperClient{Socket: *socket},
		}
		server := &http.Server{
			Addr:              *listen,
			Handler:           agent,
			TLSConfig:         agent.TLSConfig(),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      50 * time.Second,
			IdleTimeout:       15 * time.Second,
			MaxHeaderBytes:    8 << 10,
		}
		go func() {
			<-ctx.Done()
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if server.Shutdown(shutdown) != nil {
				_ = server.Close()
			}
		}()
		if e = server.ListenAndServeTLS("", ""); errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	case "helper", "watchdog":
		if os.Geteuid() != 0 {
			return errors.New("node privileged helper and watchdog require root")
		}
		binary, e := os.Executable()
		if e != nil {
			return e
		}
		binary, e = filepath.EvalSymlinks(binary)
		if e != nil {
			return e
		}
		var watchdog node.Watchdog = helper.ProcessWatchdog{Binary: binary, StateDir: dir}
		backend := node.NewUCIBackend()
		verifier := wireless.NewVerifier(dir, "node", "/etc/openrhp-node")
		backend.Capabilities = func(ctx context.Context) node.Capabilities {
			return node.VerifiedCapabilities(ctx, verifier, "/etc/openrhp-node")
		}
		manager, e := node.NewManager(dir, backend, watchdog)
		if e != nil {
			return e
		}
		defer func() { _ = manager.Close() }()
		if args[0] == "watchdog" {
			if len(*transaction) != 32 {
				return errors.New("watchdog transaction identity required")
			}
			if *readyFD < 3 {
				return errors.New("watchdog readiness descriptor required")
			}
			ready := os.NewFile(uintptr(*readyFD), "watchdog-ready")
			if ready == nil {
				return errors.New("invalid watchdog readiness descriptor")
			}
			if _, e = ready.WriteString("ready\n"); e != nil {
				_ = ready.Close()
				return e
			}
			_ = ready.Close()
			for {
				call, cancel := context.WithTimeout(ctx, 40*time.Second)
				done, e := manager.Recover(call)
				cancel()
				if done && e == nil {
					return nil
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(time.Second):
				}
			}
		}
		if *uid == 0 || uint64(*uid) > uint64(^uint32(0)) {
			return errors.New("--uid must identify the separate unprivileged node service user")
		}
		// A helper restart resumes durable rollback checks independently of TLS.
		go func() {
			for {
				call, cancel := context.WithTimeout(ctx, 40*time.Second)
				// Pending recovery stays durable and is retried on the next tick.
				_, _ = manager.Recover(call)
				cancel()
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
				}
			}
		}()
		return node.ServeHelper(ctx, *socket, uint32(*uid), node.LocalOperator{Manager: manager})
	case "version":
		return json.NewEncoder(os.Stdout).
			Encode(map[string]string{"project": "OpenRHP", "role": "node", "protocol": "1", "uid": strconv.Itoa(os.Geteuid())})
	default:
		return errors.New("unknown node command")
	}
}
