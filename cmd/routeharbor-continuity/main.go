package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/tibeahx/RouteHarbor/internal/continuityrun"
	"github.com/tibeahx/RouteHarbor/internal/node"
)

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("use identity --state DIR or the helper-managed worker")
	}
	if args[0] == "identity" {
		f := flag.NewFlagSet("identity", flag.ContinueOnError)
		state := f.String("state", "/etc/routeharbor/continuity", "private identity directory")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if f.NArg() != 0 {
			return errors.New("unexpected identity arguments")
		}
		id, e := node.LoadIdentity(*state)
		if e != nil {
			return errors.New("continuity identity unavailable")
		}
		fmt.Println(id.Fingerprint)
		return nil
	}
	if args[0] != "worker" || len(args) != 1 {
		return errors.New("unknown continuity operation")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	return continuityrun.RunWorker(ctx)
}

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
