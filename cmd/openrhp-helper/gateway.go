package main

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"time"

	"github.com/tibeahx/OpenRHP/internal/coverage"
	"github.com/tibeahx/OpenRHP/internal/helper"
	"github.com/tibeahx/OpenRHP/internal/wireless"
)

func gatewayManager(dir, binary string, verifier *wireless.Verifier) (*coverage.Manager, error) {
	backend := coverage.NewUCIBackend(nil)
	backend.Eligibility = func(ctx context.Context, plan coverage.Plan) error {
		radio, err := backend.RadioForPlan(ctx, plan)
		if err != nil {
			return err
		}
		return verifier.Check(ctx, radio, plan.Mode, plan.PeerFingerprint)
	}
	return coverage.NewManager(
		dir,
		backend,
		helper.GatewayWatchdog{Binary: binary, StateDir: dir},
	)
}

func runGatewayWatchdog(dir, id string, readyFD int) error {
	if len(id) != 32 {
		return errors.New("gateway watchdog requires a transaction identity")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return errors.New("gateway watchdog requires a transaction identity")
	}
	manager, err := coverage.NewManager(dir, coverage.NewUCIBackend(nil), nil)
	if err != nil {
		return err
	}
	defer func() { _ = manager.Close() }()
	// Readiness precedes journal locking: the applying parent still holds that lock.
	if readyFD >= 3 {
		ready := os.NewFile(uintptr(readyFD), "gateway-watchdog-ready")
		if ready == nil {
			return errors.New("invalid gateway readiness descriptor")
		}
		_, err = ready.Write([]byte("ready\n"))
		_ = ready.Close()
		if err != nil {
			return err
		}
	}
	for {
		state, statusErr := manager.Status()
		if statusErr == nil {
			transaction, _ := state["transaction"].(*coverage.Transaction)
			if transaction == nil || transaction.ID != id {
				return nil
			}
		}
		done, err := manager.Recover(context.Background())
		if done && err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
}
