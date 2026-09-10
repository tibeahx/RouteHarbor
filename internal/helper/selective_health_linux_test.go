//go:build linux

package helper

import (
	"context"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/dispatch"
	"github.com/tibeahx/OpenRHP/internal/routing"
)

func dispatcherLabEngineHangHealth(
	t *testing.T,
	spec dispatch.Spec,
	ref routing.SnapshotRef,
	engine, front string,
) {
	t.Helper()
	desired := securityDispatcherIntent(spec, ref)
	readyDeadline := time.Now().Add(5 * time.Second)
	for err := SelectiveHealth(context.Background(), desired); err != nil; err = SelectiveHealth(context.Background(), desired) {
		if time.Now().After(readyDeadline) {
			t.Fatal("native dispatcher unhealthy before suspension", err)
		}
		time.Sleep(30 * time.Millisecond)
	}
	pid, err := strconv.Atoi(engine)
	if err != nil {
		t.Fatal(err)
	}
	frontPID, err := strconv.Atoi(front)
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Kill(pid, syscall.SIGCONT) }()
	listener, err := net.DialTimeout(
		"tcp4",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(spec.Allocation.Path.TransparentPort)),
		time.Second,
	)
	if err != nil {
		t.Fatal("fixture failed to retain native kernel listener", err)
	}
	_ = listener.Close()
	if err = syscall.Kill(frontPID, 0); err != nil {
		t.Fatal("DNS frontend died with suspended engine", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	err = SelectiveHealth(ctx, desired)
	cancel()
	if err == nil {
		t.Fatal("suspended engine DNS was reported healthy by live frontend")
	}
	if err = syscall.Kill(pid, syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(6 * time.Second)
	for SelectiveHealth(context.Background(), desired) != nil {
		if time.Now().After(deadline) {
			t.Fatal("native health did not recover after SIGCONT")
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Log(
		"native engine SIGSTOP detected despite live kernel TCP listener and DNS frontend; SIGCONT health restored",
	)
}
