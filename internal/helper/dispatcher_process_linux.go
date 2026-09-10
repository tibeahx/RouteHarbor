//go:build linux

package helper

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/dispatch"
	"github.com/tibeahx/OpenRHP/internal/routing"
)

type dispatcherWorkerConfig struct {
	Spec   dispatch.Spec `json:"spec"`
	Secret string        `json:"secret"`
}

func (s *Server) prepareDispatcherFiles(r *dispatcherRegistration, uid, gid uint32) error {
	snapshot, err := s.readDispatcherSnapshot(r.ref)
	if err != nil {
		return err
	}
	data, err := routing.CompileRuleSet(snapshot, nil)
	if err != nil {
		return errors.New("dispatcher_rules_invalid")
	}
	if err = os.Mkdir(dispatcherRuntimeRoot, 0o755); err != nil && !os.IsExist(err) {
		return errors.New("dispatcher_runtime_unavailable")
	}
	root, err := os.Lstat(dispatcherRuntimeRoot)
	if err != nil || !root.IsDir() || root.Mode().Perm()&0o022 != 0 || !ownedByCurrentUID(root) {
		return errors.New("dispatcher_runtime_untrusted")
	}
	dir := dispatcherDir(r.spec.Allocation.Path.Slot)
	if err = os.Mkdir(dir, 0o750); err != nil && !os.IsExist(err) {
		return errors.New("dispatcher_runtime_unavailable")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || !ownedByCurrentUID(info) {
		return errors.New("dispatcher_runtime_untrusted")
	}
	if err = os.Chown(dir, 0, int(gid)); err != nil {
		return err
	}
	if err = os.Mkdir(dispatcherCacheRoot, 0o755); err != nil && !os.IsExist(err) {
		return errors.New("dispatcher_cache_unavailable")
	}
	parent, err := os.Lstat(dispatcherCacheRoot)
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o022 != 0 ||
		!ownedByCurrentUID(parent) {
		return errors.New("dispatcher_cache_untrusted")
	}
	cache := filepath.Dir(
		dispatcherFiles(r.spec.Allocation.Path.Slot, r.spec.Allocation.FakePool).Cache,
	)
	if err = os.Mkdir(cache, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	info, err = os.Lstat(cache)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("dispatcher_cache_untrusted")
	}
	if err = os.Chown(cache, int(uid), int(gid)); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".rules-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }()
	if err = f.Chown(0, int(gid)); err == nil {
		err = f.Chmod(0o640)
	}
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil {
		return err
	}
	if ce != nil {
		return ce
	}
	return os.Rename(
		name,
		dispatcherFiles(r.spec.Allocation.Path.Slot, r.spec.Allocation.FakePool).RuleSet,
	)
}

func StartDispatcherWorker(
	ctx context.Context,
	spec dispatch.Spec,
	secret string,
	uid, gid uint32,
) (*exec.Cmd, io.Closer, io.ReadCloser, error) {
	if os.Geteuid() != 0 || uid == 0 || gid == 0 {
		return nil, nil, nil, errors.New("dispatcher_identity_invalid")
	}
	if err := dispatch.Validate(spec); err != nil {
		return nil, nil, nil, err
	}
	if err := trustedContinuityBinary(engineWorkerBinary); err != nil {
		return nil, nil, nil, err
	}
	// Compilation has returned and its full-registry buffers are dead. Return
	// that transient heap before the native engine builds its domain tries;
	// otherwise both heaps peak together on constrained routers.
	debug.FreeOSMemory()
	raw, err := json.Marshal(dispatcherWorkerConfig{spec, secret})
	if err != nil || len(raw) > MaxRequestBytes {
		return nil, nil, nil, errors.New("dispatcher_request_too_large")
	}
	var all []*os.File
	pipe := func() (*os.File, *os.File, error) {
		a, b, e := os.Pipe()
		if e == nil {
			all = append(all, a, b)
		}
		return a, b, e
	}
	ok := false
	defer func() {
		if !ok {
			for _, f := range all {
				_ = f.Close()
			}
		}
	}()
	lr, lw, err := pipe()
	if err != nil {
		return nil, nil, nil, err
	}
	rr, rw, err := pipe()
	if err != nil {
		return nil, nil, nil, err
	}
	qr, qw, err := pipe()
	if err != nil {
		return nil, nil, nil, err
	}
	or, ow, err := pipe()
	if err != nil {
		return nil, nil, nil, err
	}
	cmd := exec.Command(
		engineWorkerBinary,
		"dispatcher-worker",
		"--uid",
		strconv.FormatUint(uint64(uid), 10),
		"--gid",
		strconv.FormatUint(uint64(gid), 10),
	)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	cmd.ExtraFiles = []*os.File{lr, rw, qr, ow}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err = cmd.Start(); err != nil {
		return nil, nil, nil, errors.New("dispatcher_supervisor_start_failed")
	}
	_ = lr.Close()
	_ = rw.Close()
	_ = qr.Close()
	_ = ow.Close()
	go func() { _, _ = qw.Write(raw); _ = qw.Close() }()
	ready := make(chan bool, 1)
	go func() { var b [6]byte; _, e := io.ReadFull(rr, b[:]); ready <- e == nil && string(b[:]) == "ready\n" }()
	defer func() { _ = rr.Close() }()
	success := false
	select {
	case success = <-ready:
	case <-ctx.Done():
	case <-time.After(12 * time.Second):
	}
	if !success {
		_ = lw.Close()
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
		return nil, nil, nil, errors.New("dispatcher_start_failed")
	}
	ok = true
	return cmd, lw, or, nil
}

func RunDispatcherSupervisor(uid, gid uint32) error {
	if os.Geteuid() != 0 || uid == 0 || gid == 0 {
		return errors.New("dispatcher_identity_invalid")
	}
	life, e := enginePipe(3, "dispatcher-life")
	if e != nil {
		return e
	}
	defer func() { _ = life.Close() }()
	ready, e := enginePipe(4, "dispatcher-ready")
	if e != nil {
		return e
	}
	defer func() { _ = ready.Close() }()
	input, e := enginePipe(5, "dispatcher-config")
	if e != nil {
		return e
	}
	defer func() { _ = input.Close() }()
	observations, e := enginePipe(6, "dispatcher-observations")
	if e != nil {
		return e
	}
	defer func() { _ = observations.Close() }()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	go func() { var b [1]byte; _, _ = life.Read(b[:]); cancel() }()
	go func() { <-ctx.Done(); _ = input.Close() }()
	raw, e := io.ReadAll(io.LimitReader(input, MaxRequestBytes+1))
	if e != nil {
		return errors.New("dispatcher_config_invalid")
	}
	var req dispatcherWorkerConfig
	if DecodeStrict(raw, &req) != nil || dispatch.Validate(req.Spec) != nil {
		return errors.New("dispatcher_config_invalid")
	}
	if e = adapter.VerifyEngineInstallation(ctx, "sing-box"); e != nil {
		return errors.New("dispatcher_engine_unavailable")
	}
	config, e := dispatch.Generate(
		req.Spec,
		dispatcherFiles(req.Spec.Allocation.Path.Slot, req.Spec.Allocation.FakePool),
		req.Secret,
	)
	if e != nil {
		return e
	}
	file, e := engineConfigFD(config, gid)
	if e != nil {
		return e
	}
	defer func() { _ = file.Close() }()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	attrs := func(caps bool) *syscall.SysProcAttr {
		a := &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}},
			Pdeathsig:  syscall.SIGKILL,
		}
		if caps {
			a.AmbientCaps = []uintptr{capNetRaw}
		}
		return a
	}
	checkCtx, checkCancel := context.WithTimeout(ctx, 5*time.Second)
	check := exec.CommandContext(checkCtx, "/usr/bin/sing-box", "check", "-c", "/proc/self/fd/3")
	// A full registry contains millions of domains. Bound Go's transient heap
	// growth during native rule construction as well as during later reloads.
	// GOMEMLIMIT is cooperative; this does not replace process admission limits.
	check.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "GOMEMLIMIT=256MiB", "GOGC=50"}
	check.ExtraFiles = []*os.File{file}
	check.SysProcAttr = attrs(true)
	e = check.Run()
	checkCancel()
	if e != nil {
		return errors.New("dispatcher_native_validation_failed")
	}
	engine := exec.Command("/usr/bin/sing-box", "run", "-c", "/proc/self/fd/3")
	engine.Env = check.Env
	engine.ExtraFiles = []*os.File{file}
	engine.SysProcAttr = attrs(true)
	if e = engine.Start(); e != nil {
		return errors.New("dispatcher_engine_start_failed")
	}
	engineDone := make(chan error, 1)
	go func() { engineDone <- engine.Wait() }()
	stopChild := func(cmd *exec.Cmd, done <-chan error) {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}
	engineExited := false
	defer func() {
		if !engineExited {
			stopChild(engine, engineDone)
		}
	}()
	p := req.Spec.Allocation.Path
	p.DNSPort = 0
	deadline := time.Now().Add(5 * time.Second)
	for !engineInputsReady(engine.Process.Pid, p, engineInput{"4", "tcp", req.Spec.Allocation.Path.DNSPort}, engineInput{"4", "udp", req.Spec.Allocation.Path.DNSPort}, engineInput{"4", "tcp", req.Spec.Allocation.DirectPort}, engineInput{"4", "tcp", req.Spec.Allocation.APIPort}) {
		select {
		case <-engineDone:
			engineExited = true
			return errors.New("dispatcher_engine_exited")
		case <-ctx.Done():
			return nil
		case <-time.After(20 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return errors.New("dispatcher_bind_timeout")
		}
	}
	if e = selectDispatcher(ctx, req.Spec, req.Secret, req.Spec.Selected); e != nil {
		return e
	}
	frontRaw, e := json.Marshal(
		dnsFrontConfig{
			Port:          req.Spec.Allocation.DNSFrontPort,
			UpstreamPort:  req.Spec.Allocation.Path.DNSPort,
			LocalPrefixes: req.Spec.Network.LocalPrefixes,
		},
	)
	if e != nil {
		return errors.New("dispatcher_dns_config_invalid")
	}
	frontConfig, e := engineConfigFD(frontRaw, gid)
	if e != nil {
		return e
	}
	defer func() { _ = frontConfig.Close() }()
	frontReadyR, frontReadyW, e := os.Pipe()
	if e != nil {
		return e
	}
	defer func() { _ = frontReadyR.Close() }()
	front := exec.Command(engineWorkerBinary, "dns-front")
	front.Env = check.Env
	front.ExtraFiles = []*os.File{frontConfig, frontReadyW, observations}
	front.SysProcAttr = attrs(false)
	if e = front.Start(); e != nil {
		_ = frontReadyW.Close()
		return errors.New("dispatcher_dns_start_failed")
	}
	_ = frontReadyW.Close()
	frontDone := make(chan error, 1)
	go func() { frontDone <- front.Wait() }()
	frontExited := false
	defer func() {
		if !frontExited {
			stopChild(front, frontDone)
		}
	}()
	_ = frontReadyR.SetReadDeadline(time.Now().Add(5 * time.Second))
	var token [6]byte
	if _, e = io.ReadFull(frontReadyR, token[:]); e != nil || string(token[:]) != "ready\n" {
		return errors.New("dispatcher_dns_start_failed")
	}
	if _, e = io.WriteString(ready, "ready\n"); e != nil {
		return errors.New("dispatcher_owner_disconnected")
	}
	_ = ready.Close()
	select {
	case <-ctx.Done():
		return nil
	case <-engineDone:
		engineExited = true
		return errors.New("dispatcher_engine_exited")
	case <-frontDone:
		frontExited = true
		return errors.New("dispatcher_dns_exited")
	}
}
