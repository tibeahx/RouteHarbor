//go:build linux

package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/adapter"
)

const (
	engineWorkerBinary = "/usr/libexec/routeharbor-helper"
	capNetRaw          = 13
)

// StartEngineWorker starts a fixed supervisor with a private typed request. The
// returned writer must be retained only while the authenticated API is alive.
// Neither credentials nor generated configuration enter a command line.
func StartEngineWorker(
	ctx context.Context,
	request EngineRequest,
	uid, gid uint32,
) (*exec.Cmd, io.Closer, error) {
	if uid == 0 || gid == 0 || uid == ^uint32(0) || gid == ^uint32(0) || os.Geteuid() != 0 {
		return nil, nil, errors.New("engine_identity_invalid")
	}
	if err := ValidateEngineRequest(request); err != nil {
		return nil, nil, err
	}
	for _, name := range []string{"/usr", "/usr/libexec", engineWorkerBinary} {
		st, err := os.Lstat(name)
		if err != nil {
			return nil, nil, errors.New("engine_supervisor_unavailable")
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || st.Mode().Perm()&0o022 != 0 || st.Mode()&os.ModeSymlink != 0 ||
			name == engineWorkerBinary && (!st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0) {
			return nil, nil, errors.New("engine_supervisor_untrusted")
		}
	}
	raw, err := json.Marshal(request)
	if err != nil || len(raw) > MaxRequestBytes {
		return nil, nil, errors.New("engine_request_too_large")
	}
	lifeRead, lifeWrite, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		_ = lifeRead.Close()
		_ = lifeWrite.Close()
		return nil, nil, err
	}
	requestRead, requestWrite, err := os.Pipe()
	if err != nil {
		_ = lifeRead.Close()
		_ = lifeWrite.Close()
		_ = readyRead.Close()
		_ = readyWrite.Close()
		return nil, nil, err
	}
	cmd := exec.Command(
		engineWorkerBinary,
		"engine-worker",
		"--uid",
		strconv.FormatUint(uint64(uid), 10),
		"--gid",
		strconv.FormatUint(uint64(gid), 10),
	)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	cmd.Stderr = os.Stderr // The worker reports fixed error codes; native output remains suppressed.
	cmd.ExtraFiles = []*os.File{lifeRead, readyWrite, requestRead}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	err = cmd.Start()
	_ = lifeRead.Close()
	_ = readyWrite.Close()
	_ = requestRead.Close()
	if err != nil {
		_ = lifeWrite.Close()
		_ = readyRead.Close()
		_ = requestWrite.Close()
		return nil, nil, errors.New("engine_supervisor_start_failed")
	}
	defer func() { _ = readyRead.Close() }()
	go func() { _, _ = requestWrite.Write(raw); _ = requestWrite.Close() }()
	ready := make(chan bool, 1)
	go func() {
		var token [6]byte
		_, err := io.ReadFull(readyRead, token[:])
		ready <- err == nil && string(token[:]) == "ready\n"
	}()
	ok := false
	select {
	case ok = <-ready:
	case <-ctx.Done():
	case <-time.After(8 * time.Second):
	}
	if !ok {
		_ = lifeWrite.Close()
		_ = requestWrite.Close()
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
		return nil, nil, errors.New("engine_start_failed: source inputs did not become ready")
	}
	return cmd, lifeWrite, nil
}

func enginePipe(fd uintptr, name string) (*os.File, error) {
	f := os.NewFile(fd, name)
	if f == nil {
		return nil, errors.New("engine_worker_descriptor_invalid")
	}
	syscall.CloseOnExec(int(fd))
	st, err := f.Stat()
	if err != nil || st.Mode()&os.ModeNamedPipe == 0 {
		_ = f.Close()
		return nil, errors.New("engine_worker_descriptor_invalid")
	}
	return f, nil
}

func engineConfigFD(raw []byte, gid uint32) (*os.File, error) {
	const dir = "/var/run/routeharbor-engine-worker"
	parent, err := filepath.EvalSymlinks(filepath.Dir(dir))
	if err != nil {
		return nil, err
	}
	for current := parent; ; current = filepath.Dir(current) {
		st, err := os.Lstat(current)
		if err != nil {
			return nil, err
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || !st.IsDir() ||
			st.Mode().Perm()&0o022 != 0 && st.Mode()&os.ModeSticky == 0 {
			return nil, errors.New("engine_config_parent_untrusted")
		}
		if current == "/" {
			break
		}
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || !st.IsDir() || st.Mode().Perm() != 0o700 {
		return nil, errors.New("engine_config_directory_untrusted")
	}
	f, err := os.CreateTemp(dir, ".engine-config-")
	if err != nil {
		return nil, err
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err = f.Write(raw); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err = f.Chown(0, int(gid)); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err = f.Chmod(0o440); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	// Read-only, unlinked, root-owned. The child may reopen its own inherited FD
	// through procfs, but cannot change contents, ownership or mode.
	read, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	if err = os.Remove(name); err != nil {
		_ = read.Close()
		return nil, err
	}
	return read, nil
}

func RunEngineWorker(uid, gid uint32) error {
	if os.Geteuid() != 0 || uid == 0 || gid == 0 || uid == ^uint32(0) || gid == ^uint32(0) {
		return errors.New("engine_identity_invalid")
	}
	life, err := enginePipe(3, "engine-api-liveness")
	if err != nil {
		return err
	}
	defer func() { _ = life.Close() }()
	ready, err := enginePipe(4, "engine-readiness")
	if err != nil {
		return err
	}
	defer func() { _ = ready.Close() }()
	requestFile, err := enginePipe(5, "engine-request")
	if err != nil {
		return err
	}
	defer func() { _ = requestFile.Close() }()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	go func() { var b [1]byte; _, _ = life.Read(b[:]); cancel() }()
	// Cancel request reads too if the authenticated owner disappears mid-start.
	go func() { <-ctx.Done(); _ = requestFile.Close() }()
	raw, err := io.ReadAll(io.LimitReader(requestFile, MaxRequestBytes+1))
	if err != nil {
		return errors.New("engine_request_unreadable")
	}
	var request EngineRequest
	if err = DecodeStrict(raw, &request); err != nil {
		return err
	}
	if err = ValidateEngineRequest(request); err != nil {
		return err
	}
	engine := request.Source.Type
	if engine == "socks5" || engine == "http-connect" {
		engine = "sing-box"
	}
	if err = adapter.VerifyEngineInstallation(ctx, engine); err != nil {
		return errors.New("engine_installation_unavailable")
	}
	p := request.Path
	p.DNSResolver = request.DNSResolver
	config, err := adapter.EngineConfig(request.Source, p)
	if err != nil {
		return errors.New("engine_config_invalid")
	}
	file, err := engineConfigFD(config, gid)
	if err != nil {
		return errors.New("engine_config_unavailable")
	}
	defer func() { _ = file.Close() }()
	// Pin the supervising thread for the entire child lifetime: Linux parent-
	// death signals refer to the spawning thread, not the Go process as a whole.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	childAttr := func() *syscall.SysProcAttr {
		return &syscall.SysProcAttr{
			Credential:  &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}},
			AmbientCaps: []uintptr{capNetRaw},
			Pdeathsig:   syscall.SIGKILL,
		}
	}
	checkCtx, checkCancel := context.WithTimeout(ctx, 3*time.Second)
	checkArgs := []string{"check", "-c", "/proc/self/fd/3"}
	if engine == "xray" {
		checkArgs = []string{"run", "-test", "-format", "json", "-config", "/proc/self/fd/3"}
	}
	check := exec.CommandContext(checkCtx, "/usr/bin/"+engine, checkArgs...)
	check.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	check.ExtraFiles = []*os.File{file}
	check.SysProcAttr = childAttr()
	err = check.Run()
	checkCancel()
	if err != nil {
		return errors.New("engine_native_validation_failed")
	}
	args := []string{"run", "-c", "/proc/self/fd/3"}
	if engine == "xray" {
		args = []string{"run", "-format", "json", "-config", "/proc/self/fd/3"}
	}
	if ctx.Err() != nil {
		return nil
	}
	cmd := exec.Command("/usr/bin/"+engine, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	cmd.ExtraFiles = []*os.File{file}
	// Go's Linux fork/exec setup drops the service UID/GID and supplementary
	// groups before exec. Only CAP_NET_RAW survives in permitted/effective/
	// inheritable/ambient sets; the API and supervisor receive no ambient caps.
	cmd.SysProcAttr = childAttr()
	if err = cmd.Start(); err != nil {
		return errors.New("engine_child_start_failed")
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	stop := func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(750 * time.Millisecond):
			_ = cmd.Process.Kill()
			<-exited
		}
	}
	deadline := time.NewTimer(4 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for !engineInputsReady(cmd.Process.Pid, p) {
		select {
		case <-exited:
			return errors.New("engine_exited_before_ready")
		case <-ctx.Done():
			stop()
			return nil
		case <-deadline.C:
			stop()
			return errors.New("engine_input_bind_timeout")
		case <-tick.C:
		}
	}
	if _, err = io.WriteString(ready, "ready\n"); err != nil {
		stop()
		return errors.New("engine_owner_disconnected")
	}
	_ = ready.Close()
	select {
	case err = <-exited:
		if err != nil {
			return errors.New("engine_child_exited")
		}
		return nil
	case <-ctx.Done():
		stop()
		return nil
	}
}

type engineInput struct {
	family, proto string
	port          int
}

func engineInputsReady(pid int, p adapter.Path, extra ...engineInput) bool {
	owners := map[string]bool{}
	files, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return false
	}
	for _, entry := range files {
		target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name()))
		if err == nil && strings.HasPrefix(target, "socket:[") {
			owners[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
		}
	}
	wanted := []engineInput{{"4", "tcp", p.ProxyPort}, {"4", "tcp", p.TransparentPort}}
	if p.UDP {
		wanted = append(wanted, engineInput{"4", "udp", p.TransparentPort})
	}
	if p.DNSPort != 0 {
		wanted = append(
			wanted,
			engineInput{"4", "tcp", p.DNSPort},
			engineInput{"4", "udp", p.DNSPort},
		)
	}
	if p.IPv6 {
		wanted = append(wanted, engineInput{"6", "tcp", p.TransparentPort})
		if p.UDP {
			wanted = append(wanted, engineInput{"6", "udp", p.TransparentPort})
		}
		if p.DNSPort != 0 {
			wanted = append(
				wanted,
				engineInput{"6", "tcp", p.DNSPort},
				engineInput{"6", "udp", p.DNSPort},
			)
		}
	}
	seen := map[engineInput]bool{}
	wanted = append(wanted, extra...)
	for _, family := range []string{"4", "6"} {
		for _, proto := range []string{"tcp", "udp"} {
			suffix := ""
			if family == "6" {
				suffix = "6"
			}
			f, err := os.Open(filepath.Join("/proc/net", proto+suffix))
			if err != nil {
				continue
			}
			data, _ := io.ReadAll(io.LimitReader(f, 2<<20))
			_ = f.Close()
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) < 10 || !owners[fields[9]] {
					continue
				}
				parts := strings.Split(fields[1], ":")
				if len(parts) != 2 {
					continue
				}
				host := parts[0]
				if family == "4" && host != "0100007F" && host != "7F000001" {
					continue
				}
				if family == "6" && host != "00000000000000000000000001000000" &&
					host != "00000000000000000000000000000001" {
					continue
				}
				if proto == "tcp" && fields[3] != "0A" {
					continue
				}
				port, err := strconv.ParseUint(parts[1], 16, 16)
				if err == nil {
					seen[engineInput{family, proto, int(port)}] = true
				}
			}
		}
	}
	for _, input := range wanted {
		if !seen[input] {
			return false
		}
	}
	return true
}
