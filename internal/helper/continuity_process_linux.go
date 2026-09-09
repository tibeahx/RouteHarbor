//go:build linux

package helper

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"
)

const continuityWorkerBinary = "/usr/libexec/openrhp-continuity"

func trustedContinuityBinary(path string) error {
	for _, name := range []string{"/usr", "/usr/libexec", path} {
		st, e := os.Lstat(name)
		if e != nil {
			return errors.New("continuity_installation_unavailable")
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || st.Mode().Perm()&0o022 != 0 || st.Mode()&os.ModeSymlink != 0 ||
			name == path && (!st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0) {
			return errors.New("continuity_installation_untrusted")
		}
	}
	return nil
}

func startContinuityProcess(
	ctx context.Context,
	r ContinuityWorkerRequest,
	uid, gid uint32,
) (*exec.Cmd, io.Closer, io.WriteCloser, *bufio.Reader, error) {
	if uid == 0 || gid == 0 || uid == ^uint32(0) || gid == ^uint32(0) || os.Geteuid() != 0 {
		return nil, nil, nil, nil, errors.New("continuity_identity_invalid")
	}
	if e := ValidateContinuityWorker(r); e != nil {
		return nil, nil, nil, nil, e
	}
	if e := trustedContinuityBinary(engineWorkerBinary); e != nil {
		return nil, nil, nil, nil, e
	}
	if e := trustedContinuityBinary(continuityWorkerBinary); e != nil {
		return nil, nil, nil, nil, e
	}
	var opened []*os.File
	pipe := func() (*os.File, *os.File, error) {
		a, b, e := os.Pipe()
		if e == nil {
			opened = append(opened, a, b)
		}
		return a, b, e
	}
	good := false
	defer func() {
		if !good {
			for _, f := range opened {
				_ = f.Close()
			}
		}
	}()
	lr, lw, e := pipe()
	if e != nil {
		return nil, nil, nil, nil, e
	}
	sr, sw, e := pipe()
	if e != nil {
		return nil, nil, nil, nil, e
	}
	rr, rw, e := pipe()
	if e != nil {
		return nil, nil, nil, nil, e
	}
	cr, cw, e := pipe()
	if e != nil {
		return nil, nil, nil, nil, e
	}
	cmd := exec.Command(
		engineWorkerBinary,
		"continuity-worker",
		"--uid",
		strconv.FormatUint(uint64(uid), 10),
		"--gid",
		strconv.FormatUint(uint64(gid), 10),
	)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	cmd.ExtraFiles = []*os.File{lr, sw, rr, cr}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if e = cmd.Start(); e != nil {
		return nil, nil, nil, nil, errors.New("continuity_supervisor_start_failed")
	}
	_ = lr.Close()
	_ = sw.Close()
	_ = rr.Close()
	_ = cr.Close()
	raw, _ := json.Marshal(r)
	go func() { _, _ = rw.Write(raw); _ = rw.Close() }()
	reader := bufio.NewReaderSize(sr, MaxRequestBytes+1)
	ready := make(chan bool, 1)
	go func() { line, e := reader.ReadSlice('\n'); ready <- e == nil && string(line) == "ready\n" }()
	ok := false
	select {
	case ok = <-ready:
	case <-ctx.Done():
	case <-time.After(8 * time.Second):
	}
	if !ok {
		_ = lw.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, nil, nil, nil, errors.New("continuity_start_failed")
	}
	good = true
	return cmd, &continuityLifetime{closers: []io.Closer{lw, sr}}, cw, reader, nil
}

// RunContinuitySupervisor opens only the typed transparent listeners before
// dropping every capability in the data worker. It retains a pinned OS thread
// so the child's parent-death signal follows the whole supervision lifetime.
func RunContinuitySupervisor(uid, gid uint32) error {
	if uid == 0 || gid == 0 || uid == ^uint32(0) || gid == ^uint32(0) || os.Geteuid() != 0 {
		return errors.New("continuity_identity_invalid")
	}
	if e := trustedContinuityBinary(continuityWorkerBinary); e != nil {
		return e
	}
	life, e := enginePipe(3, "continuity-life")
	if e != nil {
		return e
	}
	defer func() { _ = life.Close() }()
	status, e := enginePipe(4, "continuity-status")
	if e != nil {
		return e
	}
	defer func() { _ = status.Close() }()
	input, e := enginePipe(5, "continuity-request")
	if e != nil {
		return e
	}
	defer func() { _ = input.Close() }()
	commands, e := enginePipe(6, "continuity-commands")
	if e != nil {
		return e
	}
	defer func() { _ = commands.Close() }()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	go func() { var b [1]byte; _, _ = life.Read(b[:]); cancel() }()
	go func() { <-ctx.Done(); _ = input.Close() }()
	raw, e := io.ReadAll(io.LimitReader(input, MaxRequestBytes+1))
	if e != nil || len(raw) > MaxRequestBytes {
		return errors.New("continuity_request_unreadable")
	}
	var request ContinuityWorkerRequest
	if e = DecodeStrict(raw, &request); e != nil {
		return e
	}
	if e = ValidateContinuityWorker(request); e != nil {
		return e
	}
	files, listeners, e := openContinuityListeners(ctx, request)
	if e != nil {
		return e
	}
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	request.Listeners = listeners
	raw, _ = json.Marshal(request)
	config, e := engineConfigFD(raw, gid)
	if e != nil {
		return errors.New("continuity_config_unavailable")
	}
	defer func() { _ = config.Close() }()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cmd := exec.Command(continuityWorkerBinary, "worker")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	cmd.ExtraFiles = append([]*os.File{life, status, config, commands}, files...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}},
		Pdeathsig:  syscall.SIGKILL,
	}
	if e = cmd.Start(); e != nil {
		return errors.New("continuity_child_start_failed")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(750 * time.Millisecond):
		_ = cmd.Process.Kill()
		<-done
	}
	return nil
}

func transparentControl(network, address string, raw syscall.RawConn) error {
	var inner error
	e := raw.Control(func(fd uintptr) {
		level, opt := syscall.SOL_IP, 19 // IP_TRANSPARENT
		if network == "tcp6" || network == "udp6" {
			level, opt = syscall.SOL_IPV6, 75
			inner = syscall.SetsockoptInt(int(fd), syscall.SOL_IPV6, syscall.IPV6_V6ONLY, 1)
		}
		if inner == nil {
			inner = syscall.SetsockoptInt(int(fd), level, opt, 1)
		}
		if inner == nil && (network == "udp4" || network == "udp6") {
			orig := 20
			if network == "udp6" {
				orig = 74
			}
			inner = syscall.SetsockoptInt(int(fd), level, orig, 1)
		}
	})
	if e != nil {
		return e
	}
	return inner
}

func openContinuityListeners(
	ctx context.Context,
	r ContinuityWorkerRequest,
) ([]*os.File, []ContinuityListener, error) {
	var files []*os.File
	var specs []ContinuityListener
	ok := false
	defer func() {
		if !ok {
			for _, f := range files {
				_ = f.Close()
			}
		}
	}()
	ports := []int{r.Path.TransparentPort}
	if r.Path.DNSPort != 0 {
		ports = append(ports, r.Path.DNSPort)
	}
	families := []string{"4"}
	if r.Path.IPv6 {
		families = append(families, "6")
	}
	for _, fam := range families {
		for i, port := range ports {
			for _, proto := range []string{"tcp", "udp"} {
				host := "0.0.0.0"
				if fam == "6" {
					host = "::"
				}
				network := proto + fam
				address := net.JoinHostPort(host, strconv.Itoa(port))
				lc := net.ListenConfig{Control: transparentControl}
				var file *os.File
				var err error
				if proto == "tcp" {
					l, e := lc.Listen(ctx, network, address)
					if e != nil {
						return nil, nil, errors.New("continuity_listener_unavailable")
					}
					file, err = l.(*net.TCPListener).File()
					_ = l.Close()
				} else {
					l, e := lc.ListenPacket(ctx, network, address)
					if e != nil {
						return nil, nil, errors.New("continuity_listener_unavailable")
					}
					file, err = l.(*net.UDPConn).File()
					_ = l.Close()
				}
				if err != nil {
					return nil, nil, errors.New("continuity_listener_unavailable")
				}
				specs = append(
					specs,
					ContinuityListener{Network: network, DNS: i == 1, FD: 7 + len(files)},
				)
				files = append(files, file)
			}
		}
	}
	ok = true
	return files, specs, nil
}

func (c *Client) DialContinuity(ctx context.Context, sourceID string) (net.Conn, error) {
	return c.receiveContinuityConn(ctx, ContinuityRequest{Action: "dial", SourceID: sourceID})
}

func (c *Client) ContinuityUDPReply(
	ctx context.Context,
	client, destination string,
) (net.Conn, error) {
	conn, err := c.receiveContinuityConn(
		ctx,
		ContinuityRequest{Action: "udp_reply", ClientAddress: client, Destination: destination},
	)
	if err != nil {
		return nil, err
	}
	return continuityReplyClient{Conn: conn}, nil
}

func (c *Client) receiveContinuityConn(ctx context.Context, r ContinuityRequest) (net.Conn, error) {
	conn, e := c.connect(ctx)
	if e != nil {
		return nil, e
	}
	defer func() { _ = conn.Close() }()
	request := Request{Operation: "continuity", Continuity: &r}
	if e = validateRequest(request); e != nil {
		return nil, e
	}
	raw, _ := json.Marshal(request)
	if _, e = conn.Write(append(raw, '\n')); e != nil {
		return nil, e
	}
	buf := make([]byte, 4096)
	oob := make([]byte, syscall.CmsgSpace(4))
	n, on, flags, _, e := conn.ReadMsgUnix(buf, oob)
	if e != nil {
		return nil, e
	}
	var fds []int
	defer func() {
		for _, fd := range fds {
			_ = syscall.Close(fd)
		}
	}()
	msgs, e := syscall.ParseSocketControlMessage(oob[:on])
	if e != nil {
		return nil, errors.New("invalid_helper_response")
	}
	for _, m := range msgs {
		rs, err := syscall.ParseUnixRights(&m)
		if err != nil {
			return nil, errors.New("invalid_helper_response")
		}
		fds = append(fds, rs...)
	}
	var response Response
	if flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 ||
		DecodeStrict(buf[:n], &response) != nil {
		return nil, errors.New("invalid_helper_response")
	}
	if !response.OK {
		return nil, errors.New(response.Error)
	}
	if len(fds) != 1 {
		return nil, errors.New("invalid_helper_response")
	}
	syscall.CloseOnExec(fds[0])
	f := os.NewFile(uintptr(fds[0]), "continuity-carrier")
	fds = nil
	defer func() { _ = f.Close() }()
	return net.FileConn(f)
}
