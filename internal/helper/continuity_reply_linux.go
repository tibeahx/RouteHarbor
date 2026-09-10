//go:build linux

package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
	"github.com/tibeahx/OpenRHP/internal/platform"
)

// An unprivileged worker receives a bounded local datagram channel, never the
// transparent IP socket: even a compromised worker cannot reconnect/sendto a
// different peer or reuse the privileged source address outside this one flow.
func (s *Server) continuityUDPReply(
	ctx context.Context,
	c *net.UnixConn,
	reg *continuityRegistration,
	r ContinuityRequest,
) {
	if validateContinuityRequest(r) != nil {
		writeResponse(c, Response{Error: "continuity_datagram_denied"})
		return
	}
	select {
	case reg.leases <- struct{}{}:
	default:
		writeResponse(c, Response{Error: "continuity_reply_capacity"})
		return
	}
	if !reg.tryReserveReply(512) {
		<-reg.leases
		writeResponse(c, Response{Error: "continuity_reply_capacity"})
		return
	}
	owned := true
	defer func() {
		if owned {
			<-reg.leases
			reg.releaseReply(512)
		}
	}()
	client, _ := netip.ParseAddrPort(r.ClientAddress)
	destination, _ := netip.ParseAddrPort(r.Destination)
	if err := admitContinuityReply(ctx, reg.request, client, destination); err != nil {
		writeResponse(c, Response{Error: "continuity_datagram_denied"})
		return
	}
	device, err := continuityClientDevice(ctx, reg.request.Network.LANInterfaces, client)
	if err != nil {
		writeResponse(c, Response{Error: "continuity_datagram_denied"})
		return
	}
	conn, err := openContinuityReply(ctx, client, destination, device)
	if err != nil {
		writeResponse(c, Response{Error: "continuity_reply_unavailable"})
		return
	}
	local, worker, err := continuityReplyPair()
	if err != nil {
		_ = conn.Close()
		writeResponse(c, Response{Error: "continuity_reply_unavailable"})
		return
	}
	defer func() { _ = worker.Close() }()
	data, _ := json.Marshal(Response{OK: true})
	if _, _, err = c.WriteMsgUnix(
		append(data, '\n'),
		syscall.UnixRights(int(worker.Fd())),
		nil,
	); err != nil {
		_ = conn.Close()
		_ = local.Close()
		return
	}
	owned = false
	go func() {
		defer func() { <-reg.leases; reg.releaseReply(512) }()
		bridgeCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		go func() {
			select {
			case <-reg.done:
				cancel()
			case <-bridgeCtx.Done():
			}
		}()
		bridgeContinuityReply(bridgeCtx, reg, local, conn)
	}()
}

func admitContinuityReply(
	ctx context.Context,
	worker ContinuityWorkerRequest,
	client, destination netip.AddrPort,
) error {
	if err := validateContinuityReplyScope(worker, client, destination); err != nil {
		return err
	}
	// Match the exact kernel-observed original tuple and this worker's connection
	// mark. Root never trusts a claimed destination/port from the data worker.
	binary, err := conntrackBinary()
	if err != nil {
		return err
	}
	family := "ipv4"
	if client.Addr().Is6() {
		family = "ipv6"
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(
		bounded,
		binary,
		"--dump",
		"--family",
		family,
		"--proto",
		"udp",
		"--orig-src",
		client.Addr().String(),
		"--orig-dst",
		destination.Addr().String(),
		"--sport",
		strconv.Itoa(int(client.Port())),
		"--dport",
		strconv.Itoa(int(destination.Port())),
		"--mark",
		fmt.Sprintf("0x%08x/0xffff0000", dataplane.Mark(uint16(worker.Path.Slot))),
	)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.WaitDelay = 100 * time.Millisecond
	out := &presenceWriter{}
	cmd.Stdout, cmd.Stderr = out, io.Discard
	if err = cmd.Run(); err != nil || !out.present {
		return errors.New("continuity_datagram_unobserved")
	}
	return nil
}

func validateContinuityReplyScope(
	worker ContinuityWorkerRequest,
	client, destination netip.AddrPort,
) error {
	r := ContinuityRequest{
		Action:        "udp_reply",
		ClientAddress: client.String(),
		Destination:   destination.String(),
	}
	if validateContinuityRequest(r) != nil || client.Addr().Is6() && !worker.Path.IPv6 {
		return errors.New("continuity_datagram_denied")
	}
	allowed := false
	for _, raw := range worker.Network.LocalPrefixes {
		p, e := netip.ParsePrefix(raw)
		if e == nil && p.Contains(client.Addr()) &&
			(client.Addr() != p.Addr() || p.Bits() == p.Addr().BitLen()) {
			allowed = true
		}
	}
	if !allowed {
		return errors.New("continuity_datagram_denied")
	}
	// Local DNS requests are intercepted before the router-address exceptions.
	// Admit their reply source only when it is an actual router address on port53.
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return errors.New("continuity_datagram_denied")
	}
	local := false
	for _, a := range addresses {
		p, e := netip.ParsePrefix(a.String())
		if e == nil && p.Addr().Unmap() == destination.Addr() {
			local = true
		}
	}
	if local || !platform.PublicAddress(destination.Addr()) {
		if !local || destination.Port() != 53 || worker.Network.DNS != "selected-path" {
			return errors.New("continuity_datagram_denied")
		}
	}
	return nil
}

func continuityClientDevice(
	ctx context.Context,
	devices []string,
	client netip.AddrPort,
) (string, error) {
	family := "-4"
	if client.Addr().Is6() {
		family = "-6"
	}
	raw, err := (platform.ProductionRunner{}).Run(
		ctx,
		"/sbin/ip",
		[]string{family, "-j", "route", "get", client.Addr().String()},
		nil,
	)
	var routes []struct{ Dev, Type string }
	if err != nil || json.Unmarshal(raw, &routes) != nil || len(routes) != 1 ||
		routes[0].Type == "local" ||
		!slices.Contains(devices, routes[0].Dev) {
		return "", errors.New("continuity_client_not_on_lan")
	}
	return routes[0].Dev, nil
}

func openContinuityReply(
	ctx context.Context,
	client, destination netip.AddrPort,
	device string,
) (net.Conn, error) {
	network := "udp4"
	if client.Addr().Is6() {
		network = "udp6"
	}
	listener := net.ListenConfig{
		Control: func(n, a string, raw syscall.RawConn) error {
			if err := transparentControl(n, a, raw); err != nil {
				return err
			}
			var inner error
			err := raw.Control(func(fd uintptr) {
				inner = syscall.SetsockoptString(
					int(fd),
					syscall.SOL_SOCKET,
					syscall.SO_BINDTODEVICE,
					device,
				)
				if inner == nil {
					inner = syscall.SetsockoptInt(
						int(fd),
						syscall.SOL_SOCKET,
						syscall.SO_REUSEADDR,
						1,
					)
				}
			})
			if err != nil {
				return err
			}
			return inner
		},
	}
	conn, err := listener.ListenPacket(ctx, network, destination.String())
	if err != nil {
		return nil, err
	}
	return continuityReplyTarget{UDPConn: conn.(*net.UDPConn), peer: client}, nil
}

// Keep the transparent reply socket unconnected: an established UDP socket with
// this original tuple would steal later LAN requests from the TPROXY listener.
// Only the helper owns this socket; the worker cannot alter its fixed peer.
type continuityReplyTarget struct {
	*net.UDPConn
	peer netip.AddrPort
}

func (c continuityReplyTarget) Write(payload []byte) (int, error) {
	return c.WriteToUDPAddrPort(payload, c.peer)
}
func (c continuityReplyTarget) RemoteAddr() net.Addr { return net.UDPAddrFromAddrPort(c.peer) }

func continuityReplyPair() (*net.UnixConn, *os.File, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	localFile := os.NewFile(uintptr(fds[0]), "continuity-reply-local")
	defer func() { _ = localFile.Close() }()
	worker := os.NewFile(uintptr(fds[1]), "continuity-reply-worker")
	conn, err := net.FileConn(localFile)
	if err != nil {
		_ = worker.Close()
		return nil, nil, err
	}
	return conn.(*net.UnixConn), worker, nil
}

type continuityReplyClient struct{ net.Conn }

func (c continuityReplyClient) Write(payload []byte) (int, error) {
	if len(payload) > 65507 {
		return 0, errors.New("continuity_datagram_too_large")
	}
	conn, ok := c.Conn.(*net.UnixConn)
	if !ok {
		return 0, errors.New("invalid_reply_channel")
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	// writev sends one SOCK_SEQPACKET record without copying the caller's payload.
	// The leading byte distinguishes an empty UDP datagram from channel EOF.
	prefix := [1]byte{}
	iov := []syscall.Iovec{{Base: &prefix[0]}}
	iov[0].SetLen(1)
	if len(payload) > 0 {
		iov = append(iov, syscall.Iovec{Base: &payload[0]})
		iov[1].SetLen(len(payload))
	}
	var written uintptr
	var writeErr syscall.Errno
	err = raw.Write(func(fd uintptr) bool {
		written, _, writeErr = syscall.Syscall(
			syscall.SYS_WRITEV,
			fd,
			uintptr(unsafe.Pointer(&iov[0])),
			uintptr(len(iov)),
		)
		return writeErr != syscall.EAGAIN && writeErr != syscall.EWOULDBLOCK
	})
	runtime.KeepAlive(payload)
	runtime.KeepAlive(prefix)
	runtime.KeepAlive(iov)
	if err != nil {
		return 0, err
	}
	if writeErr != 0 {
		return 0, writeErr
	}
	if written != uintptr(len(payload)+1) {
		return 0, io.ErrShortWrite
	}
	return len(payload), nil
}

func bridgeContinuityReply(
	ctx context.Context,
	reg *continuityRegistration,
	local *net.UnixConn,
	target net.Conn,
) {
	defer func() { _ = local.Close() }()
	defer func() { _ = target.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = local.Close(); _ = target.Close() })
	defer stop()
	raw, err := local.SyscallConn()
	if err != nil {
		return
	}
	for {
		_ = local.SetReadDeadline(time.Now().Add(120 * time.Second))
		var size int
		var peekErr error
		err = raw.Read(func(fd uintptr) bool {
			size, _, _, _, peekErr = syscall.Recvmsg(
				int(fd),
				nil,
				nil,
				syscall.MSG_PEEK|syscall.MSG_TRUNC|syscall.MSG_DONTWAIT,
			)
			return peekErr != syscall.EAGAIN && peekErr != syscall.EWOULDBLOCK
		})
		if err != nil || peekErr != nil || size < 1 || size > 65508 {
			return
		}
		if !reg.tryReserveReply(int64(size)) {
			// Consume and count a new datagram that cannot fit; preserve the
			// established reply lease instead of tearing down the UDP mapping.
			var discard [1]byte
			if _, _, _, _, err := local.ReadMsgUnix(discard[:], nil); err != nil {
				return
			}
			reg.mu.Lock()
			reg.helperDroppedUDP++
			reg.mu.Unlock()
			continue
		}
		payload := make([]byte, size)
		n, _, flags, _, err := local.ReadMsgUnix(payload, nil)
		valid := err == nil && n == size && flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) == 0 &&
			payload[0] == 0
		if valid {
			_ = target.SetWriteDeadline(time.Now().Add(time.Second))
			_, err = target.Write(payload[1:])
		}
		reg.releaseReply(int64(size))
		if !valid || err != nil {
			return
		}
	}
}

func (r *continuityRegistration) tryReserveReply(n int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n < 0 || r.replyBytes+n > int64(r.request.Config.UDPReserveBytes)/2 {
		return false
	}
	r.replyBytes += n
	return true
}

func (r *continuityRegistration) releaseReply(n int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.replyBytes -= n
}
