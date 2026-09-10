//go:build linux

package helper

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
)

func TestLinuxContinuityReplyBridgeConfinementAndBoundaries(t *testing.T) {
	requireNetLab(t)
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()
	target, err := net.DialUDP("udp4", nil, udp.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	local, fd, err := continuityReplyPair()
	if err != nil {
		t.Fatal(err)
	}
	worker, err := net.FileConn(fd)
	_ = fd.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = worker.Close() }()
	raw, err := worker.(*net.UnixConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var domain int
	var reconnect error
	if err = raw.Control(func(fd uintptr) {
		domain, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_DOMAIN)
		reconnect = syscall.Connect(
			int(fd),
			&syscall.SockaddrInet4{Addr: [4]byte{8, 8, 8, 8}, Port: 53},
		)
	}); err != nil {
		t.Fatal(err)
	}
	if domain != syscall.AF_UNIX || reconnect == nil {
		t.Fatal("worker received a reconnectable IP socket", domain, reconnect)
	}
	r := &continuityRegistration{request: continuityFixture(t), done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan struct{})
	go func() { bridgeContinuityReply(ctx, r, local, target); close(finished) }()
	client := continuityReplyClient{Conn: worker}
	for _, payload := range [][]byte{{}, {0}, {1, 0, 2, 255}, bytes.Repeat([]byte{42}, 1200), bytes.Repeat([]byte{17}, 65507)} {
		if n, err := client.Write(payload); err != nil || n != len(payload) {
			t.Fatal(n, err)
		}
		_ = udp.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 65535)
		n, _, err := udp.ReadFromUDP(buf)
		if err != nil || !bytes.Equal(buf[:n], payload) {
			t.Fatal("datagram boundary/payload changed", n, len(payload), err)
		}
	}
	_ = worker.Close()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("closed reply lease leaked")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.replyBytes != 0 {
		t.Fatal("reply buffer accounting leak", r.replyBytes)
	}
}

func TestLinuxContinuityReplyBudgetDropsNewDatagramKeepsLease(t *testing.T) {
	requireNetLab(t)
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()
	target, err := net.DialUDP("udp4", nil, udp.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	local, fd, err := continuityReplyPair()
	if err != nil {
		t.Fatal(err)
	}
	worker, err := net.FileConn(fd)
	_ = fd.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = worker.Close() }()
	r := &continuityRegistration{request: continuityFixture(t), done: make(chan struct{})}
	r.request.Config.UDPReserveBytes = 64 << 10
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan struct{})
	go func() { bridgeContinuityReply(ctx, r, local, target); close(finished) }()
	client := continuityReplyClient{Conn: worker}
	if _, err = client.Write(make([]byte, 40<<10)); err != nil {
		t.Fatal(err)
	}
	if _, err = client.Write([]byte("survived")); err != nil {
		t.Fatal(err)
	}
	_ = udp.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 65535)
	n, _, err := udp.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "survived" {
		t.Fatal("overflow killed established lease", n, err)
	}
	_ = worker.Close()
	<-finished
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.replyBytes != 0 || r.helperDroppedUDP != 1 {
		t.Fatal("overflow accounting", r.replyBytes, r.helperDroppedUDP)
	}
}

func TestLinuxContinuityReplyRequiresObservedOwnedTuple(t *testing.T) {
	prepareLab(t)
	worker := continuityFixture(t)
	client := netip.MustParseAddrPort("10.44.0.2:42000")
	destination := netip.MustParseAddrPort("8.8.8.8:443")
	if err := admitContinuityReply(context.Background(), worker, client, destination); err == nil {
		t.Fatal("unobserved tuple admitted")
	}
	binary, err := conntrackBinary()
	if err != nil {
		t.Fatal(err)
	}
	labCommand(
		t,
		binary,
		"--create",
		"--proto",
		"udp",
		"--orig-src",
		client.Addr().String(),
		"--orig-dst",
		destination.Addr().String(),
		"--sport",
		"42000",
		"--dport",
		"443",
		"--timeout",
		"120",
		"--mark",
		fmt.Sprintf("0x%08x", dataplane.Mark(uint16(worker.Path.Slot))),
	)
	if err = admitContinuityReply(context.Background(), worker, client, destination); err != nil {
		t.Fatal("observed tuple rejected", err)
	}
	for _, wrong := range []netip.AddrPort{netip.MustParseAddrPort("8.8.4.4:443"), netip.MustParseAddrPort("8.8.8.8:22")} {
		if err = admitContinuityReply(context.Background(), worker, client, wrong); err == nil {
			t.Fatal("foreign tuple admitted", wrong)
		}
	}
	worker.Path.Slot--
	if err = admitContinuityReply(context.Background(), worker, client, destination); err == nil {
		t.Fatal("foreign connmark admitted")
	}
	worker.Path.Slot++
	worker.Network.DNS = "selected-path"
	dns := netip.MustParseAddrPort("10.44.0.1:53")
	labCommand(
		t,
		binary,
		"--create",
		"--proto",
		"udp",
		"--orig-src",
		client.Addr().String(),
		"--orig-dst",
		dns.Addr().String(),
		"--sport",
		"42000",
		"--dport",
		"53",
		"--timeout",
		"120",
		"--mark",
		fmt.Sprintf("0x%08x", dataplane.Mark(uint16(worker.Path.Slot))),
	)
	if err = admitContinuityReply(context.Background(), worker, client, dns); err != nil {
		t.Fatal("owned router DNS reply rejected", err)
	}
	for _, wrong := range []netip.AddrPort{netip.MustParseAddrPort("10.44.0.2:53"), netip.MustParseAddrPort("10.44.0.1:22")} {
		if err = validateContinuityReplyScope(worker, client, wrong); err == nil {
			t.Fatal("private spoofed reply source admitted", wrong)
		}
	}
}

func TestLinuxContinuitySupervisorDropsPrivilegesAndStopsWithOwner(t *testing.T) {
	requireNetLab(t)
	worker := continuityFixture(t)
	worker.HelperSocket = "/tmp/absent-openrhp-helper.sock"
	if _, _, _, _, err := startContinuityProcess(
		context.Background(),
		worker,
		0,
		65534,
	); err == nil {
		t.Fatal("root worker allowed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd, life, commands, status, err := startContinuityProcess(ctx, worker, 65534, 65534)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = life.Close() }()
	defer func() { _ = commands.Close() }()
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	child := ""
	tasks, _ := filepath.Glob("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/task/*/children")
	for _, task := range tasks {
		children, _ := os.ReadFile(task)
		for _, pid := range strings.Fields(string(children)) {
			if exe, _ := os.Readlink("/proc/" + pid + "/exe"); exe == continuityWorkerBinary {
				child = pid
			}
		}
	}
	if child == "" {
		t.Fatal("continuity worker was not launched")
	}
	raw, err := os.ReadFile("/proc/" + child + "/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Uid:\t65534\t65534\t65534\t65534", "Gid:\t65534\t65534\t65534\t65534", "CapEff:\t0000000000000000", "CapPrm:\t0000000000000000"} {
		if !strings.Contains(string(raw), want) {
			t.Fatal("worker retained privilege", want)
		}
	}
	lines := make(chan error, 1)
	go func() { _, e := status.ReadSlice('\n'); lines <- e }()
	select {
	case err := <-lines:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("worker not reporting bounded status")
	}
	_ = life.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		waited = true
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not stop with owner")
	}
	pid, err := strconv.Atoi(child)
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.Kill(pid, 0); err == nil {
		t.Fatal("data worker survived supervisor ownership loss")
	}
}
