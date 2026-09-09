//go:build linux

package helper

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/continuity"
	"github.com/tibeahx/OpenRHP/internal/dataplane"
)

type continuityE2EMessage struct {
	Worker  ContinuityWorkerRequest
	Socket  string
	Action  string
	Primary string
	Standby string
	Payload []byte
	Status  ContinuityStatus
	IDs     []string
}

type continuityE2EProcess struct {
	in  io.WriteCloser
	out *json.Decoder
	cmd *exec.Cmd
}

func continuityE2EChild(
	t *testing.T,
	ctx context.Context,
	namespace, role string,
	unprivileged bool,
) *continuityE2EProcess {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"-test.run=^TestLinuxContinuityTransparentE2EChild$"}
	if namespace != "" {
		args = append([]string{"netns", "exec", namespace, executable}, args...)
		executable = "/sbin/ip"
	}
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = append(os.Environ(), "OPENRHP_CONTINUITY_E2E_ROLE="+role)
	if unprivileged {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}},
		}
	}
	cmd.Stderr = os.Stderr
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, response, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.ExtraFiles = []*os.File{response}
	cmd.Stdout = os.Stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = response.Close()
	t.Cleanup(
		func() { _ = input.Close(); _ = output.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() },
	)
	return &continuityE2EProcess{input, json.NewDecoder(output), cmd}
}

func (p *continuityE2EProcess) exchange(
	t *testing.T,
	message continuityE2EMessage,
) continuityE2EMessage {
	t.Helper()
	if err := json.NewEncoder(p.in).Encode(message); err != nil {
		t.Fatal(err)
	}
	var answer continuityE2EMessage
	done := make(chan error, 1)
	go func() { done <- p.out.Decode(&answer) }()
	select {
	case err := <-done:
		if err != nil {
			extra, _ := io.ReadAll(p.out.Buffered())
			t.Fatal("E2E child response", err, string(extra))
		}
	case <-time.After(20 * time.Second):
		t.Fatal("E2E child response timed out")
	}
	return answer
}

// This test uses real nftables/TPROXY, conntrack admission, Unix credential RPC,
// the installed root supervisor and unprivileged worker, and real mTLS carriers.
// Both named carriers share one isolated synthetic egress; this is functional
// continuity evidence, not WAN independence or physical latency qualification.
func TestLinuxContinuityTransparentE2E(t *testing.T) {
	requireNetLab(t)
	if os.Getenv("OPENRHP_CONTINUITY_E2E_NAMESPACE") != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(
			"unshare",
			"--net",
			executable,
			"-test.v",
			"-test.run=^TestLinuxContinuityTransparentE2E$",
		)
		cmd.Env = append(os.Environ(), "OPENRHP_CONTINUITY_E2E_NAMESPACE=1")
		output, err := cmd.CombinedOutput()
		t.Log(string(output))
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	prepareLab(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	const origin = "rhp-cont-origin"
	const client = "rhp-cont-client"
	const target = "rhp-cont-target"
	for _, namespace := range []string{origin, client, target} {
		_ = exec.Command("/sbin/ip", "netns", "del", namespace).Run()
		labCommand(t, "/sbin/ip", "netns", "add", namespace)
		t.Cleanup(func() { _ = exec.Command("/sbin/ip", "netns", "del", namespace).Run() })
	}
	ns := func(namespace string, args ...string) {
		labCommand(
			t,
			"/sbin/ip",
			append([]string{"netns", "exec", namespace, "/sbin/ip"}, args...)...)
	}
	for _, pair := range []struct{ device, peer, namespace, local, remote string }{{"outside0", "origin-peer", origin, "192.0.2.1/24", "192.0.2.2/24"}, {"home0", "client-peer", client, "10.44.0.1/24", "10.44.0.2/24"}} {
		labCommand(t, "/sbin/ip", "link", "del", pair.device)
		labCommand(
			t,
			"/sbin/ip",
			"link",
			"add",
			pair.device,
			"type",
			"veth",
			"peer",
			"name",
			pair.peer,
		)
		labCommand(t, "/sbin/ip", "link", "set", pair.peer, "netns", pair.namespace)
		labCommand(t, "/sbin/ip", "addr", "add", pair.local, "dev", pair.device)
		labCommand(t, "/sbin/ip", "link", "set", pair.device, "up")
		ns(pair.namespace, "addr", "add", pair.remote, "dev", pair.peer)
		ns(pair.namespace, "link", "set", pair.peer, "up")
		ns(pair.namespace, "link", "set", "lo", "up")
	}
	labCommand(t, "/sbin/ip", "link", "set", "lo", "up")
	labCommand(t, "/sbin/ip", "route", "replace", "default", "via", "192.0.2.2", "dev", "outside0")
	ns(client, "route", "add", "default", "via", "10.44.0.1")
	ns(origin, "addr", "add", "8.8.8.8/32", "dev", "lo")
	ns(origin, "link", "add", "target-link", "type", "veth", "peer", "name", "target-peer")
	ns(origin, "link", "set", "target-peer", "netns", target)
	ns(origin, "addr", "add", "10.77.0.1/24", "dev", "target-link")
	ns(origin, "link", "set", "target-link", "up")
	ns(target, "addr", "add", "10.77.0.2/24", "dev", "target-peer")
	ns(target, "link", "set", "target-peer", "up")
	ns(target, "link", "set", "lo", "up")
	ns(target, "addr", "add", "1.1.1.1/32", "dev", "lo")
	ns(origin, "route", "add", "1.1.1.1/32", "via", "10.77.0.2")
	// Transparent replies use a nonlocal source address; disable strict reverse
	// path validation only inside this disposable router network namespace.
	for _, device := range []string{"all", "default", "home0", "outside0"} {
		if err := os.WriteFile(
			"/proc/sys/net/ipv4/conf/"+device+"/rp_filter",
			[]byte("0"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	r := continuityFixture(t)
	r.Sources = append(r.Sources, adapter.AllocatePath("b", "direct", 2))
	r.Standby = "b"
	r.Network.DNS = "selected-path"
	r.Network.DNSResolver = "1.1.1.1"
	r.Path.DNSPort = 14501
	r.Config.RelayAddress = "8.8.8.8:8443"
	cert, err := tls.X509KeyPair([]byte(r.Certificate), []byte(r.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	r.Config.RelayFingerprint = continuity.CertificateFingerprint(leaf)
	echo := continuityE2EChild(t, ctx, target, "origin", false)
	echo.exchange(t, continuityE2EMessage{})
	relay := continuityE2EChild(t, ctx, origin, "relay", false)
	relay.exchange(t, continuityE2EMessage{Worker: r})
	dir, err := os.MkdirTemp("/tmp", "rhp-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err = os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	server := &Server{
		Manager:        testManager(t, labBackend(), &testWatchdog{}),
		AllowedUID:     65534,
		SocketPath:     filepath.Join(dir, "helper.sock"),
		MaxConnections: 32,
	}
	serving := make(chan error, 1)
	go func() { serving <- server.Serve(ctx) }()
	for start := time.Now(); ; {
		if st, e := os.Stat(server.SocketPath); e == nil && st.Mode()&os.ModeSocket != 0 {
			break
		}
		select {
		case e := <-serving:
			t.Fatal(e)
		default:
		}
		if time.Since(start) > time.Second {
			t.Fatal("helper did not listen")
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Cleanup(func() {
		if t.Failed() {
			server.probeMu.Lock()
			reg := server.continuity
			server.probeMu.Unlock()
			if reg != nil {
				reg.mu.Lock()
				t.Logf("worker status: %+v", reg.status)
				reg.mu.Unlock()
			}
			out, _ := exec.Command("/usr/sbin/conntrack", "-L", "-p", "udp").CombinedOutput()
			t.Log("conntrack:", string(out))
		}
	})
	controller := continuityE2EChild(t, ctx, "", "controller", true)
	initial := controller.exchange(t, continuityE2EMessage{Worker: r, Socket: server.SocketPath})
	if initial.Status.ActivePath != "a" {
		t.Fatalf("wrong initial path: %+v", initial.Status)
	}
	lan := continuityE2EChild(t, ctx, client, "client", false)
	first := lan.exchange(t, continuityE2EMessage{Payload: []byte{0, 1, 2, 255}})
	lan.exchange(t, continuityE2EMessage{Payload: []byte("same-path-second")})
	before := string(labCommand(t, "/usr/sbin/nft", "list", "table", "inet", dataplane.Table))
	for _, primary := range []string{"b", "a", "b"} {
		standby := "a"
		if primary == "a" {
			standby = "b"
		}
		switched := controller.exchange(
			t,
			continuityE2EMessage{Action: "select", Primary: primary, Standby: standby},
		)
		if switched.Status.SessionID != initial.Status.SessionID ||
			switched.Status.Generation != initial.Status.Generation {
			t.Fatal("carrier switch replaced logical session")
		}
		after := lan.exchange(t, continuityE2EMessage{Payload: []byte("after-" + primary)})
		if strings.Join(first.IDs, "|") != strings.Join(after.IDs, "|") {
			t.Fatalf("destination TCP/UDP sockets changed: %v -> %v", first.IDs, after.IDs)
		}
	}
	empty := lan.exchange(t, continuityE2EMessage{Payload: []byte{}})
	if strings.Join(first.IDs, "|") != strings.Join(empty.IDs, "|") {
		t.Fatal("empty datagram changed socket")
	}
	after := string(labCommand(t, "/usr/sbin/nft", "list", "table", "inet", dataplane.Table))
	if before != after {
		t.Fatal("carrier selection changed LAN nftables rules")
	}
	t.Log(
		"TCP, UDP, TCP DNS and UDP DNS retained destination sockets across a→b→a→b; binary and empty datagrams returned from original addresses; LAN nftables unchanged",
	)
}

var continuityE2EOutput *json.Encoder

func TestLinuxContinuityTransparentE2EChild(t *testing.T) {
	role := os.Getenv("OPENRHP_CONTINUITY_E2E_ROLE")
	if role == "" {
		t.Skip("private integration subprocess")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("fixture refuses non-container host")
	}
	response := os.NewFile(3, "e2e-response")
	defer func() { _ = response.Close() }()
	continuityE2EOutput = json.NewEncoder(response)
	decoder := json.NewDecoder(os.Stdin)
	switch role {
	case "relay":
		continuityE2ERelay(t, decoder)
	case "origin":
		continuityE2EOrigin(t, decoder)
	case "controller":
		continuityE2EController(t, decoder)
	case "client":
		continuityE2ELAN(t, decoder)
	default:
		t.Fatal("invalid private fixture role")
	}
}

func continuityE2EAnswer(t *testing.T, message continuityE2EMessage) {
	t.Helper()
	if err := continuityE2EOutput.Encode(message); err != nil {
		t.Fatal(err)
	}
}

func continuityE2EController(t *testing.T, decoder *json.Decoder) {
	var initial continuityE2EMessage
	if err := decoder.Decode(&initial); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	c := &Client{SocketPath: initial.Socket, ExpectedUID: 0}
	r := initial.Worker
	for _, p := range r.Sources {
		if err := c.RegisterProbe(ctx, p.SourceID, p.Kind, p.Slot, p.Interface); err != nil {
			t.Fatal(err)
		}
	}
	process, err := c.StartContinuity(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = process.Close(context.Background()) }()
	wait := func(primary string) ContinuityStatus {
		deadline := time.Now().Add(12 * time.Second)
		for {
			s, e := c.ContinuityStatus(ctx)
			if e != nil {
				t.Fatal(e)
			}
			ready := 0
			for _, p := range s.Paths {
				if p.Ready {
					ready++
				}
			}
			if s.ActivePath == primary && ready == 2 {
				return s
			}
			if time.Now().After(deadline) {
				t.Fatalf("carriers did not become ready: %+v", s)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	status := wait(r.Preferred)
	d := dataplane.Desired{
		Network:    r.Network,
		Selected:   r.Preferred,
		Fallback:   "closed",
		Continuity: &dataplane.ContinuityIntent{Config: r.Config, Path: continuityAllocation(r)},
	}
	for _, p := range r.Sources {
		d.Paths = append(d.Paths, continuitySourceAllocation(p))
	}
	tx, err := c.Prepare(ctx, d)
	if err != nil {
		t.Fatal("prepare", err)
	}
	if _, err = c.Apply(ctx, tx.ID, 30*time.Second); err != nil {
		t.Fatal("apply", err)
	}
	if _, err = c.Confirm(ctx, tx.ID); err != nil {
		t.Fatal("confirm", err)
	}
	continuityE2EAnswer(t, continuityE2EMessage{Status: status})
	for {
		var command continuityE2EMessage
		if err = decoder.Decode(&command); err == io.EOF {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if command.Action != "select" {
			t.Fatal("unknown controller command")
		}
		if err = c.SelectContinuity(ctx, command.Primary, command.Standby); err != nil {
			t.Fatal(err)
		}
		continuityE2EAnswer(t, continuityE2EMessage{Status: wait(command.Primary)})
	}
}

func continuityE2ERelay(t *testing.T, decoder *json.Decoder) {
	var initial continuityE2EMessage
	if err := decoder.Decode(&initial); err != nil {
		t.Fatal(err)
	}
	r := initial.Worker
	cert, err := tls.X509KeyPair([]byte(r.Certificate), []byte(r.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig, err := continuity.ServerTLS(cert, []string{r.Config.RelayFingerprint})
	if err != nil {
		t.Fatal(err)
	}
	relay, err := continuity.NewRelay(continuity.RelayConfig{TLSConfig: tlsConfig})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = relay.Close() }()
	listener, err := net.Listen("tcp4", r.Config.RelayAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go func() { _ = relay.Serve(listener) }()
	continuityE2EAnswer(t, continuityE2EMessage{Action: "ready"})
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func continuityE2EOrigin(t *testing.T, decoder *json.Decoder) {
	var initial continuityE2EMessage
	if err := decoder.Decode(&initial); err != nil {
		t.Fatal(err)
	}
	var sequence atomic.Uint64
	for _, port := range []string{"18080", "53"} {
		listener, e := net.Listen("tcp4", "1.1.1.1:"+port)
		if e != nil {
			t.Fatal(e)
		}
		defer func() { _ = listener.Close() }()
		go func() {
			for {
				c, e := listener.Accept()
				if e != nil {
					return
				}
				id := fmt.Sprintf("tcp-%d", sequence.Add(1))
				go func() {
					defer func() { _ = c.Close() }()
					for {
						data, e := continuityE2ERead(c)
						if e != nil {
							return
						}
						if e = continuityE2EWrite(c, append([]byte(id+"|"), data...)); e != nil {
							return
						}
					}
				}()
			}
		}()
		udp, e := net.ListenPacket("udp4", "1.1.1.1:"+port)
		if e != nil {
			t.Fatal(e)
		}
		defer func() { _ = udp.Close() }()
		go func() {
			buf := make([]byte, 65535)
			for {
				n, address, e := udp.ReadFrom(buf)
				if e != nil {
					return
				}
				data := append([]byte(address.String()+"|"), buf[:n]...)
				if _, e = udp.WriteTo(data, address); e != nil {
					return
				}
			}
		}()
	}
	continuityE2EAnswer(t, continuityE2EMessage{Action: "ready"})
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func continuityE2ELAN(t *testing.T, decoder *json.Decoder) {
	var connections []net.Conn
	for _, network := range []string{"tcp4", "udp4"} {
		for _, address := range []string{"1.1.1.1:18080", "10.44.0.1:53"} {
			c, err := net.DialTimeout(network, address, 5*time.Second)
			if err != nil {
				t.Fatal(network, address, err)
			}
			defer func() { _ = c.Close() }()
			connections = append(connections, c)
		}
	}
	for {
		var command continuityE2EMessage
		err := decoder.Decode(&command)
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for i, c := range connections {
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			var result []byte
			if i < 2 {
				if err = continuityE2EWrite(c, command.Payload); err == nil {
					result, err = continuityE2ERead(c)
				}
			} else {
				_, err = c.Write(command.Payload)
				if err == nil {
					buf := make([]byte, 65535)
					var n int
					n, err = c.Read(buf)
					result = buf[:n]
				}
			}
			if err != nil {
				t.Fatalf("LAN flow %d failed: %v", i, err)
			}
			parts := bytes.SplitN(result, []byte("|"), 2)
			if len(parts) != 2 || !bytes.Equal(parts[1], command.Payload) {
				t.Fatalf("LAN flow %d payload changed", i)
			}
			ids = append(ids, string(parts[0]))
		}
		continuityE2EAnswer(t, continuityE2EMessage{IDs: ids})
	}
}

func continuityE2ERead(r io.Reader) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	payload := make([]byte, binary.BigEndian.Uint16(header[:]))
	_, err := io.ReadFull(r, payload)
	return payload, err
}

func continuityE2EWrite(w io.Writer, payload []byte) error {
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(payload)))
	writer := bufio.NewWriter(w)
	if _, err := writer.Write(header[:]); err != nil {
		return err
	}
	if _, err := writer.Write(payload); err != nil {
		return err
	}
	return writer.Flush()
}
