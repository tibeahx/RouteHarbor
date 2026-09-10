//go:build linux

package helper

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/dispatch"
	"github.com/tibeahx/OpenRHP/internal/routing"
)

type dispatcherLabReady struct {
	Slots []int    `json:"slots"`
	Ports []int    `json:"ports"`
	Fake  []string `json:"fake"`
}

// A one-slot test helper may close the next connection while its preceding
// completed response is still unwinding. Only fixture-owned idempotent uploads
// and reads use this bounded admission retry; worker starts are never replayed.
func dispatcherLabRPC(ctx context.Context, operation func() error) error {
	var err error
	for attempt := 0; attempt < 8; attempt++ {
		if err = operation(); err == nil {
			return nil
		}
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) &&
			!errors.Is(err, syscall.EPIPE) &&
			!errors.Is(err, syscall.ECONNRESET) &&
			err.Error() != "helper_busy" {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	return err
}

func TestLinuxDispatcherHotPublishFixture(t *testing.T) {
	if os.Getenv("OPENRHP_DISPATCHER_PUBLISH_SLOT") == "" {
		t.Skip("subprocess fixture only")
	}
	if os.Geteuid() != 65534 {
		t.Fatal("publication must use unprivileged API")
	}
	slot, err := strconv.Atoi(os.Getenv("OPENRHP_DISPATCHER_PUBLISH_SLOT"))
	if err != nil {
		t.Fatal(err)
	}
	var ref routing.SnapshotRef
	if err = json.Unmarshal([]byte(os.Getenv("OPENRHP_DISPATCHER_PUBLISH_REF")), &ref); err != nil {
		t.Fatal(err)
	}
	client := &Client{SocketPath: os.Getenv("OPENRHP_DISPATCHER_WORKER_SOCKET"), ExpectedUID: 0}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	started := time.Now()
	status, err := client.Dispatcher(
		ctx,
		DispatcherRequest{
			Action:   "publish",
			Slot:     slot,
			Snapshot: &ref,
			Learned:  []string{"openrhp-scale-learned.example"},
		},
	)
	if err != nil || status.PublishedGeneration != 2 {
		t.Fatal("typed live publication", err)
	}
	t.Logf("typed full-list hot publication: elapsed=%s", time.Since(started))
}

func dispatcherLabPublicFixtures(t *testing.T) int {
	t.Helper()
	dns, err := net.Listen("tcp4", "11.0.0.53:53")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dns.Close() })
	go func() {
		for {
			connection, err := dns.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = connection.Close() }()
				for {
					var header [2]byte
					if _, err := io.ReadFull(connection, header[:]); err != nil {
						return
					}
					size := int(binary.BigEndian.Uint16(header[:]))
					if size < 17 || size > 4096 {
						return
					}
					question := make([]byte, size)
					if _, err := io.ReadFull(connection, question); err != nil {
						return
					}
					end := 12
					for end < size && question[end] != 0 {
						end += int(question[end]) + 1
					}
					if end+5 > size {
						return
					}
					typ := binary.BigEndian.Uint16(question[end+1 : end+3])
					question = question[:end+5]
					question[2], question[3] = 0x81, 0x80
					for index := 6; index < 12; index++ {
						question[index] = 0
					}
					if typ == 1 {
						binary.BigEndian.PutUint16(question[6:8], 1)
						question = append(
							question,
							0xc0,
							0x0c,
							0,
							1,
							0,
							1,
							0,
							0,
							0,
							30,
							0,
							4,
							11,
							0,
							0,
							2,
						)
					}
					response := append(
						[]byte{byte(len(question) >> 8), byte(len(question))},
						question...)
					if _, err := connection.Write(response); err != nil {
						return
					}
				}
			}()
		}
	}()
	echo, err := net.Listen("tcp4", "11.0.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	go func() {
		for {
			connection, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer func() { _ = connection.Close() }(); _, _ = io.Copy(connection, connection) }()
		}
	}()
	return echo.Addr().(*net.TCPAddr).Port
}

func dispatcherLabTransparent(t *testing.T, port int) {
	t.Helper()
	labCommand(t, "/sbin/ip", "netns", "add", "lab-dispatcher-client")
	t.Cleanup(
		func() { _ = exec.Command("/sbin/ip", "netns", "del", "lab-dispatcher-client").Run() },
	)
	labCommand(
		t,
		"/sbin/ip",
		"link",
		"add",
		"lab-lan",
		"type",
		"veth",
		"peer",
		"name",
		"lab-client",
	)
	t.Cleanup(func() { _ = exec.Command("/sbin/ip", "link", "del", "lab-lan").Run() })
	labCommand(t, "/sbin/ip", "link", "set", "lab-client", "netns", "lab-dispatcher-client")
	labCommand(t, "/sbin/ip", "address", "add", "192.168.1.1/24", "dev", "lab-lan")
	labCommand(t, "/sbin/ip", "link", "set", "lab-lan", "up")
	labCommand(
		t,
		"/sbin/ip",
		"-n",
		"lab-dispatcher-client",
		"address",
		"add",
		"192.168.1.2/24",
		"dev",
		"lab-client",
	)
	labCommand(t, "/sbin/ip", "-n", "lab-dispatcher-client", "link", "set", "lo", "up")
	labCommand(t, "/sbin/ip", "-n", "lab-dispatcher-client", "link", "set", "lab-client", "up")
	labCommand(
		t,
		"/sbin/ip",
		"-n",
		"lab-dispatcher-client",
		"route",
		"add",
		"default",
		"via",
		"192.168.1.1",
	)
	for _, path := range []string{"/proc/sys/net/ipv4/conf/all/rp_filter", "/proc/sys/net/ipv4/conf/default/rp_filter", "/proc/sys/net/ipv4/conf/lab-lan/rp_filter"} {
		if err := os.WriteFile(path, []byte("0"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	labCommand(t, "/sbin/ip", "-4", "route", "add", "local", "198.18.0.0/15", "dev", "lo")
	command := exec.Command("/usr/sbin/nft", "-f", "-")
	command.Stdin = strings.NewReader(
		"table ip lab_dispatcher {\n chain prerouting {\n type filter hook prerouting priority mangle; policy accept;\n ip daddr 198.18.0.0/15 ip protocol tcp tproxy to 127.0.0.1:" + strconv.Itoa(
			port,
		) + " accept;\n }\n}\n",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("lab classifier interception: %v %s", err, output)
	}
	t.Cleanup(func() {
		_ = exec.Command("/usr/sbin/nft", "delete", "table", "ip", "lab_dispatcher").Run()
		_ = exec.Command("/sbin/ip", "-4", "route", "del", "local", "198.18.0.0/15", "dev", "lo").
			Run()
	})
}

func TestLinuxDispatcherTrafficFixture(t *testing.T) {
	ordinaryTarget := os.Getenv("OPENRHP_DISPATCHER_ORDINARY_TARGET")
	if ordinaryTarget == "" {
		t.Skip("subprocess fixture only")
	}
	learnedTarget := os.Getenv("OPENRHP_DISPATCHER_LEARNED_TARGET")
	held, err := net.DialTimeout("tcp4", ordinaryTarget, time.Second)
	if err != nil {
		t.Fatal("ordinary direct setup", err)
	}
	defer func() { _ = held.Close() }()
	dispatcherLabEcho(t, held)
	unknown, err := net.DialTimeout("tcp4", learnedTarget, time.Second)
	if err != nil {
		t.Fatal("unknown direct setup", err)
	}
	dispatcherLabEcho(t, unknown)
	_ = unknown.Close()
	if err = os.WriteFile(
		os.Getenv("OPENRHP_DISPATCHER_TRAFFIC_READY"),
		[]byte("ready"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(45 * time.Second)
	for {
		if _, err = os.Stat(os.Getenv("OPENRHP_DISPATCHER_TRAFFIC_PUBLISHED")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("publication never signaled")
		}
		time.Sleep(20 * time.Millisecond)
	}
	started := time.Now()
	for {
		learned, err := net.DialTimeout("tcp4", learnedTarget, time.Second)
		if err == nil {
			err = dispatcherLabExchange(learned)
			_ = learned.Close()
		}
		if err != nil {
			break
		}
		if time.Since(started) > 12*time.Second {
			t.Fatal("published learned rule never applied by native engine")
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Logf(
		"native full-list rule application observed after publication: elapsed=%s",
		time.Since(started),
	)
	dispatcherLabEcho(t, held)
	ordinary, err := net.DialTimeout("tcp4", ordinaryTarget, time.Second)
	if err != nil {
		t.Fatal("publication broke new ordinary direct flows", err)
	}
	dispatcherLabEcho(t, ordinary)
	_ = ordinary.Close()
}

func dispatcherLabFakeTarget(t *testing.T, dnsPort int, domain string, targetPort int) string {
	t.Helper()
	reply := dispatcherLabDNS(t, dnsPort, "udp", domain, 1)
	if len(reply) < 16 || binary.BigEndian.Uint16(reply[6:8]) != 1 {
		t.Fatal("missing classification FakeIP")
	}
	address, ok := netip.AddrFromSlice(reply[len(reply)-4:])
	if !ok || !netip.MustParsePrefix(dispatch.FakeIPv4).Contains(address) {
		t.Fatal("invalid classification FakeIP")
	}
	return net.JoinHostPort(address.String(), strconv.Itoa(targetPort))
}

func dispatcherLabExchange(connection net.Conn) error {
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	if _, err := connection.Write([]byte("ordinary direct remains alive")); err != nil {
		return err
	}
	got := make([]byte, len("ordinary direct remains alive"))
	if _, err := io.ReadFull(connection, got); err != nil {
		return err
	}
	if string(got) != "ordinary direct remains alive" {
		return errors.New("direct stream response mismatch")
	}
	return nil
}

func dispatcherLabEcho(t *testing.T, connection net.Conn) {
	t.Helper()
	if err := dispatcherLabExchange(connection); err != nil {
		t.Fatal("ordinary direct stream was interrupted", err)
	}
}

func dispatcherLabDNS(t *testing.T, port int, network, name string, typ uint16) []byte {
	t.Helper()
	q := make([]byte, 12)
	q[0] = 0x72
	q[2] = 1
	binary.BigEndian.PutUint16(q[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, byte(typ>>8), byte(typ), 0, 1)
	c, e := net.DialTimeout(network, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	var out []byte
	if network == "tcp" {
		packet := append([]byte{byte(len(q) >> 8), byte(len(q))}, q...)
		if _, e = c.Write(packet); e != nil {
			t.Fatal(e)
		}
		var h [2]byte
		if _, e = io.ReadFull(c, h[:]); e != nil {
			t.Fatal(e)
		}
		out = make([]byte, binary.BigEndian.Uint16(h[:]))
		if _, e = io.ReadFull(c, out); e != nil {
			t.Fatal(e)
		}
	} else {
		if _, e = c.Write(q); e != nil {
			t.Fatal(e)
		}
		out = make([]byte, 4096)
		n, e := c.Read(out)
		if e != nil {
			t.Fatal(e)
		}
		out = out[:n]
	}
	if len(out) < 12 || out[0] != q[0] || out[1] != q[1] || out[2]&0x80 == 0 || out[3]&15 != 0 {
		t.Fatal("DNS health/data response invalid")
	}
	return out
}

// The child exercises the production Unix RPC and worker launch as the actual
// unprivileged service UID. It has no network capabilities or direct file access
// to the helper's root-owned routing snapshots.
func TestLinuxDispatcherWorkerClientFixture(t *testing.T) {
	if os.Getenv("OPENRHP_DISPATCHER_WORKER_CHILD") != "1" {
		t.Skip("subprocess fixture only")
	}
	if os.Geteuid() == 0 {
		t.Fatal("dispatcher API fixture must be unprivileged")
	}
	client := &Client{SocketPath: os.Getenv("OPENRHP_DISPATCHER_WORKER_SOCKET"), ExpectedUID: 0}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if e := dispatcherLabRPC(
		ctx,
		func() error { return client.RegisterProbe(ctx, "tunnel", "interface", 4, "lo") },
	); e != nil {
		t.Fatal("register prepared fixture path", e)
	}
	snapshot := routing.Snapshot{
		Generation: 1,
		CreatedAt:  time.Now().UTC(),
		Domains:    []string{"blocked.example"},
		CIDRs:      []string{},
	}
	if path := os.Getenv("OPENRHP_DISPATCHER_SCALE_DOMAINS"); path != "" {
		started := time.Now()
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		snapshot.Domains, snapshot.RejectedDomains, err = routing.ParseRegistryDomains(file)
		_ = file.Close()
		if err != nil {
			t.Fatal("offline provider fixture", err)
		}
		t.Logf(
			"offline provider parse: domains=%d rejected=%d elapsed=%s",
			len(snapshot.Domains),
			snapshot.RejectedDomains,
			time.Since(started),
		)
	}
	started := time.Now()
	var ref routing.SnapshotRef
	e := dispatcherLabRPC(
		ctx,
		func() error { var err error; ref, err = client.UploadSnapshot(ctx, snapshot); return err },
	)
	if e != nil {
		t.Fatal("typed snapshot upload", e)
	}
	t.Logf("typed snapshot upload: bytes=%d elapsed=%s", ref.Size, time.Since(started))
	started = time.Now()
	var recovered routing.Snapshot
	var loadedRef routing.SnapshotRef
	e = dispatcherLabRPC(ctx, func() error {
		var err error
		recovered, loadedRef, err = client.LoadRoutingSnapshot(ctx, ref.Generation, ref.SHA256)
		return err
	})
	if e != nil || loadedRef != ref || len(recovered.Domains) != len(snapshot.Domains) {
		t.Fatal("typed snapshot recovery", e)
	}
	t.Logf("typed snapshot recovery: elapsed=%s", time.Since(started))
	manager := adapter.NewManager(os.Getenv("OPENRHP_DISPATCHER_WORKER_STATE"))
	events := make(chan string, 16)
	var processes []adapter.ManagedProcess
	var heldKeys []string
	defer func() {
		for _, p := range processes {
			_ = p.Close(context.Background())
		}
		for _, key := range heldKeys {
			manager.ForgetDispatcherFor(key)
		}
	}()
	ready := dispatcherLabReady{}
	poolCount := uint8(2)
	if os.Getenv("OPENRHP_DISPATCHER_SCALE_DOMAINS") != "" {
		poolCount = 1
		if os.Getenv("OPENRHP_DISPATCHER_SCALE_WORKERS") == "2" {
			poolCount = 2
		}
	}
	for pool := uint8(0); pool < poolCount; pool++ {
		key := "lab-dispatcher-" + strconv.Itoa(int(pool))
		a, e := manager.ReserveDispatcherFor(key, nil, 0, false)
		if e != nil {
			t.Fatal(e)
		}
		heldKeys = append(heldKeys, key)
		a.FakePool = pool
		spec := securityDispatcherSpec()
		spec.Allocation = a
		spec.Network.WANInterface = "lo"
		spec.Network.IPv6 = "block"
		spec.Sources[0].Interface = "lo"
		spec.Sources[0].IPv6 = false
		if os.Getenv("OPENRHP_DISPATCHER_WORKER_CRASH") == "1" {
			// Reuse the earlier healthy worker's persisted cache, but prepare
			// bypass-unavailable mode. Persisted Clash mode must not override it.
			spec.Selected = ""
		}
		manager.ReleaseDispatcherInputsFor(key)
		started = time.Now()
		process, e := client.StartDispatcher(ctx, spec, ref, func(domain string) {
			select {
			case events <- domain:
			default:
			}
		})
		if e != nil {
			t.Fatal("typed dispatcher start", e)
		}
		t.Logf("typed dispatcher ready: pool=%d elapsed=%s", pool, time.Since(started))
		processes = append(processes, process)
		var status DispatcherStatus
		e = dispatcherLabRPC(ctx, func() error {
			var err error
			status, err = client.Dispatcher(
				ctx,
				DispatcherRequest{Action: "status", Slot: a.Path.Slot},
			)
			return err
		})
		if e != nil || !status.Running {
			t.Fatal("dispatcher blocked ordinary RPC admission", e)
		}
		if e = dispatcherLabRPC(
			ctx,
			func() error { _, err := client.Status(ctx); return err },
		); e != nil {
			t.Fatal("long-lived dispatcher retained RPC slot", e)
		}
		for _, network := range []string{"udp", "tcp"} {
			response := dispatcherLabDNS(t, a.DNSFrontPort, network, routing.DNSHealthName, 1)
			if binary.BigEndian.Uint16(response[6:8]) != 1 {
				t.Fatal("health name did not confirm native engine DNS")
			}
		}
		response := dispatcherLabDNS(t, a.DNSFrontPort, "udp", "observed.example", 1)
		if binary.BigEndian.Uint16(response[6:8]) != 1 || len(response) < 16 {
			t.Fatal("missing real FakeIP answer")
		}
		ip, ok := netip.AddrFromSlice(response[len(response)-4:])
		if !ok || !netip.MustParsePrefix(dispatch.FakePoolIPv4(pool)).Contains(ip) {
			t.Fatal("worker returned wrong FakeIP pool", ip)
		}
		ready.Fake = append(ready.Fake, ip.String())
		select {
		case name := <-events:
			if name != "observed.example" {
				t.Fatal("unexpected DNS observation", name)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("production DNS observation pipe is silent")
		}
		response = dispatcherLabDNS(t, a.DNSFrontPort, "tcp", "observed.example", 65)
		if binary.BigEndian.Uint16(response[6:8]) != 0 {
			t.Fatal("HTTPS record bypassed FakeIP classification")
		}
		select {
		case <-events:
			t.Fatal("health/HTTPS query emitted extra DNS observation")
		default:
		}
		ready.Slots = append(ready.Slots, a.Path.Slot)
		ready.Ports = append(
			ready.Ports,
			a.Path.TransparentPort,
			a.Path.ProxyPort,
			a.Path.DNSPort,
			a.DNSFrontPort,
			a.DirectPort,
			a.APIPort,
		)
	}
	if len(ready.Fake) == 2 && ready.Fake[0] == ready.Fake[1] {
		t.Fatal("staged instances shared FakeIP address")
	}
	raw, _ := json.Marshal(ready)
	if e = os.WriteFile(os.Getenv("OPENRHP_DISPATCHER_WORKER_READY"), raw, 0o600); e != nil {
		t.Fatal(e)
	}
	if os.Getenv("OPENRHP_DISPATCHER_WORKER_CRASH") == "1" {
		select {}
	}
	for {
		if _, e = os.Stat(os.Getenv("OPENRHP_DISPATCHER_WORKER_STOP")); e == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("owner stop signal missing")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, p := range processes {
		if e = p.Close(ctx); e != nil {
			t.Fatal("owner close", e)
		}
	}
	processes = nil
	for _, port := range ready.Ports {
		l, e := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if e != nil {
			t.Fatal("owner close returned before listener release", e)
		}
		_ = l.Close()
	}
}

func dispatcherLabChildPID(worker int, fragment string) string {
	tasks, _ := filepath.Glob("/proc/" + strconv.Itoa(worker) + "/task/*/children")
	for _, task := range tasks {
		children, _ := os.ReadFile(task)
		for _, pid := range strings.Fields(string(children)) {
			args, _ := os.ReadFile("/proc/" + pid + "/cmdline")
			if strings.Contains(strings.ReplaceAll(string(args), "\x00", " "), fragment) {
				return pid
			}
		}
	}
	return ""
}

func dispatcherLabCredentials(t *testing.T, pid, capability string) {
	t.Helper()
	status, e := os.ReadFile("/proc/" + pid + "/status")
	if e != nil {
		t.Fatal(e)
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(status), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			fields[key] = strings.TrimSpace(value)
		}
	}
	if fields["Uid"] != "65534\t65534\t65534\t65534" ||
		fields["Gid"] != "65534\t65534\t65534\t65534" ||
		fields["Groups"] != "" {
		t.Fatal("worker identity/groups were not dropped")
	}
	for _, name := range []string{"CapEff", "CapPrm", "CapInh", "CapAmb"} {
		if fields[name] != capability {
			t.Fatalf("%s was %s, expected %s", name, fields[name], capability)
		}
	}
}

func TestLinuxDispatcherConfigurationIsolationFixture(t *testing.T) {
	engine := os.Getenv("OPENRHP_DISPATCHER_ISOLATION_ENGINE")
	if engine == "" {
		t.Skip("subprocess fixture only")
	}
	if os.Geteuid() != 65534 {
		t.Fatal("configuration isolation fixture must be service UID")
	}
	if _, err := os.ReadFile(filepath.Join("/proc", engine, "fd", "3")); !os.IsPermission(err) {
		t.Fatal("service UID could access privileged engine configuration", err)
	}
	front := os.Getenv("OPENRHP_DISPATCHER_ISOLATION_FRONT")
	raw, err := os.ReadFile(filepath.Join("/proc", front, "fd", "3"))
	if err != nil {
		t.Fatal("capability-free DNS frontend descriptor unavailable", err)
	}
	var config dnsFrontConfig
	if DecodeStrict(raw, &config) != nil || !config.valid() {
		t.Fatal("DNS frontend inherited fields beyond its narrow configuration")
	}
}

func TestLinuxDispatcherWorkerRPCPrivilegesDNSAndOwnerCleanup(t *testing.T) {
	requireNetLab(t)
	if os.Getenv("OPENRHP_DISPATCHER_WORKER_LAB") != "1" {
		t.Skip("requires isolated pinned sing-box worker lab")
	}
	echoPort := dispatcherLabPublicFixtures(t)
	for _, crash := range []bool{false, true} {
		if crash && os.Getenv("OPENRHP_DISPATCHER_SCALE_DOMAINS") != "" {
			continue
		}
		t.Run(map[bool]string{false: "close", true: "owner_crash"}[crash], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			root, e := os.MkdirTemp("", "openrhp-dispatcher-rpc-")
			if e != nil {
				t.Fatal(e)
			}
			defer func() { _ = os.RemoveAll(root) }()
			if e = os.Chmod(root, 0o755); e != nil {
				t.Fatal(e)
			}
			out := filepath.Join(root, "owner")
			if e = os.Mkdir(out, 0o700); e != nil {
				t.Fatal(e)
			}
			if e = os.Chown(out, 65534, 65534); e != nil {
				t.Fatal(e)
			}
			socket := filepath.Join(root, "helper.sock")
			s := &Server{
				Manager:        testManager(t, &memoryBackend{}, &testWatchdog{}),
				AllowedUID:     65534,
				SocketPath:     socket,
				MaxConnections: 1,
				inspectProbeTunnel: func(ctx context.Context, device string) error {
					if device != "lo" {
						return errors.New("unexpected lab interface")
					}
					return nil
				},
			}
			if os.Getenv("OPENRHP_DISPATCHER_SCALE_DOMAINS") != "" {
				// Use production admission capacity for the bulk transfer. The
				// small fixture separately verifies long-lived workers release it.
				s.MaxConnections = 8
			}
			done := make(chan error, 1)
			go func() { done <- s.Serve(ctx) }()
			defer func() { cancel(); <-done }()
			deadline := time.Now().Add(2 * time.Second)
			for {
				if _, e = os.Stat(socket); e == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("helper socket unavailable")
				}
				time.Sleep(10 * time.Millisecond)
			}
			readyFile, stopFile := filepath.Join(out, "ready.json"), filepath.Join(out, "stop")
			child := exec.Command(
				os.Args[0],
				"-test.run=^TestLinuxDispatcherWorkerClientFixture$",
				"-test.v",
			)
			child.Env = append(
				os.Environ(),
				"OPENRHP_DISPATCHER_WORKER_CHILD=1",
				"OPENRHP_DISPATCHER_WORKER_SOCKET="+socket,
				"OPENRHP_DISPATCHER_WORKER_STATE="+out,
				"OPENRHP_DISPATCHER_WORKER_READY="+readyFile,
				"OPENRHP_DISPATCHER_WORKER_STOP="+stopFile,
			)
			if crash {
				child.Env = append(child.Env, "OPENRHP_DISPATCHER_WORKER_CRASH=1")
			}
			child.SysProcAttr = &syscall.SysProcAttr{
				Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}},
			}
			child.Stdout, child.Stderr = os.Stderr, os.Stderr
			if e = child.Start(); e != nil {
				t.Fatal(e)
			}
			childDone := make(chan error, 1)
			go func() { childDone <- child.Wait() }()
			defer func() { _ = child.Process.Kill() }()
			var ready dispatcherLabReady
			deadline = time.Now().Add(110 * time.Second)
			for {
				raw, err := os.ReadFile(readyFile)
				if err == nil && json.Unmarshal(raw, &ready) == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("unprivileged dispatcher fixture failed to become ready")
				}
				select {
				case err := <-childDone:
					t.Fatal("unprivileged dispatcher fixture exited before ready", err)
				default:
				}
				time.Sleep(20 * time.Millisecond)
			}
			dispatcherLabCredentials(t, strconv.Itoa(child.Process.Pid), "0000000000000000")
			var pids []string
			for _, slot := range ready.Slots {
				s.probeMu.Lock()
				record := s.dispatchers[slot]
				if record == nil || record.cmd == nil {
					s.probeMu.Unlock()
					t.Fatal("ready dispatcher not registered")
				}
				worker := record.cmd.Process.Pid
				secret := record.secret
				apiPort := record.spec.Allocation.APIPort
				s.probeMu.Unlock()
				request, err := http.NewRequestWithContext(
					ctx,
					http.MethodGet,
					"http://127.0.0.1:"+strconv.Itoa(apiPort)+"/configs",
					nil,
				)
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("Authorization", "Bearer "+secret)
				transport := &http.Transport{}
				client := &http.Client{Transport: transport, Timeout: time.Second}
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				var apiConfig struct {
					Mode string `json:"mode"`
				}
				err = json.NewDecoder(io.LimitReader(response.Body, 8192)).Decode(&apiConfig)
				_ = response.Body.Close()
				transport.CloseIdleConnections()
				wantMode := "rule"
				if crash {
					wantMode = "global"
				}
				if err != nil || strings.ToLower(apiConfig.Mode) != wantMode {
					t.Fatal("persisted mode overrode typed prepared selection", apiConfig.Mode, err)
				}
				engine := engineChildPID(worker, "sing-box")
				front := dispatcherLabChildPID(worker, "dns-front")
				if engine == "" || front == "" {
					t.Fatal("native engine/DNS frontend not owned by supervisor")
				}
				dispatcherLabCredentials(t, engine, "0000000000002000")
				dispatcherLabCredentials(t, front, "0000000000000000")
				if !crash && os.Getenv("OPENRHP_DISPATCHER_SCALE_DOMAINS") == "" {
					dispatcherLabEngineHangHealth(t, record.spec, record.ref, engine, front)
				}
				for label, pid := range map[string]string{"helper": strconv.Itoa(os.Getpid()), "control": strconv.Itoa(child.Process.Pid), "engine": engine, "dns_front": front} {
					status, err := os.ReadFile("/proc/" + pid + "/status")
					if err != nil {
						t.Fatal(err)
					}
					for _, line := range strings.Split(string(status), "\n") {
						if strings.HasPrefix(line, "VmRSS:") || strings.HasPrefix(line, "VmHWM:") {
							t.Logf("process memory %s %s", label, line)
						}
					}
				}
				pids = append(pids, engine, front, strconv.Itoa(worker))
				for _, pid := range []string{engine, front} {
					args, e := os.ReadFile("/proc/" + pid + "/cmdline")
					if e != nil || bytes.Contains(args, []byte(secret)) {
						t.Fatal("private dispatcher configuration leaked into arguments")
					}
					fd := filepath.Join("/proc", pid, "fd", "3")
					contents, e := os.ReadFile(fd)
					if e != nil || len(contents) == 0 ||
						bytes.Contains(contents, []byte(secret)) != (pid == engine) {
						t.Fatal("configuration descriptor exceeded process authority")
					}
					info, e := os.Stat(fd)
					if e != nil || info.Mode().Perm()&0o007 != 0 {
						t.Fatal("inherited configuration world readable")
					}
				}
				isolation := exec.Command(
					os.Args[0],
					"-test.run=^TestLinuxDispatcherConfigurationIsolationFixture$",
					"-test.v",
				)
				isolation.Env = append(
					os.Environ(),
					"OPENRHP_DISPATCHER_ISOLATION_ENGINE="+engine,
					"OPENRHP_DISPATCHER_ISOLATION_FRONT="+front,
				)
				isolation.SysProcAttr = &syscall.SysProcAttr{
					Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}},
				}
				if output, err := isolation.CombinedOutput(); err != nil {
					t.Fatalf("same-UID configuration isolation: %v\n%s", err, output)
				}
			}
			if !crash {
				s.probeMu.Lock()
				record := s.dispatchers[ready.Slots[0]]
				spec, ref, workerPID := record.spec, record.ref, record.cmd.Process.Pid
				s.probeMu.Unlock()
				enginePID := engineChildPID(workerPID, "sing-box")
				if _, err := s.dispatcherAction(
					ctx,
					DispatcherRequest{Action: "select", Slot: ready.Slots[0], Selected: ""},
				); err != nil {
					t.Fatal(err)
				}
				dispatcherLabTransparent(t, spec.Allocation.Path.TransparentPort)
				ordinaryTarget := dispatcherLabFakeTarget(
					t,
					spec.Allocation.DNSFrontPort,
					"ordinary-scale.example",
					echoPort,
				)
				learnedTarget := dispatcherLabFakeTarget(
					t,
					spec.Allocation.DNSFrontPort,
					"openrhp-scale-learned.example",
					echoPort,
				)
				trafficReady, trafficPublished := filepath.Join(
					out,
					"traffic-ready",
				), filepath.Join(
					out,
					"traffic-published",
				)
				traffic := exec.Command(
					"/sbin/ip",
					"netns",
					"exec",
					"lab-dispatcher-client",
					os.Args[0],
					"-test.run=^TestLinuxDispatcherTrafficFixture$",
					"-test.v",
				)
				traffic.Env = append(
					os.Environ(),
					"OPENRHP_DISPATCHER_ORDINARY_TARGET="+ordinaryTarget,
					"OPENRHP_DISPATCHER_LEARNED_TARGET="+learnedTarget,
					"OPENRHP_DISPATCHER_TRAFFIC_READY="+trafficReady,
					"OPENRHP_DISPATCHER_TRAFFIC_PUBLISHED="+trafficPublished,
				)
				traffic.Stdout, traffic.Stderr = os.Stderr, os.Stderr
				if err := traffic.Start(); err != nil {
					t.Fatal(err)
				}
				defer func() { _ = traffic.Process.Kill() }()
				trafficDone := make(chan error, 1)
				go func() { trafficDone <- traffic.Wait() }()
				deadline = time.Now().Add(10 * time.Second)
				for {
					if _, err := os.Stat(trafficReady); err == nil {
						break
					}
					select {
					case err := <-trafficDone:
						t.Fatal("direct traffic fixture failed", err)
					default:
					}
					if time.Now().After(deadline) {
						t.Fatal("direct traffic fixture did not become ready")
					}
					time.Sleep(20 * time.Millisecond)
				}
				if err := s.Manager.locked(func(state *State) error {
					desired := securityDispatcherIntent(spec, ref)
					state.Committed = &desired
					return s.Manager.save(state)
				}); err != nil {
					t.Fatal(err)
				}
				refJSON, _ := json.Marshal(ref)
				publish := exec.Command(
					os.Args[0],
					"-test.run=^TestLinuxDispatcherHotPublishFixture$",
					"-test.v",
				)
				publish.Env = append(
					os.Environ(),
					"OPENRHP_DISPATCHER_WORKER_SOCKET="+socket,
					"OPENRHP_DISPATCHER_PUBLISH_SLOT="+strconv.Itoa(ready.Slots[0]),
					"OPENRHP_DISPATCHER_PUBLISH_REF="+string(refJSON),
				)
				publish.SysProcAttr = &syscall.SysProcAttr{
					Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}},
				}
				started := time.Now()
				output, err := publish.CombinedOutput()
				if err != nil {
					t.Fatalf("hot publication: %v\n%s", err, output)
				}
				t.Logf("%s", output)
				if err = os.WriteFile(trafficPublished, []byte("published"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err = <-trafficDone; err != nil {
					t.Fatal("held/new direct traffic after native publication", err)
				}
				t.Logf(
					"full-list publish and native application with held direct connection: elapsed=%s",
					time.Since(started),
				)
				s.probeMu.Lock()
				live := s.dispatchers[ready.Slots[0]]
				unchanged := live == record && live.cmd.Process.Pid == workerPID
				s.probeMu.Unlock()
				if !unchanged {
					t.Fatal("hot publication replaced the worker")
				}
				if enginePID == "" || engineChildPID(workerPID, "sing-box") != enginePID {
					t.Fatal("hot publication restarted the native dispatcher")
				}
			}
			if crash {
				if e = child.Process.Kill(); e != nil {
					t.Fatal(e)
				}
				<-childDone
			} else {
				if e = os.WriteFile(stopFile, []byte("stop"), 0o644); e != nil {
					t.Fatal(e)
				}
				if e = <-childDone; e != nil {
					t.Fatal("explicit owner close failed", e)
				}
			}
			deadline = time.Now().Add(5 * time.Second)
			for {
				s.probeMu.Lock()
				count := len(s.dispatchers)
				s.probeMu.Unlock()
				gone := count == 0
				for _, pid := range pids {
					if _, e = os.Stat("/proc/" + pid); !os.IsNotExist(e) {
						gone = false
					}
				}
				if gone {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("owner loss retained dispatcher process or registration")
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	}
}
