//go:build linux

package continuityrun

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/adapter"
	"github.com/tibeahx/RouteHarbor/internal/continuity"
	"github.com/tibeahx/RouteHarbor/internal/dataplane"
	"github.com/tibeahx/RouteHarbor/internal/dispatch"
	"github.com/tibeahx/RouteHarbor/internal/model"
	"github.com/tibeahx/RouteHarbor/internal/node"
	"github.com/tibeahx/RouteHarbor/internal/probe"
	"github.com/tibeahx/RouteHarbor/internal/routing"
)

// The test composes the production classifier, comparative probe, detector and
// private relay bridge. Its addresses belong only to disconnected namespaces.
type selectiveAcceptanceMessage struct {
	Action, Domain, Network, Payload, IP, ID, Source, Error string
	TTL                                                     uint32
}

type selectiveAcceptanceChild struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out *json.Decoder
}

func (c *selectiveAcceptanceChild) request(
	t *testing.T,
	v selectiveAcceptanceMessage,
) selectiveAcceptanceMessage {
	t.Helper()
	if err := json.NewEncoder(c.in).Encode(v); err != nil {
		t.Fatal(err)
	}
	var out selectiveAcceptanceMessage
	done := make(chan error, 1)
	go func() { done <- c.out.Decode(&out) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("namespace child response", err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("namespace child response timed out")
	}
	return out
}

type selectiveAcceptanceLab struct {
	t                     *testing.T
	ctx                   context.Context
	dir, rules, config    string
	server, client, relay *selectiveAcceptanceChild
	engine                *exec.Cmd
	rootCAs               *x509.CertPool
	gatewayIdentity       node.Identity
	relayIdentity         node.Identity
	spec                  dispatch.Spec
	observations          chan string
}

func selectiveAcceptanceCommand(t *testing.T, name string, args ...string) []byte {
	t.Helper()
	value, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("lab command %s %v: %v %s", name, args, err, value)
	}
	return value
}

func newSelectiveAcceptanceLab(t *testing.T) *selectiveAcceptanceLab {
	t.Helper()
	if os.Getenv("ROUTEHARBOR_SELECTIVE_ACCEPTANCE_LAB") != "1" {
		t.Skip("requires disconnected native selective acceptance lab")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil || os.Geteuid() != 0 {
		t.Fatal("fixture requires isolated root Docker namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	t.Cleanup(cancel)
	f := &selectiveAcceptanceLab{
		t:            t,
		ctx:          ctx,
		dir:          t.TempDir(),
		observations: make(chan string, 64),
	}
	ip := func(args ...string) { selectiveAcceptanceCommand(t, "/sbin/ip", args...) }
	ns := func(namespace string, args ...string) {
		ip(append([]string{"netns", "exec", namespace, "/sbin/ip"}, args...)...)
	}
	for _, namespace := range []string{"selective-client", "selective-origin", "selective-relay"} {
		ip("netns", "add", namespace)
		t.Cleanup(func() { _ = exec.Command("/sbin/ip", "netns", "del", namespace).Run() })
		ns(namespace, "link", "set", "lo", "up")
	}
	ip("link", "set", "lo", "up")
	for _, p := range []struct{ local, remote, ns, a, b string }{
		{"lan0", "client0", "selective-client", "10.78.0.1/24", "10.78.0.2/24"},
		{"wan0", "origin0", "selective-origin", "11.1.0.1/24", "11.1.0.99/24"},
		{"vpn0", "origin1", "selective-origin", "12.1.0.1/24", "12.1.0.2/24"},
		{"relay0", "relaypeer", "selective-relay", "13.1.0.1/24", "13.1.0.2/24"},
	} {
		ip("link", "add", p.local, "type", "veth", "peer", "name", p.remote)
		t.Cleanup(func() { _ = exec.Command("/sbin/ip", "link", "del", p.local).Run() })
		ip("link", "set", p.remote, "netns", p.ns)
		ip("addr", "add", p.a, "dev", p.local)
		ip("link", "set", p.local, "up")
		ns(p.ns, "addr", "add", p.b, "dev", p.remote)
		ns(p.ns, "link", "set", p.remote, "up")
	}
	ns("selective-client", "route", "add", "default", "via", "10.78.0.1")
	ns("selective-relay", "route", "add", "11.1.0.0/24", "via", "13.1.0.1")
	ns("selective-origin", "route", "add", "13.1.0.0/24", "via", "11.1.0.1")
	mac := strings.TrimSpace(
		string(
			selectiveAcceptanceCommand(
				t,
				"/sbin/ip",
				"netns",
				"exec",
				"selective-origin",
				"cat",
				"/sys/class/net/origin1/address",
			),
		),
	)
	for _, last := range []string{"53", "95", "96", "97", "98", "99"} {
		address := "11.1.0." + last
		if last != "99" {
			ns("selective-origin", "addr", "add", address+"/32", "dev", "origin0")
		}
		ip("neigh", "replace", address, "lladdr", mac, "nud", "permanent", "dev", "vpn0")
	}
	for _, dev := range []string{"all", "default", "lan0", "wan0", "vpn0", "relay0"} {
		if err := os.WriteFile(
			"/proc/sys/net/ipv4/conf/"+dev+"/rp_filter",
			[]byte("0"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.createCertificates()
	var err error
	f.gatewayIdentity, err = node.LoadIdentity(filepath.Join(f.dir, "gateway"))
	if err != nil {
		t.Fatal(err)
	}
	f.relayIdentity, err = node.LoadIdentity(filepath.Join(f.dir, "relay"))
	if err != nil {
		t.Fatal(err)
	}
	f.server = f.child("selective-origin", "server")
	if got := f.server.request(t, selectiveAcceptanceMessage{}); got.Action != "ready" {
		t.Fatal(got)
	}
	f.relay = f.child("selective-relay", "relay")
	if got := f.relay.request(t, selectiveAcceptanceMessage{}); got.Action != "ready" {
		t.Fatal(got)
	}
	f.client = f.child("selective-client", "client")
	p := adapter.AllocatePath(adapter.DispatcherSourceID, "dispatcher", 240)
	p.TransparentPort, p.ProxyPort, p.DNSPort, p.UDP = 11240, 12240, 13240, true
	source := adapter.AllocatePath("vpn", "interface", 4)
	source.Interface, source.UDP = "vpn0", true
	f.spec = dispatch.Spec{
		Allocation: adapter.DispatcherAllocation{
			Path:         p,
			DNSFrontPort: 14240,
			DirectPort:   15240,
			APIPort:      16240,
		},
		Network: model.Network{
			Enabled:       true,
			LANInterfaces: []string{"lan0"},
			WANInterface:  "wan0",
			LocalPrefixes: []string{"10.78.0.0/24"},
			IPv6:          "block",
			DNS:           "selected-path",
			DNSResolver:   "11.1.0.53",
		},
		Routing: model.RoutingConfig{
			Mode:          "selective",
			FailurePolicy: "direct",
			Registry:      model.RoutingRegistry{Provider: "antifilter"},
		},
		Sources:  []adapter.Path{source},
		Selected: "vpn",
	}
	f.rules, f.config = filepath.Join(f.dir, "rules.json"), filepath.Join(f.dir, "config.json")
	f.publish(nil)
	return f
}

func (f *selectiveAcceptanceLab) createCertificates() {
	f.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "selective lab"},
		DNSNames: []string{
			"learn.example",
			"cname.example",
			"control.example",
			"down.example",
			"alternate.example",
			"mismatch.example",
			"wan-failure.example",
			"allowed.example",
			"blocked.example",
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		f.t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		f.t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for path, data := range map[string][]byte{"tls.crt": cert, "tls.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})} {
		if err = os.WriteFile(filepath.Join(f.dir, path), data, 0o600); err != nil {
			f.t.Fatal(err)
		}
	}
	f.rootCAs = x509.NewCertPool()
	f.rootCAs.AppendCertsFromPEM(cert)
}

func (f *selectiveAcceptanceLab) child(namespace, role string) *selectiveAcceptanceChild {
	f.t.Helper()
	executable, err := os.Executable()
	if err != nil {
		f.t.Fatal(err)
	}
	c := exec.CommandContext(
		f.ctx,
		"/sbin/ip",
		"netns",
		"exec",
		namespace,
		executable,
		"-test.run=^TestSelectiveAcceptanceChild$",
	)
	c.Env = append(
		os.Environ(),
		"ROUTEHARBOR_SELECTIVE_ACCEPTANCE_ROLE="+role,
		"ROUTEHARBOR_SELECTIVE_ACCEPTANCE_DIR="+f.dir,
	)
	in, err := c.StdinPipe()
	if err != nil {
		f.t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		f.t.Fatal(err)
	}
	c.ExtraFiles, c.Stdout, c.Stderr = []*os.File{w}, os.Stderr, os.Stderr
	if err = c.Start(); err != nil {
		f.t.Fatal(err)
	}
	_ = w.Close()
	f.t.Cleanup(func() { _ = in.Close(); _ = r.Close(); _ = c.Process.Kill(); _ = c.Wait() })
	return &selectiveAcceptanceChild{c, in, json.NewDecoder(r)}
}

func (f *selectiveAcceptanceLab) publish(names []string) {
	f.t.Helper()
	raw, err := routing.CompileRuleSet(
		routing.Snapshot{
			Generation: 1,
			CreatedAt:  time.Now(),
			Domains:    []string{},
			CIDRs:      []string{},
		},
		names,
	)
	if err != nil {
		f.t.Fatal(err)
	}
	if err = os.WriteFile(f.rules+".new", raw, 0o600); err != nil {
		f.t.Fatal(err)
	}
	if err = os.Rename(f.rules+".new", f.rules); err != nil {
		f.t.Fatal(err)
	}
}

func (f *selectiveAcceptanceLab) start() {
	f.t.Helper()
	raw, err := dispatch.Generate(
		f.spec,
		dispatch.Files{RuleSet: f.rules, Cache: filepath.Join(f.dir, "cache.db")},
		strings.Repeat("c", 32),
	)
	if err != nil {
		f.t.Fatal(err)
	}
	if err = os.WriteFile(f.config, raw, 0o600); err != nil {
		f.t.Fatal(err)
	}
	f.startEngine()
	proxy := routing.DNSProxy{
		LocalDNS:       "127.0.0.1:53",
		ExternalDNS:    "127.0.0.1:13240",
		AllowedClients: []netip.Prefix{netip.MustParsePrefix("10.78.0.0/24")},
		Observe: func(domain string) {
			select {
			case f.observations <- domain:
			default:
			}
		},
	}
	udp, err := net.ListenPacket("udp4", "0.0.0.0:14240")
	if err != nil {
		f.t.Fatal(err)
	}
	tcp, err := net.Listen("tcp4", "0.0.0.0:14240")
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = udp.Close(); _ = tcp.Close() })
	go func() { _ = proxy.Serve(f.ctx, udp, tcp) }()
	d := dataplane.Desired{
		Network:  f.spec.Network,
		Selected: f.spec.Selected,
		Fallback: "closed",
		Selective: &dataplane.SelectiveIntent{
			Path: dataplane.Path{
				SourceID: dataplane.SelectiveSourceID,
				Kind:     "tproxy",
				Slot:     240,
				Port:     11240,
				UDP:      true,
			},
			DNSFrontPort:  14240,
			FakeIPv4:      dispatch.FakeIPv4,
			FakeIPv6:      dispatch.FakeIPv6,
			FailurePolicy: "direct",
			PolicyHash:    dispatch.PolicyHash(f.spec.Routing),
			Snapshot: dataplane.SelectiveSnapshotRef{
				Generation: 1,
				SHA256:     strings.Repeat("a", 64),
			},
		},
	}
	for _, p := range f.spec.Sources {
		d.Paths = append(
			d.Paths,
			dataplane.Path{
				SourceID:  p.SourceID,
				Kind:      p.Kind,
				Slot:      uint16(p.Slot),
				Interface: p.Interface,
				UDP:       p.UDP,
			},
		)
	}
	if f.spec.Continuity != nil {
		d.Continuity = &dataplane.ContinuityIntent{
			Config: model.ContinuityConfig{
				Enabled:                  true,
				RelayAddress:             "13.1.0.2:8443",
				RelayFingerprint:         f.relayIdentity.Fingerprint,
				BufferBytes:              32 << 20,
				UDPReserveBytes:          4 << 20,
				DisconnectedGraceSeconds: 30,
			},
			Path: dataplane.Path{
				SourceID: dataplane.ContinuitySourceID,
				Kind:     "tproxy",
				Slot:     239,
				Port:     11239,
				DNSPort:  13239,
				UDP:      true,
			},
		}
	}
	plan, err := dataplane.Compile(d)
	if err != nil {
		f.t.Fatal(err)
	}
	plan, err = dataplane.WithRouterAddresses(
		plan,
		[]netip.Addr{
			netip.MustParseAddr("10.78.0.1"),
			netip.MustParseAddr("11.1.0.1"),
			netip.MustParseAddr("12.1.0.1"),
		},
	)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, r := range plan.Routes {
		family := "-" + strconv.Itoa(r.Family)
		args := []string{family, "route", "add", "table", strconv.Itoa(r.Table)}
		if r.Local {
			args = append(args, "local")
		}
		args = append(args, "default", "dev", r.Device)
		if r.Table != 254 {
			selectiveAcceptanceCommand(f.t, "/sbin/ip", args...)
		}
		selectiveAcceptanceCommand(
			f.t,
			"/sbin/ip",
			family,
			"rule",
			"add",
			"priority",
			strconv.Itoa(r.Priority),
			"fwmark",
			fmt.Sprintf("0x%08x/0xffff0000", r.Mark),
			"lookup",
			strconv.Itoa(r.Table),
		)
	}
	cmd := exec.Command("/usr/sbin/nft", "--file", "-")
	cmd.Stdin = strings.NewReader(plan.NFT)
	if out, err := cmd.CombinedOutput(); err != nil {
		f.t.Fatal("selective kernel apply", err, string(out))
	}
	f.t.Cleanup(func() { _ = exec.Command("/usr/sbin/nft", "flush", "ruleset").Run() })
}

func (f *selectiveAcceptanceLab) startEngine() {
	f.t.Helper()
	f.engine = exec.CommandContext(f.ctx, "/usr/bin/sing-box", "run", "-c", f.config)
	f.engine.Stdout, f.engine.Stderr = os.Stderr, os.Stderr
	if err := f.engine.Start(); err != nil {
		f.t.Fatal(err)
	}
	engine := f.engine
	f.t.Cleanup(func() { _ = engine.Process.Kill(); _ = engine.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", "127.0.0.1:13240", 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			f.t.Fatal("native classifier not ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSelectiveAcceptanceChild(t *testing.T) {
	role := os.Getenv("ROUTEHARBOR_SELECTIVE_ACCEPTANCE_ROLE")
	if role == "" {
		t.Skip("private namespace subprocess")
	}
	output := os.NewFile(3, "acceptance-response")
	defer func() { _ = output.Close() }()
	in, out := json.NewDecoder(os.Stdin), json.NewEncoder(output)
	switch role {
	case "server":
		selectiveAcceptanceServer(t, in, out)
	case "relay":
		selectiveAcceptanceRelay(t, in, out)
	case "client":
		selectiveAcceptanceClient(t, in, out)
	default:
		t.Fatal("invalid role")
	}
}

func selectiveAcceptanceName(name string) []byte {
	var out []byte
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

func selectiveAcceptanceDNS(q []byte, peer string) []byte {
	if len(q) < 17 {
		return nil
	}
	i := 12
	var labels []string
	for i < len(q) && q[i] != 0 {
		n := int(q[i])
		i++
		if n > 63 || i+n >= len(q) {
			return nil
		}
		labels = append(labels, string(q[i:i+n]))
		i += n
	}
	i++
	if i+4 > len(q) {
		return nil
	}
	name, typ := strings.Join(labels, "."), binary.BigEndian.Uint16(q[i:i+2])
	out := append([]byte{}, q[:i+4]...)
	out[2], out[3] = 0x81, 0x80
	for j := 6; j < 12; j++ {
		out[j] = 0
	}
	if typ != 1 {
		return out
	}
	addresses := []string{"11.1.0.99"}
	switch name {
	case "control.example":
		addresses = []string{"11.1.0.98"}
	case "down.example":
		addresses = []string{"11.1.0.97"}
	case "alternate.example":
		addresses = []string{"11.1.0.96", "11.1.0.98"}
	case "mismatch.example":
		if strings.HasPrefix(peer, "11.1.0.1:") {
			addresses = []string{"11.1.0.95"}
		}
	}
	count := len(addresses)
	if name == "cname.example" {
		target := selectiveAcceptanceName("learn.example")
		out = append(out, 0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 2, 0, byte(len(target)))
		out = append(out, target...)
		count++
	}
	for _, address := range addresses {
		if name == "cname.example" {
			out = append(out, selectiveAcceptanceName("learn.example")...)
		} else {
			out = append(out, 0xc0, 0x0c)
		}
		out = append(out, 0, 1, 0, 1, 0, 0, 0, 2, 0, 4)
		out = append(out, net.ParseIP(address).To4()...)
	}
	binary.BigEndian.PutUint16(out[6:8], uint16(count))
	return out
}

func selectiveAcceptanceFrame(c io.ReadWriter, payload []byte, read bool) ([]byte, error) {
	if !read {
		if len(payload) > 65535 {
			return nil, errors.New("frame too large")
		}
		b := make([]byte, 2+len(payload))
		binary.BigEndian.PutUint16(b, uint16(len(payload)))
		copy(b[2:], payload)
		_, err := c.Write(b)
		return nil, err
	}
	var size [2]byte
	if _, err := io.ReadFull(c, size[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint16(size[:]))
	_, err := io.ReadFull(c, b)
	return b, err
}

func selectiveAcceptanceServer(t *testing.T, in *json.Decoder, out *json.Encoder) {
	dir := os.Getenv("ROUTEHARBOR_SELECTIVE_ACCEPTANCE_DIR")
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if err != nil {
		t.Fatal(err)
	}
	var wanDown atomic.Bool
	var sequence atomic.Uint64
	for _, port := range []string{"53", "443", "18080"} {
		l, err := net.Listen("tcp4", "0.0.0.0:"+port)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() {
					defer func() { _ = c.Close() }()
					if port == "443" {
						server := tls.Server(
							c,
							&tls.Config{
								Certificates: []tls.Certificate{cert},
								MinVersion:   tls.VersionTLS12,
								GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
									direct := strings.HasPrefix(
										c.RemoteAddr().String(),
										"11.1.0.1:",
									)
									if hello.ServerName == "down.example" ||
										direct &&
											(wanDown.Load() || hello.ServerName == "learn.example" || hello.ServerName == "cname.example" || hello.ServerName == "alternate.example" && strings.HasPrefix(c.LocalAddr().String(), "11.1.0.96:")) {
										return nil, errors.New("synthetic path restriction")
									}
									return nil, nil
								},
							},
						)
						_ = server.SetDeadline(time.Now().Add(4 * time.Second))
						if server.Handshake() == nil {
							_, _ = io.WriteString(server, c.RemoteAddr().String()+"\n")
						}
						return
					}
					id := fmt.Sprintf("socket-%d", sequence.Add(1))
					for {
						payload, err := selectiveAcceptanceFrame(c, nil, true)
						if err != nil {
							return
						}
						response := []byte(
							id + "|" + c.RemoteAddr().String() + "|" + string(payload),
						)
						if port == "53" {
							response = selectiveAcceptanceDNS(payload, c.RemoteAddr().String())
						}
						if _, err = selectiveAcceptanceFrame(c, response, false); err != nil {
							return
						}
					}
				}()
			}
		}()
	}
	for _, port := range []string{"53", "18080"} {
		u, err := net.ListenPacket("udp4", "0.0.0.0:"+port)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = u.Close() }()
		go func() {
			buf := make([]byte, 65535)
			for {
				n, peer, err := u.ReadFrom(buf)
				if err != nil {
					return
				}
				response := []byte(
					"mapping-" + peer.String() + "|" + peer.String() + "|" + string(buf[:n]),
				)
				if port == "53" {
					response = selectiveAcceptanceDNS(buf[:n], peer.String())
				}
				_, _ = u.WriteTo(response, peer)
			}
		}()
	}
	for {
		var command selectiveAcceptanceMessage
		if err := in.Decode(&command); err != nil {
			return
		}
		if command.Action == "wan-down" {
			wanDown.Store(true)
		}
		_ = out.Encode(selectiveAcceptanceMessage{Action: "ready"})
	}
}

func selectiveAcceptanceRelay(t *testing.T, in *json.Decoder, out *json.Encoder) {
	dir := os.Getenv("ROUTEHARBOR_SELECTIVE_ACCEPTANCE_DIR")
	relayID, err := node.LoadIdentity(filepath.Join(dir, "relay"))
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := node.LoadIdentity(filepath.Join(dir, "gateway"))
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := continuity.ServerTLS(relayID.Certificate, []string{clientID.Fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	relay, err := continuity.NewRelay(continuity.RelayConfig{TLSConfig: serverTLS})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = relay.Close() }()
	l, err := net.Listen("tcp4", "13.1.0.2:8443")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	go func() { _ = relay.Serve(l) }()
	for {
		var command selectiveAcceptanceMessage
		if err := in.Decode(&command); err != nil {
			return
		}
		switch command.Action {
		case "relay-down":
			_ = relay.Close()
			_ = l.Close()
		}
		_ = out.Encode(selectiveAcceptanceMessage{Action: "ready"})
	}
}

func selectiveAcceptanceResolve(domain string) (string, uint32, error) {
	q := make([]byte, 12)
	q[0], q[2], q[5] = 77, 1, 1
	q = append(q, selectiveAcceptanceName(domain)...)
	q = append(q, 0, 1, 0, 1)
	c, err := net.DialTimeout("udp4", "10.78.0.1:53", time.Second)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = c.Write(q); err != nil {
		return "", 0, err
	}
	b := make([]byte, 4096)
	n, err := c.Read(b)
	if err != nil || n < len(q)+16 || b[3]&15 != 0 || binary.BigEndian.Uint16(b[6:8]) != 1 {
		return "", 0, fmt.Errorf("FakeIP response invalid: %v", err)
	}
	return net.IP(b[n-4 : n]).String(), binary.BigEndian.Uint32(b[n-10 : n-6]), nil
}

func selectiveAcceptanceClient(t *testing.T, in *json.Decoder, out *json.Encoder) {
	cert, err := os.ReadFile(
		filepath.Join(os.Getenv("ROUTEHARBOR_SELECTIVE_ACCEPTANCE_DIR"), "tls.crt"),
	)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(cert)
	connections := map[string]net.Conn{}
	defer func() {
		for _, c := range connections {
			_ = c.Close()
		}
	}()
	for {
		var command selectiveAcceptanceMessage
		if err := in.Decode(&command); err != nil {
			return
		}
		answer := selectiveAcceptanceMessage{}
		perform := func() error {
			ip := command.IP
			if ip == "" {
				var err error
				ip, answer.TTL, err = selectiveAcceptanceResolve(command.Domain)
				if err != nil {
					return err
				}
			}
			answer.IP = ip
			if command.Action == "dns" {
				return nil
			}
			if command.Action == "tls" {
				c, err := tls.DialWithDialer(
					&net.Dialer{Timeout: 2 * time.Second},
					"tcp4",
					net.JoinHostPort(ip, "443"),
					&tls.Config{
						RootCAs:    roots,
						ServerName: command.Domain,
						MinVersion: tls.VersionTLS12,
					},
				)
				if err != nil {
					return err
				}
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				line, err := bufio.NewReader(c).ReadString('\n')
				answer.Source, _, _ = net.SplitHostPort(strings.TrimSpace(line))
				return err
			}
			key := command.Domain + ":" + command.Network
			c := connections[key]
			if c == nil {
				var err error
				c, err = net.DialTimeout(
					command.Network,
					net.JoinHostPort(ip, "18080"),
					2*time.Second,
				)
				if err != nil {
					return err
				}
				connections[key] = c
			}
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			var response []byte
			var err error
			if strings.HasPrefix(command.Network, "tcp") {
				_, err = selectiveAcceptanceFrame(c, []byte(command.Payload), false)
				if err == nil {
					response, err = selectiveAcceptanceFrame(c, nil, true)
				}
			} else {
				_, err = c.Write([]byte(command.Payload))
				if err == nil {
					b := make([]byte, 4096)
					var n int
					n, err = c.Read(b)
					response = b[:n]
				}
			}
			if err != nil {
				return err
			}
			parts := bytes.SplitN(response, []byte("|"), 3)
			if len(parts) != 3 || string(parts[2]) != command.Payload {
				return errors.New("application bytes changed")
			}
			answer.ID = string(parts[0])
			answer.Source, _, err = net.SplitHostPort(string(parts[1]))
			return err
		}
		if err := perform(); err != nil {
			answer.Error = err.Error()
		}
		_ = out.Encode(answer)
	}
}

func TestLinuxSelectiveLearnsThroughActualTLSAndHotRules(t *testing.T) {
	f := newSelectiveAcceptanceLab(t)
	f.start()
	runner := probe.NewRunner(nil)
	runner.ConfigureDNS(true, "11.1.0.53")
	runner.TLSConfig = &tls.Config{RootCAs: f.rootCAs, MinVersion: tls.VersionTLS12}
	path := func(port int) adapter.Path {
		return adapter.Path{
			Kind:     "socks5",
			ProxyURL: &url.URL{Scheme: "socks5", Host: "127.0.0.1:" + strconv.Itoa(port)},
			UDP:      true,
		}
	}
	direct, bypass := path(15240), path(12240)
	settings := model.ProbeSettings{Concurrency: 2, TimeoutSeconds: 3}
	control := model.Target{
		ID:          "control",
		URL:         "https://control.example/",
		StatusCodes: []int{200},
		MaxBytes:    1024,
	}
	before := f.client.request(
		t,
		selectiveAcceptanceMessage{Action: "tls", Domain: "learn.example"},
	)
	if before.Error == "" {
		t.Fatal("unknown restricted domain did not initially use direct", before)
	}
	detectors := map[string]*routing.Detector{}
	for _, domain := range []string{"learn.example", "cname.example", "down.example", "alternate.example", "mismatch.example", "wan-failure.example", "bad-certificate.example"} {
		d := routing.NewDetector(true)
		answer := f.client.request(t, selectiveAcceptanceMessage{Action: "dns", Domain: domain})
		if answer.Error != "" || answer.TTL != 600 {
			t.Fatal("native FakeIP query/TTL", domain, answer)
		}
		deadline := time.After(time.Second)
		observed := false
		for !observed {
			select {
			case name := <-f.observations:
				if name == domain {
					d.Observe(name, time.Now())
					observed = true
				}
			case <-deadline:
				t.Fatal("external DNS observation missing", domain)
			}
		}
		detectors[domain] = d
	}
	compare := func(domain string) routing.Round {
		t.Helper()
		round, err := runner.Compare(f.ctx, domain, direct, bypass, settings)
		if err != nil {
			t.Fatal(domain, err)
		}
		at, err := runner.ControlTLSForFamilies(f.ctx, control, direct, settings, true, false)
		if err == nil {
			round.ControlOK, round.ControlAt = true, at
		}
		candidate, ok := detectors[domain].Next(time.Now(), "synthetic-wan:vpn")
		if !ok {
			t.Fatal("candidate not due", domain)
		}
		detectors[domain].Record(candidate, round, time.Now())
		return round
	}
	for _, domain := range []string{"down.example", "alternate.example", "mismatch.example", "bad-certificate.example"} {
		round := compare(domain)
		if len(detectors[domain].Learned(time.Now())) != 0 {
			t.Fatal("false positive", domain, round)
		}
		if domain == "alternate.example" &&
			(!round.Complete || len(round.Addresses) != 2 || !round.Addresses[1].DirectSuccess) {
			t.Fatal("working alternative was not actually checked", round)
		}
		if domain == "bad-certificate.example" &&
			(len(round.Addresses) != 1 || !round.Addresses[0].CertificateError) {
			t.Fatal("certificate failure was not observed", round)
		}
		if domain == "mismatch.example" && !round.DNSError {
			t.Fatal("different path DNS was not observed", round)
		}
	}
	for n := 0; n < 3; n++ {
		if n > 0 {
			time.Sleep(routing.DetectionSpacing + 50*time.Millisecond)
		}
		for _, domain := range []string{"learn.example", "cname.example"} {
			round := compare(domain)
			if !round.Complete || !round.ControlOK || len(round.Addresses) != 1 ||
				round.Addresses[0].DirectSuccess ||
				!round.Addresses[0].BypassSuccess ||
				round.Addresses[0].CertificateError {
				t.Fatal("real comparative premise failed", domain, round)
			}
			if got := len(detectors[domain].Learned(time.Now())); (n == 2) != (got == 1) {
				t.Fatal("wrong confirmation threshold", n, got)
			}
		}
	}
	learned := []string{}
	for domain, detector := range detectors {
		for exact := range detector.Learned(time.Now()) {
			if exact != domain {
				t.Fatal("learned rule broadened", domain, exact)
			}
			learned = append(learned, exact)
		}
	}
	if len(learned) != 2 {
		t.Fatal("unexpected learned domain set", learned)
	}
	f.publish(learned)
	time.Sleep(500 * time.Millisecond)
	for _, domain := range []string{"learn.example", "cname.example"} {
		after := f.client.request(t, selectiveAcceptanceMessage{Action: "tls", Domain: domain})
		if after.Error != "" || after.Source != "12.1.0.1" {
			t.Fatal("learned next connection did not use native bypass", domain, after)
		}
	}
	f.server.request(t, selectiveAcceptanceMessage{Action: "wan-down"})
	round := compare("wan-failure.example")
	if round.ControlOK || len(detectors["wan-failure.example"].Learned(time.Now())) != 0 {
		t.Fatal("general WAN failure learned a restriction", round)
	}
	cache := f.client.request(t, selectiveAcceptanceMessage{Action: "dns", Domain: "learn.example"})
	if cache.Error != "" || cache.TTL == 0 || cache.TTL > 600 ||
		!netip.MustParsePrefix(dispatch.FakeIPv4).Contains(netip.MustParseAddr(cache.IP)) {
		t.Fatal("invalid FakeIP TTL", cache)
	}
	_ = f.engine.Process.Signal(syscall.SIGTERM)
	if err := f.engine.Wait(); err != nil {
		t.Fatal(err)
	}
	f.startEngine()
	reused := f.client.request(
		t,
		selectiveAcceptanceMessage{Action: "tls", Domain: "learn.example", IP: cache.IP},
	)
	if reused.Error != "" || reused.Source != "12.1.0.1" {
		t.Fatal("saved FakeIP mapping failed across dispatcher restart", reused)
	}
	again := f.client.request(t, selectiveAcceptanceMessage{Action: "dns", Domain: "learn.example"})
	if again.Error != "" || again.IP != cache.IP {
		t.Fatal("restart reused cached address for another mapping", cache, again)
	}
	t.Log(
		"three actual TLS rounds spaced >=10s learned exact domains including CNAME; site/WAN/DNS/alternative-address failures stayed unlearned; hot rules changed next LAN flows and FakeIP cache survived native restart",
	)
}

type selectiveAcceptanceCarrier struct {
	mu     sync.Mutex
	failed bool
	conns  []net.Conn
}

func (p *selectiveAcceptanceCarrier) dial(ctx context.Context) (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failed {
		return nil, errors.New("synthetic carrier failure")
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp4", "13.1.0.2:8443")
	if err == nil {
		p.conns = append(p.conns, c)
	}
	return c, err
}

func (p *selectiveAcceptanceCarrier) fail() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failed = true
	for _, c := range p.conns {
		_ = c.Close()
	}
}

func TestLinuxSelectiveRelaySwitchAndFailurePreserveDirect(t *testing.T) {
	f := newSelectiveAcceptanceLab(t)
	clientTLS, err := continuity.ClientTLS(
		f.gatewayIdentity.Certificate,
		f.relayIdentity.Fingerprint,
	)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := continuity.NewGateway(continuity.GatewayConfig{TLSConfig: clientTLS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Close() })
	a, b := &selectiveAcceptanceCarrier{}, &selectiveAcceptanceCarrier{}
	if err := gateway.AddPath(f.ctx, "a", a.dial); err != nil {
		t.Fatal(err)
	}
	if err := gateway.AddPath(f.ctx, "b", b.dial); err != nil {
		t.Fatal(err)
	}
	if err := gateway.SetPreferred("a"); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:17240")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	bridge := dispatch.Bridge{
		Port:     17240,
		Username: strings.Repeat("a", 32),
		Password: strings.Repeat("b", 64),
	}
	go serveBridge(f.ctx, gateway, listener, bridge, make(chan struct{}, 8))
	f.spec.Continuity = &bridge
	f.spec.Sources = []adapter.Path{
		adapter.AllocatePath("a", "direct", 1),
		adapter.AllocatePath("b", "direct", 2),
	}
	f.spec.Selected = "a"
	f.publish([]string{"blocked.example"})
	f.start()
	runner := probe.NewRunner(nil)
	runner.ConfigureDNS(true, "11.1.0.53")
	runner.TLSConfig = &tls.Config{RootCAs: f.rootCAs, MinVersion: tls.VersionTLS12}
	probePath := func(port string) adapter.Path {
		return adapter.Path{
			Kind:     "socks5",
			ProxyURL: &url.URL{Scheme: "socks5", Host: "127.0.0.1:" + port},
			UDP:      true,
		}
	}
	round, err := runner.Compare(
		f.ctx,
		"learn.example",
		probePath("15240"),
		probePath("12240"),
		model.ProbeSettings{Concurrency: 2, TimeoutSeconds: 3},
	)
	if err != nil || !round.Complete || round.DNSError || len(round.Addresses) != 1 ||
		round.Addresses[0].DirectSuccess ||
		!round.Addresses[0].BypassSuccess ||
		round.Addresses[0].CertificateError {
		t.Fatal("continuity comparison did not check actual relay exit TLS", round, err)
	}
	before := map[string]selectiveAcceptanceMessage{}
	check := func(domain, network string) selectiveAcceptanceMessage {
		t.Helper()
		got := f.client.request(
			t,
			selectiveAcceptanceMessage{
				Action:  "flow",
				Domain:  domain,
				Network: network,
				Payload: "unchanged\x00application\xffbytes",
			},
		)
		want := "11.1.0.1"
		if domain == "blocked.example" {
			want = "13.1.0.2"
		}
		if got.Error != "" || got.Source != want {
			t.Fatal("wrong actual path", domain, network, got)
		}
		return got
	}
	for _, domain := range []string{"allowed.example", "blocked.example"} {
		for _, network := range []string{"tcp4", "udp4"} {
			before[domain+network] = check(domain, network)
		}
	}
	session := gateway.Snapshot()
	for _, primary := range []string{"b", "a", "failed-a"} {
		if primary == "failed-a" {
			a.fail()
		} else if err := gateway.SetPreferred(primary); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(5 * time.Second)
		want := primary
		if primary == "failed-a" {
			want = "b"
		}
		for gateway.Snapshot().ActivePath != want {
			if time.Now().After(deadline) {
				t.Fatal("relay did not switch carrier", gateway.Snapshot())
			}
			time.Sleep(10 * time.Millisecond)
		}
		for _, domain := range []string{"allowed.example", "blocked.example"} {
			for _, network := range []string{"tcp4", "udp4"} {
				got := check(domain, network)
				if got.ID != before[domain+network].ID {
					t.Fatal("existing destination socket changed", primary, domain, network, got)
				}
			}
		}
		if current := gateway.Snapshot(); current.SessionID != session.SessionID ||
			current.Generation != session.Generation {
			t.Fatal("relay session changed")
		}
	}
	f.relay.request(t, selectiveAcceptanceMessage{Action: "relay-down"})
	for _, network := range []string{"tcp4", "udp4"} {
		got := check("allowed.example", network)
		if got.ID != before["allowed.example"+network].ID {
			t.Fatal("relay death interrupted direct socket")
		}
	}
	failed := f.client.request(
		t,
		selectiveAcceptanceMessage{
			Action:  "flow",
			Domain:  "blocked.example",
			Network: "tcp4",
			Payload: "must-not-fall-back",
		},
	)
	if failed.Error == "" {
		t.Fatal("dead relay bypass escaped directly", failed)
	}
	t.Log(
		"native classifier sent only blocked domain to private relay; direct and relay TCP/UDP destination sockets survived a→b→a and actual carrier socket loss; relay death retained direct sockets and blocked bypass",
	)
}
