package helper

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/dataplane"
	"github.com/tibeahx/OpenRHP/internal/model"
)

func continuityFixture(t *testing.T) ContinuityWorkerRequest {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-router"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	p := adapter.AllocatePath(dataplane.ContinuitySourceID, "continuity", 250)
	p.TransparentPort = 14500
	return ContinuityWorkerRequest{
		Config: model.ContinuityConfig{
			Enabled:                  true,
			RelayAddress:             "8.8.8.8:443",
			RelayFingerprint:         strings.Repeat("ab", 32),
			BufferBytes:              32 << 20,
			UDPReserveBytes:          4 << 20,
			DisconnectedGraceSeconds: 30,
		},
		Path:        p,
		Network:     testDesired().Network,
		Sources:     []adapter.Path{adapter.AllocatePath("a", "direct", 1)},
		Preferred:   "a",
		Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		PrivateKey:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
	}
}

func TestContinuityTypedBoundaryRejectsForgedAllocationsAndConfig(t *testing.T) {
	base := continuityFixture(t)
	if err := ValidateContinuityWorker(base); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ContinuityWorkerRequest){
		func(r *ContinuityWorkerRequest) { r.Config.RelayAddress = "127.0.0.1:22" },
		func(r *ContinuityWorkerRequest) { r.Config.RelayAddress = "[::ffff:127.0.0.1]:22" },
		func(r *ContinuityWorkerRequest) { r.Config.RelayFingerprint = "bad" },
		func(r *ContinuityWorkerRequest) { r.Config.BufferBytes = 1 << 20; r.Config.UDPReserveBytes = 768 << 10 },
		func(r *ContinuityWorkerRequest) { r.PrivateKey = "invalid" },
		func(r *ContinuityWorkerRequest) { r.Path.Mark++ },
		func(r *ContinuityWorkerRequest) { r.Path.TransparentPort = 65536 + 14500 },
		func(r *ContinuityWorkerRequest) { r.Sources[0].Slot = 250; r.Sources[0].Mark = adapter.Mark(250) },
		func(r *ContinuityWorkerRequest) { r.Sources[0].ProxyPort = 12001 },
		func(r *ContinuityWorkerRequest) { r.Sources[0].TransparentPort = 65536 },
		func(r *ContinuityWorkerRequest) { r.Sources[0].Queue = 1 },
		func(r *ContinuityWorkerRequest) { r.Preferred = "unknown" },
		func(r *ContinuityWorkerRequest) { r.Standby = r.Preferred },
	} {
		r := base
		r.Sources = append([]adapter.Path(nil), base.Sources...)
		mutate(&r)
		if err := ValidateContinuityWorker(r); err == nil {
			t.Fatalf("forged request accepted: %+v", r.Path)
		}
	}
	for _, r := range []ContinuityRequest{
		{Action: "dial", SourceID: "a", Destination: "8.8.8.8:22"},
		{Action: "status", Start: &base},
		{Action: "udp_reply", ClientAddress: "10.44.0.2:8000", Destination: "192.168.1.1:22"},
		{Action: "udp_reply", ClientAddress: "[::ffff:10.44.0.2]:8000", Destination: "[::ffff:8.8.8.8]:443"},
		{Action: "udp_reply", ClientAddress: "[fe80::1%eth0]:8000", Destination: "[2001:4860:4860::8888]:443"},
	} {
		if err := validateContinuityRequest(r); err == nil {
			t.Fatal("unexpected field/socket target accepted", r.Action)
		}
	}
}

func TestContinuityOwnershipReservationsAndInventory(t *testing.T) {
	request := continuityFixture(t)
	s := &Server{Manager: testManager(t, &memoryBackend{}, &testWatchdog{})}
	if err := s.validateContinuitySourcesLocked(request.Sources); err == nil {
		t.Fatal("unregistered native source accepted")
	}
	s.nativeProbes = map[string]nativeProbeRegistration{
		"a": {Path: NativeProbePath{SourceID: "a", Kind: "direct", Slot: 1}, Seen: time.Now()},
	}
	if err := s.validateContinuitySourcesLocked(request.Sources); err != nil {
		t.Fatal(err)
	}
	reg := &continuityRegistration{request: request, done: make(chan struct{})}
	s.continuity = reg
	if err := s.validateProbeAllocationLocked(
		dataplane.Path{SourceID: "impostor", Kind: "direct", Slot: 250},
	); err == nil {
		t.Fatal("starting virtual allocation was stolen")
	}
	d := testDesired()
	d.Paths = []dataplane.Path{continuitySourceAllocation(request.Sources[0])}
	d.Continuity = &dataplane.ContinuityIntent{
		Config: request.Config,
		Path:   continuityAllocation(request),
	}
	if err := s.validateContinuityPathLocked(d); err == nil {
		t.Fatal("unready process admitted")
	}
	reg.ready = true
	if err := s.validateContinuityPathLocked(d); err != nil {
		t.Fatal(err)
	}
	d.Paths = append(d.Paths, dataplane.Path{SourceID: "unknown", Kind: "direct", Slot: 2})
	if err := s.validateContinuityPathLocked(d); err == nil {
		t.Fatal("worker source inventory changed silently")
	}
	close(reg.done)
	d.Paths = d.Paths[:1]
	if err := s.validateContinuityPathLocked(d); err == nil {
		t.Fatal("dead worker admitted")
	}
}

func TestContinuityRetainedDNSAndSafeRollback(t *testing.T) {
	request := continuityFixture(t)
	request.Network.DNS = "selected-path"
	request.Network.DNSResolver = "8.8.8.8"
	request.Path.DNSPort = 14501
	d := testDesired()
	d.Network = request.Network
	d.Continuity = &dataplane.ContinuityIntent{
		Config: request.Config,
		Path:   continuityAllocation(request),
	}
	d.Paths = append(
		d.Paths,
		dataplane.Path{
			SourceID: "old-dns",
			Kind:     "tproxy",
			Slot:     3,
			Port:     12003,
			DNSPort:  14003,
			UDP:      true,
		},
		dataplane.Path{SourceID: "carrier", Kind: "tproxy", Slot: 4, Port: 12004, UDP: false},
	)
	p, err := dataplane.Compile(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{"ct mark & 0xffff0000 == 0x4f010000 meta nfproto ipv4", "tproxy to :14003", "tproxy to :14501"} {
		if !strings.Contains(p.NFT, rule) {
			t.Fatal("retained DNS missing", rule)
		}
	}
	if strings.Contains(p.NFT, "tproxy to :0") {
		t.Fatal("unsupported carrier DNS intercepted")
	}
	safe := dataplane.SafeRollback(d, nil)
	if safe.Continuity != nil {
		t.Fatal("rollback retained virtual interception")
	}
	rollback, err := dataplane.Compile(safe)
	if err != nil || strings.Contains(rollback.NFT, "tproxy") {
		t.Fatal("rollback was not closed", err)
	}
}

type continuityCloseSignal struct {
	once   sync.Once
	closed chan struct{}
}

func (c *continuityCloseSignal) Close() error { c.once.Do(func() { close(c.closed) }); return nil }

func TestContinuityStatusReaderBoundsMalformedWorker(t *testing.T) {
	life := &continuityCloseSignal{closed: make(chan struct{})}
	r := &continuityRegistration{}
	r.readStatus(
		bufio.NewReaderSize(
			strings.NewReader(strings.Repeat("x", 2*MaxRequestBytes)+"\n"),
			MaxRequestBytes+1,
		),
		life,
	)
	select {
	case <-life.closed:
	default:
		t.Fatal("invalid worker status did not stop process")
	}
}

func TestContinuityCommandsTimeoutWithoutHoldingStatusLock(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = read.Close() }()
	defer func() { _ = write.Close() }()
	if err = write.SetWriteDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, err := write.Write(make([]byte, 1<<20)); err == nil || n == 0 {
		t.Fatal("could not create blocked command fixture", n, err)
	}
	r := &continuityRegistration{
		done:     make(chan struct{}),
		commands: make(chan continuityCommand, 16),
	}
	life := &continuityCloseSignal{closed: make(chan struct{})}
	go r.writeCommands(write, life)
	started := time.Now()
	if err := r.sendCommand(
		context.Background(),
		ContinuityRequest{Action: "select", SourceID: "a"},
	); err == nil {
		t.Fatal("blocked writer reported success")
	}
	if time.Since(started) > 2500*time.Millisecond {
		t.Fatal("unbounded command write")
	}
	r.mu.Lock()
	_ = r.status
	r.mu.Unlock()
	select {
	case <-life.closed:
	case <-time.After(time.Second):
		t.Fatal("stalled process not terminated")
	}
}

func TestContinuityStartingSelectReturnsErrorWithoutPanic(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux helper Unix RPC fixture runs in the isolated lab")
	}
	dir, err := os.MkdirTemp("/tmp", "rhp-c-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	address := filepath.Join(dir, "socket")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: address, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: address, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	s := &Server{
		continuity: &continuityRegistration{
			request: continuityFixture(t),
			done:    make(chan struct{}),
		},
	}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		s.handleContinuity(
			context.Background(),
			server,
			bufio.NewReader(server),
			ContinuityRequest{Action: "select", SourceID: "a"},
			func() {},
		)
	}()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	raw, err := bufio.NewReader(client).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var response Response
	if err = json.Unmarshal(
		raw,
		&response,
	); err != nil || response.OK ||
		response.Error != "continuity_starting" {
		t.Fatal(response, err)
	}
	<-finished
}
