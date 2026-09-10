package control

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/adapter"
	"github.com/tibeahx/RouteHarbor/internal/continuity"
	"github.com/tibeahx/RouteHarbor/internal/continuityrun"
	"github.com/tibeahx/RouteHarbor/internal/dataplane"
	"github.com/tibeahx/RouteHarbor/internal/dispatch"
	"github.com/tibeahx/RouteHarbor/internal/helper"
	"github.com/tibeahx/RouteHarbor/internal/model"
	"github.com/tibeahx/RouteHarbor/internal/node"
)

// ContinuityControl owns the private worker lifetime. Its public snapshot is an
// allowlisted protocol status and never contains the worker launch request.
type ContinuityControl struct {
	Client                   *helper.Client
	identity                 node.Identity
	mu                       sync.Mutex
	process                  adapter.ManagedProcess
	request                  *helper.ContinuityWorkerRequest
	status                   helper.ContinuityStatus
	lastPrimary, lastStandby string
}

func NewContinuityControl(client *helper.Client, state string) (*ContinuityControl, error) {
	id, e := node.LoadIdentity(state)
	if e != nil {
		return nil, errors.New("continuity identity unavailable")
	}
	return &ContinuityControl{
		Client:   client,
		identity: id,
		status:   helper.ContinuityStatus{Snapshot: continuity.Snapshot{Status: "Disabled"}},
	}, nil
}

func continuityEnabled(c model.Config) bool { return c.Continuity != nil && c.Continuity.Enabled }

func sameContinuitySources(a, b []model.Source) bool {
	before := map[string]model.Source{}
	for _, s := range a {
		if s.Enabled {
			before[s.ID] = s
		}
	}
	for _, s := range b {
		if !s.Enabled {
			continue
		}
		old, ok := before[s.ID]
		if !ok || !sameSourceEndpoint(old, s) {
			return false
		}
		delete(before, s.ID)
	}
	return len(before) == 0
}

func selectionTargets(c model.Config) []model.Target {
	if continuityEnabled(c) {
		return []model.Target{{ID: "relay", Required: true, URL: c.Continuity.RelayAddress}}
	}
	return c.Targets
}

func (cc *ContinuityControl) Public() map[string]any {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	out := toMap(cc.status)
	out["worker_fingerprint"] = cc.identity.Fingerprint
	if cc.process != nil && !cc.process.Alive() {
		out["running"] = false
		out["status"] = "Disconnected"
		out["degraded_reason"] = "worker_stopped"
		out["qualified"] = false
	}
	return out
}

// Bridge returns a private copy for the local dispatcher configuration. It must
// never be included in Public, diagnostics, logs or network transaction journals.
func (cc *ContinuityControl) Bridge() *dispatch.Bridge {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cc.request == nil || cc.request.Bridge == nil {
		return nil
	}
	b := *cc.request.Bridge
	return &b
}

// reserveContinuityBridge keeps the chosen port bound until helper takeover.
// Existing engine/dispatcher allocations are already reserved or listening, so
// the kernel excludes them. The helper independently checks and binds the port.
func reserveContinuityBridge() (*dispatch.Bridge, net.Listener, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, nil, errors.New("continuity bridge allocation unavailable")
	}
	credentials := make([]byte, 48)
	if _, err := rand.Read(credentials); err != nil {
		_ = l.Close()
		return nil, nil, errors.New("continuity bridge identity unavailable")
	}
	b := &dispatch.Bridge{
		Port:     l.Addr().(*net.TCPAddr).Port,
		Username: hex.EncodeToString(credentials[:16]),
		Password: hex.EncodeToString(credentials[16:]),
	}
	return b, l, nil
}

func (cc *ContinuityControl) Refresh(ctx context.Context) {
	if cc.Client == nil {
		return
	}
	s, e := cc.Client.ContinuityStatus(ctx)
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if e != nil {
		cc.status.Running = false
		cc.status.Status = "Disconnected"
		cc.status.DegradedReason = "helper_unavailable"
		cc.status.Qualified = false
		return
	}
	cc.status = s
}

func (cc *ContinuityControl) Ready(name string) bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if !cc.status.Running {
		return false
	}
	for _, path := range cc.status.Paths {
		if path.Name == name {
			return path.Ready
		}
	}
	return false
}

// A terminated owner cannot recover old application sockets. A new worker uses
// the same confirmed LAN allocation for NEW connections and a new session ID.
func (cc *ContinuityControl) EnsureRunning(ctx context.Context) error {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cc.process != nil && cc.process.Alive() {
		return nil
	}
	if cc.Client == nil || cc.request == nil {
		return errors.New("continuity worker unavailable")
	}
	request := *cc.request
	request.Preferred, request.Standby = cc.lastPrimary, cc.lastStandby
	p, e := cc.Client.StartContinuity(ctx, request)
	if e != nil {
		return e
	}
	cc.process = p
	cc.status = helper.ContinuityStatus{
		Snapshot: continuity.Snapshot{
			Status:         "Disconnected",
			DegradedReason: "new_session_after_owner_loss",
		},
	}
	return nil
}

func (cc *ContinuityControl) Close(ctx context.Context) error {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cc.process == nil {
		return nil
	}
	e := cc.process.Close(ctx)
	if e != nil {
		return e
	}
	cc.process = nil
	cc.request = nil
	cc.status = helper.ContinuityStatus{Snapshot: continuity.Snapshot{Status: "Disabled"}}
	return nil
}

func (r *Runtime) continuityStandby(primary string, paths []adapter.Path) string {
	if primary == "" {
		return ""
	}
	r.mu.Lock()
	health := r.selector.Health(time.Now())
	configuration := r.currentConfig
	r.mu.Unlock()
	if r.Store != nil {
		configuration = r.Store.Get()
	}
	automatic := map[string]bool{}
	for _, source := range configuration.Sources {
		automatic[source.ID] = source.Enabled && source.Auto
	}
	known := map[string]bool{}
	for _, p := range paths {
		known[p.SourceID] = automatic[p.SourceID]
	}
	// Both measured throughput and RTT inform the hot reserve. Unknown paths
	// may be warmed, but readiness and qualification remain explicitly separate.
	sort.SliceStable(health, func(i, j int) bool {
		a, b := health[i], health[j]
		if (a.State == "healthy") != (b.State == "healthy") {
			return a.State == "healthy"
		}
		if a.SuccessRate != b.SuccessRate {
			return a.SuccessRate > b.SuccessRate
		}
		if a.SpeedBPS != nil && b.SpeedBPS != nil && *a.SpeedBPS != *b.SpeedBPS {
			return *a.SpeedBPS > *b.SpeedBPS
		}
		return a.LatencyMS < b.LatencyMS
	})
	for _, h := range health {
		if h.SourceID != primary && known[h.SourceID] && h.SuccessRate > 0 &&
			(h.State == "healthy" || h.State == "degraded") {
			return h.SourceID
		}
	}
	observed := map[string]bool{}
	for _, h := range health {
		observed[h.SourceID] = true
	}
	for _, p := range paths {
		if p.SourceID != primary && known[p.SourceID] && !observed[p.SourceID] {
			return p.SourceID
		}
	}
	return ""
}

func (cc *ContinuityControl) Prepare(
	ctx context.Context,
	r *Runtime,
	c model.Config,
	paths []adapter.Path,
	selected string,
	restored *dataplane.ContinuityIntent,
) (*dataplane.ContinuityIntent, error) {
	if !continuityEnabled(c) {
		return nil, nil
	}
	if cc.Client == nil {
		return nil, errors.New("continuity requires privileged helper")
	}
	var fixed *adapter.Path
	if restored != nil {
		p := restored.Path
		a := adapter.AllocatePath(adapter.ContinuitySourceID, "continuity", int(p.Slot))
		a.TransparentPort = int(p.Port)
		a.DNSPort = int(p.DNSPort)
		a.IPv6 = p.IPv6
		a.UDP = true
		fixed = &a
	}
	path, e := r.Adapters.ReserveContinuity(
		fixed,
		c.Network.IPv6 == "proxy",
		c.Network.DNS == "selected-path",
	)
	if e != nil {
		return nil, e
	}
	intent := &dataplane.ContinuityIntent{
		Config: *c.Continuity,
		Path: dataplane.Path{
			SourceID: dataplane.ContinuitySourceID,
			Kind:     "tproxy",
			Slot:     uint16(path.Slot),
			Port:     uint16(path.TransparentPort),
			DNSPort:  uint16(path.DNSPort),
			IPv6:     path.IPv6,
			UDP:      true,
		},
	}
	standby := r.continuityStandby(selected, paths)
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cc.process != nil && cc.process.Alive() {
		if cc.request == nil || !reflect.DeepEqual(cc.request.Config, *c.Continuity) ||
			!reflect.DeepEqual(cc.request.Network, c.Network) ||
			cc.request.Path != path {
			return nil, errors.New(
				"disable and confirm continuity before changing its active relay or allocation",
			)
		}
		return intent, nil
	}
	key, e := x509.MarshalPKCS8PrivateKey(cc.identity.Certificate.PrivateKey)
	if e != nil {
		return nil, errors.New("continuity identity unavailable")
	}
	certificate := ""
	for _, der := range cc.identity.Certificate.Certificate {
		certificate += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	request := helper.ContinuityWorkerRequest{
		Config:      *c.Continuity,
		Path:        path,
		Network:     c.Network,
		Sources:     append([]adapter.Path(nil), paths...),
		Preferred:   selected,
		Standby:     standby,
		Certificate: certificate,
		PrivateKey:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})),
	}
	var bridgeReservation net.Listener
	// A dormant private input is also prepared for legacy mode, allowing the
	// routing transaction to migrate either way without replacing relay sessions.
	if cc.request != nil && cc.request.Bridge != nil {
		b := *cc.request.Bridge
		request.Bridge = &b
	} else {
		request.Bridge, bridgeReservation, e = reserveContinuityBridge()
		if e != nil {
			return nil, e
		}
		defer func() { _ = bridgeReservation.Close() }()
	}
	for i := range request.Sources {
		request.Sources[i].ProxyURL = nil
	}
	r.Adapters.ReleaseContinuityInputs()
	if bridgeReservation != nil {
		_ = bridgeReservation.Close()
	}
	process, e := cc.Client.StartContinuity(ctx, request)
	if e != nil {
		return nil, e
	}
	cc.process = process
	cc.request = &request
	cc.lastPrimary = selected
	cc.lastStandby = standby
	return intent, nil
}

func (cc *ContinuityControl) Select(ctx context.Context, r *Runtime, primary string) error {
	cc.mu.Lock()
	if cc.request == nil || cc.process == nil || !cc.process.Alive() {
		cc.mu.Unlock()
		return errors.New("continuity worker unavailable")
	}
	paths := append([]adapter.Path(nil), cc.request.Sources...)
	cc.mu.Unlock()
	standby := r.continuityStandby(primary, paths)
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if primary == cc.lastPrimary && standby == cc.lastStandby {
		return nil
	}
	if e := cc.Client.SelectContinuity(ctx, primary, standby); e != nil {
		return e
	}
	cc.lastPrimary, cc.lastStandby = primary, standby
	return nil
}

// Relay probes never mix destination-site errors into source reachability.
// This small protocol transfer is telemetry, not proof of 100 Mbit/s capacity.
func (cc *ContinuityControl) Probe(
	ctx context.Context,
	r *Runtime,
	c model.Config,
	source model.Source,
) (model.Measurement, error) {
	m := model.Measurement{
		SourceID:  source.ID,
		At:        time.Now().UTC(),
		Path:      source.Type,
		Resources: []model.ResourceResult{{TargetID: "relay", Required: true}},
	}
	bounded, cancel := context.WithTimeout(ctx, time.Duration(c.Probes.TimeoutSeconds)*time.Second)
	defer cancel()
	path, e := r.Adapters.ProbePath(bounded, source)
	if e == nil && cc.Client != nil {
		e = cc.Client.BindContinuityRelay(bounded, *c.Continuity)
	}
	if e == nil {
		var result continuity.ProbeResult
		tlsConfig, err := continuity.ClientTLS(
			cc.identity.Certificate,
			c.Continuity.RelayFingerprint,
		)
		e = err
		if e == nil {
			result, e = continuity.ProbeRelay(
				bounded,
				tlsConfig,
				func(ctx context.Context) (net.Conn, error) {
					return continuityrun.SourceTransport(
						ctx,
						cc.Client,
						path,
						c.Continuity.RelayAddress,
					)
				},
			)
		}
		if e == nil {
			v := &m.Resources[0]
			v.Success = true
			v.LatencyMS = float64(result.RTT) / float64(time.Millisecond)
			v.Bytes = result.Bytes
			if result.Duration > 0 {
				bps := float64(result.Bytes*8) / result.Duration.Seconds()
				v.SpeedBPS = &bps
			}
		}
	}
	if e != nil {
		m.Resources[0].ErrorCode = "relay_path_unavailable"
		return m, errors.New("relay_path_unavailable")
	}
	return m, nil
}
