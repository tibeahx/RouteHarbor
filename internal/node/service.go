package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
)

type Record struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Address      string       `json:"address"`
	Fingerprint  string       `json:"fingerprint"`
	Capabilities Capabilities `json:"capabilities"`
	PairedAt     time.Time    `json:"paired_at"`
}

type Service struct {
	mu              sync.Mutex
	coverageMu      sync.Mutex
	gatewayOperator GatewayOperator
	recoveryCancel  context.CancelFunc
	recoveryWG      sync.WaitGroup
	root            *os.Root
	identity        Identity
	gateway         func(context.Context) Capabilities
	records         map[string]Record
}

func NewService(dir string, gateway func(context.Context) Capabilities) (*Service, error) {
	if gateway == nil {
		return nil, errors.New("gateway capability discovery required")
	}
	identity, e := LoadIdentity(dir)
	if e != nil {
		return nil, e
	}
	r, e := openStateRoot(dir)
	if e != nil {
		return nil, e
	}
	s := &Service{root: r, identity: identity, gateway: gateway, records: map[string]Record{}}
	data, e := readPrivate(r, "nodes.json")
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		_ = r.Close()
		return nil, e
	}
	if e == nil && adapter.StrictDecode(data, &s.records) != nil {
		_ = r.Close()
		return nil, errors.New("invalid node registry")
	}
	for id, record := range s.records {
		if !transactionID.MatchString(id) || record.ID != id ||
			!validFingerprint(record.Fingerprint) ||
			validateAddress(record.Address) != nil {
			_ = r.Close()
			return nil, errors.New("invalid node registry entry")
		}
	}
	return s, nil
}

func (s *Service) Close() error {
	s.coverageMu.Lock()
	if s.recoveryCancel != nil {
		s.recoveryCancel()
	}
	s.coverageMu.Unlock()
	s.recoveryWG.Wait()
	return s.root.Close()
}

func (s *Service) save() error {
	data, e := json.Marshal(s.records)
	if e != nil {
		return e
	}
	return writePrivate(s.root, "nodes.json", data)
}

func (s *Service) List() any {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Record, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Service) Discover(ctx context.Context) any {
	result := map[string]any{
		"nodes":                    s.List(),
		"gateway_fingerprint":      s.identity.Fingerprint,
		"gateway_capabilities":     s.gateway(ctx),
		"address_entry":            true,
		"discovery_grants_control": false,
		"message":                  "Enter the node LAN HTTPS address and verify its fingerprint through existing administrator access. Unpaired discovery does not authorize control.",
	}
	s.addGatewaySetup(ctx, result)
	return result
}

func validateAddress(address string) error {
	u, e := url.Parse(address)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" ||
		u.Fragment != "" ||
		u.Opaque != "" ||
		(u.Path != "" && u.Path != "/") {
		return errors.New("node address must be an HTTPS origin without credentials")
	}
	ip, e := netip.ParseAddr(u.Hostname())
	if e != nil || (!ip.IsPrivate() && !ip.IsLoopback()) || ip.IsUnspecified() {
		return errors.New("node address must be an explicit LAN IP literal")
	}
	if u.Port() == "0" {
		return errors.New("invalid node port")
	}
	return nil
}

func (s *Service) request(
	ctx context.Context,
	address, pin, method, path string,
	body any,
) (map[string]any, error) {
	if e := validateAddress(address); e != nil {
		return nil, e
	}
	tlsConfig, e := PinnedTLS(s.identity, pin)
	if e != nil {
		return nil, e
	}
	transport := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       tlsConfig,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 40 * time.Second,
		MaxConnsPerHost:       1,
		DisableKeepAlives:     true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport:     transport,
		Timeout:       45 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("node redirects are prohibited") },
	}
	var data []byte
	if body != nil {
		data, e = json.Marshal(body)
		if e != nil {
			return nil, errors.New("invalid node request")
		}
	}
	r, e := http.NewRequestWithContext(
		ctx,
		method,
		strings.TrimSuffix(address, "/")+path,
		bytes.NewReader(data),
	)
	if e != nil {
		return nil, errors.New("invalid node request")
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	response, e := client.Do(r)
	if e != nil {
		return nil, errors.New("node connection or identity verification failed")
	}
	defer func() { _ = response.Body.Close() }()
	data, e = io.ReadAll(io.LimitReader(response.Body, 256<<10+1))
	if e != nil || len(data) > 256<<10 {
		return nil, errors.New("invalid node response")
	}
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("node request rejected")
	}
	var result map[string]any
	if e = adapter.StrictDecode(data, &result); e != nil {
		return nil, errors.New("invalid node response")
	}
	return result, nil
}

func (s *Service) Pair(ctx context.Context, raw json.RawMessage) (map[string]any, error) {
	var request struct {
		Address     string `json:"address"`
		Fingerprint string `json:"fingerprint"`
		Code        string `json:"code"`
		Name        string `json:"name"`
	}
	if adapter.StrictDecode(raw, &request) != nil || len(raw) > 64<<10 || len(request.Name) > 128 ||
		strings.ContainsAny(request.Name, "\x00\r\n") {
		return nil, errors.New("invalid pairing request")
	}
	if e := validateAddress(request.Address); e != nil {
		return nil, e
	}
	if !validFingerprint(request.Fingerprint) {
		return nil, errors.New("verified node fingerprint required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range s.records {
		if record.Fingerprint == request.Fingerprint && record.Address == request.Address {
			return map[string]any{"node": record}, nil
		}
	}
	result, e := s.request(
		ctx,
		request.Address,
		request.Fingerprint,
		http.MethodPost,
		"/node/v1/pair",
		map[string]string{"code": request.Code},
	)
	if e != nil {
		result, e = s.request(
			ctx,
			request.Address,
			request.Fingerprint,
			http.MethodGet,
			"/node/v1/capabilities",
			nil,
		)
		if e != nil {
			return nil, e
		}
	}
	id, ok := result["id"].(string)
	if !ok || !transactionID.MatchString(id) {
		return nil, errors.New("invalid node identity response")
	}
	var caps Capabilities
	data, e := json.Marshal(result["capabilities"])
	if e != nil || adapter.StrictDecode(data, &caps) != nil {
		return nil, errors.New("invalid node capabilities")
	}
	if existing, ok := s.records[id]; ok && existing.Fingerprint != request.Fingerprint {
		return nil, errors.New("node identity conflict")
	}
	name := request.Name
	if name == "" {
		name = "Coverage node"
	}
	record := Record{
		ID:           id,
		Name:         name,
		Address:      request.Address,
		Fingerprint:  request.Fingerprint,
		Capabilities: caps,
		PairedAt:     time.Now().UTC(),
	}
	s.records[id] = record
	if e = s.save(); e != nil {
		delete(s.records, id)
		return nil, e
	}
	return map[string]any{
		"node":             record,
		"compatible_modes": CompatibleModes(s.gateway(ctx), caps),
	}, nil
}

func (s *Service) Unpair(ctx context.Context, id string) error {
	s.coverageMu.Lock()
	defer s.coverageMu.Unlock()
	if e := s.checkCoverageUnpair(id); e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok {
		return errors.New("node_not_found")
	}
	if _, e := s.request(
		ctx,
		record.Address,
		record.Fingerprint,
		http.MethodPost,
		"/node/v1/unpair",
		struct{}{},
	); e != nil {
		return e
	}
	delete(s.records, id)
	if e := s.save(); e != nil {
		s.records[id] = record
		return e
	}
	return nil
}

func (s *Service) node(ctx context.Context, id string) (Record, error) {
	s.mu.Lock()
	record, ok := s.records[id]
	s.mu.Unlock()
	if !ok {
		return Record{}, errors.New("node_not_found")
	}
	response, e := s.request(
		ctx,
		record.Address,
		record.Fingerprint,
		http.MethodGet,
		"/node/v1/capabilities",
		nil,
	)
	if e != nil {
		return record, e
	}
	data, e := json.Marshal(response["capabilities"])
	if e != nil || adapter.StrictDecode(data, &record.Capabilities) != nil {
		return record, errors.New("invalid_node_capabilities")
	}
	return record, nil
}

func (s *Service) Plan(
	ctx context.Context,
	id string,
	raw json.RawMessage,
) (map[string]any, error) {
	var proposed coveragePlan
	if len(raw) > 64<<10 || adapter.StrictDecode(raw, &proposed) != nil {
		return nil, errors.New("invalid_node_plan")
	}
	p := proposed.Plan
	if p.Mode != "ethernet" || proposed.GatewayPlan != nil {
		return s.planCoverage(ctx, id, proposed)
	}
	record, e := s.node(ctx, id)
	if e != nil {
		return nil, e
	}
	gateway := s.gateway(ctx)
	if e = ValidatePlan(p, gateway, record.Capabilities); e != nil {
		return nil, e
	}
	return map[string]any{
		"plan":                               RedactPlan(p),
		"compatible_modes":                   CompatibleModes(gateway, record.Capabilities),
		"requires_confirmation":              true,
		"requires_independent_node_watchdog": true,
		"warning":                            "Client roaming and shared-radio throughput are not guaranteed; confirm client DHCP, DNS, management access, and gateway policy before committing",
	}, nil
}

func (s *Service) Operate(
	ctx context.Context,
	id, action string,
	raw json.RawMessage,
) (map[string]any, error) {
	var requested coverageOperation
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	if len(raw) > 64<<10 || adapter.StrictDecode(raw, &requested) != nil {
		return nil, errors.New("invalid_node_operation")
	}
	op := requested.Operation
	if op.Action != "" && op.Action != action {
		return nil, errors.New("node_action_mismatch")
	}
	op.Action = action
	requested.Action = action
	if result, handled, err := s.operateCoverage(ctx, id, requested); handled {
		return result, err
	}
	record, e := s.node(ctx, id)
	if e != nil {
		return nil, e
	}
	if action == "prepare" {
		if op.Plan == nil {
			return nil, errors.New("node_plan_required")
		}
		if e = ValidatePlan(*op.Plan, s.gateway(ctx), record.Capabilities); e != nil {
			return nil, e
		}
	}
	if action == "status" {
		result, e := s.request(
			ctx,
			record.Address,
			record.Fingerprint,
			http.MethodGet,
			"/node/v1/status",
			nil,
		)
		if e == nil {
			result["gateway_fingerprint"] = s.identity.Fingerprint
			s.addGatewaySetup(ctx, result)
		}
		return result, e
	}
	return s.request(
		ctx,
		record.Address,
		record.Fingerprint,
		http.MethodPost,
		"/node/v1/operations",
		op,
	)
}
