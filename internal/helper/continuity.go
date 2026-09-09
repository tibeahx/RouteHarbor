package helper

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"reflect"
	"sync"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/continuity"
	"github.com/tibeahx/OpenRHP/internal/dataplane"
	"github.com/tibeahx/OpenRHP/internal/model"
	"github.com/tibeahx/OpenRHP/internal/platform"
)

// ContinuityWorkerRequest is private. Keys are transported only in inherited
// descriptors and the authenticated local helper channel, never argv/status.
type ContinuityWorkerRequest struct {
	Config       model.ContinuityConfig `json:"config"`
	Path         adapter.Path           `json:"path"`
	Network      model.Network          `json:"network"`
	Sources      []adapter.Path         `json:"sources"`
	Preferred    string                 `json:"preferred"`
	Standby      string                 `json:"standby"`
	Certificate  string                 `json:"certificate"`
	PrivateKey   string                 `json:"private_key"`
	HelperSocket string                 `json:"helper_socket,omitempty"`
	Listeners    []ContinuityListener   `json:"listeners,omitempty"`
}

type ContinuityListener struct {
	Network string `json:"network"`
	DNS     bool   `json:"dns"`
	FD      int    `json:"fd"`
}

type ContinuityRequest struct {
	Action        string                   `json:"action"`
	Config        *model.ContinuityConfig  `json:"config,omitempty"`
	Start         *ContinuityWorkerRequest `json:"start,omitempty"`
	SourceID      string                   `json:"source_id,omitempty"`
	Standby       string                   `json:"standby,omitempty"`
	ClientAddress string                   `json:"client_address,omitempty"`
	Destination   string                   `json:"destination,omitempty"`
}

type ContinuityStatus struct {
	continuity.Snapshot
	Fingerprint      string `json:"fingerprint"`
	Running          bool   `json:"running"`
	ErrorCode        string `json:"error_code,omitempty"`
	HelperQueueBytes int64  `json:"helper_queue_bytes"`
}

type continuityRegistration struct {
	request          ContinuityWorkerRequest
	cmd              *exec.Cmd
	commands         chan continuityCommand
	done             chan struct{}
	ready            bool // protected by Server.probeMu
	leases           chan struct{}
	mu               sync.Mutex
	status           ContinuityStatus
	replyBytes       int64
	helperDroppedUDP uint64
}

func ValidateContinuityWorker(r ContinuityWorkerRequest) error {
	a, e := netip.ParseAddrPort(r.Config.RelayAddress)
	pin, pe := hex.DecodeString(r.Config.RelayFingerprint)
	if !r.Config.Enabled || e != nil || a.Port() == 0 || a.Addr().Is4In6() ||
		!platform.PublicAddress(a.Addr()) ||
		pe != nil ||
		len(pin) != 32 ||
		r.Config.BufferBytes < 2<<20 ||
		r.Config.BufferBytes > 64<<20 ||
		r.Config.UDPReserveBytes < 512<<10 ||
		r.Config.UDPReserveBytes >= r.Config.BufferBytes-model.ContinuityFixedReserveBytes ||
		r.Config.DisconnectedGraceSeconds < 1 ||
		r.Config.DisconnectedGraceSeconds > 300 {
		return errors.New("invalid_continuity_config")
	}
	if _, e := tls.X509KeyPair([]byte(r.Certificate), []byte(r.PrivateKey)); e != nil {
		return errors.New("invalid_continuity_identity")
	}
	p := r.Path
	if p.SourceID != dataplane.ContinuitySourceID || p.Kind != "continuity" || p.Slot < 1 ||
		p.Slot > 250 ||
		p.Mark != adapter.Mark(p.Slot) ||
		p.Queue != uint16(21000+p.Slot) ||
		p.ProxyURL != nil ||
		p.ProxyPort != 0 ||
		p.Interface != "" ||
		!p.UDP ||
		p.TransparentPort < 1024 ||
		p.TransparentPort > 65535 ||
		p.DNSPort != 0 &&
			(p.DNSPort < 1024 || p.DNSPort > 65535 || p.DNSPort == p.TransparentPort) {
		return errors.New("invalid_continuity_allocation")
	}
	if p.IPv6 != (r.Network.IPv6 == "proxy") ||
		(p.DNSPort != 0) != (r.Network.DNS == "selected-path") ||
		len(r.Sources) == 0 ||
		len(r.Sources) > 249 {
		return errors.New("invalid_continuity_network")
	}
	seen := map[string]bool{}
	d := dataplane.Desired{
		Network:    r.Network,
		Fallback:   "closed",
		Selected:   r.Preferred,
		Continuity: &dataplane.ContinuityIntent{Config: r.Config, Path: continuityAllocation(r)},
	}
	for _, s := range r.Sources {
		if !packetSourceID.MatchString(s.SourceID) || s.SourceID == dataplane.ContinuitySourceID ||
			seen[s.SourceID] ||
			s.ProxyURL != nil ||
			s.Slot < 1 ||
			s.Slot > 250 ||
			s.Mark != adapter.Mark(s.Slot) {
			return errors.New("invalid_continuity_source")
		}
		seen[s.SourceID] = true
		if err := validateContinuitySource(s); err != nil {
			return err
		}
		d.Paths = append(d.Paths, continuitySourceAllocation(s))
	}
	if r.Preferred != "" && !seen[r.Preferred] ||
		r.Standby != "" && (!seen[r.Standby] || r.Standby == r.Preferred) {
		return errors.New("invalid_continuity_selection")
	}
	if _, e := dataplane.Compile(d); e != nil {
		return errors.New("invalid_continuity_network")
	}
	return nil
}

func continuityAllocation(r ContinuityWorkerRequest) dataplane.Path {
	return dataplane.Path{
		SourceID: dataplane.ContinuitySourceID,
		Kind:     "tproxy",
		Slot:     uint16(r.Path.Slot),
		Port:     uint16(r.Path.TransparentPort),
		DNSPort:  uint16(r.Path.DNSPort),
		IPv6:     r.Path.IPv6,
		UDP:      true,
	}
}

func validateContinuityRequest(r ContinuityRequest) error {
	if r.Action == "bind" {
		if r.Config == nil || r.Start != nil || r.SourceID != "" || r.Standby != "" ||
			r.ClientAddress != "" ||
			r.Destination != "" {
			return errors.New("invalid_request")
		}
		a, e := netip.ParseAddrPort(r.Config.RelayAddress)
		pin, pe := hex.DecodeString(r.Config.RelayFingerprint)
		if !r.Config.Enabled || e != nil || a.Port() == 0 || a.Addr().Is4In6() ||
			!platform.PublicAddress(a.Addr()) ||
			pe != nil ||
			len(pin) != 32 {
			return errors.New("invalid_continuity_config")
		}
		return nil
	}
	if r.Config != nil {
		return errors.New("invalid_request")
	}
	if r.Action == "udp_reply" {
		if r.Start != nil || r.SourceID != "" || r.Standby != "" {
			return errors.New("invalid_request")
		}
		c, e := netip.ParseAddrPort(r.ClientAddress)
		d, de := netip.ParseAddrPort(r.Destination)
		if e != nil || de != nil || c.Port() == 0 || d.Port() == 0 ||
			c.Addr().Is6() != d.Addr().Is6() ||
			c.Addr().Is4In6() ||
			d.Addr().Is4In6() ||
			c.Addr().Zone() != "" ||
			d.Addr().Zone() != "" ||
			!c.Addr().IsGlobalUnicast() ||
			(!platform.PublicAddress(d.Addr()) && (d.Port() != 53 || !d.Addr().IsPrivate())) {
			return errors.New("invalid_continuity_datagram")
		}
		return nil
	}
	if r.ClientAddress != "" || r.Destination != "" {
		return errors.New("invalid_request")
	}
	if r.Action == "start" {
		if r.Start == nil || r.SourceID != "" || r.Standby != "" || r.Start.HelperSocket != "" ||
			len(r.Start.Listeners) != 0 {
			return errors.New("invalid_request")
		}
		return ValidateContinuityWorker(*r.Start)
	}
	if r.Start != nil {
		return errors.New("invalid_request")
	}
	switch r.Action {
	case "status":
		if r.SourceID != "" || r.Standby != "" {
			return errors.New("invalid_request")
		}
	case "dial":
		if !packetSourceID.MatchString(r.SourceID) || r.Standby != "" {
			return errors.New("invalid_request")
		}
	case "select":
		if r.SourceID != "" && !packetSourceID.MatchString(r.SourceID) ||
			r.Standby != "" &&
				(!packetSourceID.MatchString(r.Standby) || r.SourceID == r.Standby || r.SourceID == "") {
			return errors.New("invalid_request")
		}
	default:
		return errors.New("invalid_request")
	}
	return nil
}

func (s *Server) validateContinuityPathLocked(d dataplane.Desired) error {
	if d.Continuity == nil {
		return nil
	}
	r := s.continuity
	if r == nil || !r.ready {
		return errors.New("continuity_input_unowned")
	}
	select {
	case <-r.done:
		return errors.New("continuity_input_unavailable")
	default:
	}
	if !reflect.DeepEqual(d.Continuity.Config, r.request.Config) ||
		d.Continuity.Path != continuityAllocation(r.request) ||
		!reflect.DeepEqual(d.Network, r.request.Network) ||
		!sameContinuitySources(d.Paths, r.request.Sources) {
		return errors.New("continuity_input_mismatch")
	}
	return nil
}

func (s *Server) handleContinuity(
	ctx context.Context,
	c *net.UnixConn,
	reader *bufio.Reader,
	r ContinuityRequest,
	release func(),
) {
	if r.Action == "bind" {
		s.probeMu.Lock()
		ok := s.continuity == nil || reflect.DeepEqual(s.continuity.request.Config, *r.Config)
		if ok {
			v := *r.Config
			s.continuityRelay = &v
		}
		s.probeMu.Unlock()
		if !ok {
			writeResponse(c, Response{Error: "continuity_binding_active"})
		} else {
			writeResponse(c, Response{OK: true})
		}
		return
	}
	if r.Action == "start" {
		s.startContinuity(ctx, c, reader, *r.Start, release)
		return
	}
	s.probeMu.Lock()
	reg := s.continuity
	bound := s.continuityRelay
	ready := reg != nil && reg.ready
	s.probeMu.Unlock()
	if r.Action == "dial" && reg == nil && bound != nil {
		path, err := s.probePath(r.SourceID)
		if err == nil && path.Kind == "interface" {
			inspect := s.inspectProbeTunnel
			if inspect == nil {
				inspect = inspectNativeProbeTunnel
			}
			err = inspect(ctx, path.Interface)
		}
		if err != nil {
			writeResponse(c, Response{Error: "continuity_source_unavailable"})
			return
		}
		bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		if validateLiveContinuityRelay(bound.RelayAddress) != nil {
			writeResponse(c, Response{Error: "continuity_relay_forbidden"})
			return
		}
		conn, err := dialMarked(bounded, path, bound.RelayAddress)
		if err != nil {
			writeResponse(c, Response{Error: "continuity_connect_failed"})
			return
		}
		defer func() { _ = conn.Close() }()
		_ = sendConn(c, conn)
		return
	}
	if reg == nil {
		writeResponse(
			c,
			Response{
				OK:         r.Action == "status",
				Continuity: &ContinuityStatus{Snapshot: continuity.Snapshot{Status: "Disabled"}},
				Error: func() string {
					if r.Action == "status" {
						return ""
					}
					return "continuity_unavailable"
				}(),
			},
		)
		return
	}
	if r.Action != "status" {
		if !ready {
			writeResponse(c, Response{Error: "continuity_starting"})
			return
		}
		select {
		case <-reg.done:
			writeResponse(c, Response{Error: "continuity_unavailable"})
			return
		default:
		}
	}
	switch r.Action {
	case "udp_reply":
		s.continuityUDPReply(ctx, c, reg, r)
		return
	case "status":
		reg.mu.Lock()
		status := reg.status
		status.QueueBytes += reg.replyBytes
		status.UDPQueueBytes += reg.replyBytes
		status.HelperQueueBytes = reg.replyBytes
		status.DroppedUDP += reg.helperDroppedUDP
		reg.mu.Unlock()
		writeResponse(c, Response{OK: true, Continuity: &status})
	case "select":
		known := func(id string) bool {
			if id == "" {
				return true
			}
			for _, p := range reg.request.Sources {
				if p.SourceID == id {
					return true
				}
			}
			return false
		}
		if !known(r.SourceID) || !known(r.Standby) {
			writeResponse(c, Response{Error: "continuity_source_unprepared"})
			return
		}
		err := reg.sendCommand(ctx, r)
		writeResponse(c, Response{OK: err == nil, Error: func() string {
			if err != nil {
				return "continuity_command_failed"
			}
			return ""
		}()})
	case "dial":
		var allowed bool
		for _, p := range reg.request.Sources {
			if p.SourceID == r.SourceID && p.ProxyPort == 0 {
				allowed = true
			}
		}
		if !allowed {
			writeResponse(c, Response{Error: "continuity_source_unprepared"})
			return
		}
		path, err := s.probePath(r.SourceID)
		if err == nil {
			for _, p := range reg.request.Sources {
				if p.SourceID == r.SourceID &&
					!sameProbeAllocation(path, continuitySourceAllocation(p)) {
					err = errors.New("continuity_source_mismatch")
				}
			}
		}
		if err == nil && path.Kind == "interface" {
			inspect := s.inspectProbeTunnel
			if inspect == nil {
				inspect = inspectNativeProbeTunnel
			}
			err = inspect(ctx, path.Interface)
		}
		if err != nil {
			writeResponse(c, Response{Error: "continuity_source_unavailable"})
			return
		}
		bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		if validateLiveContinuityRelay(reg.request.Config.RelayAddress) != nil {
			writeResponse(c, Response{Error: "continuity_relay_forbidden"})
			return
		}
		conn, err := dialMarked(bounded, path, reg.request.Config.RelayAddress)
		if err != nil {
			writeResponse(c, Response{Error: "continuity_connect_failed"})
			return
		}
		defer func() { _ = conn.Close() }()
		_ = sendConn(c, conn)
	}
}

func (s *Server) startContinuity(
	ctx context.Context,
	c *net.UnixConn,
	reader *bufio.Reader,
	request ContinuityWorkerRequest,
	release func(),
) {
	uid, err := peerUID(c)
	if err != nil || uid != s.AllowedUID || uid == 0 {
		writeResponse(c, Response{Error: "continuity_identity_invalid"})
		return
	}
	gid, err := peerGID(c)
	if err != nil || gid == 0 {
		writeResponse(c, Response{Error: "continuity_identity_invalid"})
		return
	}
	request.HelperSocket = s.SocketPath
	reg := &continuityRegistration{
		request:  request,
		done:     make(chan struct{}),
		commands: make(chan continuityCommand, 16),
		leases:   make(chan struct{}, 256),
		status:   ContinuityStatus{Snapshot: continuity.Snapshot{Status: "Disconnected"}},
	}
	s.probeMu.Lock()
	if s.continuity != nil {
		err = errors.New("continuity_already_running")
	}
	if err == nil {
		err = s.validateProbeAllocationLocked(continuityAllocation(request))
	}
	if err == nil {
		err = s.validateContinuitySourcesLocked(request.Sources)
	}
	if err == nil && s.continuityRelay != nil &&
		!reflect.DeepEqual(*s.continuityRelay, request.Config) {
		err = errors.New("continuity_binding_mismatch")
	}
	if err == nil {
		s.continuity = reg
	}
	s.probeMu.Unlock()
	if err != nil {
		writeResponse(c, Response{Error: safeError(err)})
		return
	}
	defer func() {
		s.probeMu.Lock()
		if s.continuity == reg {
			s.continuity = nil
		}
		s.probeMu.Unlock()
	}()
	var life io.Closer
	var statuses *bufio.Reader
	var cmd *exec.Cmd
	var commandPipe io.WriteCloser
	err = s.Manager.WithRuntime(func() error {
		var e error
		cmd, life, commandPipe, statuses, e = startContinuityProcess(ctx, request, uid, gid)
		return e
	})
	if err != nil {
		close(reg.done)
		writeResponse(c, Response{Error: safeError(err)})
		return
	}
	defer func() { _ = life.Close() }()
	defer func() { _ = commandPipe.Close() }()
	s.probeMu.Lock()
	reg.cmd, reg.ready = cmd, true
	s.probeMu.Unlock()
	done := reg.done
	go func() { _ = cmd.Wait(); close(done) }()
	go reg.writeCommands(commandPipe, life)
	go reg.readStatus(statuses, life)
	writeResponse(c, Response{OK: true})
	_ = c.SetDeadline(time.Time{})
	release()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	ownerDone := make(chan struct{})
	go func() { var b [1]byte; _, _ = reader.Read(b[:]); close(ownerDone) }()
	select {
	case <-done:
	case <-ownerDone:
	case <-ctx.Done():
	}
	_ = life.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		_ = reg.cmd.Process.Kill()
		<-done
	}
	s.probeMu.Lock()
	if s.continuity == reg {
		s.continuity = nil
	}
	s.probeMu.Unlock()
	_ = c.Close()
}

func (c *Client) ContinuityStatus(ctx context.Context) (ContinuityStatus, error) {
	r, e := c.call(
		ctx,
		Request{Operation: "continuity", Continuity: &ContinuityRequest{Action: "status"}},
	)
	if e != nil {
		return ContinuityStatus{}, e
	}
	if r.Continuity == nil {
		return ContinuityStatus{}, errors.New("invalid_helper_response")
	}
	return *r.Continuity, nil
}

func (c *Client) SelectContinuity(ctx context.Context, primary, standby string) error {
	_, e := c.call(
		ctx,
		Request{
			Operation:  "continuity",
			Continuity: &ContinuityRequest{Action: "select", SourceID: primary, Standby: standby},
		},
	)
	return e
}

func (c *Client) BindContinuityRelay(ctx context.Context, config model.ContinuityConfig) error {
	_, e := c.call(
		ctx,
		Request{
			Operation:  "continuity",
			Continuity: &ContinuityRequest{Action: "bind", Config: &config},
		},
	)
	return e
}

func (c *Client) StartContinuity(
	ctx context.Context,
	request ContinuityWorkerRequest,
) (adapter.ManagedProcess, error) {
	r := Request{
		Operation:  "continuity",
		Continuity: &ContinuityRequest{Action: "start", Start: &request},
	}
	if e := validateRequest(r); e != nil {
		return nil, e
	}
	conn, e := c.connect(ctx)
	if e != nil {
		return nil, e
	}
	raw, _ := json.Marshal(r)
	if len(raw)+1 > MaxRequestBytes {
		_ = conn.Close()
		return nil, errors.New("request_too_large")
	}
	if _, e = conn.Write(append(raw, '\n')); e != nil {
		_ = conn.Close()
		return nil, e
	}
	reader := bufio.NewReaderSize(conn, MaxRequestBytes+1)
	line, e := reader.ReadSlice('\n')
	var reply Response
	if e != nil || DecodeStrict(line, &reply) != nil || !reply.OK {
		_ = conn.Close()
		return nil, errors.New("continuity_start_failed")
	}
	_ = conn.SetDeadline(time.Time{})
	p := &managedEngineProcess{conn: conn, done: make(chan struct{})}
	go func() { _, _ = io.Copy(io.Discard, reader); _ = conn.Close(); close(p.done) }()
	return p, nil
}
