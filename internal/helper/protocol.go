package helper

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tibeahx/OpenRHP/internal/coverage"
	"github.com/tibeahx/OpenRHP/internal/dataplane"
	"github.com/tibeahx/OpenRHP/internal/maintenance"
	"github.com/tibeahx/OpenRHP/internal/model"
	"github.com/tibeahx/OpenRHP/internal/platform"
)

type Request struct {
	Continuity     *ContinuityRequest       `json:"continuity,omitempty"`
	Maintenance    *maintenance.WireRequest `json:"maintenance,omitempty"`
	Gateway        *coverage.Operation      `json:"gateway,omitempty"`
	Engine         *EngineRequest           `json:"engine,omitempty"`
	ProbePath      *NativeProbePath         `json:"probe_path,omitempty"`
	Operation      string                   `json:"operation"`
	Desired        *dataplane.Desired       `json:"desired,omitempty"`
	TransactionID  string                   `json:"transaction_id,omitempty"`
	TimeoutSeconds int                      `json:"timeout_seconds,omitempty"`
	SourceID       string                   `json:"source_id,omitempty"`
	Address        string                   `json:"address,omitempty"`
	Slot           uint16                   `json:"slot,omitempty"`
}
type Response struct {
	Continuity  *ContinuityStatus         `json:"continuity,omitempty"`
	Maintenance *maintenance.WireResponse `json:"maintenance,omitempty"`
	Gateway     map[string]any            `json:"gateway,omitempty"`
	OK          bool                      `json:"ok"`
	Error       string                    `json:"error,omitempty"`
	State       *State                    `json:"state,omitempty"`
	Transaction *Transaction              `json:"transaction,omitempty"`
	Platform    *platform.Report          `json:"platform,omitempty"`
}
type Server struct {
	continuity         *continuityRegistration
	continuityRelay    *model.ContinuityConfig
	Maintenance        maintenance.Service
	Gateway            coverage.Operator
	probeMu            sync.Mutex
	nativeProbes       map[string]nativeProbeRegistration
	engines            map[string]*engineRegistration
	inspectProbeTunnel func(context.Context, string) error
	Manager            *Manager
	AllowedUID         uint32
	SocketPath         string
	MaxConnections     int
	Packet             *PacketManager
}

func (s *Server) Serve(ctx context.Context) error {
	if err := supportedPeerCredentials(); err != nil {
		return err
	}
	if s.Manager == nil || !filepath.IsAbs(s.SocketPath) {
		return errors.New("helper requires manager and absolute socket path")
	}
	parent, err := os.Lstat(filepath.Dir(s.SocketPath))
	if err != nil {
		return err
	}
	if !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0o022 != 0 ||
		!ownedByCurrentUID(parent) {
		return errors.New("socket parent must be owned by helper and not writable by other users")
	}
	if existing, e := os.Lstat(s.SocketPath); e == nil {
		if existing.Mode()&os.ModeSocket == 0 || !ownedByCurrentUID(existing) {
			return errors.New("refusing to replace a foreign socket or file")
		}
		conn, e := net.DialTimeout("unix", s.SocketPath, 250*time.Millisecond)
		if e == nil {
			_ = conn.Close()
			return errors.New("helper socket is already serving")
		}
		if e = os.Remove(s.SocketPath); e != nil {
			return e
		}
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.SocketPath, Net: "unix"})
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	defer func() { _ = os.Remove(s.SocketPath) }()
	if err = os.Chmod(s.SocketPath, 0o600); err != nil {
		return err
	}
	if err = os.Chown(s.SocketPath, int(s.AllowedUID), -1); err != nil {
		return err
	}
	go func() { <-ctx.Done(); _ = listener.Close() }()
	n := s.MaxConnections
	if n <= 0 || n > 32 {
		n = 8
	}
	slots := make(chan struct{}, n)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			wg.Add(1)
			go func() {
				defer wg.Done()
				var once sync.Once
				release := func() { once.Do(func() { <-slots }) }
				defer release()
				defer func() { _ = conn.Close() }()
				s.handle(ctx, conn, release)
			}()
		default:
			_ = conn.Close()
		}
	}
}

func (s *Server) handle(ctx context.Context, conn *net.UnixConn, release func()) {
	_ = conn.SetDeadline(time.Now().Add(25 * time.Second))
	uid, err := peerUID(conn)
	if err != nil || uid != s.AllowedUID {
		return
	}
	reader := bufio.NewReaderSize(conn, MaxRequestBytes+1)
	data, err := reader.ReadSlice('\n')
	if err != nil || len(data) > MaxRequestBytes {
		return
	}
	var req Request
	if err = DecodeStrict(data, &req); err != nil {
		writeResponse(conn, Response{Error: "invalid_request"})
		return
	}
	if err = validateRequest(req); err != nil {
		writeResponse(conn, Response{Error: "invalid_request"})
		return
	}
	if req.Operation == "continuity" {
		s.handleContinuity(ctx, conn, reader, *req.Continuity, release)
		return
	}
	if req.Operation == "dial_probe" {
		s.handleProbe(ctx, conn, req)
		return
	}
	if req.Operation == "start_engine" {
		s.handleEngine(ctx, conn, reader, *req.Engine, release)
		return
	}
	resp := Response{OK: true}
	switch req.Operation {
	case "maintenance":
		resp.Maintenance, err = serveMaintenance(ctx, s.Maintenance, *req.Maintenance)
	case "gateway":
		if s.Gateway == nil {
			err = errors.New("gateway_helper_unavailable")
		} else {
			err = s.Manager.WithRuntime(func() error {
				var gatewayErr error
				resp.Gateway, gatewayErr = s.Gateway.Do(ctx, *req.Gateway)
				return gatewayErr
			})
		}
	case "platform":
		detect := platform.Detect
		if backend, ok := s.Manager.backend.(*NetworkBackend); ok && backend.Detect != nil {
			detect = backend.Detect
		}
		report := detect(ctx)
		resp.Platform = &report
	case "register_probe":
		err = s.registerProbe(ctx, *req.ProbePath)
	case "unregister_probe":
		err = s.unregisterProbe(req.SourceID)
	case "start_packet":
		if s.Packet == nil {
			err = errors.New("capability_unavailable")
		} else {
			s.probeMu.Lock()
			err = s.validateProbeAllocationLocked(
				dataplane.Path{SourceID: req.SourceID, Kind: "packet-engine", Slot: req.Slot},
			)
			if err == nil {
				err = s.Manager.WithRuntime(
					func() error { return s.Packet.Start(ctx, req.SourceID, int(req.Slot)) },
				)
			}
			s.probeMu.Unlock()
		}
	case "stop_packet":
		if s.Packet == nil {
			err = errors.New("capability_unavailable")
		} else {
			err = s.Packet.Stop(ctx, req.SourceID)
		}
	case "status":
		state, e := s.Manager.Status()
		err = e
		state.IngressBound = false
		state.Ingress = nil
		state.DNSGuard = nil // Private ownership metadata never leaves the privileged journal.
		resp.State = &state
	case "prepare":
		s.probeMu.Lock()
		err = s.validateContinuityPathLocked(*req.Desired)
		for _, p := range req.Desired.Paths {
			if err != nil {
				break
			}
			if err = s.validateProbeAllocationLocked(p); err != nil {
				break
			}
			if err = s.validateManagedPlanPathLocked(p); err != nil {
				break
			}
		}
		if err == nil {
			t, e := s.Manager.Prepare(ctx, *req.Desired)
			err = e
			resp.Transaction = &t
		}
		s.probeMu.Unlock()
	case "apply":
		s.probeMu.Lock()
		state, e := s.Manager.Status()
		err = e
		if err == nil && state.Transaction != nil && state.Transaction.ID == req.TransactionID {
			err = s.validateContinuityPathLocked(state.Transaction.Candidate)
		}
		if err == nil {
			t, e := s.Manager.Apply(
				ctx,
				req.TransactionID,
				time.Duration(req.TimeoutSeconds)*time.Second,
			)
			err = e
			resp.Transaction = &t
		}
		s.probeMu.Unlock()
	case "confirm":
		t, e := s.Manager.Confirm(req.TransactionID)
		err = e
		resp.Transaction = &t
	case "rollback":
		t, e := s.Manager.Rollback(ctx, req.TransactionID)
		err = e
		resp.Transaction = &t
	case "switch":
		t, e := s.switchRegistered(ctx, req.SourceID)
		err = e
		resp.Transaction = &t
	default:
		err = errors.New("operation_not_allowed")
	}
	if err != nil {
		resp = Response{Error: safeError(err)}
	}
	writeResponse(conn, resp)
}

func validateRequest(r Request) error {
	if r.Operation == "continuity" {
		if r.Continuity == nil || r.Maintenance != nil || r.Gateway != nil || r.Engine != nil ||
			r.ProbePath != nil ||
			r.Desired != nil ||
			r.TransactionID != "" ||
			r.TimeoutSeconds != 0 ||
			r.SourceID != "" ||
			r.Address != "" ||
			r.Slot != 0 {
			return errors.New("invalid_request")
		}
		return validateContinuityRequest(*r.Continuity)
	}
	if r.Continuity != nil {
		return errors.New("invalid_request")
	}
	if r.Operation != "maintenance" && r.Maintenance != nil {
		return errors.New("invalid_request")
	}
	if r.Operation != "gateway" && r.Gateway != nil {
		return errors.New("invalid_request")
	}
	if r.Operation != "start_engine" && r.Engine != nil {
		return errors.New("invalid_request")
	}
	if r.Operation != "register_probe" && r.ProbePath != nil {
		return errors.New("invalid_request")
	}
	if len(r.SourceID) > 80 || len(r.Address) > 256 ||
		(r.Operation != "start_packet" && r.Slot != 0) {
		return errors.New("invalid_request")
	}
	switch r.Operation {
	case "maintenance":
		if r.Maintenance == nil || r.Gateway != nil || r.Engine != nil || r.ProbePath != nil ||
			r.Desired != nil ||
			r.TransactionID != "" ||
			r.TimeoutSeconds != 0 ||
			r.SourceID != "" ||
			r.Address != "" ||
			r.Slot != 0 {
			return errors.New("invalid_request")
		}
		return maintenance.ValidateWire(*r.Maintenance)
	case "gateway":
		if r.Gateway == nil || r.Engine != nil || r.ProbePath != nil || r.Desired != nil ||
			r.TransactionID != "" ||
			r.TimeoutSeconds != 0 ||
			r.SourceID != "" ||
			r.Address != "" ||
			r.Slot != 0 {
			return errors.New("invalid_request")
		}
		return validateGatewayOperation(*r.Gateway)
	case "start_engine":
		if r.Engine == nil || r.ProbePath != nil || r.Desired != nil || r.TransactionID != "" ||
			r.TimeoutSeconds != 0 ||
			r.SourceID != "" ||
			r.Address != "" ||
			r.Slot != 0 {
			return errors.New("invalid_request")
		}
		return ValidateEngineRequest(*r.Engine)
	case "register_probe":
		if r.ProbePath == nil || r.Desired != nil || r.TransactionID != "" ||
			r.TimeoutSeconds != 0 ||
			r.SourceID != "" ||
			r.Address != "" ||
			r.Slot != 0 {
			return errors.New("invalid_request")
		}
		return validateNativeProbe(*r.ProbePath)
	case "unregister_probe":
		if !packetSourceID.MatchString(r.SourceID) || r.Desired != nil || r.TransactionID != "" ||
			r.TimeoutSeconds != 0 ||
			r.Address != "" ||
			r.Slot != 0 {
			return errors.New("invalid_request")
		}
	case "start_packet", "stop_packet":
		if r.Desired != nil || r.TransactionID != "" || r.TimeoutSeconds != 0 || r.Address != "" {
			return errors.New("invalid_request")
		}
		slot := int(r.Slot)
		if r.Operation == "stop_packet" {
			slot = 1
		}
		if err := validatePacketRequest(r.SourceID, slot); err != nil {
			return err
		}
	case "status", "platform":
		if r.Desired != nil || r.TransactionID != "" || r.TimeoutSeconds != 0 || r.SourceID != "" ||
			r.Address != "" {
			return errors.New("invalid_request")
		}
	case "prepare":
		if r.Desired == nil || r.TransactionID != "" || r.TimeoutSeconds != 0 || r.SourceID != "" ||
			r.Address != "" {
			return errors.New("invalid_request")
		}
	case "apply", "confirm", "rollback":
		if !validTransactionID(r.TransactionID) || r.Desired != nil || r.SourceID != "" ||
			r.Address != "" {
			return errors.New("invalid_request")
		}
		if r.Operation == "apply" {
			if r.TimeoutSeconds < 30 || r.TimeoutSeconds > 180 {
				return errors.New("invalid_request")
			}
		} else if r.TimeoutSeconds != 0 {
			return errors.New("invalid_request")
		}
	case "switch":
		if r.Desired != nil || r.TransactionID != "" || r.TimeoutSeconds != 0 || r.Address != "" {
			return errors.New("invalid_request")
		}
	case "dial_probe":
		if r.SourceID == "" || r.Address == "" || r.Desired != nil || r.TransactionID != "" ||
			r.TimeoutSeconds != 0 {
			return errors.New("invalid_request")
		}
	default:
		return errors.New("operation_not_allowed")
	}
	return nil
}

func safeError(err error) string {
	code, _, _ := strings.Cut(err.Error(), ":")
	if len(code) > 64 {
		return "helper_failed"
	}
	for _, r := range code {
		if (r < 'a' || r > 'z') && r != '_' {
			return "helper_failed"
		}
	}
	return code
}

func writeResponse(conn *net.UnixConn, r Response) {
	data, _ := json.Marshal(r)
	data = append(data, '\n')
	_, _ = conn.Write(data)
}

type Client struct {
	SocketPath  string
	ExpectedUID uint32
}

func (c *Client) connect(ctx context.Context) (*net.UnixConn, error) {
	if err := supportedPeerCredentials(); err != nil {
		return nil, err
	}
	info, err := os.Lstat(c.SocketPath)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("helper socket permissions are unsafe")
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return nil, err
	}
	uc := conn.(*net.UnixConn)
	uid, err := peerUID(uc)
	if err != nil || uid != c.ExpectedUID {
		_ = conn.Close()
		return nil, errors.New("helper socket owner identity is invalid")
	}
	deadline := time.Now().Add(25 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = uc.SetDeadline(deadline)
	return uc, nil
}

func (c *Client) call(ctx context.Context, req Request) (Response, error) {
	var resp Response
	if err := validateRequest(req); err != nil {
		return resp, err
	}
	conn, err := c.connect(ctx)
	if err != nil {
		return resp, err
	}
	defer func() { _ = conn.Close() }()
	data, err := json.Marshal(req)
	if err != nil {
		return resp, err
	}
	if len(data)+1 > MaxRequestBytes {
		return resp, errors.New("request_too_large")
	}
	if _, err = conn.Write(append(data, '\n')); err != nil {
		return resp, err
	}
	data, err = bufio.NewReader(io.LimitReader(conn, MaxRequestBytes+1)).ReadBytes('\n')
	if err != nil {
		return resp, err
	}
	if err = DecodeStrict(data, &resp); err != nil {
		return resp, err
	}
	if !resp.OK {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

func (c *Client) Status(ctx context.Context) (State, error) {
	r, e := c.call(ctx, Request{Operation: "status"})
	if e != nil {
		return State{}, e
	}
	if r.State == nil {
		return State{}, errors.New("invalid_helper_response")
	}
	return *r.State, nil
}

func (c *Client) Prepare(ctx context.Context, d dataplane.Desired) (Transaction, error) {
	r, e := c.call(ctx, Request{Operation: "prepare", Desired: &d})
	return transactionResponse(r, e)
}

func (c *Client) Apply(ctx context.Context, id string, timeout time.Duration) (Transaction, error) {
	r, e := c.call(
		ctx,
		Request{Operation: "apply", TransactionID: id, TimeoutSeconds: int(timeout / time.Second)},
	)
	return transactionResponse(r, e)
}

func (c *Client) Confirm(ctx context.Context, id string) (Transaction, error) {
	r, e := c.call(ctx, Request{Operation: "confirm", TransactionID: id})
	return transactionResponse(r, e)
}

func (c *Client) Rollback(ctx context.Context, id string) (Transaction, error) {
	r, e := c.call(ctx, Request{Operation: "rollback", TransactionID: id})
	return transactionResponse(r, e)
}

func (c *Client) Switch(ctx context.Context, sourceID string) (Transaction, error) {
	r, e := c.call(ctx, Request{Operation: "switch", SourceID: sourceID})
	return transactionResponse(r, e)
}

func transactionResponse(r Response, e error) (Transaction, error) {
	if e != nil {
		return Transaction{}, e
	}
	if r.Transaction == nil {
		return Transaction{}, errors.New("invalid_helper_response")
	}
	return *r.Transaction, nil
}

func (m *Manager) Switch(ctx context.Context, sourceID string) (Transaction, error) {
	if tx, handled, err := m.switchSelection(ctx, sourceID); handled || err != nil {
		return tx, err
	}
	s, err := m.Status()
	if err != nil {
		return Transaction{}, err
	}
	if s.Committed == nil {
		return Transaction{}, errors.New(
			"network_unconfigured: confirm network configuration first",
		)
	}
	if active(s.Transaction) {
		return Transaction{}, ErrBusy
	}
	if s.MaintenanceJob != "" || s.MaintenanceHold {
		return Transaction{}, ErrMaintenanceActive
	}
	d := *s.Committed
	d.Selected = sourceID
	if d.Selected == s.Committed.Selected && s.Transaction != nil && !s.Guarded {
		return *s.Transaction, nil
	}
	t, err := m.prepare(ctx, d, true)
	if err != nil {
		return t, err
	}
	t, err = m.Apply(ctx, t.ID, 30*time.Second)
	if err != nil {
		return t, err
	}
	return m.Confirm(t.ID)
}

func (c *Client) StartPacket(ctx context.Context, sourceID string, slot int) error {
	if slot < 1 || slot > 250 {
		return errors.New("invalid_packet_source")
	}
	_, e := c.call(ctx, Request{Operation: "start_packet", SourceID: sourceID, Slot: uint16(slot)})
	return e
}

func (c *Client) StopPacket(ctx context.Context, sourceID string) error {
	_, e := c.call(ctx, Request{Operation: "stop_packet", SourceID: sourceID})
	return e
}

// PeerUID is shared with the separately typed node helper. It always fails on
// platforms that cannot enforce the Linux peer-credential boundary.
func PeerUID(c *net.UnixConn) (uint32, error) {
	return peerUID(c)
}

func SupportedPeerCredentials() error {
	return supportedPeerCredentials()
}
