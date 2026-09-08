package helper

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/dataplane"
	"github.com/tibeahx/OpenRHP/internal/model"
)

type engineRegistration struct {
	Request EngineRequest
	cmd     *exec.Cmd
	ready   bool
	done    <-chan struct{}
}

func engineAllocation(r EngineRequest) dataplane.Path {
	return dataplane.Path{
		SourceID: r.Source.ID,
		Kind:     "tproxy",
		Slot:     uint16(r.Path.Slot),
		Port:     uint16(r.Path.TransparentPort),
		DNSPort:  uint16(r.Path.DNSPort),
		UDP:      r.Path.UDP,
		IPv6:     r.Path.IPv6,
	}
}

func (s *Server) handleEngine(
	ctx context.Context,
	conn *net.UnixConn,
	reader *bufio.Reader,
	request EngineRequest,
	release func(),
) {
	uid, e := peerUID(conn)
	if e != nil || uid != s.AllowedUID || uid == 0 {
		writeResponse(conn, Response{Error: "engine_service_identity_invalid"})
		return
	}
	gid, e := peerGID(conn)
	if e != nil || gid == 0 {
		writeResponse(conn, Response{Error: "engine_service_identity_invalid"})
		return
	}
	record := &engineRegistration{Request: request}
	s.probeMu.Lock()
	if e = s.validateProbeAllocationLocked(engineAllocation(request)); e == nil {
		if s.engines == nil {
			s.engines = map[string]*engineRegistration{}
		}
		if len(s.engines) >= 250 {
			e = errors.New("engine_resource_limit")
		} else if s.engines[request.Source.ID] != nil {
			e = errors.New("engine_source_busy")
		} else {
			s.engines[request.Source.ID] = record
		}
	}
	s.probeMu.Unlock()
	if e != nil {
		writeResponse(conn, Response{Error: safeError(e)})
		return
	}
	defer func() {
		s.probeMu.Lock()
		if s.engines[request.Source.ID] == record {
			delete(s.engines, request.Source.ID)
		}
		s.probeMu.Unlock()
	}()
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	cmd, life, e := StartEngineWorker(bounded, request, uid, gid)
	cancel()
	if e != nil {
		writeResponse(conn, Response{Error: safeError(e)})
		return
	}
	defer func() { _ = life.Close() }()
	exited := make(chan struct{})
	s.probeMu.Lock()
	record.cmd, record.ready, record.done = cmd, true, exited
	s.probeMu.Unlock()
	go func() { _ = cmd.Wait(); close(exited) }()
	writeResponse(conn, Response{OK: true})
	_ = conn.SetDeadline(time.Time{})
	release() // Ready engines have their own bounded registry, not RPC admission slots.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	requestStop := make(chan struct{})
	go func() { var b [1]byte; _, _ = reader.Read(b[:]); close(requestStop) }()
	select {
	case <-exited:
	case <-requestStop:
	case <-ctx.Done():
	}
	_ = life.Close()
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-exited
	}
	// Remove ownership only after the child is reaped, and before EOF lets the
	// client retry its same allocation. This avoids a stopped-generation race.
	s.probeMu.Lock()
	if s.engines[request.Source.ID] == record {
		delete(s.engines, request.Source.ID)
	}
	s.probeMu.Unlock()
	// Explicit client Close waits for this EOF before reusing listener ports.
	_ = conn.Close()
	<-requestStop
}

type managedEngineProcess struct {
	conn *net.UnixConn
	done chan struct{}
	once sync.Once
}

func (p *managedEngineProcess) Alive() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func (p *managedEngineProcess) Done() <-chan struct{} {
	return p.done
}

func (p *managedEngineProcess) Close(ctx context.Context) error {
	p.once.Do(func() {
		_ = p.conn.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = p.conn.Write([]byte("stop\n"))
	})
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		_ = p.conn.Close()
		return ctx.Err()
	}
}

func (c *Client) StartEngine(
	ctx context.Context,
	source model.Source,
	path adapter.Path,
) (adapter.ManagedProcess, error) {
	path.ProxyURL = nil
	request := Request{
		Operation: "start_engine",
		Engine:    &EngineRequest{Source: source, Path: path, DNSResolver: path.DNSResolver},
	}
	if e := validateRequest(request); e != nil {
		return nil, e
	}
	conn, e := c.connect(ctx)
	if e != nil {
		return nil, e
	}
	fail := true
	defer func() {
		if fail {
			_ = conn.Close()
		}
	}()
	raw, e := json.Marshal(request)
	if e != nil || len(raw)+1 > MaxRequestBytes {
		return nil, errors.New("invalid_engine_request")
	}
	if _, e = conn.Write(append(raw, '\n')); e != nil {
		return nil, errors.New("engine_helper_unavailable")
	}
	reader := bufio.NewReader(io.LimitReader(conn, MaxRequestBytes+1))
	reply, e := reader.ReadBytes('\n')
	if e != nil {
		return nil, errors.New("engine_helper_unavailable")
	}
	var response Response
	if DecodeStrict(reply, &response) != nil {
		return nil, errors.New("invalid_helper_response")
	}
	if !response.OK {
		return nil, errors.New(response.Error)
	}
	_ = conn.SetDeadline(time.Time{})
	p := &managedEngineProcess{conn: conn, done: make(chan struct{})}
	go func() { _, _ = io.Copy(io.Discard, reader); _ = conn.Close(); close(p.done) }()
	fail = false
	return p, nil
}

func (s *Server) validateManagedPlanPathLocked(p dataplane.Path) error {
	if p.Kind != "tproxy" {
		return nil
	}
	record := s.engines[p.SourceID]
	if record == nil || !record.ready {
		return errors.New("engine_input_unowned")
	}
	select {
	case <-record.done:
		return errors.New("engine_input_unavailable")
	default:
	}
	expected := engineAllocation(record.Request)
	if p.Slot != expected.Slot || p.Port != expected.Port || p.DNSPort != expected.DNSPort ||
		p.IPv6 != expected.IPv6 ||
		p.UDP != expected.UDP {
		return errors.New("engine_input_mismatch")
	}
	return nil
}
