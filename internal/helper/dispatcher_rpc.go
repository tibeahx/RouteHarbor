package helper

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os/exec"
	"reflect"
	"syscall"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/dataplane"
	"github.com/tibeahx/OpenRHP/internal/dispatch"
	"github.com/tibeahx/OpenRHP/internal/routing"
)

type DispatcherRequest struct {
	Slot     int                  `json:"slot,omitempty"`
	Action   string               `json:"action"`
	Spec     *dispatch.Spec       `json:"spec,omitempty"`
	Snapshot *routing.SnapshotRef `json:"snapshot,omitempty"`
	Data     []byte               `json:"data,omitempty"`
	Offset   int64                `json:"offset,omitempty"`
	Learned  []string             `json:"learned,omitempty"`
	Selected string               `json:"selected,omitempty"`
}

type DispatcherStatus struct {
	Snapshot            *routing.SnapshotRef `json:"snapshot,omitempty"`
	Data                []byte               `json:"data,omitempty"`
	WANIdentity         string               `json:"wan_identity,omitempty"`
	Running             bool                 `json:"running"`
	Selected            string               `json:"selected"`
	PublishedGeneration uint64               `json:"published_generation"`
}

type dispatcherRegistration struct {
	spec        dispatch.Spec
	ref         routing.SnapshotRef
	secret      string
	cmd         *exec.Cmd
	done        <-chan struct{}
	ready       bool
	publication uint64
}

func validateDispatcherRequest(r DispatcherRequest) error {
	if r.Snapshot != nil {
		ref := *r.Snapshot
		if r.Action == "snapshot-info" && ref.Size == 0 {
			ref.Size = 1
		}
		if routing.ValidateReference(ref) != nil {
			return errors.New("invalid_dispatcher_snapshot")
		}
	}
	if r.Slot < 0 || r.Slot > adapter.MaxActivePaths || r.Offset < 0 || len(r.Data) > 48<<10 ||
		len(r.Learned) > routing.MaxLearned ||
		len(r.Selected) > 64 {
		return errors.New("invalid_dispatcher_request")
	}
	switch r.Action {
	case "start":
		if r.Spec == nil || r.Snapshot == nil || len(r.Data) != 0 || r.Offset != 0 ||
			len(r.Learned) != 0 ||
			r.Selected != "" {
			return errors.New("invalid_dispatcher_request")
		}
		return dispatch.Validate(*r.Spec)
	case "snapshot-info", "snapshot-begin", "snapshot-commit":
		if r.Snapshot == nil || r.Spec != nil || len(r.Data) != 0 || r.Offset != 0 ||
			len(r.Learned) != 0 ||
			r.Selected != "" {
			return errors.New("invalid_dispatcher_request")
		}
	case "snapshot-read":
		if r.Snapshot == nil || r.Spec != nil || len(r.Data) != 0 || len(r.Learned) != 0 ||
			r.Selected != "" {
			return errors.New("invalid_dispatcher_request")
		}
	case "snapshot-chunk":
		if r.Snapshot == nil || r.Spec != nil || len(r.Data) == 0 || len(r.Learned) != 0 ||
			r.Selected != "" {
			return errors.New("invalid_dispatcher_request")
		}
	case "publish":
		if r.Snapshot == nil || r.Spec != nil || len(r.Data) != 0 || r.Offset != 0 ||
			r.Selected != "" {
			return errors.New("invalid_dispatcher_request")
		}
		for _, d := range r.Learned {
			v, e := routing.CanonicalDomain(d)
			if e != nil || v != d || routing.LocalDomain(v) {
				return errors.New("invalid_dispatcher_rule")
			}
		}
	case "select":
		if r.Spec != nil || r.Snapshot != nil || len(r.Data) != 0 || r.Offset != 0 ||
			len(r.Learned) != 0 {
			return errors.New("invalid_dispatcher_request")
		}
	case "status":
		if r.Spec != nil || r.Snapshot != nil || len(r.Data) != 0 || r.Offset != 0 ||
			len(r.Learned) != 0 ||
			r.Selected != "" {
			return errors.New("invalid_dispatcher_request")
		}
	default:
		return errors.New("invalid_dispatcher_action")
	}
	return nil
}

func dispatcherPath(s dispatch.Spec) dataplane.Path {
	p := s.Allocation.Path
	return dataplane.Path{
		SourceID: dataplane.SelectiveSourceID,
		Kind:     "tproxy",
		Slot:     uint16(p.Slot),
		Port:     uint16(p.TransparentPort),
		UDP:      true,
		IPv6:     p.IPv6,
	}
}

func (s *Server) validateDispatcherLocked(spec dispatch.Spec) error {
	if err := dispatch.Validate(spec); err != nil {
		return err
	}
	for _, old := range s.dispatchers {
		if old.spec.Allocation.FakePool == spec.Allocation.FakePool {
			return errors.New("dispatcher_fake_pool_busy")
		}
	}
	if err := s.validateProbeAllocationLocked(dispatcherPath(spec)); err != nil {
		return err
	}
	for _, p := range spec.Sources {
		kind := p.Kind
		if p.ProxyPort != 0 {
			kind = "tproxy"
		}
		d := dataplane.Path{
			SourceID:  p.SourceID,
			Kind:      kind,
			Slot:      uint16(p.Slot),
			Port:      uint16(p.TransparentPort),
			DNSPort:   uint16(p.DNSPort),
			Interface: p.Interface,
			UDP:       p.UDP,
			IPv6:      p.IPv6,
		}
		if err := s.validateProbeAllocationLocked(d); err != nil {
			return err
		}
		if err := s.validateManagedPlanPathLocked(d); err != nil {
			return err
		}
		if p.ProxyPort != 0 {
			r := s.engines[p.SourceID]
			if r == nil || r.Request.Path.ProxyPort != p.ProxyPort {
				return errors.New("dispatcher_source_unowned")
			}
		}
	}
	if spec.Continuity != nil {
		if s.continuity == nil || !reflect.DeepEqual(s.continuity.request.Bridge, spec.Continuity) {
			return errors.New("dispatcher_bridge_unowned")
		}
	}
	return nil
}

func (s *Server) validateDispatcherPlanLocked(d dataplane.Desired) error {
	if d.Selective == nil {
		return nil
	}
	r := s.dispatchers[int(d.Selective.Path.Slot)]
	if r == nil || !r.ready {
		return errors.New("dispatcher_unavailable")
	}
	select {
	case <-r.done:
		return errors.New("dispatcher_unavailable")
	default:
	}
	if (d.Continuity != nil) != (r.spec.Continuity != nil) {
		return errors.New("dispatcher_intent_mismatch")
	}
	if r.spec.Continuity != nil &&
		(s.continuity == nil || !reflect.DeepEqual(s.continuity.request.Bridge, r.spec.Continuity)) {
		return errors.New("dispatcher_bridge_unowned")
	}
	if d.Selective.FakePool != r.spec.Allocation.FakePool ||
		d.Selective.Path != dispatcherPath(r.spec) ||
		int(d.Selective.DNSFrontPort) != r.spec.Allocation.DNSFrontPort ||
		d.Selective.Snapshot.Generation != r.ref.Generation ||
		d.Selective.Snapshot.SHA256 != r.ref.SHA256 ||
		!reflect.DeepEqual(d.Network, r.spec.Network) ||
		d.Selective.PolicyHash != dispatch.PolicyHash(r.spec.Routing) {
		return errors.New("dispatcher_intent_mismatch")
	}
	return nil
}

func (s *Server) handleDispatcher(
	ctx context.Context,
	conn *net.UnixConn,
	reader *bufio.Reader,
	r DispatcherRequest,
	release func(),
) {
	if r.Action != "start" {
		status, err := s.dispatcherAction(ctx, r)
		if err != nil {
			writeResponse(conn, Response{Error: safeError(err)})
		} else {
			writeResponse(conn, Response{OK: true, Dispatcher: &status})
		}
		return
	}
	uid, err := peerUID(conn)
	gid, gerr := peerGID(conn)
	if err != nil || gerr != nil || uid == 0 || gid == 0 || uid != s.AllowedUID {
		writeResponse(conn, Response{Error: "dispatcher_identity_invalid"})
		return
	}
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		writeResponse(conn, Response{Error: "dispatcher_random_failed"})
		return
	}
	record := &dispatcherRegistration{
		spec:   *r.Spec,
		ref:    *r.Snapshot,
		secret: hex.EncodeToString(secret),
	}
	s.probeMu.Lock()
	slot := r.Spec.Allocation.Path.Slot
	if len(s.dispatchers) >= 2 || s.dispatchers[slot] != nil {
		err = errors.New("dispatcher_busy")
	} else if err = s.validateDispatcherLocked(*r.Spec); err == nil {
		if s.dispatchers == nil {
			s.dispatchers = make(map[int]*dispatcherRegistration)
		}
		s.dispatchers[slot] = record
	}
	s.probeMu.Unlock()
	if err != nil {
		writeResponse(conn, Response{Error: safeError(err)})
		return
	}
	defer func() {
		s.probeMu.Lock()
		if s.dispatchers[slot] == record {
			delete(s.dispatchers, slot)
		}
		s.probeMu.Unlock()
	}()
	var cmd *exec.Cmd
	var life io.Closer
	var observations io.ReadCloser
	err = s.Manager.WithRuntime(func() error {
		if e := s.prepareDispatcherFiles(record, uid, gid); e != nil {
			return e
		}
		var e error
		cmd, life, observations, e = StartDispatcherWorker(
			ctx,
			record.spec,
			record.secret,
			uid,
			gid,
		)
		return e
	})
	if err != nil {
		writeResponse(conn, Response{Error: safeError(err)})
		return
	}
	defer func() { _ = life.Close() }()
	defer func() { _ = observations.Close() }()
	done := make(chan struct{})
	s.probeMu.Lock()
	record.cmd, record.done, record.ready = cmd, done, true
	record.publication = 1
	s.probeMu.Unlock()
	go func() { _ = cmd.Wait(); close(done) }()
	writeResponse(conn, Response{OK: true})
	_ = conn.SetDeadline(time.Time{})
	release()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	ownerDone := make(chan struct{})
	go func() { var b [1]byte; _, _ = reader.Read(b[:]); close(ownerDone) }()
	copyDone := make(chan struct{})
	go func() {
		defer close(copyDone)
		scan := bufio.NewScanner(observations)
		scan.Buffer(make([]byte, 512), 1024)
		for scan.Scan() {
			domain, e := routing.CanonicalDomain(scan.Text())
			if e != nil || routing.LocalDomain(domain) {
				continue
			}
			raw, _ := json.Marshal(struct {
				Domain string `json:"domain"`
			}{domain})
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
			if _, e = conn.Write(append(raw, '\n')); e != nil {
				return
			}
		}
	}()
	select {
	case <-done:
	case <-ownerDone:
	case <-ctx.Done():
	}
	_ = life.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
	}
	_ = observations.Close()
	<-copyDone
	_ = conn.Close()
	<-ownerDone
}

func (c *Client) Dispatcher(ctx context.Context, r DispatcherRequest) (DispatcherStatus, error) {
	resp, e := c.call(ctx, Request{Operation: "dispatcher", Dispatcher: &r})
	if e != nil {
		return DispatcherStatus{}, e
	}
	if resp.Dispatcher == nil {
		return DispatcherStatus{}, errors.New("invalid_helper_response")
	}
	return *resp.Dispatcher, nil
}

func (c *Client) StartDispatcher(
	ctx context.Context,
	spec dispatch.Spec,
	ref routing.SnapshotRef,
	observe func(string),
) (adapter.ManagedProcess, error) {
	r := Request{
		Operation:  "dispatcher",
		Dispatcher: &DispatcherRequest{Action: "start", Spec: &spec, Snapshot: &ref},
	}
	if e := validateRequest(r); e != nil {
		return nil, e
	}
	conn, e := c.connect(ctx)
	if e != nil {
		return nil, e
	}
	failed := true
	defer func() {
		if failed {
			_ = conn.Close()
		}
	}()
	raw, e := json.Marshal(r)
	if e != nil || len(raw)+1 > MaxRequestBytes {
		return nil, errors.New("dispatcher_request_too_large")
	}
	if _, e = conn.Write(append(raw, '\n')); e != nil {
		return nil, errors.New("dispatcher_helper_unavailable")
	}
	reader := bufio.NewReaderSize(conn, 4096)
	line, e := reader.ReadSlice('\n')
	if e != nil {
		return nil, errors.New("dispatcher_helper_unavailable")
	}
	var resp Response
	if DecodeStrict(line, &resp) != nil {
		return nil, errors.New("invalid_helper_response")
	}
	if !resp.OK {
		return nil, errors.New(resp.Error)
	}
	_ = conn.SetDeadline(time.Time{})
	p := &managedEngineProcess{conn: conn, done: make(chan struct{})}
	go func() {
		defer close(p.done)
		defer func() { _ = conn.Close() }()
		for {
			line, e := reader.ReadSlice('\n')
			if e != nil {
				return
			}
			var event struct {
				Domain string `json:"domain"`
			}
			if len(line) > 1024 || DecodeStrict(line, &event) != nil {
				return
			}
			if observe != nil {
				observe(event.Domain)
			}
		}
	}()
	failed = false
	return p, nil
}

// UploadSnapshot keeps each RPC well below the helper's fixed request limit.
func (c *Client) UploadSnapshot(
	ctx context.Context,
	snapshot routing.Snapshot,
) (routing.SnapshotRef, error) {
	raw, e := routing.EncodeSnapshot(snapshot)
	if e != nil {
		return routing.SnapshotRef{}, e
	}
	ref := routing.Reference(snapshot, raw)
	if _, e = c.Dispatcher(
		ctx,
		DispatcherRequest{Action: "snapshot-begin", Snapshot: &ref},
	); e != nil {
		return ref, e
	}
	for offset := 0; offset < len(raw); offset += 48 << 10 {
		end := min(offset+(48<<10), len(raw))
		if _, e = c.Dispatcher(
			ctx,
			DispatcherRequest{
				Action:   "snapshot-chunk",
				Snapshot: &ref,
				Offset:   int64(offset),
				Data:     raw[offset:end],
			},
		); e != nil {
			return ref, e
		}
	}
	_, e = c.Dispatcher(ctx, DispatcherRequest{Action: "snapshot-commit", Snapshot: &ref})
	return ref, e
}
