package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/tibeahx/OpenRHP/internal/dispatch"
	"github.com/tibeahx/OpenRHP/internal/routing"
)

const (
	dispatcherRuntimeRoot = "/var/run/openrhp-dispatcher"
	dispatcherCacheRoot   = "/etc/openrhp-dispatcher-cache"
)

type dispatcherUpload struct {
	ref    routing.SnapshotRef
	file   *os.File
	offset int64
	seen   time.Time
}

func dispatcherDir(
	slot int,
) string {
	return filepath.Join(dispatcherRuntimeRoot, strconv.Itoa(slot))
}

func dispatcherFiles(slot int, pool uint8) dispatch.Files {
	d := dispatcherDir(slot)
	return dispatch.Files{
		RuleSet: filepath.Join(d, "rules.json"),
		Cache:   filepath.Join(dispatcherCacheRoot, strconv.Itoa(int(pool)), "cache.db"),
	}
}
func (s *Server) snapshotDir() string { return filepath.Join(s.Manager.dir, "routing") }
func (s *Server) snapshotName(ref routing.SnapshotRef) string {
	return filepath.Join(
		s.snapshotDir(),
		strconv.FormatUint(ref.Generation, 10)+"-"+ref.SHA256+".json",
	)
}

func (s *Server) readDispatcherSnapshot(ref routing.SnapshotRef) (routing.Snapshot, error) {
	if routing.ValidateReference(ref) != nil {
		return routing.Snapshot{}, errors.New("invalid_dispatcher_snapshot")
	}
	f, e := openPrivate(s.snapshotName(ref), os.O_RDONLY, 0o600)
	if e != nil {
		return routing.Snapshot{}, errors.New("dispatcher_snapshot_unavailable")
	}
	defer func() { _ = f.Close() }()
	b, e := io.ReadAll(io.LimitReader(f, ref.Size+1))
	if e != nil || int64(len(b)) != ref.Size {
		return routing.Snapshot{}, errors.New("dispatcher_snapshot_invalid")
	}
	v, e := routing.DecodeSnapshot(b)
	if e != nil || routing.Reference(v, b) != ref {
		return routing.Snapshot{}, errors.New("dispatcher_snapshot_invalid")
	}
	return v, nil
}

func (s *Server) dispatcherAction(
	ctx context.Context,
	r DispatcherRequest,
) (DispatcherStatus, error) {
	if r.Action == "snapshot-info" || r.Action == "snapshot-read" {
		return s.dispatcherSnapshotRead(r)
	}
	s.dispatcherMu.Lock()
	defer s.dispatcherMu.Unlock()
	if r.Action == "snapshot-begin" || r.Action == "snapshot-chunk" ||
		r.Action == "snapshot-commit" {
		err := s.dispatcherSnapshotAction(r)
		if err == nil && r.Action == "snapshot-commit" {
			s.pruneDispatcherSnapshots(*r.Snapshot)
		}
		return DispatcherStatus{}, err
	}
	s.probeMu.Lock()
	record := s.dispatchers[r.Slot]
	if record == nil || !record.ready {
		s.probeMu.Unlock()
		if r.Action == "status" {
			return DispatcherStatus{}, nil
		}
		return DispatcherStatus{}, errors.New("dispatcher_unavailable")
	}
	select {
	case <-record.done:
		s.probeMu.Unlock()
		return DispatcherStatus{}, errors.New("dispatcher_unavailable")
	default:
	}
	status := DispatcherStatus{
		Running:             true,
		Selected:            record.spec.Selected,
		PublishedGeneration: record.publication,
	}
	spec, secret := record.spec, record.secret
	s.probeMu.Unlock()
	switch r.Action {
	case "status":
		status.WANIdentity, _ = dispatcherWANIdentity(ctx, spec.Network.WANInterface)
		return status, nil
	case "publish":
		// Do not overlap the helper's dead decode/compile buffers with native
		// construction of the replacement rule set. The deferred collection
		// also releases the old/new publication bytes before the reload peak.
		defer debug.FreeOSMemory()
		snapshot, e := s.readDispatcherSnapshot(*r.Snapshot)
		if e != nil {
			return status, e
		}
		data, e := routing.CompileRuleSet(snapshot, r.Learned)
		if e != nil {
			return status, errors.New("dispatcher_rules_invalid")
		}
		debug.FreeOSMemory()
		file := dispatcherFiles(spec.Allocation.Path.Slot, spec.Allocation.FakePool).RuleSet
		info, e := os.Lstat(file)
		if e != nil || !info.Mode().IsRegular() || !ownedByCurrentUID(info) {
			return status, errors.New("dispatcher_rules_untrusted")
		}
		if e = s.publishDispatcher(ctx, record, *r.Snapshot, file, data); e != nil {
			return status, e
		}

		s.probeMu.Lock()
		if s.dispatchers[r.Slot] == record {
			record.ref = *r.Snapshot
			record.publication++
			status.PublishedGeneration = record.publication
		}
		s.probeMu.Unlock()
		return status, nil
	case "select":
		if e := selectDispatcher(ctx, spec, secret, r.Selected); e != nil {
			return status, e
		}

		s.probeMu.Lock()
		if s.dispatchers[r.Slot] == record {
			record.spec.Selected = r.Selected
		}
		s.probeMu.Unlock()
		status.Selected = r.Selected
		return status, nil
	}
	return status, errors.New("invalid_dispatcher_action")
}

func (s *Server) dispatcherSnapshotAction(r DispatcherRequest) error {
	if e := os.Mkdir(s.snapshotDir(), 0o700); e != nil && !os.IsExist(e) {
		return errors.New("dispatcher_snapshot_store_unavailable")
	}
	info, e := os.Lstat(s.snapshotDir())
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || !ownedByCurrentUID(info) {
		return errors.New("dispatcher_snapshot_store_untrusted")
	}
	u := s.dispatcherUpload
	switch r.Action {
	case "snapshot-begin":
		if u != nil {
			_ = u.file.Close()
			_ = os.Remove(u.file.Name())
			s.dispatcherUpload = nil
		}

		// A crash loses the in-memory upload handle. Remove only our regular,
		// private orphan spools before allocating the next bounded upload.
		entries, e := os.ReadDir(s.snapshotDir())
		if e != nil {
			return errors.New("dispatcher_snapshot_store_unavailable")
		}
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), ".upload-") {
				continue
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
				!ownedByCurrentUID(info) {
				return errors.New("dispatcher_snapshot_store_untrusted")
			}
			if err = os.Remove(filepath.Join(s.snapshotDir(), entry.Name())); err != nil {
				return errors.New("dispatcher_snapshot_store_unavailable")
			}
		}
		f, e := os.CreateTemp(s.snapshotDir(), ".upload-")
		if e != nil {
			return errors.New("dispatcher_snapshot_store_unavailable")
		}
		s.dispatcherUpload = &dispatcherUpload{ref: *r.Snapshot, file: f, seen: time.Now()}
		return nil
	case "snapshot-chunk", "snapshot-commit":
		if u == nil || u.ref != *r.Snapshot || time.Since(u.seen) > 5*time.Minute {
			return errors.New("dispatcher_snapshot_upload_missing")
		}
		if r.Action == "snapshot-chunk" {
			if r.Offset != u.offset || u.offset+int64(len(r.Data)) > u.ref.Size {
				return errors.New("dispatcher_snapshot_chunk_invalid")
			}
			n, e := u.file.Write(r.Data)
			if e != nil || n != len(r.Data) {
				return errors.New("dispatcher_snapshot_write_failed")
			}
			u.offset += int64(n)
			u.seen = time.Now()
			return nil
		}
		defer func() { _ = u.file.Close(); _ = os.Remove(u.file.Name()); s.dispatcherUpload = nil }()
		if u.offset != u.ref.Size {
			return errors.New("dispatcher_snapshot_incomplete")
		}
		if _, e = u.file.Seek(0, io.SeekStart); e != nil {
			return errors.New("dispatcher_snapshot_invalid")
		}
		data, e := io.ReadAll(io.LimitReader(u.file, u.ref.Size+1))
		if e != nil {
			return errors.New("dispatcher_snapshot_invalid")
		}
		snap, e := routing.DecodeSnapshot(data)
		if e != nil || routing.Reference(snap, data) != u.ref {
			return errors.New("dispatcher_snapshot_invalid")
		}
		if e = u.file.Sync(); e != nil {
			return errors.New("dispatcher_snapshot_write_failed")
		}
		if e = u.file.Close(); e != nil {
			return errors.New("dispatcher_snapshot_write_failed")
		}
		if e = os.Rename(u.file.Name(), s.snapshotName(u.ref)); e != nil {
			return errors.New("dispatcher_snapshot_write_failed")
		}
		dir, e := os.Open(s.snapshotDir())
		if e != nil {
			return e
		}
		defer func() { _ = dir.Close() }()
		return dir.Sync()
	}
	return errors.New("invalid_dispatcher_action")
}

func replaceDispatcherRuleFile(path string, data []byte) error {
	old, e := os.Stat(path)
	if e != nil {
		return errors.New("dispatcher_rules_unavailable")
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".rules-")
	if e != nil {
		return errors.New("dispatcher_rules_unavailable")
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }()
	if e = copyDispatcherOwnership(f, old); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return errors.New("dispatcher_rules_write_failed")
	}
	if oldData, err := os.ReadFile(path); err == nil {
		if err = writeDispatcherBackup(path+".previous", oldData); err != nil {
			return errors.New("dispatcher_rules_backup_failed")
		}
	} else {
		return errors.New("dispatcher_rules_backup_failed")
	}
	if e = os.Rename(name, path); e != nil {
		return errors.New("dispatcher_rules_write_failed")
	}
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

func dispatcherAPI(ctx context.Context, port int, secret, method, path string, body any) error {
	if path != "/proxies/bypass" && path != "/configs" {
		return errors.New("invalid_dispatcher_api_action")
	}
	raw, _ := json.Marshal(body)
	request, e := http.NewRequestWithContext(
		ctx,
		method,
		"http://127.0.0.1:"+strconv.Itoa(port)+path,
		bytes.NewReader(raw),
	)
	if e != nil {
		return e
	}
	request.Header.Set("Authorization", "Bearer "+secret)
	request.Header.Set("Content-Type", "application/json")
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: time.Second}).DialContext,
		MaxResponseHeaderBytes: 4096,
		DisableKeepAlives:      true,
	}
	defer transport.CloseIdleConnections()
	client := http.Client{
		Transport:     transport,
		Timeout:       2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, e := client.Do(request)
	if e != nil {
		return errors.New("dispatcher_control_unavailable")
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New("dispatcher_control_failed")
	}
	return nil
}

func writeDispatcherBackup(path string, data []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".previous-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }()
	if _, e = f.Write(data); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(name, path)
}

// Force the typed prepared choice after native startup: sing-box persists
// selector and Clash mode alongside FakeIP, so configuration defaults alone
// cannot be authoritative after restart or cache-pool reuse.
func selectDispatcher(ctx context.Context, spec dispatch.Spec, secret, selected string) error {
	tag := ""
	for _, p := range spec.Sources {
		if p.SourceID == selected {
			if spec.Continuity != nil {
				tag = "relay"
			} else if p.Kind != "direct" {
				tag = "source-" + strconv.Itoa(p.Slot)
			}
		}
	}
	if selected != "" && tag == "" {
		return errors.New("invalid_dispatcher_selection")
	}
	if tag != "" {
		if e := dispatcherAPI(
			ctx,
			spec.Allocation.APIPort,
			secret,
			http.MethodPut,
			"/proxies/bypass",
			map[string]string{"name": tag},
		); e != nil {
			return e
		}
	}
	mode := "rule"
	if tag == "" {
		mode = "global"
	}
	if e := dispatcherAPI(
		ctx,
		spec.Allocation.APIPort,
		secret,
		http.MethodPatch,
		"/configs",
		map[string]string{"mode": mode},
	); e != nil {
		return e
	}
	return nil
}
