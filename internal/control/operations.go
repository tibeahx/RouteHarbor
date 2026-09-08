// Package control coordinates bounded jobs, configuration and independent probes.
package control

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type Operation struct {
	ID          string         `json:"id"`
	Kind        string         `json:"kind"`
	State       string         `json:"state"`
	CreatedAt   time.Time      `json:"created_at"`
	CompletedAt *time.Time     `json:"completed_at,omitempty"`
	Revision    uint64         `json:"revision,omitempty"`
	ErrorCode   string         `json:"error_code,omitempty"`
	Result      map[string]any `json:"result,omitempty"`
	Key         string         `json:"-"`
	Hash        string         `json:"-"`
}
type record struct {
	Operation
	Key  string `json:"key"`
	Hash string `json:"hash"`
}
type Journal struct {
	mu      sync.Mutex
	dir     string
	entries []record
}

var (
	ErrIdempotency = errors.New("idempotency key reused for a different request")
	ErrQueueFull   = errors.New("operation queue full")
)

func NewJournal(dir string) (*Journal, error) {
	if e := os.MkdirAll(dir, 0o700); e != nil {
		return nil, e
	}
	f, e := os.Lstat(dir)
	if e != nil || !f.IsDir() || f.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("operation directory must be private")
	}
	j := &Journal{dir: dir}
	path := filepath.Join(dir, "operations.json")
	f, e = os.Lstat(path)
	if e == nil && (!f.Mode().IsRegular() || f.Mode().Perm()&0o077 != 0 || f.Size() > 2<<20) {
		return nil, errors.New("unsafe operation journal")
	}
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return j, nil
	}
	if e != nil {
		return nil, e
	}
	if e = json.Unmarshal(b, &j.entries); e != nil {
		return nil, errors.New("invalid operation journal")
	}
	if len(j.entries) > 512 {
		return nil, errors.New("operation journal over capacity")
	}
	changed := false
	now := time.Now().UTC()
	for i := range j.entries {
		v := &j.entries[i]
		if v.State == "running" || v.State == "pending" {
			v.State = "failed"
			v.ErrorCode = "interrupted_check_current_state"
			v.CompletedAt = &now
			changed = true
		}
	}
	if changed {
		if e = j.save(); e != nil {
			return nil, e
		}
	}
	return j, nil
}

// Begin reserves a durable logical operation before any side effect. On a crash,
// retries observe interruption and current revision; they never duplicate a write.
func (j *Journal) Begin(kind, key, hash string) (Operation, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now().UTC()
	for _, r := range j.entries {
		if r.Key == key {
			if r.Hash != hash {
				return Operation{}, false, ErrIdempotency
			}
			return r.Operation, true, nil
		}
	}
	kept := j.entries[:0]
	running := 0
	for _, r := range j.entries {
		if r.State == "running" || r.State == "pending" {
			running++
		}
		if now.Sub(r.CreatedAt) < 24*time.Hour || r.CompletedAt == nil {
			kept = append(kept, r)
		}
	}
	j.entries = kept
	if len(j.entries) >= 512 || running >= 16 {
		return Operation{}, false, ErrQueueFull
	}
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return Operation{}, false, e
	}
	op := Operation{ID: hex.EncodeToString(b), Kind: kind, State: "running", CreatedAt: now}
	j.entries = append(j.entries, record{Operation: op, Key: key, Hash: hash})
	if e := j.save(); e != nil {
		j.entries = j.entries[:len(j.entries)-1]
		return Operation{}, false, e
	}
	return op, false, nil
}

func (j *Journal) Finish(
	id string,
	revision uint64,
	result map[string]any,
	code string,
) (Operation, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for i := range j.entries {
		r := &j.entries[i]
		if r.ID == id {
			r.State = "succeeded"
			r.ErrorCode = code
			if code != "" {
				r.State = "failed"
			}
			r.Revision = revision
			r.Result = result
			now := time.Now().UTC()
			r.CompletedAt = &now
			return r.Operation, j.save()
		}
	}
	return Operation{}, errors.New("operation not found")
}

func (j *Journal) Get(id string) (Operation, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, r := range j.entries {
		if r.ID == id {
			return cloneOperation(r.Operation), true
		}
	}
	return Operation{}, false
}

func (j *Journal) List() []Operation {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]Operation, 0, len(j.entries))
	for _, r := range j.entries {
		out = append(out, cloneOperation(r.Operation))
	}
	sort.Slice(out, func(i, k int) bool { return out[i].CreatedAt.After(out[k].CreatedAt) })
	return out
}

func cloneOperation(o Operation) Operation {
	b, _ := json.Marshal(o)
	var v Operation
	_ = json.Unmarshal(b, &v)
	return v
}

func (j *Journal) save() error {
	b, e := json.Marshal(j.entries)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(j.dir, ".operations-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }()
	if e = f.Chmod(0o600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e = os.Rename(name, filepath.Join(j.dir, "operations.json")); e != nil {
		return e
	}
	d, e := os.Open(j.dir)
	if e != nil {
		return e
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
