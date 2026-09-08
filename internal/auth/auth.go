// Package auth holds revocable local API credentials. Tokens are never logged.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Credential struct {
	ID        string    `json:"id"`
	Role      string    `json:"role"`
	Hash      string    `json:"hash"`
	CreatedAt time.Time `json:"created_at"`
}
type Store struct {
	mu      sync.RWMutex
	dir     string
	entries []Credential
}

var ErrCredential = errors.New("invalid credential")

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("credential directory must be private")
	}
	s := &Store{dir: dir}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("credential directory must be owned by the service user")
	}
	lock, e := s.lockDisk()
	if e != nil {
		return nil, e
	}
	defer unlockDisk(lock)
	if e = s.reload(); e != nil {
		return nil, e
	}
	return s, nil
}

func (s *Store) Issue(role string) (Credential, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, e := s.lockDisk()
	if e != nil {
		return Credential{}, "", e
	}
	defer unlockDisk(lock)
	if e = s.reload(); e != nil {
		return Credential{}, "", e
	}
	if role != "admin" && role != "read" {
		return Credential{}, "", errors.New("role must be admin or read")
	}
	if len(s.entries) >= 64 {
		return Credential{}, "", errors.New("revoke an unused credential first")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return Credential{}, "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	c := Credential{
		ID:        hex.EncodeToString(sum[:8]),
		Role:      role,
		Hash:      hex.EncodeToString(sum[:]),
		CreatedAt: time.Now().UTC(),
	}
	s.entries = append(s.entries, c)
	if err := s.save(); err != nil {
		s.entries = s.entries[:len(s.entries)-1]
		return Credential{}, "", err
	}
	return c, token, nil
}

func (s *Store) Verify(token string) (Credential, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(token) != 43 {
		return Credential{}, false
	}
	lock, e := s.lockDisk()
	if e != nil {
		return Credential{}, false
	}
	defer unlockDisk(lock)
	if e = s.reload(); e != nil {
		return Credential{}, false
	}
	sum := sha256.Sum256([]byte(token))
	for _, c := range s.entries {
		h, e := hex.DecodeString(c.Hash)
		if e == nil && subtle.ConstantTimeCompare(sum[:], h) == 1 {
			c.Hash = ""
			return c, true
		}
	}
	return Credential{}, false
}

func (s *Store) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, e := s.lockDisk()
	if e != nil {
		return e
	}
	defer unlockDisk(lock)
	if e = s.reload(); e != nil {
		return e
	}
	for i, c := range s.entries {
		if c.ID == id {
			old := append([]Credential(nil), s.entries...)
			s.entries = append(s.entries[:i], s.entries[i+1:]...)
			if e := s.save(); e != nil {
				s.entries = old
				return e
			}
			return nil
		}
	}
	return ErrCredential
}

func (s *Store) List() []Credential {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, e := s.lockDisk()
	if e != nil {
		return []Credential{}
	}
	defer unlockDisk(lock)
	if s.reload() != nil {
		return []Credential{}
	}
	out := append([]Credential{}, s.entries...)
	for i := range out {
		out[i].Hash = ""
	}
	return out
}

func (s *Store) save() error {
	b, e := json.MarshalIndent(s.entries, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(s.dir, ".credentials-*")
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
	if e = os.Rename(name, filepath.Join(s.dir, "credentials.json")); e != nil {
		return e
	}
	d, e := os.Open(s.dir)
	if e != nil {
		return e
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

func ReadToken(path string) (string, error) {
	fd, e := syscall.Open(
		path,
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC,
		0,
	)
	if e != nil {
		return "", e
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()
	fi, e := f.Stat()
	if e != nil {
		return "", e
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 || fi.Size() > 256 {
		return "", errors.New("token file must be regular, private (0600), and bounded")
	}
	b, e := io.ReadAll(io.LimitReader(f, 257))
	if e != nil || len(b) > 256 {
		return "", errors.New("token file exceeds byte limit")
	}
	s := strings.TrimSpace(string(b))
	if len(s) != 43 {
		return "", ErrCredential
	}
	return s, nil
}

// reload is performed under the inter-process lock, so local token issuance and revocation take effect in a running API immediately.
func (s *Store) reload() error {
	f, e := s.openCredentials()
	if os.IsNotExist(e) {
		s.entries = nil
		return nil
	}
	if e != nil {
		return errors.New("cannot safely read credential store")
	}
	defer func() { _ = f.Close() }()
	b, e := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if e != nil || len(b) > 64<<10 {
		return errors.New("credential store exceeds limit")
	}
	var entries []Credential
	if json.Unmarshal(b, &entries) != nil || len(entries) > 64 {
		return errors.New("invalid credential store")
	}
	seen := map[string]bool{}
	for _, c := range entries {
		hash, e := hex.DecodeString(c.Hash)
		id, ie := hex.DecodeString(c.ID)
		if e != nil || ie != nil || len(hash) != 32 || len(id) != 8 ||
			c.Role != "admin" && c.Role != "read" ||
			seen[c.ID] {
			return errors.New("invalid credential store entry")
		}
		seen[c.ID] = true
	}
	s.entries = entries
	return nil
}
