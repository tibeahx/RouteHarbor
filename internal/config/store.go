package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/tibeahx/OpenRHP/internal/model"
)

var (
	ErrConflict = errors.New("configuration revision conflict")
	ErrBusy     = errors.New("configuration store is busy")
)

const configFile = "config.json"

// Store owns a directory handle: later renaming a parent directory cannot
// redirect configuration writes. Advisory locking also serializes other daemon
// processes, so revision checks are performed against disk under the same lock.
type Store struct {
	mu     sync.RWMutex
	root   *os.Root
	config model.Config
	closed bool
}

func NewStore(dir string) (*Store, error) {
	clean, err := filepath.Abs(dir)
	if err != nil {
		return nil, errors.New("invalid configuration directory")
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return nil, fmt.Errorf("create configuration directory: %w", err)
	}
	before, err := os.Lstat(clean)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("configuration directory must be a real directory")
	}
	r, err := os.OpenRoot(clean)
	if err != nil {
		return nil, errors.New("open configuration directory")
	}
	ok := false
	defer func() {
		if !ok {
			_ = r.Close()
		}
	}()
	f, err := r.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, errors.New("open configuration directory handle")
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !os.SameFile(before, info) || !owned(info) {
		return nil, errors.New("configuration directory ownership changed or is unsafe")
	}
	if err := f.Chmod(0o700); err != nil {
		return nil, errors.New("secure configuration directory permissions")
	}
	s := &Store{root: r}
	lock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock(lock)
	c, err := s.read()
	if errors.Is(err, os.ErrNotExist) {
		c = Defaults()
		err = s.write(c)
	}
	if err != nil {
		return nil, err
	}
	s.config = c
	ok = true
	return s, nil
}

// Get returns a private deep copy for trusted in-process consumers. Public API
// handlers must use Redact; exporting the full object is a separate permission.
func (s *Store) Get() model.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return clone(s.config)
}

func (s *Store) Replace(expected uint64, c model.Config) (model.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return model.Config{}, errors.New("configuration store is closed")
	}
	if c.Revision != expected {
		return model.Config{}, ErrConflict
	}
	if err := Validate(c); err != nil {
		return model.Config{}, err
	}
	lock, err := s.lock()
	if err != nil {
		return model.Config{}, err
	}
	defer unlock(lock)
	current, err := s.read()
	if err != nil {
		return model.Config{}, err
	}
	s.config = current
	if expected != current.Revision || expected == math.MaxUint64 {
		return model.Config{}, ErrConflict
	}
	c = clone(c)
	c.Revision = current.Revision + 1
	if err := s.write(c); err != nil {
		return model.Config{}, err
	}
	s.config = c
	return clone(c), nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.root.Close()
}

func owned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func secureRegular(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return errors.New("cannot inspect private configuration file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !owned(info) || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		stat.Nlink != 1 {
		return errors.New(
			"configuration file must be privately owned, unlinked, regular, and mode 0600",
		)
	}
	return nil
}

func (s *Store) lock() (*os.File, error) {
	f, err := s.root.OpenFile(
		".lock",
		os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,
		0o600,
	)
	if err != nil {
		return nil, errors.New("cannot open configuration lock safely")
	}
	if err := secureRegular(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = f.Close()
			return nil, errors.New("cannot acquire configuration lock")
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, ErrBusy
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func unlock(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	_ = f.Close()
}

func (s *Store) read() (model.Config, error) {
	return s.readNamed(configFile)
}

func (s *Store) readNamed(name string) (model.Config, error) {
	f, err := s.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return model.Config{}, os.ErrNotExist
		}
		return model.Config{}, errors.New("cannot open configuration file safely")
	}
	defer func() { _ = f.Close() }()
	if err := secureRegular(f); err != nil {
		return model.Config{}, err
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxConfigBytes+1))
	if err != nil {
		return model.Config{}, errors.New("cannot read configuration file")
	}
	return Decode(data)
}

func (s *Store) write(c model.Config) error {
	return s.writeNamed(configFile, c)
}

func (s *Store) writeNamed(name string, c model.Config) error {
	data, err := json.Marshal(c)
	if err != nil {
		return errors.New("cannot encode configuration")
	}
	if len(data)+1 > MaxConfigBytes {
		return errors.New("configuration exceeds stored byte limit")
	}
	if info, err := s.root.Lstat(name); err == nil && !info.Mode().IsRegular() {
		return errors.New("refusing nonregular configuration destination")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot inspect configuration destination")
	}
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return errors.New("cannot allocate configuration transaction")
	}
	tmp := ".config-" + hex.EncodeToString(random[:]) + ".tmp"
	f, err := s.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return errors.New("cannot create private configuration transaction")
	}
	defer func() { _ = f.Close(); _ = s.root.Remove(tmp) }()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return errors.New("cannot write configuration transaction")
	}
	if err := f.Sync(); err != nil {
		return errors.New("cannot sync configuration transaction")
	}
	if err := f.Close(); err != nil {
		return errors.New("cannot close configuration transaction")
	}
	if err := s.root.Rename(tmp, name); err != nil {
		return errors.New("cannot commit configuration transaction")
	}
	dir, err := s.root.Open(".")
	if err != nil {
		return errors.New("cannot open configuration directory for sync")
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Sync(); err != nil {
		return errors.New("cannot sync configuration directory")
	}
	return nil
}

// SaveCheckpoint persists private source settings before confirming a network
// transaction. Only a helper-confirmed transaction ID may identify the active
// checkpoint; file existence alone never promotes an unconfirmed configuration.
func (s *Store) SaveCheckpoint(key string, c model.Config) error {
	name, err := checkpointName(key)
	if err != nil {
		return err
	}
	return s.saveSnapshot(name, c)
}

func (s *Store) Checkpoint(key string) (model.Config, bool, error) {
	name, err := checkpointName(key)
	if err != nil {
		return model.Config{}, false, err
	}
	return s.snapshot(name)
}

func checkpointName(key string) (string, error) {
	decoded, err := hex.DecodeString(key)
	if err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != key {
		return "", errors.New("invalid configuration checkpoint identifier")
	}
	return "checkpoint-" + key + ".json", nil
}

func (s *Store) SaveConfirmed(
	c model.Config,
) error {
	return s.saveSnapshot("confirmed.json", c)
}

func (s *Store) Confirmed() (model.Config, bool, error) {
	return s.snapshot("confirmed.json")
}

func (s *Store) saveSnapshot(name string, c model.Config) error {
	if err := Validate(c); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("configuration store is closed")
	}
	lock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock(lock)
	return s.writeNamed(name, clone(c))
}

func (s *Store) snapshot(name string) (model.Config, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return model.Config{}, false, errors.New("configuration store is closed")
	}
	c, err := s.readNamed(name)
	if errors.Is(err, os.ErrNotExist) {
		return model.Config{}, false, nil
	}
	if err != nil {
		return model.Config{}, false, err
	}
	return c, true, nil
}

// RemoveCheckpoint is for pruning transactions no longer referenced by the
// privileged journal. Callers must retain active and committed rollback IDs.
func (s *Store) RemoveCheckpoint(key string) error {
	name, err := checkpointName(key)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("configuration store is closed")
	}
	lock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock(lock)
	if err = s.root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot remove configuration checkpoint")
	}
	dir, err := s.root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}
