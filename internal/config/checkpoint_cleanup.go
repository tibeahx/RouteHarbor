package config

import (
	"errors"
	"io"
	"strings"
)

// PruneCheckpoints retains only caller-verified active/committed transaction IDs.
// It never touches the ordinary config, confirmed snapshot or unrelated files.
func (s *Store) PruneCheckpoints(keep []string) error {
	names := map[string]bool{}
	for _, id := range keep {
		name, e := checkpointName(id)
		if e != nil {
			return e
		}
		names[name] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("configuration store is closed")
	}
	lock, e := s.lock()
	if e != nil {
		return e
	}
	defer unlock(lock)
	dir, e := s.root.Open(".")
	if e != nil {
		return e
	}
	defer func() { _ = dir.Close() }()
	for {
		entries, e := dir.ReadDir(32)
		if e != nil && e != io.EOF {
			return e
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasPrefix(name, "checkpoint-") || !strings.HasSuffix(name, ".json") {
				continue
			}
			id := strings.TrimSuffix(strings.TrimPrefix(name, "checkpoint-"), ".json")
			safe, err := checkpointName(id)
			if err != nil || safe != name || names[name] {
				continue
			}
			if err = s.root.Remove(name); err != nil {
				return errors.New("cannot prune configuration checkpoint")
			}
		}
		if e == io.EOF {
			break
		}
	}
	return dir.Sync()
}
