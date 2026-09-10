package config

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/model"
)

const (
	MaxBackups          = 8
	MaxBackupTotalBytes = 2 << 20
)

var (
	ErrBackupID       = errors.New("invalid backup identifier")
	ErrBackupMissing  = errors.New("configuration backup not found")
	ErrBackupExists   = errors.New("configuration backup already exists")
	ErrBackupCapacity = errors.New("configuration backup storage is full")
	ErrBackupUnsafe   = errors.New("configuration backup storage is invalid or unsafe")
)

// BackupInfo is public metadata. It never contains source settings or filesystem
// paths. Full snapshots remain private to the anchored configuration store.
type BackupInfo struct {
	ID            string    `json:"id"`
	CreatedAt     time.Time `json:"created_at"`
	Revision      uint64    `json:"revision"`
	SchemaVersion int       `json:"schema_version"`
	SourceCount   int       `json:"source_count"`
	TargetCount   int       `json:"target_count"`
	SizeBytes     int64     `json:"size_bytes"`
}

func backupName(id string) (string, error) {
	decoded, err := hex.DecodeString(id)
	if err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != id {
		return "", ErrBackupID
	}
	return "backup-" + id + ".json", nil
}

// CreateBackup snapshots the authoritative current revision without changing it.
// The API supplies the durable operation ID, making an interrupted creation
// discoverable under that exact ID even when its completion response was lost.
func (s *Store) CreateBackup(expected uint64, id string) (BackupInfo, error) {
	name, err := backupName(id)
	if err != nil {
		return BackupInfo{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return BackupInfo{}, errors.New("configuration store is closed")
	}
	lock, err := s.lock()
	if err != nil {
		return BackupInfo{}, err
	}
	defer unlock(lock)
	current, err := s.read()
	if err != nil {
		return BackupInfo{}, err
	}
	s.config = current
	if current.Revision != expected {
		return BackupInfo{}, ErrConflict
	}
	files, total, err := s.backupFilesLocked()
	if err != nil {
		return BackupInfo{}, err
	}
	for _, file := range files {
		if file.Name() == name {
			return BackupInfo{}, ErrBackupExists
		}
	}
	encoded, err := json.Marshal(current)
	if err != nil {
		return BackupInfo{}, ErrBackupUnsafe
	}
	if len(files) >= MaxBackups || total+int64(len(encoded)+1) > MaxBackupTotalBytes {
		return BackupInfo{}, ErrBackupCapacity
	}
	if err := s.writeNamed(name, current); err != nil {
		return BackupInfo{}, err
	}
	info, _, err := s.readBackupLocked(id)
	return info, err
}

func (s *Store) Backups() ([]BackupInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, errors.New("configuration store is closed")
	}
	lock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock(lock)
	files, _, err := s.backupFilesLocked()
	if err != nil {
		return nil, err
	}
	backups := make([]BackupInfo, 0, len(files))
	for _, file := range files {
		id := strings.TrimSuffix(strings.TrimPrefix(file.Name(), "backup-"), ".json")
		info, _, err := s.readBackupLocked(id)
		if err != nil {
			return nil, err
		}
		backups = append(backups, info)
	}
	sort.Slice(backups, func(i, j int) bool {
		if backups[i].CreatedAt.Equal(backups[j].CreatedAt) {
			return backups[i].ID < backups[j].ID
		}
		return backups[i].CreatedAt.After(backups[j].CreatedAt)
	})
	return backups, nil
}

// Backup returns a private validated copy for trusted in-process restoration.
// API previews must apply Redact before returning the configuration.
func (s *Store) Backup(id string) (BackupInfo, model.Config, error) {
	if _, err := backupName(id); err != nil {
		return BackupInfo{}, model.Config{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return BackupInfo{}, model.Config{}, errors.New("configuration store is closed")
	}
	lock, err := s.lock()
	if err != nil {
		return BackupInfo{}, model.Config{}, err
	}
	defer unlock(lock)
	return s.readBackupLocked(id)
}

func (s *Store) DeleteBackup(expected uint64, id string) error {
	name, err := backupName(id)
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
	current, err := s.read()
	if err != nil {
		return err
	}
	s.config = current
	if current.Revision != expected {
		return ErrConflict
	}
	if _, _, err := s.readBackupLocked(id); err != nil {
		return err
	}
	if err := s.root.Remove(name); err != nil {
		return errors.New("cannot remove configuration backup")
	}
	dir, err := s.root.Open(".")
	if err != nil {
		return errors.New("cannot sync configuration backup directory")
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

func (s *Store) readBackupLocked(id string) (BackupInfo, model.Config, error) {
	name, err := backupName(id)
	if err != nil {
		return BackupInfo{}, model.Config{}, err
	}
	c, err := s.readNamed(name)
	if errors.Is(err, os.ErrNotExist) {
		return BackupInfo{}, model.Config{}, ErrBackupMissing
	}
	if err != nil {
		return BackupInfo{}, model.Config{}, ErrBackupUnsafe
	}
	file, err := s.root.Lstat(name)
	if err != nil || !file.Mode().IsRegular() || file.Size() > MaxConfigBytes {
		return BackupInfo{}, model.Config{}, ErrBackupUnsafe
	}
	return BackupInfo{
		ID: id, CreatedAt: file.ModTime().UTC(), Revision: c.Revision,
		SchemaVersion: c.SchemaVersion, SourceCount: len(c.Sources),
		TargetCount: len(c.Targets), SizeBytes: file.Size(),
	}, c, nil
}

func (s *Store) backupFilesLocked() ([]os.FileInfo, int64, error) {
	dir, err := s.root.Open(".")
	if err != nil {
		return nil, 0, ErrBackupUnsafe
	}
	defer func() { _ = dir.Close() }()
	var files []os.FileInfo
	var total int64
	seen := 0
	for {
		entries, err := dir.ReadDir(64)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, 0, ErrBackupUnsafe
		}
		seen += len(entries)
		if seen > 1024 {
			return nil, 0, ErrBackupUnsafe
		}
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), "backup-") ||
				!strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			id := strings.TrimSuffix(strings.TrimPrefix(entry.Name(), "backup-"), ".json")
			if _, err := backupName(id); err != nil {
				return nil, 0, ErrBackupUnsafe
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || info.Size() > MaxConfigBytes {
				return nil, 0, ErrBackupUnsafe
			}
			files = append(files, info)
			total += info.Size()
			if len(files) > MaxBackups || total > MaxBackupTotalBytes {
				return nil, 0, ErrBackupCapacity
			}
		}
		if errors.Is(err, io.EOF) {
			return files, total, nil
		}
	}
}
