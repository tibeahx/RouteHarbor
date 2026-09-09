package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tibeahx/OpenRHP/internal/model"
)

func backupStore(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func TestBackupIsImmutablePrivateAndSurvivesRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s := backupStore(t, dir)
	c := s.Get()
	c.Sources = []model.Source{
		{
			ID:   "proxy",
			Name: "Private proxy",
			Type: "socks5",
			Settings: json.RawMessage(
				`{"server":"1.1.1.1","server_port":1080,"username":"user","password":"PRIVATE-BACKUP-CANARY"}`,
			),
		},
	}
	current, err := s.Replace(c.Revision, c)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	info, err := s.CreateBackup(current.Revision, id)
	if err != nil || info.ID != id || info.Revision != current.Revision || info.CreatedAt.IsZero() {
		t.Fatal("backup metadata does not identify the saved configuration", err)
	}
	if _, err = s.CreateBackup(current.Revision, id); !errors.Is(err, ErrBackupExists) {
		t.Fatal("existing backup was overwritten", err)
	}
	file, err := os.Stat(filepath.Join(dir, "backup-"+id+".json"))
	if err != nil || file.Mode().Perm() != 0o600 {
		t.Fatal("backup file is not private", err)
	}
	current.Sources = nil
	if _, err = s.Replace(current.Revision, current); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := backupStore(t, dir)
	metadata, saved, err := reopened.Backup(id)
	if err != nil || metadata != info || len(saved.Sources) != 1 ||
		!strings.Contains(string(saved.Sources[0].Settings), "PRIVATE-BACKUP-CANARY") {
		t.Fatal("restart changed the immutable private snapshot", err)
	}
	listed, err := reopened.Backups()
	data, marshalErr := json.Marshal(listed)
	if err != nil || marshalErr != nil || len(listed) != 1 ||
		strings.Contains(string(data), "CANARY") {
		t.Fatal("public backup metadata is incomplete or exposes a secret", err, marshalErr)
	}
	if err = reopened.DeleteBackup(info.Revision, id); !errors.Is(err, ErrConflict) {
		t.Fatal("stale revision deleted a snapshot", err)
	}
	if err = reopened.DeleteBackup(reopened.Get().Revision, id); err != nil {
		t.Fatal(err)
	}
	if _, _, err = reopened.Backup(id); !errors.Is(err, ErrBackupMissing) {
		t.Fatal("deleted backup still exists", err)
	}
}

func TestBackupIdentifiersNeverSelectArbitraryFiles(t *testing.T) {
	s := backupStore(t, t.TempDir())
	for _, id := range []string{"", "../config", "config.json", strings.Repeat("A", 32), strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("0", 30) + "zz"} {
		if _, err := s.CreateBackup(1, id); !errors.Is(err, ErrBackupID) {
			t.Fatal("unsafe create identifier accepted", id)
		}
		if _, _, err := s.Backup(id); !errors.Is(err, ErrBackupID) {
			t.Fatal("unsafe read identifier accepted", id)
		}
		if err := s.DeleteBackup(1, id); !errors.Is(err, ErrBackupID) {
			t.Fatal("unsafe delete identifier accepted", id)
		}
	}
}

func TestBackupRejectsHostileFilesAndInvalidConfiguration(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "mode", "invalid-json", "future-schema", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			s := backupStore(t, dir)
			id := strings.Repeat("b", 32)
			path := filepath.Join(dir, "backup-"+id+".json")
			if _, err := s.CreateBackup(1, id); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink", "hardlink":
				outside := filepath.Join(t.TempDir(), "private-config")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(outside, data, 0o600); err != nil {
					t.Fatal(err)
				}
				if err = os.Remove(path); err != nil {
					t.Fatal(err)
				}
				link := os.Link
				if kind == "symlink" {
					link = os.Symlink
				}
				if err = link(outside, path); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			default:
				data := []byte(`{"password":"HOSTILE-INPUT-CANARY"}`)
				if kind == "oversized" {
					data = []byte(strings.Repeat("x", MaxConfigBytes+1))
				}
				if kind == "future-schema" {
					c := s.Get()
					c.SchemaVersion++
					var err error
					data, err = json.Marshal(c)
					if err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := s.Backup(id); !errors.Is(err, ErrBackupUnsafe) {
				t.Fatal("unsafe snapshot was read", err)
			}
			if _, err := s.Backups(); !errors.Is(err, ErrBackupUnsafe) {
				t.Fatal("unsafe snapshot was listed", err)
			}
			if err := s.DeleteBackup(1, id); !errors.Is(err, ErrBackupUnsafe) {
				t.Fatal("unsafe snapshot was deleted", err)
			}
		})
	}
}

func TestBackupCapacitySerializesIndependentStores(t *testing.T) {
	dir := t.TempDir()
	a, b := backupStore(t, dir), backupStore(t, dir)
	var accepted atomic.Int64
	var pending sync.WaitGroup
	for i := range 16 {
		pending.Go(func() {
			s := a
			if i%2 == 0 {
				s = b
			}
			_, err := s.CreateBackup(1, fmt.Sprintf("%032x", i))
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, ErrBackupCapacity) {
				t.Error(err)
			}
		})
	}
	pending.Wait()
	if accepted.Load() != MaxBackups {
		t.Fatal("concurrent stores bypassed backup count", accepted.Load())
	}
}

func TestBackupTotalByteBudgetIsCheckedBeforeCreation(t *testing.T) {
	s := backupStore(t, t.TempDir())
	c := s.Get()
	for i := range 200 {
		c.Sources = append(c.Sources, model.Source{
			ID:   fmt.Sprint("proxy-", i),
			Name: "Private proxy",
			Type: "sing-box",
			Settings: json.RawMessage(
				`{"type":"trojan","server":"1.1.1.1","server_port":443,"password":"` + strings.Repeat(
					"p",
					4096,
				) + `","tls":{"enabled":true}}`,
			),
		})
	}
	c, err := s.Replace(c.Revision, c)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if _, err = s.CreateBackup(c.Revision, fmt.Sprintf("%032x", i)); err != nil {
			t.Fatal(err)
		}
	}
	id := strings.Repeat("c", 32)
	if _, err = s.CreateBackup(c.Revision, id); !errors.Is(err, ErrBackupCapacity) {
		t.Fatal("total byte limit was not enforced", err)
	}
	if _, _, err = s.Backup(id); !errors.Is(err, ErrBackupMissing) {
		t.Fatal("capacity rejection left a partial backup", err)
	}
}

func TestBackupCreationStaysAnchoredAfterDirectoryReplacement(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "state")
	s := backupStore(t, dir)
	moved := filepath.Join(base, "original")
	outside := t.TempDir()
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, dir); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("d", 32)
	if _, err := s.CreateBackup(1, id); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(moved, "backup-"+id+".json")); err != nil {
		t.Fatal("snapshot did not remain in its original directory", err)
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatal("snapshot followed a replacement parent", err)
	}
}
