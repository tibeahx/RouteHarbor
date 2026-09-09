package api

import (
	"bytes"
	"errors"
	"net/http"
	"strings"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/config"
	"github.com/tibeahx/OpenRHP/internal/control"
	"github.com/tibeahx/OpenRHP/internal/model"
)

var errBackupBody = errors.New("backup operations accept only an empty JSON object")

func backupProblem(err error) (int, string, string) {
	switch {
	case errors.Is(err, errBackupBody):
		return 400, "invalid_backup_request", errBackupBody.Error()
	case errors.Is(err, config.ErrBackupID):
		return 400, "invalid_backup_id", "Use a backup identifier returned by this device"
	case errors.Is(err, config.ErrBackupMissing):
		return 404, "backup_not_found", "Configuration backup not found"
	case errors.Is(err, config.ErrBackupExists):
		return 409, "backup_exists", "Configuration backup already exists; inspect its current state"
	case errors.Is(err, config.ErrConflict):
		return 409, "revision_conflict", "Configuration changed; refresh before modifying backups"
	case errors.Is(err, config.ErrBackupCapacity):
		return 429, "backup_capacity", "Backup storage is full; inspect and explicitly delete an older backup"
	default:
		return 503, "backup_storage_unavailable", "Private backup storage failed validation or is unavailable"
	}
}

func (s *Server) readBackups(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		backups, err := s.Runtime.Store.Backups()
		if err != nil {
			status, code, message := backupProblem(err)
			problem(w, status, code, message, status == 503)
			return
		}
		write(w, 200, map[string]any{
			"backups":         backups,
			"max_backups":     config.MaxBackups,
			"max_total_bytes": config.MaxBackupTotalBytes,
		})
		return
	}
	info, c, err := s.Runtime.Store.Backup(id)
	if err != nil {
		status, code, message := backupProblem(err)
		problem(w, status, code, message, status == 503)
		return
	}
	write(w, 200, map[string]any{
		"backup": info, "configuration": config.Redact(c),
		"secrets_redacted": true, "network_changes_applied": false,
	})
}

// prepareBackupMutation never applies a restored configuration itself: the
// caller must use the same ValidateChange and revision-checked Replace flow as
// ordinary configuration writes before returning a restore result.
func (s *Server) prepareBackupMutation(
	r *http.Request,
	body []byte,
	op control.Operation,
	revision uint64,
) (*model.Config, map[string]any, error) {
	if r.Method == http.MethodDelete {
		if len(bytes.TrimSpace(body)) != 0 {
			return nil, nil, errBackupBody
		}
	} else if adapter.StrictDecode(body, &struct{}{}) != nil {
		return nil, nil, errBackupBody
	}
	id := r.PathValue("id")
	if r.URL.Path == "/api/v1/config/backups" {
		info, err := s.Runtime.Store.CreateBackup(revision, op.ID)
		return nil, map[string]any{"backup": info}, err
	}
	if r.Method == http.MethodDelete {
		err := s.Runtime.Store.DeleteBackup(revision, id)
		return nil, map[string]any{"backup_deleted": true, "backup_id": id}, err
	}
	if strings.HasSuffix(r.URL.Path, "/restore") {
		info, c, err := s.Runtime.Store.Backup(id)
		if err != nil {
			return nil, nil, err
		}
		c.Revision = revision
		return &c, map[string]any{"backup_id": id, "backup_revision": info.Revision}, nil
	}
	return nil, nil, config.ErrBackupID
}
