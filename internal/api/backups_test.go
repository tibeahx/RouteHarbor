package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/auth"
	"github.com/tibeahx/OpenRHP/internal/config"
	"github.com/tibeahx/OpenRHP/internal/control"
	"github.com/tibeahx/OpenRHP/internal/model"
)

func backupAPI(t *testing.T, dir string) *Server {
	t.Helper()
	store, err := config.NewStore(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := auth.Open(filepath.Join(dir, "auth"))
	if err != nil {
		t.Fatal(err)
	}
	journal, err := control.NewJournal(filepath.Join(dir, "operations"))
	if err != nil {
		t.Fatal(err)
	}
	runtime := control.New(store, adapter.NewManager(filepath.Join(dir, "engines")), journal)
	t.Cleanup(func() {
		runtime.Close()
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return &Server{Runtime: runtime, Tokens: tokens, AllowedHosts: []string{"gateway.test"}}
}

func backupRequest(
	handler http.Handler,
	method, path, token, revision, key, body string,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(
		method,
		"http://gateway.test/api/v1/"+path,
		strings.NewReader(body),
	)
	request.Header.Set("Authorization", "Bearer "+token)
	if revision != "" {
		request.Header.Set("If-Match", `"`+revision+`"`)
	}
	request.Header.Set("Idempotency-Key", key)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

type backupNetworkGuard struct {
	NetworkService
	checked bool
}

func (n *backupNetworkGuard) ValidateChange(_ context.Context, _, _ model.Config) error {
	n.checked = true
	return errors.New("active paths or pending transactions prevent this configuration change")
}

func TestBackupAPIRevisionMaskingRestoreGuardsAndRestart(t *testing.T) {
	dir := t.TempDir()
	s := backupAPI(t, dir)
	_, admin, err := s.Tokens.Issue("admin")
	if err != nil {
		t.Fatal(err)
	}
	_, read, err := s.Tokens.Issue("read")
	if err != nil {
		t.Fatal(err)
	}
	c := s.Runtime.Store.Get()
	c.Sources = []model.Source{
		{
			ID:   "private",
			Name: "Original source",
			Type: "socks5",
			Settings: json.RawMessage(
				`{"server":"1.1.1.1","server_port":1080,"username":"owner","password":"RESTORE-PRIVATE-CANARY"}`,
			),
		},
	}
	if _, err := s.Runtime.Store.Replace(c.Revision, c); err != nil {
		t.Fatal(err)
	}
	handler := s.Handler()
	created := backupRequest(
		handler,
		"POST",
		"config/backups",
		admin,
		"2",
		"create-original-backup",
		`{}`,
	)
	if created.Code != http.StatusOK {
		t.Fatal("snapshot creation failed", created.Code)
	}
	var operation control.Operation
	if err = json.Unmarshal(created.Body.Bytes(), &operation); err != nil {
		t.Fatal(err)
	}
	id := operation.ID
	if operation.Result["backup"].(map[string]any)["id"] != id || operation.Revision != 2 {
		t.Fatal("created snapshot lost its durable operation identity")
	}
	for _, path := range []string{"config/backups", "config/backups/" + id} {
		response := backupRequest(handler, "GET", path, read, "", "", "")
		if response.Code != http.StatusOK ||
			strings.Contains(response.Body.String(), "RESTORE-PRIVATE-CANARY") ||
			strings.Contains(response.Body.String(), admin) {
			t.Fatal("ordinary backup read failed or exposed private settings", path)
		}
	}
	for _, action := range []struct{ method, path, body string }{
		{"POST", "config/backups", `{}`},
		{"POST", "config/backups/" + id + "/restore", `{}`},
		{"DELETE", "config/backups/" + id, ""},
	} {
		response := backupRequest(
			handler,
			action.method,
			action.path,
			read,
			"2",
			"readonly-write-key",
			action.body,
		)
		if response.Code != http.StatusForbidden {
			t.Fatal("read-only credential modified a backup", action.method, action.path)
		}
	}
	c = s.Runtime.Store.Get()
	c.Sources[0].Name = "Edited source"
	c.Sources[0].Settings = json.RawMessage(`{"server":"1.1.1.1","server_port":1080}`)
	if _, err = s.Runtime.Store.Replace(c.Revision, c); err != nil {
		t.Fatal(err)
	}
	restorePath := "config/backups/" + id + "/restore"
	stale := backupRequest(handler, "POST", restorePath, admin, "2", "stale-restore-key", `{}`)
	if stale.Code != http.StatusConflict || s.Runtime.Store.Get().Revision != 3 {
		t.Fatal("stale restore changed configuration")
	}
	guard := &backupNetworkGuard{}
	s.Network = guard
	blocked := backupRequest(handler, "POST", restorePath, admin, "3", "guarded-restore-key", `{}`)
	if blocked.Code != http.StatusConflict || !guard.checked ||
		s.Runtime.Store.Get().Revision != 3 {
		t.Fatal("restore bypassed the active network transaction guard")
	}
	s.Network = nil
	restored := backupRequest(
		handler,
		"POST",
		restorePath,
		admin,
		"3",
		"restore-original-key",
		`{}`,
	)
	if restored.Code != http.StatusOK || strings.Contains(restored.Body.String(), "CANARY") {
		t.Fatal("restore failed or exposed private settings", restored.Code)
	}
	var restoredOperation control.Operation
	if err = json.Unmarshal(restored.Body.Bytes(), &restoredOperation); err != nil {
		t.Fatal(err)
	}
	current := s.Runtime.Store.Get()
	if current.Revision != 4 || current.Sources[0].Name != "Original source" ||
		!strings.Contains(string(current.Sources[0].Settings), "RESTORE-PRIVATE-CANARY") ||
		restoredOperation.Result["network_changes_applied"] != false {
		t.Fatal("restore changed revision incorrectly or did not retain private settings")
	}
	s.Runtime.Close()
	if err = s.Runtime.Store.Close(); err != nil {
		t.Fatal(err)
	}
	s = backupAPI(t, dir)
	handler = s.Handler()
	retry := backupRequest(handler, "POST", restorePath, admin, "3", "restore-original-key", `{}`)
	var replay control.Operation
	if retry.Code != http.StatusOK || json.Unmarshal(retry.Body.Bytes(), &replay) != nil ||
		replay.ID != restoredOperation.ID ||
		s.Runtime.Store.Get().Revision != 4 {
		t.Fatal("restore retry repeated the mutation after restart")
	}
	removed := backupRequest(
		handler,
		"DELETE",
		"config/backups/"+id,
		admin,
		"4",
		"delete-backup-key",
		"",
	)
	if removed.Code != http.StatusOK || s.Runtime.Store.Get().Revision != 4 {
		t.Fatal("backup deletion changed configuration")
	}
	removedAgain := backupRequest(
		handler,
		"DELETE",
		"config/backups/"+id,
		admin,
		"4",
		"delete-backup-key",
		"",
	)
	if removedAgain.Code != http.StatusOK || removedAgain.Body.String() != removed.Body.String() {
		t.Fatal("completed deletion retry changed its operation result")
	}
	missing := backupRequest(handler, "GET", "config/backups/"+id, read, "", "", "")
	if missing.Code != http.StatusNotFound {
		t.Fatal("deleted backup remains available")
	}
}

func TestBackupCreationInterruptedAfterPersistenceIsInspectableWithoutReplay(t *testing.T) {
	dir := t.TempDir()
	s := backupAPI(t, dir)
	credential, token, err := s.Tokens.Issue("admin")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("POST\n/api/v1/config/backups\n\"1\"\n{}"))
	op, _, err := s.Runtime.Journal.Begin(
		"POST /api/v1/config/backups",
		credential.ID+":interrupted-backup-key",
		hex.EncodeToString(hash[:]),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Runtime.Store.CreateBackup(1, op.ID); err != nil {
		t.Fatal(err)
	}
	// Restart after the private snapshot was synced but before Journal.Finish.
	s.Runtime.Close()
	if err = s.Runtime.Store.Close(); err != nil {
		t.Fatal(err)
	}
	s = backupAPI(t, dir)
	handler := s.Handler()
	retry := backupRequest(
		handler,
		"POST",
		"config/backups",
		token,
		"1",
		"interrupted-backup-key",
		`{}`,
	)
	var replay control.Operation
	if retry.Code != http.StatusOK || json.Unmarshal(retry.Body.Bytes(), &replay) != nil ||
		replay.ID != op.ID ||
		replay.ErrorCode != "interrupted_check_current_state" {
		t.Fatal("interrupted creation was silently repeated")
	}
	inspect := backupRequest(handler, "GET", "config/backups/"+replay.ID, token, "", "", "")
	backups, err := s.Runtime.Store.Backups()
	if inspect.Code != http.StatusOK || err != nil || len(backups) != 1 {
		t.Fatal("durable snapshot cannot be reconciled through its operation ID", err)
	}
}

func TestBackupAPIRejectsUnknownInputCorruptionAndExhaustion(t *testing.T) {
	dir := t.TempDir()
	s := backupAPI(t, dir)
	_, token, err := s.Tokens.Issue("admin")
	if err != nil {
		t.Fatal(err)
	}
	handler := s.Handler()
	for i, body := range []string{`null`, `{"path":"/etc/HOSTILE-INPUT-CANARY"}`, `{"id":"caller-chosen"}`, `{} {}`} {
		response := backupRequest(
			handler,
			"POST",
			"config/backups",
			token,
			"1",
			fmt.Sprint("invalid-body-", i),
			body,
		)
		if response.Code != http.StatusBadRequest ||
			strings.Contains(response.Body.String(), "HOSTILE-INPUT-CANARY") {
			t.Fatal("backup creation accepted arbitrary input or echoed it")
		}
	}
	for i := range config.MaxBackups {
		response := backupRequest(
			handler,
			"POST",
			"config/backups",
			token,
			"1",
			fmt.Sprint("create-key-", i),
			`{}`,
		)
		if response.Code != http.StatusOK {
			t.Fatal("backup failed below its capacity", response.Code)
		}
	}
	response := backupRequest(
		handler,
		"POST",
		"config/backups",
		token,
		"1",
		"overflow-create-key",
		`{}`,
	)
	if response.Code != http.StatusTooManyRequests || s.Runtime.Store.Get().Revision != 1 {
		t.Fatal("backup count limit was not enforced")
	}
	backups, err := s.Runtime.Store.Backups()
	if err != nil || len(backups) != config.MaxBackups {
		t.Fatal("capacity rejection changed the retained backup set", err)
	}
	id := backups[0].ID
	if err = os.WriteFile(
		filepath.Join(dir, "state", "backup-"+id+".json"),
		[]byte(`{"secret":"HOSTILE-INPUT-CANARY"}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"config/backups", "config/backups/" + id} {
		response = backupRequest(handler, "GET", path, token, "", "", "")
		if response.Code != http.StatusServiceUnavailable ||
			strings.Contains(response.Body.String(), "HOSTILE-INPUT-CANARY") {
			t.Fatal("invalid private snapshot was returned or leaked through an error")
		}
	}
	response = backupRequest(
		handler,
		"POST",
		"config/backups/"+id+"/restore",
		token,
		"1",
		"corrupt-restore-key",
		`{}`,
	)
	if response.Code != http.StatusServiceUnavailable || s.Runtime.Store.Get().Revision != 1 {
		t.Fatal("corrupt configuration snapshot was restored")
	}
}
