package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/tibeahx/RouteHarbor/internal/maintenance"
)

type maintenanceFixture struct {
	jobs        map[string]maintenance.Operation
	starts      int
	loseReply   bool
	deferWorker bool
	statusErr   error
}

func (*maintenanceFixture) Capabilities(context.Context) (map[string]any, error) {
	return map[string]any{"supported": true}, nil
}

func (*maintenanceFixture) Bundles(context.Context) ([]maintenance.BundleSummary, error) {
	return []maintenance.BundleSummary{}, nil
}

func (*maintenanceFixture) Plan(
	_ context.Context,
	request maintenance.Request,
) (maintenance.Plan, error) {
	return maintenance.Plan{Request: request, InstalledDigest: strings.Repeat("1", 64)}, nil
}

func (f *maintenanceFixture) Start(
	_ context.Context,
	id string,
	request maintenance.Request,
) (maintenance.Operation, error) {
	f.starts++
	op := maintenance.Operation{
		ID:            id,
		State:         "running",
		Phase:         "guarded",
		Action:        request.Action,
		Components:    request.Components,
		GuardRetained: true,
	}
	if f.deferWorker && f.starts == 1 {
		op.State, op.Phase, op.Retryable = "prepared", "worker_unavailable", true
	}
	f.jobs[id] = op
	if f.loseReply {
		return maintenance.Operation{}, errors.New("PRIVATE-WORKER-STDERR")
	}
	return op, nil
}

func TestMaintenanceAPIRetryRearmsOnlyTheSamePreparedJob(t *testing.T) {
	s := backupAPI(t, t.TempDir())
	_, admin, err := s.Tokens.Issue("admin")
	if err != nil {
		t.Fatal(err)
	}
	f := &maintenanceFixture{jobs: map[string]maintenance.Operation{}, deferWorker: true}
	s.Maintenance = f
	handler := s.Handler()
	body := `{"action":"remove","components":["routeharbor-conntrack"],"removal_policy":"preserve-closed","expected_installed_digest":"` + strings.Repeat(
		"1",
		64,
	) + `"}`
	var first maintenance.Operation
	response := backupRequest(
		handler,
		"POST",
		"maintenance/operations",
		admin,
		"1",
		"retry-prepared-worker",
		body,
	)
	if response.Code != 202 {
		t.Fatal(response.Code)
	}
	if err = json.Unmarshal(response.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if first.State != "prepared" {
		t.Fatal(first)
	}
	for range 2 {
		response = backupRequest(
			handler,
			"POST",
			"maintenance/operations",
			admin,
			"1",
			"retry-prepared-worker",
			body,
		)
		var current maintenance.Operation
		if err = json.Unmarshal(response.Body.Bytes(), &current); err != nil {
			t.Fatal(err)
		}
		if response.Code != 202 || current.ID != first.ID || current.State != "running" {
			t.Fatal(response.Code, current)
		}
	}
	if f.starts != 2 {
		t.Fatal("running package operation replayed", f.starts)
	}
}

func (f *maintenanceFixture) Status(_ context.Context, id string) (maintenance.Operation, error) {
	if f.statusErr != nil {
		return maintenance.Operation{}, f.statusErr
	}
	job, ok := f.jobs[id]
	if !ok {
		return maintenance.Operation{}, errors.New("PRIVATE-ROOT-STATE-PATH")
	}
	return job, nil
}

func TestMaintenanceStatusRetriesOnlyExactBusyCode(t *testing.T) {
	s := backupAPI(t, t.TempDir())
	_, admin, err := s.Tokens.Issue("admin")
	if err != nil {
		t.Fatal(err)
	}
	f := &maintenanceFixture{}
	s.Maintenance = f
	for _, tc := range []struct {
		name      string
		err       error
		status    int
		retryable bool
	}{
		{"local busy", maintenance.ErrStateBusy, 503, true},
		{"private RPC busy", errors.New(maintenance.ErrStateBusy.Error()), 503, true},
		{"interrupted inventory", errors.New("maintenance_package_database_interrupted"), 422, false},
		{"unavailable helper", errors.New("helper_failed"), 422, false},
		{"lock failure", errors.New("maintenance_lock_failed"), 422, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.statusErr = tc.err
			response := backupRequest(
				s.Handler(),
				"GET",
				"maintenance/operations/"+strings.Repeat("a", 32),
				admin,
				"",
				"",
				"",
			)
			var body struct {
				Error struct {
					Code      string `json:"code"`
					Retryable bool   `json:"retryable"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if response.Code != tc.status || body.Error.Retryable != tc.retryable {
				t.Fatal(response.Code, response.Body.String())
			}
			if tc.retryable &&
				(body.Error.Code != "maintenance_state_busy" || response.Header().Get("Retry-After") != "3") {
				t.Fatal(response.Header(), response.Body.String())
			}
			if !tc.retryable &&
				(body.Error.Code != "maintenance_rejected" || response.Header().Get("Retry-After") != "") {
				t.Fatal(response.Header(), response.Body.String())
			}
		})
	}
	if f.starts != 0 {
		t.Fatal("status inspection started package execution")
	}
}

func TestMaintenanceAPIReconcilesLostAcknowledgementAndRestartWithoutReplay(t *testing.T) {
	dir := t.TempDir()
	s := backupAPI(t, dir)
	_, admin, err := s.Tokens.Issue("admin")
	if err != nil {
		t.Fatal(err)
	}
	f := &maintenanceFixture{jobs: map[string]maintenance.Operation{}, loseReply: true}
	s.Maintenance = f
	handler := s.Handler()
	body := `{"action":"install","bundle_id":"0123456789abcdef0123456789abcdef","components":["routeharbor-sing-box"],"expected_installed_digest":"` + strings.Repeat(
		"1",
		64,
	) + `"}`
	response := backupRequest(
		handler,
		"POST",
		"maintenance/operations",
		admin,
		"1",
		"install-verified-adapter",
		body,
	)
	if response.Code != http.StatusAccepted ||
		strings.Contains(response.Body.String(), "PRIVATE-") {
		t.Fatal(response.Code, response.Body.String())
	}
	var job maintenance.Operation
	if err = json.Unmarshal(response.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	if len(job.ID) != 32 ||
		response.Header().Get("Location") != maintenanceOperationsPath+"/"+job.ID {
		t.Fatal("missing authoritative operation location")
	}
	response = backupRequest(
		handler,
		"POST",
		"maintenance/operations",
		admin,
		"1",
		"install-verified-adapter",
		body,
	)
	if response.Code != http.StatusAccepted || f.starts != 1 {
		t.Fatal("lost acknowledgement replayed package execution", response.Code, f.starts)
	}
	if err = s.Runtime.Store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted := backupAPI(t, dir)
	restarted.Maintenance = f
	job.State, job.Phase = "completed", "verified"
	f.jobs[job.ID] = job
	response = backupRequest(
		restarted.Handler(),
		"POST",
		"maintenance/operations",
		admin,
		"1",
		"install-verified-adapter",
		body,
	)
	if response.Code != http.StatusOK || f.starts != 1 ||
		!strings.Contains(response.Body.String(), `"completed"`) {
		t.Fatal("restart lost root operation identity", response.Code, response.Body.String())
	}
}

func TestMaintenanceAPIRejectsAuthorityRevisionAndArbitraryExecutionFields(t *testing.T) {
	s := backupAPI(t, t.TempDir())
	_, admin, err := s.Tokens.Issue("admin")
	if err != nil {
		t.Fatal(err)
	}
	_, readonly, err := s.Tokens.Issue("read")
	if err != nil {
		t.Fatal(err)
	}
	f := &maintenanceFixture{jobs: map[string]maintenance.Operation{}}
	s.Maintenance = f
	handler := s.Handler()
	for _, test := range []struct {
		name, token, revision, body string
		status                      int
	}{
		{"readonly", readonly, "1", `{}`, 403},
		{"missing-revision", admin, "", `{}`, 428},
		{"stale-revision", admin, "2", `{}`, 409},
		{"command", admin, "1", `{"action":"install","argv":["sh","-c","id"]}`, 400},
		{"download", admin, "1", `{"action":"install","url":"http://127.0.0.1/private"}`, 400},
		{"trust-key", admin, "1", `{"action":"install","key":"attacker-key"}`, 400},
		{"stage-path", admin, "1", `{"action":"install","path":"/etc/shadow"}`, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := backupRequest(
				handler,
				"POST",
				"maintenance/operations",
				test.token,
				test.revision,
				"reject-maintenance-"+test.name,
				test.body,
			)
			if response.Code != test.status || f.starts != 0 {
				t.Fatal(response.Code, f.starts)
			}
		})
	}
	response := backupRequest(
		handler,
		"POST",
		"maintenance/plan",
		readonly,
		"",
		"",
		`{"action":"install","components":["routeharbor-sing-box"]}`,
	)
	if response.Code != 200 || f.starts != 0 {
		t.Fatal("read-only plan performed a mutation", response.Code)
	}
	response = backupRequest(handler, "GET", "maintenance/operations/missing", readonly, "", "", "")
	if response.Code != 422 || strings.Contains(response.Body.String(), "PRIVATE-") {
		t.Fatal(response.Code, response.Body.String())
	}
}
