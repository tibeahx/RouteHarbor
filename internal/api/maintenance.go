package api

import (
	"context"
	"net/http"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/control"
	"github.com/tibeahx/OpenRHP/internal/maintenance"
)

const maintenanceOperationsPath = "/api/v1/maintenance/operations"

func (s *Server) inspectMaintenance(w http.ResponseWriter, r *http.Request) {
	if s.Maintenance == nil {
		problem(
			w,
			503,
			"maintenance_unavailable",
			"Verified offline package maintenance requires the installed privileged service",
			false,
		)
		return
	}
	var value any
	var err error
	switch r.URL.Path {
	case "/api/v1/maintenance/capabilities":
		value, err = s.Maintenance.Capabilities(r.Context())
	case "/api/v1/maintenance/bundles":
		value, err = s.Maintenance.Bundles(r.Context())
	case "/api/v1/maintenance/plan":
		var request maintenance.Request
		if readJSON(r, &request) != nil {
			problem(
				w,
				400,
				"invalid_maintenance_request",
				"Supply the documented package action and fixed component identities",
				false,
			)
			return
		}
		value, err = s.Maintenance.Plan(r.Context(), request)
	default:
		value, err = s.Maintenance.Status(r.Context(), r.PathValue("id"))
	}
	if err != nil {
		// The private RPC preserves machine-safe error codes, not Go error identity.
		if r.Method == http.MethodGet && r.PathValue("id") != "" &&
			err.Error() == maintenance.ErrStateBusy.Error() {
			w.Header().Set("Retry-After", "3")
			problem(w, http.StatusServiceUnavailable, "maintenance_state_busy",
				"Package maintenance is busy; retry this status read shortly", true)
			return
		}
		problem(
			w,
			422,
			"maintenance_rejected",
			"Package identity, installed inventory or private recovery state failed validation; inspect maintenance capabilities",
			false,
		)
		return
	}
	write(w, 200, value)
}

func maintenanceStatus(op maintenance.Operation) int {
	switch op.State {
	case "completed", "failed", "interrupted", "rollback_required", "succeeded":
		return http.StatusOK
	default:
		return http.StatusAccepted
	}
}

func (s *Server) existingMaintenance(
	w http.ResponseWriter,
	r *http.Request,
	body []byte,
	op control.Operation,
) bool {
	if r.URL.Path != maintenanceOperationsPath || s.Maintenance == nil {
		return false
	}
	// Uncertain package-manager invocations are inspected, never replayed. A
	// prepared job may only need its detached worker rearmed; the root service
	// serializes workers and persists running before invoking the package manager.
	job, err := s.Maintenance.Status(r.Context(), op.ID)
	if err != nil {
		return false
	}
	if job.State == "prepared" {
		var request maintenance.Request
		if adapter.StrictDecode(body, &request) == nil {
			if resumed, err := s.Maintenance.Start(r.Context(), op.ID, request); err == nil {
				job = resumed
			}
		}
	}
	w.Header().Set("Location", maintenanceOperationsPath+"/"+job.ID)
	write(w, maintenanceStatus(job), job)
	return true
}

func (s *Server) startMaintenance(
	w http.ResponseWriter,
	r *http.Request,
	body []byte,
	op control.Operation,
) {
	fail := func(status int, code, message string) {
		_, _ = s.Runtime.Journal.Finish(op.ID, 0, nil, code)
		problem(w, status, code, message, false)
	}
	if s.Maintenance == nil {
		fail(
			503,
			"maintenance_unavailable",
			"Verified offline package maintenance requires the installed privileged service",
		)
		return
	}
	revision, err := expectedRevision(r)
	if err != nil {
		fail(428, "revision_required", "Supply the current quoted configuration revision")
		return
	}
	if revision != s.Runtime.Store.Get().Revision {
		fail(
			409,
			"revision_conflict",
			"Refresh configuration and the package plan before starting maintenance",
		)
		return
	}
	var request maintenance.Request
	if adapter.StrictDecode(body, &request) != nil {
		fail(
			400,
			"invalid_maintenance_request",
			"Supply the documented package action and fixed component identities",
		)
		return
	}
	job, err := s.Maintenance.Start(r.Context(), op.ID, request)
	if err != nil {
		// A timed-out start may already have a durable root job. Expose that state
		// rather than inventing failure or starting another package operation.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		job, err = s.Maintenance.Status(ctx, op.ID)
		if err != nil {
			fail(
				422,
				"maintenance_rejected",
				"Package maintenance did not return a verified job; inspect the installed inventory and recovery state before retrying",
			)
			return
		}
	}
	// The generic journal records dispatch only. Package progress and completion
	// are authoritative in the root journal and survive controller replacement.
	w.Header().Set("Location", maintenanceOperationsPath+"/"+job.ID)
	_, err = s.Runtime.Journal.Finish(op.ID, revision, map[string]any{
		"maintenance_operation_id": job.ID,
		"status_path":              maintenanceOperationsPath + "/" + job.ID,
		"dispatch_accepted":        true,
	}, "")
	if err != nil {
		problem(
			w,
			503,
			"journal_write_failed",
			"Read the authoritative maintenance operation from the Location header before retrying",
			true,
		)
		return
	}
	write(w, maintenanceStatus(job), job)
}
