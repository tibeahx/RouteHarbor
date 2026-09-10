package api

import (
	"context"
	"net/http"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/config"
)

const routingOperationTimeout = 2 * time.Minute

// RoutingService exposes only allowlisted counters/state. Implementations must
// not return DNS query history, source credentials or unvalidated engine output.
type RoutingService interface {
	Status() any
	Refresh(context.Context) (any, error)
	Check(context.Context, string) (any, error)
}

func (s *Server) readRoutingStatus(w http.ResponseWriter, r *http.Request) {
	if s.Routing == nil {
		problem(
			w,
			503,
			"routing_unavailable",
			"Selective routing observations are unavailable",
			true,
		)
		return
	}
	write(w, 200, s.Routing.Status())
}

func (s *Server) routingOperation(
	w http.ResponseWriter,
	r *http.Request,
	body []byte,
	opID string,
) {
	fail := func(status int, code, message string) {
		_, _ = s.Runtime.Journal.Finish(opID, 0, nil, code)
		problem(w, status, code, message, false)
	}
	revision, err := expectedRevision(r)
	if err != nil {
		fail(428, "revision_required", "Quoted If-Match revision required")
		return
	}
	if revision != s.Runtime.Store.Get().Revision {
		fail(409, "revision_conflict", "Configuration changed; refresh before retrying")
		return
	}
	var req struct {
		Domain string `json:"domain"`
	}
	if r.URL.Path == "/api/v1/routing/refresh" {
		if adapter.StrictDecode(body, &struct{}{}) != nil {
			fail(400, "invalid_request", "Expected an empty options object")
			return
		}
	} else if adapter.StrictDecode(body, &req) != nil || !config.ValidRoutingDomain(req.Domain) {
		fail(400, "invalid_destination", "Expected a canonical public DNS domain")
		return
	}
	if s.Routing == nil {
		fail(503, "routing_unavailable", "Selective routing service is unavailable")
		return
	}
	// Network work runs outside the serialized mutation lock. Journal replay returns
	// this same operation and never launches a second refresh or comparison.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), routingOperationTimeout)
		defer cancel()
		var value any
		var err error
		if r.URL.Path == "/api/v1/routing/refresh" {
			value, err = s.Routing.Refresh(ctx)
		} else {
			value, err = s.Routing.Check(ctx, req.Domain)
		}
		if err != nil {
			_, _ = s.Runtime.Journal.Finish(opID, revision, nil, "routing_operation_failed")
			return
		}
		// The request domain is deliberately not stored in the operation journal.
		_, _ = s.Runtime.Journal.Finish(opID, revision, map[string]any{"routing": value}, "")
	}()
	if op, ok := s.Runtime.Journal.Get(opID); ok {
		write(w, 202, op)
	}
}
