// Package api implements the authenticated public control plane.
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	contract "github.com/tibeahx/OpenRHP/api"
	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/auth"
	"github.com/tibeahx/OpenRHP/internal/config"
	"github.com/tibeahx/OpenRHP/internal/control"
	"github.com/tibeahx/OpenRHP/internal/model"
	"github.com/tibeahx/OpenRHP/internal/platform"
)

type NetworkService interface {
	Prepare(context.Context, model.Config, int) (map[string]any, error)
	Action(context.Context, string, string) (map[string]any, error)
	Status(context.Context, string) (map[string]any, error)
	Current(context.Context) (map[string]any, error)
}
type CoverageService interface {
	List() any
	Discover(context.Context) any
	Pair(context.Context, json.RawMessage) (map[string]any, error)
	Unpair(context.Context, string) error
	Plan(context.Context, string, json.RawMessage) (map[string]any, error)
}
type NodeOperations interface {
	Operate(context.Context, string, string, json.RawMessage) (map[string]any, error)
}
type Server struct {
	Runtime      *control.Runtime
	Tokens       *auth.Store
	AllowedHosts []string
	UI           http.Handler
	Network      NetworkService
	Coverage     CoverageService
	mu           sync.Mutex
	limitMu      sync.Mutex
	limits       map[string]bucket
	streams      chan struct{}
	requests     chan struct{}
}
type bucket struct {
	at     time.Time
	tokens float64
}
type key int

const credentialKey key = 1

func (s *Server) Handler() http.Handler {
	s.limits = map[string]bucket{}
	s.streams = make(chan struct{}, 8)
	s.requests = make(chan struct{}, 16)
	mux := http.NewServeMux()
	for pattern, handler := range s.routes() {
		mux.HandleFunc(pattern, handler)
	}
	if s.UI != nil {
		mux.Handle("/", s.UI)
	}
	return s.security(mux)
}

// routes is also checked against the embedded public OpenAPI contract.
func (s *Server) routes() map[string]http.HandlerFunc {
	routes := map[string]http.HandlerFunc{}
	register := func(pattern string, handler http.HandlerFunc) { routes[pattern] = handler }
	for _, path := range []string{"status", "capabilities", "preflight", "openapi", "config", "sources", "operations", "diagnostics", "events", "engines", "nodes", "tokens"} {
		register("GET /api/v1/"+path, s.read)
	}
	register("GET /api/v1/operations/{id}", s.read)
	register("GET /api/v1/sources/{id}/history", s.read)
	register("GET /api/v1/transactions/{id}", s.read)
	for _, path := range []string{"config/validate", "config/plan", "config/export", "nodes/discover"} {
		register("POST /api/v1/"+path, s.inspect)
	}
	for _, pattern := range []string{"PUT /api/v1/config", "POST /api/v1/sources", "PUT /api/v1/sources/{id}", "PATCH /api/v1/sources/{id}", "DELETE /api/v1/sources/{id}", "PUT /api/v1/policy", "PUT /api/v1/targets", "PUT /api/v1/probes/settings", "PUT /api/v1/network", "POST /api/v1/sources/{id}/probe", "POST /api/v1/probes", "POST /api/v1/transactions", "POST /api/v1/transactions/{id}/apply", "POST /api/v1/transactions/{id}/confirm", "POST /api/v1/transactions/{id}/rollback", "POST /api/v1/nodes/pair", "DELETE /api/v1/nodes/{id}", "DELETE /api/v1/tokens/{id}"} {
		register(pattern, s.mutate)
	}
	register("POST /api/v1/nodes/{id}/plan", s.inspect)
	for _, a := range []string{"prepare", "apply", "confirm", "rollback"} {
		register("POST /api/v1/nodes/{id}/"+a, s.mutate)
	}
	register("GET /api/v1/nodes/{id}/status", s.read)
	return routes
}

func (s *Server) security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().
			Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("Cache-Control", "no-store")
		hostOK := false
		for _, h := range s.AllowedHosts {
			if strings.EqualFold(r.Host, h) {
				hostOK = true
				break
			}
		}
		if !hostOK {
			problem(w, 403, "host_forbidden", "Host is not permitted", false)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, e := url.Parse(origin)
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			if e != nil || u.Scheme != scheme || !strings.EqualFold(u.Host, r.Host) ||
				u.Path != "" ||
				u.RawQuery != "" ||
				u.Fragment != "" ||
				u.User != nil {
				problem(w, 403, "origin_forbidden", "Origin is not permitted", false)
				return
			}
		}
		if r.Method == "OPTIONS" {
			problem(w, 403, "cors_forbidden", "Cross-origin access is disabled", false)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, config.MaxConfigBytes)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			select {
			case s.requests <- struct{}{}:
				defer func() { <-s.requests }()
			default:
				problem(w, 429, "request_limit", "Too many concurrent requests", true)
				return
			}
			if r.URL.RawQuery != "" {
				problem(
					w,
					400,
					"query_forbidden",
					"API query parameters are not supported; send credentials in Authorization",
					false,
				)
				return
			}
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			if !s.allow(host) {
				problem(w, 429, "rate_limited", "Too many requests; retry later", true)
				return
			}
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				problem(
					w,
					401,
					"authentication_required",
					"Use a local administrator or read-only credential",
					false,
				)
				return
			}
			c, ok := s.Tokens.Verify(strings.TrimPrefix(header, "Bearer "))
			if !ok {
				problem(w, 401, "invalid_credential", "Credential is invalid or revoked", false)
				return
			}
			readOnly := r.Method == "GET"
			if r.Method == "POST" {
				switch r.URL.Path {
				case "/api/v1/config/validate", "/api/v1/config/plan", "/api/v1/nodes/discover":
					readOnly = true
				default:
					readOnly = strings.HasSuffix(r.URL.Path, "/plan")
				}
			}
			if !readOnly && c.Role != "admin" {
				problem(w, 403, "admin_required", "Administrator permission is required", false)
				return
			}
			if strings.HasPrefix(r.URL.Path, "/api/v1/tokens") && c.Role != "admin" {
				problem(w, 403, "admin_required", "Administrator permission is required", false)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), credentialKey, c))
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) allow(host string) bool {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	now := time.Now()
	b, ok := s.limits[host]
	if !ok {
		if len(s.limits) >= 1024 {
			for k, v := range s.limits {
				if now.Sub(v.at) > 5*time.Minute {
					delete(s.limits, k)
				}
			}
			if len(s.limits) >= 1024 {
				return false
			}
		}
		b = bucket{now, 120}
	}
	b.tokens += now.Sub(b.at).Seconds() * 2
	if b.tokens > 120 {
		b.tokens = 120
	}
	b.at = now
	allowed := b.tokens >= 1
	if allowed {
		b.tokens--
	}
	s.limits[host] = b
	return allowed
}

func problem(w http.ResponseWriter, status int, code, message string, retry bool) {
	write(
		w,
		status,
		map[string]any{
			"error": map[string]any{"code": code, "message": message, "retryable": retry},
		},
	)
}

func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, out any) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return errors.New("content type must be application/json")
	}
	b, e := io.ReadAll(r.Body)
	if e != nil {
		return errors.New("request exceeds byte limit")
	}
	return adapter.StrictDecode(b, out)
}

func (s *Server) read(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	id := r.PathValue("id")
	c := s.Runtime.Store.Get()
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", c.Revision))
	switch path {
	case "/api/v1/openapi":
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(contract.OpenAPI)
	case "/api/v1/config":
		write(w, 200, config.Redact(c))
	case "/api/v1/sources":
		write(w, 200, config.Redact(c).Sources)
	case "/api/v1/status":
		status := s.Runtime.Status()
		status["network_applied"] = false
		if s.Network != nil {
			v, e := s.Network.Current(r.Context())
			if e == nil {
				status["network"] = v
				status["network_applied"] = v["applied"]
			}
		}
		write(w, 200, status)
	case "/api/v1/capabilities", "/api/v1/preflight":
		report := platform.Detect(r.Context())
		write(
			w,
			200,
			map[string]any{
				"platform":          report,
				"network_helper":    s.Network != nil,
				"coverage_agent":    s.Coverage != nil,
				"release_status":    "development",
				"hardware_verified": false,
			},
		)
	case "/api/v1/operations":
		write(w, 200, s.Runtime.Journal.List())
	case "/api/v1/engines":
		write(w, 200, s.Runtime.EngineStatus())
	case "/api/v1/nodes":
		if s.Coverage == nil {
			write(w, 200, []any{})
		} else {
			write(w, 200, s.Coverage.List())
		}
	case "/api/v1/tokens":
		write(w, 200, s.Tokens.List())
	case "/api/v1/diagnostics":
		write(
			w,
			200,
			map[string]any{
				"project":         "OpenRHP",
				"version":         "0.1.0-dev",
				"schema_version":  c.SchemaVersion,
				"revision":        c.Revision,
				"role":            c.Role,
				"source_count":    len(c.Sources),
				"target_count":    len(c.Targets),
				"network_enabled": c.Network.Enabled,
				"policy_mode":     c.Policy.Mode,
				"secret_export":   false,
			},
		)
	case "/api/v1/events":
		s.events(w, r)
	default:
		if strings.HasPrefix(path, "/api/v1/nodes/") && strings.HasSuffix(path, "/status") {
			if svc, ok := s.Coverage.(NodeOperations); ok {
				v, e := svc.Operate(r.Context(), id, "status", json.RawMessage(`{}`))
				if e == nil {
					write(w, 200, v)
					return
				}
			}
			problem(w, 503, "node_unavailable", "Paired node status is unavailable", true)
			return
		}
		if strings.HasPrefix(path, "/api/v1/operations/") {
			if op, ok := s.Runtime.Journal.Get(id); ok {
				write(w, 200, op)
				return
			}
		}
		if strings.HasSuffix(path, "/history") {
			write(w, 200, s.Runtime.History(id))
			return
		}
		if strings.HasPrefix(path, "/api/v1/transactions/") {
			if s.Network == nil {
				problem(w, 503, "helper_unavailable", "The network helper is unavailable", false)
				return
			}
			v, e := s.Network.Status(r.Context(), id)
			if e == nil {
				write(w, 200, v)
				return
			}
		}
		problem(w, 404, "not_found", "Object does not exist", false)
	}
}

func (s *Server) inspect(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/api/v1/config/export" {
		var req struct {
			IncludeSecrets bool `json:"include_secrets"`
		}
		if e := readJSON(r, &req); e != nil || !req.IncludeSecrets {
			problem(
				w,
				400,
				"explicit_export_required",
				"Set include_secrets to true for a full export",
				false,
			)
			return
		}
		w.Header().Set("Content-Disposition", "attachment; filename=openrhp-config.json")
		write(w, 200, s.Runtime.Store.Get())
		return
	}
	if strings.HasPrefix(path, "/api/v1/nodes") {
		if s.Coverage == nil {
			problem(
				w,
				503,
				"coverage_unavailable",
				"No coverage agent is configured; follow the coverage setup guide",
				false,
			)
			return
		}
		if path == "/api/v1/nodes/discover" {
			write(w, 200, s.Coverage.Discover(r.Context()))
			return
		}
		var req json.RawMessage
		if e := readJSON(r, &req); e != nil {
			problem(w, 400, "invalid_request", "Invalid coverage request", false)
			return
		}
		v, e := s.Coverage.Plan(r.Context(), r.PathValue("id"), req)
		if e != nil {
			problem(
				w,
				422,
				"coverage_plan_rejected",
				"Device capabilities do not allow the requested plan",
				false,
			)
			return
		}
		write(w, 200, v)
		return
	}
	var c model.Config
	if e := readJSON(r, &c); e != nil {
		problem(
			w,
			400,
			"invalid_json",
			"Supply a complete configuration object with known fields",
			false,
		)
		return
	}
	if e := config.Validate(c); e != nil {
		problem(w, 422, "invalid_config", e.Error(), false)
		return
	}
	out := map[string]any{"valid": true, "network_changes_applied": false}
	if path == "/api/v1/config/plan" {
		old := s.Runtime.Store.Get()
		out["base_revision"] = old.Revision
		out["source_count_before"] = len(old.Sources)
		out["source_count_after"] = len(c.Sources)
		out["policy_before"] = old.Policy
		out["policy_after"] = c.Policy
		out["network_before"] = old.Network
		out["network_after"] = c.Network
		out["requires_network_transaction"] = c.Network.Enabled
	}
	write(w, 200, out)
}

func expectedRevision(r *http.Request) (uint64, error) {
	v := r.Header.Get("If-Match")
	if len(v) < 3 || v[0] != '"' || v[len(v)-1] != '"' {
		return 0, errors.New("quoted If-Match revision required")
	}
	n, e := strconv.ParseUint(v[1:len(v)-1], 10, 64)
	if n == 0 {
		return 0, errors.New("positive revision required")
	}
	return n, e
}

func (s *Server) mutate(w http.ResponseWriter, r *http.Request) {
	keyValue := r.Header.Get("Idempotency-Key")
	if len(keyValue) < 8 || len(keyValue) > 128 ||
		strings.IndexFunc(keyValue, func(c rune) bool { return c < 33 || c > 126 }) >= 0 {
		problem(
			w,
			400,
			"idempotency_key_required",
			"Supply a unique Idempotency-Key of 8 to 128 visible ASCII characters",
			false,
		)
		return
	}
	body, e := io.ReadAll(r.Body)
	if e != nil {
		problem(w, 413, "request_too_large", "Request exceeds the byte limit", false)
		return
	}
	if len(body) > 0 && r.Header.Get("Content-Type") != "application/json" {
		problem(w, 415, "json_required", "Content-Type must be application/json", false)
		return
	}
	credential := r.Context().Value(credentialKey).(auth.Credential)
	sum := sha256.Sum256(
		[]byte(
			r.Method + "\n" + r.URL.Path + "\n" + r.Header.Get("If-Match") + "\n" + string(body),
		),
	)
	hash := hex.EncodeToString(sum[:])
	keyValue = credential.ID + ":" + keyValue
	s.mu.Lock()
	defer s.mu.Unlock()
	op, existing, e := s.Runtime.Journal.Begin(r.Method+" "+r.URL.Path, keyValue, hash)
	if e != nil {
		if errors.Is(e, control.ErrIdempotency) {
			problem(w, 409, "idempotency_conflict", "The key belongs to a different request", false)
		} else {
			problem(w, 429, "operation_limit", "Operation journal or queue is full", true)
		}
		return
	}
	if existing {
		status := 200
		if op.State == "running" {
			status = 202
		}
		write(w, status, op)
		return
	}
	fail := func(status int, code, msg string) {
		_, _ = s.Runtime.Journal.Finish(op.ID, 0, nil, code)
		problem(w, status, code, msg, false)
	}
	finish := func(rev uint64, result map[string]any) {
		v, e := s.Runtime.Journal.Finish(op.ID, rev, result, "")
		if e != nil {
			problem(w, 500, "journal_write_failed", "Read current state before retrying", true)
			return
		}
		write(w, 200, v)
	}
	path := r.URL.Path
	id := r.PathValue("id")
	if path == "/api/v1/probes" || strings.HasSuffix(path, "/probe") {
		var req struct {
			Speed bool `json:"speed"`
		}
		if len(body) == 0 {
			body = []byte(`{}`)
		}
		if e = adapter.StrictDecode(body, &req); e != nil {
			fail(400, "invalid_request", "Invalid probe options")
			return
		}
		c := s.Runtime.Store.Get()
		ids := []string{}
		for _, source := range c.Sources {
			if source.Enabled && (id == "" || source.ID == id) {
				ids = append(ids, source.ID)
			}
		}
		if len(ids) == 0 || len(c.Targets) == 0 {
			fail(422, "nothing_to_probe", "Add an enabled source and probe resources first")
			return
		}
		go func() {
			failed := 0
			for _, sid := range ids {
				ctx, cancel := context.WithTimeout(
					context.Background(),
					time.Duration(c.Probes.TimeoutSeconds*len(c.Targets)+5)*time.Second,
				)
				_, err := s.Runtime.Probe(ctx, sid, req.Speed)
				cancel()
				if err != nil {
					failed++
				}
			}
			code := ""
			if failed > 0 {
				code = "one_or_more_probes_failed"
			}
			_, _ = s.Runtime.Journal.Finish(
				op.ID,
				0,
				map[string]any{"checked": len(ids), "failed": failed},
				code,
			)
		}()
		write(w, 202, op)
		return
	}
	if strings.HasPrefix(path, "/api/v1/transactions") {
		if s.Network == nil {
			fail(503, "helper_unavailable", "A supported OpenWrt network helper is required")
			return
		}
		var v map[string]any
		if path == "/api/v1/transactions" {
			rev, err := expectedRevision(r)
			if err != nil {
				fail(428, "revision_required", err.Error())
				return
			}
			c := s.Runtime.Store.Get()
			if rev != c.Revision {
				fail(409, "revision_conflict", "Refresh the configuration before preparing")
				return
			}
			var req struct {
				ConfirmTimeoutSeconds int `json:"confirm_timeout_seconds"`
			}
			if adapter.StrictDecode(body, &req) != nil {
				fail(400, "invalid_request", "Invalid transaction options")
				return
			}
			v, e = s.Network.Prepare(r.Context(), c, req.ConfirmTimeoutSeconds)
		} else {
			var req struct{}
			if adapter.StrictDecode(body, &req) != nil {
				fail(400, "invalid_request", "Expected an empty options object")
				return
			}
			action := path[strings.LastIndex(path, "/")+1:]
			v, e = s.Network.Action(r.Context(), id, action)
		}
		if e != nil {
			fail(
				422,
				"network_operation_rejected",
				"Network preflight or transaction validation failed; inspect capabilities and transaction state",
			)
			return
		}
		finish(0, v)
		return
	}
	if strings.HasPrefix(path, "/api/v1/nodes") {
		if s.Coverage == nil {
			fail(503, "coverage_unavailable", "A coverage agent is required")
			return
		}
		if id != "" && r.Method == "POST" {
			svc, ok := s.Coverage.(NodeOperations)
			if !ok {
				fail(503, "node_operations_unavailable", "Node transaction service unavailable")
				return
			}
			action := path[strings.LastIndex(path, "/")+1:]
			v, err := svc.Operate(r.Context(), id, action, body)
			if err != nil {
				fail(
					422,
					"node_operation_rejected",
					"Node operation failed validation or connectivity checks",
				)
				return
			}
			finish(0, v)
			return
		}
		if r.Method == "DELETE" {
			if e = s.Coverage.Unpair(r.Context(), id); e != nil {
				fail(422, "unpair_failed", "Node revocation failed")
				return
			}
			finish(0, nil)
			return
		}
		v, err := s.Coverage.Pair(r.Context(), body)
		if err != nil {
			fail(
				422,
				"pairing_rejected",
				"Device identity, one-time code or capability verification failed",
			)
			return
		}
		finish(0, v)
		return
	}
	if strings.HasPrefix(path, "/api/v1/tokens/") {
		if e = s.Tokens.Revoke(id); e != nil {
			fail(404, "not_found", "Credential not found")
			return
		}
		finish(0, nil)
		return
	}
	rev, e := expectedRevision(r)
	if e != nil {
		fail(428, "revision_required", e.Error())
		return
	}
	c := s.Runtime.Store.Get()
	if rev != c.Revision {
		fail(409, "revision_conflict", "Configuration changed; refresh before applying your edits")
		return
	}
	switch {
	case path == "/api/v1/config":
		if e = adapter.StrictDecode(body, &c); e != nil {
			fail(400, "invalid_config", "Expected a complete configuration object")
			return
		}
	case path == "/api/v1/targets":
		if e = adapter.StrictDecode(body, &c.Targets); e != nil {
			fail(400, "invalid_targets", "Expected an array of probe resources")
			return
		}
	case path == "/api/v1/probes/settings":
		if e = adapter.StrictDecode(body, &c.Probes); e != nil {
			fail(400, "invalid_probe_settings", "Invalid probe settings")
			return
		}
	case path == "/api/v1/network":
		if e = adapter.StrictDecode(body, &c.Network); e != nil {
			fail(400, "invalid_network", "Invalid network settings")
			return
		}
	case path == "/api/v1/policy":
		if e = adapter.StrictDecode(body, &c.Policy); e != nil {
			fail(400, "invalid_policy", "Invalid policy object")
			return
		}
	case path == "/api/v1/sources" && r.Method == "POST":
		var source model.Source
		if e = adapter.StrictDecode(body, &source); e != nil {
			fail(400, "invalid_source", "Invalid source object")
			return
		}
		c.Sources = append(c.Sources, source)
	case strings.HasPrefix(path, "/api/v1/sources/"):
		index := -1
		for i, v := range c.Sources {
			if v.ID == id {
				index = i
				break
			}
		}
		if index < 0 {
			fail(404, "not_found", "Source not found")
			return
		}
		switch r.Method {
		case "DELETE":
			if len(bytes.TrimSpace(body)) > 0 {
				fail(400, "unexpected_body", "Delete does not accept a body")
				return
			}
			c.Sources = append(c.Sources[:index], c.Sources[index+1:]...)
		case "PUT":
			var source model.Source
			if adapter.StrictDecode(body, &source) != nil || source.ID != id {
				fail(400, "invalid_source", "Source identifier must match the path")
				return
			}
			c.Sources[index] = source
		case "PATCH":
			var patch struct {
				Name    *string `json:"name"`
				Enabled *bool   `json:"enabled"`
				Auto    *bool   `json:"auto"`
			}
			if adapter.StrictDecode(body, &patch) != nil {
				fail(400, "invalid_source", "Only name, enabled and auto can be patched")
				return
			}
			if patch.Name != nil {
				c.Sources[index].Name = *patch.Name
			}
			if patch.Enabled != nil {
				c.Sources[index].Enabled = *patch.Enabled
			}
			if patch.Auto != nil {
				c.Sources[index].Auto = *patch.Auto
			}
		}
	default:
		fail(404, "not_found", "Unknown mutation")
		return
	}
	if e = config.Validate(c); e != nil {
		fail(422, "invalid_config", e.Error())
		return
	}
	if guard, ok := s.Network.(interface {
		ValidateChange(context.Context, model.Config, model.Config) error
	}); ok {
		if e = guard.ValidateChange(r.Context(), s.Runtime.Store.Get(), c); e != nil {
			fail(409, "network_config_locked", e.Error())
			return
		}
	}
	updated, e := s.Runtime.Store.Replace(rev, c)
	if e != nil {
		if errors.Is(e, config.ErrConflict) {
			fail(409, "revision_conflict", "Configuration changed; refresh before retrying")
		} else {
			fail(500, "configuration_write_failed", "Configuration could not be saved")
		}
		return
	}
	s.Runtime.Reload()
	finish(
		updated.Revision,
		map[string]any{"configuration_saved": true, "network_changes_applied": false},
	)
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	select {
	case s.streams <- struct{}{}:
		defer func() { <-s.streams }()
	default:
		problem(w, 429, "stream_limit", "Too many event streams", true)
		return
	}
	f, ok := w.(http.Flusher)
	if !ok {
		problem(w, 500, "stream_unavailable", "Event streaming is unavailable", true)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	deadline := time.NewTimer(2 * time.Minute)
	defer deadline.Stop()
	for {
		c := r.Context().Value(credentialKey).(auth.Credential)
		stillValid := false
		for _, v := range s.Tokens.List() {
			if v.ID == c.ID {
				stillValid = true
			}
		}
		if !stillValid {
			return
		}
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, e := fmt.Fprintf(
			w,
			"event: state\ndata: %s\n\n",
			s.Runtime.SnapshotJSON(),
		); e != nil {
			return
		}
		f.Flush()
		select {
		case <-r.Context().Done():
			return
		case <-deadline.C:
			return
		case <-ticker.C:
		}
	}
}
