package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/auth"
	"github.com/tibeahx/OpenRHP/internal/config"
	"github.com/tibeahx/OpenRHP/internal/control"
	"github.com/tibeahx/OpenRHP/internal/model"
	"github.com/tibeahx/OpenRHP/internal/web"
)

type harness struct {
	t           *testing.T
	s           *Server
	http        *httptest.Server
	admin, read string
}

func setup(t *testing.T) *harness {
	t.Helper()
	d := t.TempDir()
	store, e := config.NewStore(filepath.Join(d, "state"))
	if e != nil {
		t.Fatal(e)
	}
	tokens, e := auth.Open(filepath.Join(d, "auth"))
	if e != nil {
		t.Fatal(e)
	}
	_, a, e := tokens.Issue("admin")
	if e != nil {
		t.Fatal(e)
	}
	_, r, e := tokens.Issue("read")
	if e != nil {
		t.Fatal(e)
	}
	j, e := control.NewJournal(filepath.Join(d, "ops"))
	if e != nil {
		t.Fatal(e)
	}
	rt := control.New(store, adapter.NewManager(filepath.Join(d, "engines")), j)
	s := &Server{Runtime: rt, Tokens: tokens, UI: web.Handler()}
	srv := httptest.NewServer(s.Handler())
	s.AllowedHosts = []string{strings.TrimPrefix(srv.URL, "http://")}
	t.Cleanup(func() { srv.Close(); rt.Close(); closeChecked(t, store) })
	return &harness{t, s, srv, a, r}
}

func (h *harness) request(
	method, path, token string,
	body any,
	revision uint64,
	key string,
) (int, []byte) {
	h.t.Helper()
	var b []byte
	if body != nil {
		if raw, ok := body.([]byte); ok {
			b = raw
		} else {
			b, _ = json.Marshal(body)
		}
	}
	req, _ := http.NewRequest(method, h.http.URL+"/api/v1/"+path, bytes.NewReader(b))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if revision > 0 {
		req.Header.Set("If-Match", fmt.Sprintf("\"%d\"", revision))
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	res, e := h.http.Client().Do(req)
	if e != nil {
		h.t.Fatal(e)
	}
	defer closeChecked(h.t, res.Body)
	out, e := io.ReadAll(res.Body)
	if e != nil {
		h.t.Fatal(e)
	}
	return res.StatusCode, out
}

func decode[T any](t *testing.T, b []byte) T {
	t.Helper()
	var v T
	if e := json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	return v
}

func TestAuthenticationACLAndHostOrigin(t *testing.T) {
	h := setup(t)
	for _, path := range []string{"status", "config", "openapi", "operations", "capabilities", "diagnostics", "nodes"} {
		if s, _ := h.request("GET", path, "", nil, 0, ""); s != 401 {
			t.Fatalf("unauth %s: %d", path, s)
		}
	}
	for _, test := range []struct {
		method, path string
		body         any
	}{{"POST", "sources", map[string]any{}}, {"PUT", "config", config.Defaults()}, {"POST", "config/export", map[string]bool{"include_secrets": true}}, {"DELETE", "tokens/123", nil}, {"POST", "transactions", map[string]any{}}, {"POST", "nodes/pair", map[string]any{}}} {
		if s, _ := h.request(
			test.method,
			test.path,
			h.read,
			test.body,
			1,
			"read-test-key",
		); s != 403 {
			t.Fatalf("ACL %s: %d", test.path, s)
		}
	}
	for _, origin := range []string{"https://attacker.example", "null", h.http.URL + "/path"} {
		req, _ := http.NewRequest("GET", h.http.URL+"/api/v1/status", nil)
		req.Header.Set("Authorization", "Bearer "+h.admin)
		req.Header.Set("Origin", origin)
		res, e := h.http.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		if err := res.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != 403 {
			t.Fatal("origin accepted")
		}
	}
	req, _ := http.NewRequest("GET", h.http.URL+"/api/v1/status", nil)
	req.Host = "attacker.example"
	req.Header.Set("Authorization", "Bearer "+h.admin)
	res, e := h.http.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 403 {
		t.Fatal("host accepted")
	}
	if s, _ := h.request("GET", "status?token=leak", h.admin, nil, 0, ""); s != 400 {
		t.Fatal("query accepted")
	}
}

func TestSourceCASIdempotencySecretsAndLifecycle(t *testing.T) {
	h := setup(t)
	canary := "CANARY-DO-NOT-EXPOSE-password"
	source := model.Source{
		ID:      "office",
		Name:    "Office",
		Type:    "socks5",
		Enabled: true,
		Auto:    true,
		Settings: json.RawMessage(
			`{"server":"proxy.example.com","server_port":1080,"username":"test","password":"` + canary + `"}`,
		),
	}
	status, b := h.request("POST", "sources", h.admin, source, 1, "create-office-key")
	if status != 200 {
		t.Fatalf("create %d %s", status, b)
	}
	first := decode[control.Operation](t, b)
	if first.Revision != 2 || first.State != "succeeded" {
		t.Fatal(first)
	}
	status, b = h.request("POST", "sources", h.admin, source, 1, "create-office-key")
	if status != 200 || decode[control.Operation](t, b).ID != first.ID {
		t.Fatal("retry duplicated")
	}
	source.Name = "Other"
	if s, _ := h.request("POST", "sources", h.admin, source, 1, "create-office-key"); s != 409 {
		t.Fatal("idempotency collision accepted")
	}
	if s, _ := h.request(
		"PATCH",
		"sources/office",
		h.admin,
		map[string]any{"auto": false},
		1,
		"stale-edit-key",
	); s != 409 {
		t.Fatal("stale write accepted")
	}
	if s, _ := h.request(
		"PATCH",
		"sources/office",
		h.admin,
		map[string]any{"auto": false},
		2,
		"toggle-office-key",
	); s != 200 {
		t.Fatal(s)
	}
	for _, path := range []string{"config", "sources", "status", "diagnostics", "operations", "engines"} {
		status, b = h.request("GET", path, h.read, nil, 0, "")
		if status != 200 || bytes.Contains(b, []byte(canary)) ||
			bytes.Contains(b, []byte("proxy.example.com")) {
			t.Fatalf("secret exposure in %s", path)
		}
	}
	status, b = h.request(
		"POST",
		"config/export",
		h.admin,
		map[string]bool{"include_secrets": true},
		0,
		"",
	)
	if status != 200 || !bytes.Contains(b, []byte(canary)) {
		t.Fatal("explicit export absent")
	}
	if s, _ := h.request(
		"DELETE",
		"sources/office",
		h.admin,
		nil,
		3,
		"delete-office-key",
	); s != 200 {
		t.Fatal(s)
	}
	if len(h.s.Runtime.Store.Get().Sources) != 0 {
		t.Fatal("source not deleted")
	}
}

func TestInvalidImportsBoundedAndNoSecretEcho(t *testing.T) {
	h := setup(t)
	for i, b := range [][]byte{[]byte(`{"id":"evil","id":"other"}`), []byte(`{"settings":{"exec":"CANARY_SECRET"}}`), []byte(`[]`), bytes.Repeat([]byte("x"), config.MaxConfigBytes+1)} {
		status, out := h.request(
			"POST",
			"sources",
			h.admin,
			b,
			1,
			fmt.Sprintf("malicious-case-%d", i),
		)
		if status < 400 {
			t.Fatal("malformed accepted")
		}
		if bytes.Contains(out, []byte("CANARY_SECRET")) {
			t.Fatal("secret echoed")
		}
	}
}

func TestSchemaAndUIUseSafeAssets(t *testing.T) {
	h := setup(t)
	status, b := h.request("GET", "openapi", h.read, nil, 0, "")
	if status != 200 {
		t.Fatal(status)
	}
	schema := decode[map[string]any](t, b)
	if schema["openapi"] != "3.1.0" {
		t.Fatal("schema missing")
	}
	res, e := h.http.Client().Get(h.http.URL + "/app.js")
	if e != nil {
		t.Fatal(e)
	}
	defer closeChecked(h.t, res.Body)
	b, _ = io.ReadAll(res.Body)
	if bytes.Contains(b, []byte("innerHTML")) || bytes.Contains(b, []byte("localStorage")) ||
		bytes.Contains(b, []byte("sessionStorage")) {
		t.Fatal("unsafe DOM/token persistence")
	}
	if res.Header.Get("Content-Security-Policy") == "" {
		t.Fatal("CSP missing")
	}
}

type successfulProber struct{}

func (successfulProber) Run(
	ctx context.Context,
	s model.Source,
	targets []model.Target,
	p model.ProbeSettings,
	speed bool,
) (model.Measurement, error) {
	m := model.Measurement{SourceID: s.ID, At: time.Now().UTC(), Path: "test-only:" + s.ID}
	for _, t := range targets {
		m.Resources = append(
			m.Resources,
			model.ResourceResult{
				TargetID:  t.ID,
				Required:  t.Required,
				Success:   true,
				LatencyMS: 12,
			},
		)
	}
	return m, nil
}

func TestAgentOnlyWorkflowAndOperationPolling(t *testing.T) {
	h := setup(t)
	h.s.Runtime.Prober = successfulProber{}
	c := config.Defaults()
	c.Sources = []model.Source{
		{
			ID:       "direct",
			Name:     "Direct",
			Type:     "direct",
			Enabled:  true,
			Auto:     true,
			Settings: json.RawMessage(`{}`),
		},
	}
	c.Targets = []model.Target{
		{
			ID:          "resource",
			URL:         "https://example.com/",
			Required:    true,
			StatusCodes: []int{200},
			MaxBytes:    1024,
		},
	}
	c.Policy.Mode = "auto"
	c.Policy.RecoveryConfirmations = 1
	if s, b := h.request("PUT", "config", h.admin, c, 1, "configure-agent-key"); s != 200 {
		t.Fatalf("%d %s", s, b)
	}
	status, b := h.request(
		"POST",
		"sources/direct/probe",
		h.admin,
		map[string]bool{"speed": false},
		0,
		"agent-probe-key",
	)
	if status != 202 {
		t.Fatalf("%d %s", status, b)
	}
	op := decode[control.Operation](t, b)
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		_, b = h.request("GET", "operations/"+op.ID, h.read, nil, 0, "")
		v := decode[control.Operation](t, b)
		if v.State == "succeeded" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, b = h.request("GET", "status", h.read, nil, 0, "")
	state := decode[map[string]any](t, b)
	if state["network_applied"] != false {
		t.Fatal("claimed network mutation in control-only mode")
	}
	if state["decision"].(map[string]any)["selected"] != "direct" {
		t.Fatalf("selection failed %s", b)
	}
}

func TestTargetArrayEndpointRejectsNullButAcceptsValidList(t *testing.T) {
	h := setup(t)
	targets := []model.Target{
		{
			ID:          "public",
			URL:         "https://example.com/",
			Required:    true,
			StatusCodes: []int{200},
			MaxBytes:    1024,
		},
	}
	status, b := h.request("PUT", "targets", h.admin, targets, 1, "target-array-write")
	if status != 200 {
		t.Fatalf("valid targets array rejected: %d %s", status, b)
	}
	if len(h.s.Runtime.Store.Get().Targets) != 1 {
		t.Fatal("target array was not persisted")
	}
	status, _ = h.request("PUT", "targets", h.admin, []byte("null"), 2, "target-null-write")
	if status < 400 {
		t.Fatal("null targets accepted")
	}
}

func closeChecked(t *testing.T, closer io.Closer) {
	t.Helper()
	if err := closer.Close(); err != nil {
		t.Error(err)
	}
}
