package api

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/config"
	"github.com/tibeahx/OpenRHP/internal/control"
	"github.com/tibeahx/OpenRHP/internal/model"
)

func TestCompleteLegacyConfigImportDoesNotInheritSelectiveDefaults(t *testing.T) {
	h := setup(t)
	c := config.Defaults()
	c.Routing = nil
	raw, err := json.Marshal(c)
	if err != nil || strings.Contains(string(raw), `"routing"`) {
		t.Fatal("legacy fixture must omit routing", err)
	}
	if status, body := h.request(
		"PUT",
		"config",
		h.admin,
		raw,
		1,
		"legacy-config-import",
	); status != 200 {
		t.Fatal(status, string(body))
	}
	if h.s.Runtime.Store.Get().Routing != nil {
		t.Fatal("legacy import silently changed routing semantics")
	}
}

type testRoutingService struct {
	calls   atomic.Int32
	failure bool
}

func (*testRoutingService) Status() any {
	return map[string]any{
		"state":          "inactive",
		"default_action": "direct",
		"registry":       map[string]any{"stale": true},
	}
}

func (s *testRoutingService) Refresh(context.Context) (any, error) {
	s.calls.Add(1)
	if s.failure {
		return nil, errors.New("secret upstream details")
	}
	return map[string]any{"published_generation": 1}, nil
}

func (s *testRoutingService) Check(context.Context, string) (any, error) {
	s.calls.Add(1)
	return map[string]any{"action": "direct", "reason": "default", "route": "direct"}, nil
}

func TestRoutingAPIAuthCASAndSecretPreservation(t *testing.T) {
	h := setup(t)
	profile := config.RoutingDefaults()
	for _, path := range []string{"routing", "routing/status"} {
		if status, _ := h.request("GET", path, "", nil, 0, ""); status != 401 {
			t.Fatal(status)
		}
	}
	if status, b := h.request(
		"GET",
		"routing",
		h.read,
		nil,
		0,
		"",
	); status != 200 ||
		!model.SelectiveRouting(model.Config{Routing: decode[*model.RoutingConfig](t, b)}) {
		t.Fatal(status, string(b))
	}
	if status, _ := h.request("GET", "routing/status", h.read, nil, 0, ""); status != 503 {
		t.Fatal("fabricated runtime status", status)
	}
	if status, _ := h.request("PUT", "routing", h.read, profile, 1, "read-only"); status != 403 {
		t.Fatal(status)
	}
	if status, _ := h.request("PUT", "routing", h.admin, profile, 0, "missing-cas"); status != 428 {
		t.Fatal(status)
	}
	c := h.s.Runtime.Store.Get()
	c.Sources = []model.Source{
		{
			ID:   "proxy",
			Name: "Proxy",
			Type: "socks5",
			Settings: []byte(
				`{"server":"8.8.8.8","server_port":1080,"username":"owner","password":"retained-secret"}`,
			),
		},
	}
	if status, b := h.request("PUT", "config", h.admin, c, 1, "with-secret"); status != 200 {
		t.Fatal(status, string(b))
	}
	profile.Exceptions = []model.RoutingRule{{Action: "bypass", Domain: "example.org"}}
	if status, b := h.request(
		"PUT",
		"routing",
		h.admin,
		profile,
		2,
		"routing-save",
	); status != 200 ||
		strings.Contains(string(b), "retained-secret") {
		t.Fatal(status, string(b))
	}
	if !strings.Contains(string(h.s.Runtime.Store.Get().Sources[0].Settings), "retained-secret") {
		t.Fatal("settings erased")
	}
	if status, _ := h.request(
		"PUT",
		"routing",
		h.admin,
		profile,
		2,
		"routing-stale",
	); status != 409 {
		t.Fatal(status)
	}
	if status, b := h.request(
		"PUT",
		"routing",
		h.admin,
		[]byte(`{"mode":"selective","private_key":"never-print-this"}`),
		3,
		"routing-secret",
	); status != 400 ||
		strings.Contains(string(b), "never-print-this") {
		t.Fatal(status, string(b))
	}
	if status, b := h.request(
		"PUT",
		"routing",
		h.admin,
		[]byte("null"),
		3,
		"routing-legacy",
	); status != 200 ||
		h.s.Runtime.Store.Get().Routing != nil {
		t.Fatal(status, string(b))
	}
}

func TestRoutingOperationsIdempotentBoundedAndAdministrative(t *testing.T) {
	h := setup(t)
	service := &testRoutingService{}
	h.s.Routing = service
	if status, b := h.request(
		"GET",
		"routing/status",
		h.read,
		nil,
		0,
		"",
	); status != 200 ||
		!strings.Contains(string(b), "inactive") {
		t.Fatal(status, string(b))
	}
	for _, path := range []string{"routing/refresh", "routing/check"} {
		if status, _ := h.request(
			"POST",
			path,
			h.read,
			map[string]any{},
			1,
			"read-op-"+path,
		); status != 403 {
			t.Fatal(status)
		}
	}
	if status, _ := h.request(
		"POST",
		"routing/check",
		h.admin,
		map[string]string{"domain": "http://127.0.0.1"},
		1,
		"bad-domain",
	); status != 400 {
		t.Fatal(status)
	}
	body := map[string]string{"domain": "example.org"}
	if status, _ := h.request(
		"POST",
		"routing/check",
		h.admin,
		body,
		0,
		"check-no-cas",
	); status != 428 {
		t.Fatal(status)
	}
	if status, _ := h.request(
		"POST",
		"routing/check",
		h.admin,
		body,
		9,
		"check-stale",
	); status != 409 {
		t.Fatal(status)
	}
	status, b := h.request("POST", "routing/check", h.admin, body, 1, "check-once")
	if status != 202 {
		t.Fatal(status, string(b))
	}
	op := decode[control.Operation](t, b)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if done, ok := h.s.Runtime.Journal.Get(op.ID); ok && done.State == "succeeded" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	status, b = h.request("POST", "routing/check", h.admin, body, 1, "check-once")
	if status != 200 || decode[control.Operation](t, b).State != "succeeded" ||
		service.calls.Load() != 1 {
		t.Fatal(status, string(b), service.calls.Load())
	}
	if strings.Contains(string(b), "example.org") {
		t.Fatal("journal retained query domain")
	}
}

func TestRoutingRefreshRejectsParametersAndKeepsFailurePrivate(t *testing.T) {
	h := setup(t)
	if status, _ := h.request(
		"POST",
		"routing/refresh",
		h.admin,
		map[string]any{},
		1,
		"refresh-unavailable",
	); status != 503 {
		t.Fatal("missing implementation claimed success", status)
	}
	service := &testRoutingService{failure: true}
	h.s.Routing = service
	if status, _ := h.request(
		"POST",
		"routing/refresh",
		h.admin,
		map[string]string{"url": "http://127.0.0.1"},
		1,
		"refresh-injection",
	); status != 400 {
		t.Fatal("arbitrary feed accepted", status)
	}
	status, b := h.request(
		"POST",
		"routing/refresh",
		h.admin,
		map[string]any{},
		1,
		"refresh-fails-once",
	)
	if status != 202 {
		t.Fatal(status, string(b))
	}
	op := decode[control.Operation](t, b)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if done, ok := h.s.Runtime.Journal.Get(op.ID); ok && done.State == "failed" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	status, b = h.request("GET", "operations/"+op.ID, h.read, nil, 0, "")
	result := decode[control.Operation](t, b)
	if status != 200 || result.State != "failed" ||
		result.ErrorCode != "routing_operation_failed" ||
		strings.Contains(string(b), "secret upstream") {
		t.Fatal(status, string(b))
	}
	if status, b := h.request(
		"POST",
		"routing/refresh",
		h.admin,
		map[string]any{},
		1,
		"refresh-fails-once",
	); status != 200 ||
		service.calls.Load() != 1 {
		t.Fatal(status, string(b), service.calls.Load())
	}
}
