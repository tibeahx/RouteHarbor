package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tibeahx/RouteHarbor/internal/config"
	"github.com/tibeahx/RouteHarbor/internal/model"
)

func TestContinuityAPIAuthCASPreservesSecretsAndRejectsIdentity(t *testing.T) {
	h := setup(t)
	p := config.ContinuityDefaults()
	p.Enabled = true
	p.RelayAddress = "8.8.8.8:443"
	p.RelayFingerprint = strings.Repeat("ab", 32)
	if status, _ := h.request("GET", "continuity", "", nil, 0, ""); status != 401 {
		t.Fatal("unauthenticated continuity read", status)
	}
	if status, b := h.request(
		"GET",
		"continuity",
		h.read,
		nil,
		0,
		"",
	); status != 200 ||
		strings.TrimSpace(string(b)) != "null" {
		t.Fatal("absent continuity should be null", status, string(b))
	}
	if status, _ := h.request(
		"PUT",
		"continuity",
		h.read,
		p,
		1,
		"continuity-readonly",
	); status != 403 {
		t.Fatal("readonly continuity mutation", status)
	}
	if status, _ := h.request(
		"PUT",
		"continuity",
		h.admin,
		p,
		0,
		"continuity-no-cas",
	); status != 428 {
		t.Fatal("continuity omitted CAS", status)
	}
	if status, b := h.request(
		"PUT",
		"continuity",
		h.admin,
		p,
		1,
		"continuity-save",
	); status != 200 {
		t.Fatal(status, string(b))
	}
	if status, _ := h.request(
		"PUT",
		"continuity",
		h.admin,
		p,
		1,
		"continuity-stale",
	); status != 409 {
		t.Fatal("stale continuity write", status)
	}
	if status, b := h.request(
		"GET",
		"continuity",
		h.read,
		nil,
		0,
		"",
	); status != 200 ||
		decode[model.ContinuityConfig](t, b) != p {
		t.Fatal("public pairing round trip", status, string(b))
	}
	bad, _ := json.Marshal(p)
	bad = []byte(strings.Replace(string(bad), "{", `{"private_key":"never-log-this",`, 1))
	if status, b := h.request(
		"PUT",
		"continuity",
		h.admin,
		bad,
		2,
		"continuity-secret",
	); status != 400 ||
		strings.Contains(string(b), "never-log-this") {
		t.Fatal("identity accepted or leaked", status, string(b))
	}
	c := h.s.Runtime.Store.Get()
	c.Policy.BreakExisting = true
	if status, _ := h.request(
		"PUT",
		"policy",
		h.admin,
		c.Policy,
		2,
		"continuity-conflict",
	); status != 422 {
		t.Fatal("conflicting policy accepted", status)
	}
	if status, b := h.request(
		"PUT",
		"continuity",
		h.admin,
		[]byte("null"),
		2,
		"continuity-remove",
	); status != 200 {
		t.Fatal(status, string(b))
	}
	if h.s.Runtime.Store.Get().Continuity != nil {
		t.Fatal("null did not remove optional configuration")
	}
}

func TestContinuityAPIMutationPreservesStoredSourceCredentials(t *testing.T) {
	h := setup(t)
	c := h.s.Runtime.Store.Get()
	c.Sources = []model.Source{
		{
			ID:   "proxy",
			Name: "Private proxy",
			Type: "socks5",
			Settings: json.RawMessage(
				`{"server":"8.8.8.8","server_port":1080,"username":"owner","password":"retained-secret"}`,
			),
		},
	}
	if status, b := h.request("PUT", "config", h.admin, c, 1, "continuity-source"); status != 200 {
		t.Fatal(status, string(b))
	}
	p := config.ContinuityDefaults()
	if status, b := h.request(
		"PUT",
		"continuity",
		h.admin,
		p,
		2,
		"continuity-preserve",
	); status != 200 ||
		strings.Contains(string(b), "retained-secret") {
		t.Fatal(status, string(b))
	}
	if !strings.Contains(string(h.s.Runtime.Store.Get().Sources[0].Settings), "retained-secret") {
		t.Fatal("continuity mutation replaced source credentials")
	}
	for _, path := range []string{"config", "continuity", "status", "diagnostics"} {
		if status, b := h.request(
			"GET",
			path,
			h.read,
			nil,
			0,
			"",
		); status != 200 ||
			strings.Contains(string(b), "retained-secret") {
			t.Fatal("ordinary read leaked credential", path, status, string(b))
		}
	}
}
