package node

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
)

type Agent struct {
	Identity     Identity
	Pairing      *Pairing
	Capabilities func(context.Context) Capabilities
	Operator     Operator
}

func (a *Agent) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{a.Identity.Certificate},
		ClientAuth:             tls.RequireAnyClientCert,
		SessionTicketsDisabled: true,
	}
}

func (a *Agent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	reject := func(code int, reason string) {
		w.WriteHeader(code)
		if json.NewEncoder(w).Encode(map[string]string{"error": reason}) != nil {
			return
		}
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
		reject(401, "peer_certificate_required")
		return
	}
	cert := r.TLS.PeerCertificates[0]
	if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
		reject(401, "peer_certificate_expired")
		return
	}
	pin := fingerprint(cert)
	if r.URL.RawQuery != "" || r.Header.Get("Origin") != "" {
		reject(403, "browser_or_query_request_rejected")
		return
	}
	if r.URL.Path == "/node/v1/pair" && r.Method == http.MethodPost {
		var request struct {
			Code string `json:"code"`
		}
		if e := nodeDecode(r, &request); e != nil {
			reject(400, "invalid_request")
			return
		}
		if e := a.Pairing.Enroll(request.Code, pin); e != nil {
			reject(403, "enrollment_rejected")
			return
		}
		if json.NewEncoder(w).
			Encode(map[string]any{"id": a.Identity.ID, "fingerprint": a.Identity.Fingerprint, "capabilities": a.Capabilities(r.Context())}) !=
			nil {
			return
		}
		return
	}
	if !a.Pairing.Authorized(pin) {
		reject(403, "unpaired_peer")
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/node/v1/capabilities":
		if json.NewEncoder(w).
			Encode(map[string]any{"id": a.Identity.ID, "capabilities": a.Capabilities(r.Context())}) !=
			nil {
			return
		}
	case r.Method == http.MethodPost && r.URL.Path == "/node/v1/unpair":
		if e := a.Pairing.Revoke(pin); e != nil {
			reject(403, "revocation_rejected")
			return
		}
		if json.NewEncoder(w).Encode(map[string]bool{"revoked": true}) != nil {
			return
		}
	case r.Method == http.MethodGet && r.URL.Path == "/node/v1/status":
		if a.Operator == nil {
			if json.NewEncoder(w).
				Encode(map[string]any{"id": a.Identity.ID, "transaction": nil, "helper_available": false}) !=
				nil {
				return
			}
			return
		}
		result, e := a.Operator.Do(r.Context(), Operation{Action: "status"})
		if e != nil {
			reject(503, "node_helper_unavailable")
			return
		}
		result["id"] = a.Identity.ID
		result["capabilities"] = a.Capabilities(r.Context())
		if link, linkErr := a.Operator.Do(r.Context(), Operation{Action: "link"}); linkErr == nil {
			result["node_link"] = link["node_link"]
		}
		if inspected, inspectErr := a.Operator.Do(
			r.Context(),
			Operation{Action: "inspect"},
		); inspectErr == nil {
			result["setup"] = inspected["setup"]
		} else {
			result["setup_issue"] = "Node setup discovery is unavailable; check the local helper and trusted administrator access"
		}
		if json.NewEncoder(w).Encode(result) != nil {
			return
		}
	case r.Method == http.MethodPost && r.URL.Path == "/node/v1/operations":
		var operation Operation
		if e := nodeDecode(r, &operation); e != nil {
			reject(400, "invalid_operation")
			return
		}
		if a.Operator == nil {
			reject(503, "node_helper_unavailable")
			return
		}
		result, e := a.Operator.Do(r.Context(), operation)
		if e != nil {
			reject(422, "node_operation_rejected")
			return
		}
		if json.NewEncoder(w).Encode(result) != nil {
			return
		}
	default:
		reject(404, "not_found")
	}
}

func nodeDecode(r *http.Request, v any) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return errors.New("JSON content type required")
	}
	data, e := io.ReadAll(io.LimitReader(r.Body, 64<<10+1))
	if e != nil || len(data) > 64<<10 {
		return errors.New("request exceeds limit")
	}
	return adapter.StrictDecode(data, v)
}
