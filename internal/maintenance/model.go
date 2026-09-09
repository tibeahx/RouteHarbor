// Package maintenance manages verified local package sets and durable offline jobs.
package maintenance

import "context"

type Request struct {
	Action                  string   `json:"action"`
	BundleID                string   `json:"bundle_id,omitempty"`
	Components              []string `json:"components"`
	ExpectedInstalledDigest string   `json:"expected_installed_digest"`
	RemovalPolicy           string   `json:"removal_policy,omitempty"`
}

type Package struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	SHA256       string `json:"sha256"`
	Bytes        int64  `json:"bytes"`
}

type BundleSummary struct {
	ID           string    `json:"id"`
	Version      string    `json:"version"`
	Commit       string    `json:"commit"`
	Architecture string    `json:"architecture"`
	Packages     []Package `json:"packages"`
}

type Plan struct {
	Request         Request   `json:"request"`
	Digest          string    `json:"digest"`
	InstalledDigest string    `json:"installed_digest"`
	Packages        []Package `json:"packages"`
	Warnings        []string  `json:"warnings"`
}

type Operation struct {
	ID            string   `json:"id"`
	State         string   `json:"state"`
	Phase         string   `json:"phase"`
	Action        string   `json:"action"`
	Components    []string `json:"components"`
	CreatedAt     string   `json:"created_at"`
	UpdatedAt     string   `json:"updated_at"`
	ErrorCode     string   `json:"error_code,omitempty"`
	Retryable     bool     `json:"retryable"`
	GuardRetained bool     `json:"guard_retained"`
}

type Service interface {
	Capabilities(context.Context) (map[string]any, error)
	Bundles(context.Context) ([]BundleSummary, error)
	Plan(context.Context, Request) (Plan, error)
	Start(context.Context, string, Request) (Operation, error)
	Status(context.Context, string) (Operation, error)
}

// WireRequest is private helper transport. No caller-controlled paths or commands.
type WireRequest struct {
	Action  string   `json:"action"`
	ID      string   `json:"id,omitempty"`
	Request *Request `json:"request,omitempty"`
}

type WireResponse struct {
	Capabilities map[string]any  `json:"capabilities,omitempty"`
	Bundles      []BundleSummary `json:"bundles,omitempty"`
	Plan         *Plan           `json:"plan,omitempty"`
	Operation    *Operation      `json:"operation,omitempty"`
}

// PayloadFile is derived from authenticated package bytes, never from an API body.
type PayloadFile struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Mode   uint32 `json:"mode"`
	Bytes  int64  `json:"bytes,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Target string `json:"target,omitempty"`
}

type PackagePayload struct {
	Package   Package       `json:"package"`
	Files     []PayloadFile `json:"files"`
	Conffiles []string      `json:"conffiles"`
}
