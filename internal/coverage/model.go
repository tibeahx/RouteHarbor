// Package coverage owns gateway-only Wi-Fi backhaul transactions. It never
// changes routing, addresses, DHCP, NAT, firewall state, or the node's uplink.
package coverage

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/platform"
)

type Plan struct {
	Mode                   string `json:"mode"`
	APSection              string `json:"ap_section"`
	Network                string `json:"network"`
	PeerFingerprint        string `json:"peer_fingerprint"`
	AdoptExistingAP        bool   `json:"adopt_existing_ap"`
	PreserveManagementPath bool   `json:"preserve_management_path"`
}

type Operation struct {
	Action         string `json:"action"`
	Key            string `json:"key,omitempty"`
	ID             string `json:"id,omitempty"`
	Plan           *Plan  `json:"plan,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

type Operator interface {
	Do(context.Context, Operation) (map[string]any, error)
}

type Transaction struct {
	ID        string    `json:"id"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	Deadline  time.Time `json:"deadline"`
	Plan      Plan      `json:"plan"`
	ErrorCode string    `json:"error_code,omitempty"`
}

// WiFi is private material carried only over the authenticated local helper
// transport and pinned gateway-to-node TLS. Public API responses must omit it.
type WiFi struct {
	SSID       string `json:"ssid"`
	Passphrase string `json:"passphrase"`
	Channel    int    `json:"channel"`
}

type AccessPoint struct {
	Section        string   `json:"section"`
	Network        string   `json:"network"`
	Radio          string   `json:"radio"`
	SSID           string   `json:"ssid"`
	Channel        int      `json:"channel"`
	Encryption     string   `json:"encryption"`
	CandidateModes []string `json:"candidate_modes"`
	Reason         string   `json:"reason"`
}

type Setup struct {
	Managed    bool          `json:"managed"`
	ObservedAt time.Time     `json:"observed_at"`
	APs        []AccessPoint `json:"aps"`
	Reason     string        `json:"reason"`
}

var fingerprint = regexp.MustCompile(`^[a-f0-9]{64}$`)

var (
	transactionID = regexp.MustCompile(`^[a-f0-9]{32}$`)
	requestKey    = regexp.MustCompile(`^[a-zA-Z0-9_.-]{16,128}$`)
)

func ValidateOperation(o Operation) error {
	if o.Action == "inspect" || o.Action == "status" {
		if o.ID != "" || o.Key != "" || o.Plan != nil || o.TimeoutSeconds != 0 {
			return errors.New("gateway_operation_fields_invalid")
		}
		return nil
	}
	if o.Action == "prepare" || (o.Action == "validate" && o.Plan != nil) {
		if o.Plan == nil || o.ID != "" || o.TimeoutSeconds != 0 {
			return errors.New("gateway_operation_fields_invalid")
		}
		if o.Action == "prepare" && !requestKey.MatchString(o.Key) {
			return errors.New("gateway_idempotency_key_required")
		}
		if o.Action == "validate" && o.Key != "" {
			return errors.New("gateway_operation_fields_invalid")
		}
		return ValidatePlan(*o.Plan)
	}
	if !transactionID.MatchString(o.ID) || o.Key != "" || o.Plan != nil {
		return errors.New("gateway_operation_identity_invalid")
	}
	switch o.Action {
	case "apply":
		if o.TimeoutSeconds < 30 || o.TimeoutSeconds > 180 {
			return errors.New("gateway_confirmation_window_invalid")
		}
	case "validate", "confirm", "rollback", "finalize":
		if o.TimeoutSeconds != 0 {
			return errors.New("gateway_operation_fields_invalid")
		}
	default:
		return errors.New("unsupported_gateway_operation")
	}
	return nil
}

func ValidatePlan(p Plan) error {
	if p.Mode != "wds" && p.Mode != "mesh" {
		return errors.New("gateway_backhaul_mode_invalid")
	}
	if !platform.ValidInterfaceName(p.APSection) || !platform.ValidInterfaceName(p.Network) ||
		p.Network == "wan" ||
		p.Network == "wan6" ||
		p.Network == "loopback" {
		return errors.New("gateway_backhaul_scope_invalid")
	}
	if !fingerprint.MatchString(p.PeerFingerprint) {
		return errors.New("gateway_paired_peer_required")
	}
	if !p.AdoptExistingAP || !p.PreserveManagementPath {
		return errors.New("gateway_explicit_ap_adoption_and_management_path_required")
	}
	return nil
}
