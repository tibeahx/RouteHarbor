package helper

import (
	"strings"
	"testing"

	"github.com/tibeahx/OpenRHP/internal/maintenance"
)

func TestPrivateMaintenanceEnvelopeIsTypedAndLocalOnly(t *testing.T) {
	valid := maintenance.WireRequest{Action: "capabilities"}
	if err := validateRequest(Request{Operation: "maintenance", Maintenance: &valid}); err != nil {
		t.Fatal(err)
	}
	for _, req := range []Request{
		{Operation: "maintenance"},
		{Operation: "status", Maintenance: &valid},
		{Operation: "maintenance", Maintenance: &valid, Address: "/root/package.ipk"},
		{Operation: "maintenance", Maintenance: &valid, SourceID: "source"},
		{Operation: "maintenance", Maintenance: &valid, TransactionID: strings.Repeat("a", 32)},
		{Operation: "maintenance", Maintenance: &valid, TimeoutSeconds: 30},
		{Operation: "maintenance", Maintenance: &maintenance.WireRequest{Action: "stage"}},
		{Operation: "maintenance", Maintenance: &maintenance.WireRequest{Action: "recover"}},
		{Operation: "maintenance", Maintenance: &maintenance.WireRequest{Action: "exec"}},
		{Operation: "maintenance", Maintenance: &maintenance.WireRequest{Action: "status", ID: "../../etc/passwd"}},
		{Operation: "maintenance", Maintenance: &maintenance.WireRequest{Action: "plan", Request: &maintenance.Request{Action: "upgrade", BundleID: strings.Repeat("a", 32), Components: []string{"openrhp-guard"}}}},
	} {
		if err := validateRequest(req); err == nil {
			t.Fatalf("unsafe maintenance envelope accepted: %+v", req)
		}
	}
	for _, raw := range []string{
		`{"operation":"maintenance","maintenance":{"action":"capabilities","command":"opkg"}}`,
		`{"operation":"maintenance","maintenance":{"action":"capabilities","action":"stage"}}`,
		`{"operation":"maintenance","maintenance":{"action":"start","request":{"action":"install","source":"https://example.invalid/package.ipk"}}}`,
	} {
		var req Request
		if err := DecodeStrict([]byte(raw), &req); err == nil {
			t.Fatal("unknown or duplicate wire fields accepted")
		}
	}
}
