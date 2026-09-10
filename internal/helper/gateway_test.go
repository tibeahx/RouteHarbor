package helper

import (
	"strings"
	"testing"

	"github.com/tibeahx/RouteHarbor/internal/coverage"
)

func TestPrivateGatewayEnvelopeRejectsMixedOperations(t *testing.T) {
	good := coverage.Operation{Action: "inspect"}
	if err := validateRequest(Request{Operation: "gateway", Gateway: &good}); err != nil {
		t.Fatal(err)
	}
	for _, req := range []Request{
		{Operation: "status", Gateway: &good},
		{Operation: "gateway", Gateway: &good, SourceID: "source"},
		{Operation: "gateway", Gateway: &good, TransactionID: strings.Repeat("a", 32)},
		{Operation: "gateway"},
		{Operation: "gateway", Gateway: &coverage.Operation{Action: "exec"}},
		{Operation: "gateway", Gateway: &coverage.Operation{Action: "inspect", Key: "extra"}},
		{Operation: "gateway", Gateway: &coverage.Operation{Action: "prepare", Key: "$(command)"}},
		{Operation: "gateway", Gateway: &coverage.Operation{Action: "apply", ID: strings.Repeat("a", 32), TimeoutSeconds: 181}},
	} {
		if err := validateRequest(req); err == nil {
			t.Fatalf("unsafe request accepted: %+v", req)
		}
	}
}
