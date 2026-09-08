package helper

import (
	"context"
	"errors"

	"github.com/tibeahx/OpenRHP/internal/coverage"
)

// GatewayWatchdog uses the same trusted detached process boundary with a separate
// command and durable state directory. Routing and Wi-Fi journals never mix.
type GatewayWatchdog struct{ Binary, StateDir string }

func (w GatewayWatchdog) Arm(id string) error {
	return ProcessWatchdog(w).arm(id, "gateway-watchdog")
}

// Do is a private helper transport. Its node_wifi result contains credentials and
// is consumed only by the paired coordinator; it must never be an ordinary API result.
func (c *Client) Do(ctx context.Context, operation coverage.Operation) (map[string]any, error) {
	response, err := c.call(ctx, Request{Operation: "gateway", Gateway: &operation})
	if err != nil {
		return nil, err
	}
	if response.Gateway == nil {
		return nil, errors.New("invalid_helper_response")
	}
	return response.Gateway, nil
}

func validateGatewayOperation(o coverage.Operation) error {
	return coverage.ValidateOperation(o)
}
