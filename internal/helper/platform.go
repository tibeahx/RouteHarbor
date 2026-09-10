package helper

import (
	"context"
	"errors"

	"github.com/tibeahx/RouteHarbor/internal/platform"
)

// Platform reads the root helper's bounded, nonsecret OpenWrt capability report.
// The unprivileged API does not receive general ubus or firewall permissions.
func (c *Client) Platform(ctx context.Context) (platform.Report, error) {
	response, err := c.call(ctx, Request{Operation: "platform"})
	if err != nil {
		return platform.Report{}, err
	}
	if response.Platform == nil {
		return platform.Report{}, errors.New("invalid_helper_response")
	}
	return *response.Platform, nil
}
