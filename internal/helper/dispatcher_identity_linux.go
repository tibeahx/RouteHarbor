//go:build linux

package helper

import (
	"context"
	"time"

	"github.com/tibeahx/OpenRHP/internal/platform"
)

func dispatcherWANIdentity(ctx context.Context, iface string) (string, error) {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return inspectDispatcherWANIdentity(bounded, platform.ProductionRunner{}, iface)
}
