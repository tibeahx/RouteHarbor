//go:build !linux

package helper

import (
	"context"
	"errors"
)

func dispatcherWANIdentity(context.Context, string) (string, error) {
	return "", errors.New("wan_identity_unavailable")
}
