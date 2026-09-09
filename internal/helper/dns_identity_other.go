//go:build !linux

package helper

import (
	"context"
	"errors"
)

func inspectDNSIdentity(context.Context) (DNSGuardIdentity, error) {
	return DNSGuardIdentity{}, errors.New(
		"dns_guard_unavailable: dedicated DNS socket ownership requires OpenWrt Linux",
	)
}
