//go:build !linux

package continuityrun

import (
	"errors"
	"net/netip"
)

func originalDestination([]byte) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("transparent UDP requires Linux")
}
