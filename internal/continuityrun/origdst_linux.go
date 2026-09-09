//go:build linux

package continuityrun

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"syscall"
)

func originalDestination(oob []byte) (netip.AddrPort, error) {
	messages, e := syscall.ParseSocketControlMessage(oob)
	if e != nil {
		return netip.AddrPort{}, e
	}
	for _, m := range messages {
		if m.Header.Level == syscall.SOL_IP && m.Header.Type == 20 && len(m.Data) >= 16 {
			var a [4]byte
			copy(a[:], m.Data[4:8])
			return netip.AddrPortFrom(netip.AddrFrom4(a), binary.BigEndian.Uint16(m.Data[2:4])), nil
		}
		if m.Header.Level == syscall.SOL_IPV6 && m.Header.Type == 74 && len(m.Data) >= 28 {
			var a [16]byte
			copy(a[:], m.Data[8:24])
			return netip.AddrPortFrom(
				netip.AddrFrom16(a),
				binary.BigEndian.Uint16(m.Data[2:4]),
			), nil
		}
	}
	return netip.AddrPort{}, errors.New("missing original destination")
}
