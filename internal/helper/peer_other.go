//go:build !linux

package helper

import (
	"errors"
	"net"
)

func supportedPeerCredentials() error {
	return errors.New("platform_unsupported: privileged helper socket requires Linux SO_PEERCRED")
}

func peerUID(*net.UnixConn) (uint32, error) {
	return 0, supportedPeerCredentials()
}

func peerGID(*net.UnixConn) (uint32, error) {
	return 0, supportedPeerCredentials()
}
