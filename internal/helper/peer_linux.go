//go:build linux

package helper

import (
	"net"
	"syscall"
)

func supportedPeerCredentials() error {
	return nil
}

func peerUID(c *net.UnixConn) (uint32, error) {
	raw, e := c.SyscallConn()
	if e != nil {
		return 0, e
	}
	var uid uint32
	var inner error
	e = raw.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		inner = err
		if err == nil {
			uid = cred.Uid
		}
	})
	if e != nil {
		return 0, e
	}
	return uid, inner
}

func peerGID(c *net.UnixConn) (uint32, error) {
	raw, e := c.SyscallConn()
	if e != nil {
		return 0, e
	}
	var gid uint32
	var inner error
	e = raw.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		inner = err
		if err == nil {
			gid = cred.Gid
		}
	})
	if e != nil {
		return 0, e
	}
	return gid, inner
}
