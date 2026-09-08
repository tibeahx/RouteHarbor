//go:build !linux

package helper

import (
	"context"
	"errors"
	"net"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
)

func dialMarked(context.Context, dataplane.Path, string) (*net.TCPConn, error) {
	return nil, errors.New("platform_unsupported")
}

func sendConn(*net.UnixConn, *net.TCPConn) error {
	return errors.New("platform_unsupported")
}

func (*Client) DialProbe(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("platform_unsupported: marked probe sockets require Linux")
}
