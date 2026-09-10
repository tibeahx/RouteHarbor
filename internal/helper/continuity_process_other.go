//go:build !linux

package helper

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os/exec"
)

func startContinuityProcess(
	context.Context,
	ContinuityWorkerRequest,
	uint32,
	uint32,
) (*exec.Cmd, io.Closer, io.WriteCloser, *bufio.Reader, error) {
	return nil, nil, nil, nil, errors.New("platform_unsupported")
}
func RunContinuitySupervisor(uint32, uint32) error { return errors.New("platform_unsupported") }
func (*Client) DialContinuity(context.Context, string) (net.Conn, error) {
	return nil, errors.New("platform_unsupported")
}

func (*Client) ContinuityUDPReply(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("platform_unsupported")
}

func (s *Server) continuityUDPReply(
	context.Context,
	*net.UnixConn,
	*continuityRegistration,
	ContinuityRequest,
) {
}
