//go:build !linux

package helper

import (
	"context"
	"errors"
	"io"
	"os/exec"

	"github.com/tibeahx/RouteHarbor/internal/dispatch"
)

func StartDispatcherWorker(
	context.Context,
	dispatch.Spec,
	string,
	uint32,
	uint32,
) (*exec.Cmd, io.Closer, io.ReadCloser, error) {
	return nil, nil, nil, errors.New("dispatcher_requires_linux")
}

func RunDispatcherSupervisor(
	uint32,
	uint32,
) error {
	return errors.New("dispatcher_requires_linux")
}

func (s *Server) prepareDispatcherFiles(*dispatcherRegistration, uint32, uint32) error {
	return errors.New("dispatcher_requires_linux")
}
