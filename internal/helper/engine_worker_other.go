//go:build !linux

package helper

import (
	"context"
	"errors"
	"io"
	"os/exec"
)

func StartEngineWorker(
	context.Context,
	EngineRequest,
	uint32,
	uint32,
) (*exec.Cmd, io.Closer, error) {
	return nil, nil, errors.New("capability_unavailable: managed engines require Linux")
}

func RunEngineWorker(uint32, uint32) error {
	return errors.New("capability_unavailable: managed engines require Linux")
}
