//go:build !linux && !darwin

package helper

import (
	"errors"
	"os"
)

func copyDispatcherOwnership(*os.File, os.FileInfo) error {
	return errors.New("dispatcher_requires_unix")
}
