//go:build linux || darwin

package helper

import (
	"errors"
	"os"
	"syscall"
)

// The production helper runs as root. Unit tests may exercise atomic files in
// a private directory owned by their own unprivileged test identity.
func copyDispatcherOwnership(f *os.File, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("dispatcher_rules_untrusted")
	}
	if err := f.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
		return err
	}
	return f.Chmod(0o640)
}
