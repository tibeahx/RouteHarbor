//go:build linux || darwin

package helper

import (
	"errors"
	"os"
	"syscall"
)

func ownedByCurrentUID(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid())
}

func openPrivate(path string, flags int, mode os.FileMode) (*os.File, error) {
	fd, err := syscall.Open(path, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, uint32(mode))
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	i, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !i.Mode().IsRegular() || i.Mode().Perm()&0o077 != 0 || !ownedByCurrentUID(i) {
		_ = f.Close()
		return nil, errors.New("helper state must be a private regular file owned by the helper")
	}
	return f, nil
}

func lockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

func unlockFile(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
