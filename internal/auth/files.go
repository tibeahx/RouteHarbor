package auth

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func (s *Store) lockDisk() (*os.File, error) {
	path := filepath.Join(s.dir, ".credentials.lock")
	fd, e := syscall.Open(
		path,
		syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC,
		0o600,
	)
	if e != nil {
		return nil, errors.New("cannot open credential lock safely")
	}
	f := os.NewFile(uintptr(fd), path)
	if e = s.checkPrivate(f); e != nil {
		_ = f.Close()
		return nil, e
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			return f, nil
		}
		if e != syscall.EWOULDBLOCK && e != syscall.EAGAIN {
			_ = f.Close()
			return nil, errors.New("cannot acquire credential lock")
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, errors.New("credential store busy")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func unlockDisk(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	_ = f.Close()
}

func (s *Store) checkPrivate(f *os.File) error {
	info, e := f.Stat()
	if e != nil {
		return errors.New("cannot inspect credential file")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || st.Nlink != 1 ||
		st.Uid != uint32(os.Geteuid()) {
		return errors.New("credential files must be privately owned regular files with one link")
	}
	return nil
}

func (s *Store) openCredentials() (*os.File, error) {
	path := filepath.Join(s.dir, "credentials.json")
	fd, e := syscall.Open(
		path,
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC,
		0,
	)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	if e = s.checkPrivate(f); e != nil {
		_ = f.Close()
		return nil, e
	}
	return f, nil
}
