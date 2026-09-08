package node

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const maxStateBytes = 2 << 20

func stateLock(r *os.Root, name string) (*os.File, error) {
	f, e := r.OpenFile(name, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if e != nil {
		return nil, e
	}
	if e = privateRegular(f); e != nil {
		_ = f.Close()
		return nil, e
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			return f, nil
		}
		if (!errors.Is(e, syscall.EAGAIN) && !errors.Is(e, syscall.EWOULDBLOCK)) ||
			time.Now().After(deadline) {
			_ = f.Close()
			return nil, errors.New("node state busy")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func stateUnlock(f *os.File) {
	// Closing the descriptor also releases its advisory lock.
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	_ = f.Close()
}

func openStateRoot(dir string) (*os.Root, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("node state directory must be absolute")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	before, err := os.Lstat(dir)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("node state must be a real private directory")
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	f, err := r.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		_ = r.Close()
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !os.SameFile(before, info) {
		_ = r.Close()
		return nil, errors.New("node state directory changed")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		_ = r.Close()
		return nil, errors.New("node state ownership mismatch")
	}
	if err = f.Chmod(0o700); err != nil {
		_ = r.Close()
		return nil, err
	}
	return r, nil
}

func readPrivate(r *os.Root, name string) ([]byte, error) {
	f, e := r.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	defer func() { _ = f.Close() }()
	if e = privateRegular(f); e != nil {
		return nil, e
	}
	data, e := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
	if len(data) > maxStateBytes {
		return nil, errors.New("node state exceeds byte limit")
	}
	return data, e
}

func privateRegular(f *os.File) error {
	info, e := f.Stat()
	if e != nil {
		return e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		st.Uid != uint32(os.Geteuid()) ||
		st.Nlink != 1 {
		return errors.New(
			"node state file must be privately owned, mode 0600, regular, and singly linked",
		)
	}
	return nil
}

func writePrivate(r *os.Root, name string, data []byte) error {
	if len(data) > maxStateBytes {
		return errors.New("node state exceeds byte limit")
	}
	if info, e := r.Lstat(name); e == nil && !info.Mode().IsRegular() {
		return errors.New("refusing unsafe node state destination")
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	var nonce [12]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return e
	}
	tmp := ".node-" + hex.EncodeToString(nonce[:]) + ".tmp"
	f, e := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if e != nil {
		return e
	}
	defer func() { _ = f.Close(); _ = r.Remove(tmp) }()
	if _, e = f.Write(data); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = r.Rename(tmp, name); e != nil {
		return e
	}
	d, e := r.Open(".")
	if e != nil {
		return e
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
