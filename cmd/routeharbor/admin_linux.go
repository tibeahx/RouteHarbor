//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

func runAsService(args []string) error {
	account, err := user.Lookup("routeharbor")
	if err != nil {
		return errors.New("the installed routeharbor service account is required")
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 {
		return errors.New("the routeharbor service account must have a non-root UID and GID")
	}
	// Never re-execute a path supplied by the service or the caller's PATH. The
	// installed executable and its parents must be root-owned and not writable
	// by another identity before credentials are dropped in the child process.
	const binary = "/usr/bin/routeharbor"
	for _, path := range []string{"/", "/usr", "/usr/bin", binary} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return errors.New(
				"as-service requires the trusted root-owned /usr/bin/routeharbor installation",
			)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 ||
			(path == binary && (!info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0)) ||
			(path != binary && !info.IsDir()) {
			return errors.New(
				"as-service requires the trusted root-owned /usr/bin/routeharbor installation",
			)
		}
	}
	cmd := exec.Command(binary, args...)
	cmd.Env = []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LC_ALL=C",
		"HOME=/etc/routeharbor",
		"USER=routeharbor",
		"LOGNAME=routeharbor",
	}
	cmd.Dir = "/"
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}},
	}
	if err := cmd.Run(); err != nil {
		return errors.New(
			"service-user administration failed; check the preceding error and use a private output path writable by routeharbor",
		)
	}
	return nil
}
