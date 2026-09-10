package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func asService(args []string) error {
	if len(args) == 0 || (args[0] != "token" && args[0] != "backup") {
		return errors.New(
			"usage: routeharbor as-service token|backup [flags]; only local credential and backup administration is permitted",
		)
	}
	if os.Geteuid() != 0 {
		return errors.New(
			"as-service requires existing root administrator access; the service user can invoke token or backup directly",
		)
	}
	return runAsService(args)
}

func checkAdministrationOwner(state, command string) error {
	info, err := os.Lstat(state)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("administration state must be a private directory, not a symbolic link")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 && stat.Uid != 0 {
		return fmt.Errorf(
			"service-owned state must be administered without root file access; use routeharbor as-service %s with the same flags and a new output file under /etc/routeharbor/admin",
			command,
		)
	}
	return nil
}
