//go:build !linux

package main

import "errors"

func runAsService([]string) error {
	return errors.New(
		"as-service is available only for the installed Linux/OpenWrt service; invoke token or backup as the state owner on development systems",
	)
}
