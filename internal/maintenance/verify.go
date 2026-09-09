package maintenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func criticalPayload(name string) bool {
	switch name {
	case "usr/bin/openrhp",
		"usr/libexec/openrhp-setup",
		"etc/init.d/openrhp",
		"usr/bin/sing-box",
		"usr/bin/xray",
		"usr/sbin/conntrack":
		return true
	}
	return false
}

func configurationPayload(name string, conffiles []string) bool {
	if criticalPayload(name) {
		return false
	}
	for _, entry := range conffiles {
		if name == entry || strings.HasPrefix(name, entry+"/") {
			return true
		}
	}
	return false
}

func verifyPayload(root *os.Root, packages []PackagePayload, removed bool) error {
	for _, p := range packages {
		for _, expected := range p.Files {
			name, err := archivePath(expected.Path)
			if err != nil || name == "" || name != expected.Path {
				return errors.New("maintenance_payload_metadata_invalid")
			}
			if configurationPayload(name, p.Conffiles) {
				continue
			}
			info, err := root.Lstat(name)
			if removed {
				// Shared directories are retained by the package manager.
				if expected.Type == "dir" {
					continue
				}
				if !errors.Is(err, os.ErrNotExist) {
					return errors.New("maintenance_removed_payload_present")
				}
				continue
			}
			if err != nil {
				return errors.New("maintenance_installed_payload_missing")
			}
			owner, ok := info.Sys().(*syscall.Stat_t)
			if !ok || owner.Uid != uint32(os.Geteuid()) {
				return errors.New("maintenance_installed_payload_owner")
			}
			switch expected.Type {
			case "dir":
				if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
					return errors.New("maintenance_installed_payload_type")
				}
			case "symlink":
				target, err := root.Readlink(name)
				if err != nil || target != expected.Target {
					return errors.New("maintenance_installed_link_mismatch")
				}
			case "hardlink":
				target, err := root.Lstat(filepath.Clean(expected.Target))
				if err != nil || !info.Mode().IsRegular() || !os.SameFile(info, target) {
					return errors.New("maintenance_installed_link_mismatch")
				}
			case "file":
				if !info.Mode().IsRegular() ||
					info.Mode().Perm() != os.FileMode(expected.Mode)&0o777 ||
					info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 ||
					info.Size() != expected.Bytes ||
					!hashID.MatchString(expected.SHA256) {
					return errors.New("maintenance_installed_payload_mismatch")
				}
				f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
				if err != nil {
					return errors.New("maintenance_installed_payload_unreadable")
				}
				after, err := f.Stat()
				if err != nil || !os.SameFile(info, after) {
					_ = f.Close()
					return errors.New("maintenance_installed_payload_changed")
				}
				hash := sha256.New()
				count, err := io.Copy(hash, io.LimitReader(f, expected.Bytes+1))
				closeErr := f.Close()
				if err != nil || closeErr != nil || count != expected.Bytes ||
					hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
					return errors.New("maintenance_installed_payload_hash_mismatch")
				}
			default:
				return errors.New("maintenance_payload_metadata_invalid")
			}
		}
	}
	return nil
}

func (b *OpkgBackend) Verify(ctx context.Context, plan Plan, packages []PackagePayload) error {
	inventory, err := b.Inventory(ctx)
	if err != nil {
		return err
	}
	if inventory.Packages["openrhp-guard"] == "" {
		return errors.New("maintenance_guard_missing")
	}
	for _, p := range plan.Packages {
		if plan.Request.Action == "remove" {
			if inventory.Packages[p.Name] != "" {
				return errors.New("maintenance_removed_package_present")
			}
		} else if inventory.Packages[p.Name] != p.Version {
			return errors.New("maintenance_installed_version_mismatch")
		}
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return verifyPayload(root, packages, plan.Request.Action == "remove")
}
