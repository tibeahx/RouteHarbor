//go:build linux

package platform

import "syscall"

func freeSpace(path string) uint64 {
	var s syscall.Statfs_t
	if syscall.Statfs(path, &s) != nil {
		return 0
	}
	return uint64(s.Bavail) * uint64(s.Bsize)
}
