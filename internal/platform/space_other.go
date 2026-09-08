//go:build !linux

package platform

func freeSpace(string) uint64 {
	return 0
}
