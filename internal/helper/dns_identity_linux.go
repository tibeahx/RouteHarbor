//go:build linux

package helper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tibeahx/OpenRHP/internal/platform"
)

const dnsBinary = "/usr/sbin/dnsmasq"

var (
	dnsConfigName  = regexp.MustCompile(`^/var/etc/dnsmasq\.conf\.(cfg[a-fA-F0-9]{6})$`)
	errDNSIdentity = errors.New(
		"dns_guard_unavailable: require a trusted dedicated non-root dnsmasq service with randomized upstream sockets and no custom source binding",
	)
)

func trustedDNSDirectory(path string) (*os.Root, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errDNSIdentity
	}
	// Check every original and resolved component. Root-owned /var -> /tmp is
	// normal OpenWrt layout; a user-owned alias into a trusted directory is not.
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, errDNSIdentity
	}
	for _, candidate := range []string{path, resolved} {
		for dir := candidate; ; dir = filepath.Dir(dir) {
			info, err := os.Lstat(dir)
			if err != nil {
				return nil, errDNSIdentity
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || st.Uid != 0 {
				return nil, errDNSIdentity
			}
			if info.Mode()&os.ModeSymlink == 0 {
				if !info.IsDir() ||
					info.Mode().Perm()&0o022 != 0 &&
						(dir != "/tmp" || info.Mode()&os.ModeSticky == 0) {
					return nil, errDNSIdentity
				}
			}
			if dir == "/" {
				break
			}
		}
	}
	root, err := os.OpenRoot(resolved)
	if err != nil {
		return nil, errDNSIdentity
	}
	return root, nil
}

func trustedDNSFile(path string, limit int64) ([]byte, error) {
	root, err := trustedDNSDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	name := filepath.Base(path)
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() {
		return nil, errDNSIdentity
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || before.Mode().Perm()&0o022 != 0 {
		return nil, errDNSIdentity
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, errDNSIdentity
	}
	defer func() { _ = file.Close() }()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errDNSIdentity
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errDNSIdentity
	}
	return data, nil
}

func dnsAccount(data []byte) (uint32, uint32, error) {
	var uid, gid uint64
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 || fields[0] != "dnsmasq" {
			continue
		}
		count++
		var err error
		uid, err = strconv.ParseUint(fields[2], 10, 31)
		if err != nil {
			return 0, 0, errDNSIdentity
		}
		gid, err = strconv.ParseUint(fields[3], 10, 31)
		if err != nil {
			return 0, 0, errDNSIdentity
		}
	}
	if count != 1 || uid == 0 || gid == 0 {
		return 0, 0, errDNSIdentity
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 7 && fields[0] != "dnsmasq" {
			other, err := strconv.ParseUint(fields[2], 10, 32)
			if err != nil || other == uid {
				return 0, 0, errDNSIdentity
			}
		}
	}
	return uint32(uid), uint32(gid), nil
}

// Configuration is inspected privately; no values or paths appear in failures.
// Fixed query/source ports are allocated while dnsmasq is still root in 2.90.
func checkDNSConfig(path string, seen map[string]bool) error {
	if seen[path] {
		return nil
	}
	if len(seen) >= 64 {
		return errDNSIdentity
	}
	seen[path] = true
	data, err := trustedDNSFile(path, 256<<10)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		// dnsmasq2.90 uses fgets(MAXDNAME=1025): a long physical comment can
		// otherwise turn into a second executable option in the next buffer read.
		if len(line) > 1023 {
			return errDNSIdentity
		}
		for index, value := range []byte(line) {
			if value == 127 ||
				value < 32 && value != '\t' && (value != '\r' || index != len(line)-1) {
				return errDNSIdentity
			}
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, _ := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if strings.HasPrefix(key, "-") || strings.ContainsAny(key, "\"'\\") ||
			strings.ContainsAny(value, "\"'\\") {
			return errDNSIdentity
		}
		switch key {
		case "user", "group":
			if value != "dnsmasq" {
				return errDNSIdentity
			}
		case "query-port":
			return errDNSIdentity
		case "conf-script", "servers-file":
			return errDNSIdentity
		case "server", "rev-server":
			if strings.Contains(value, "@") {
				return errDNSIdentity
			}
			if _, port, ok := strings.Cut(value, "#"); ok && port != "53" {
				return errDNSIdentity
			}
		case "conf-file":
			if !filepath.IsAbs(value) || strings.Contains(value, ",") {
				return errDNSIdentity
			}
			if err := checkDNSConfig(value, seen); err != nil {
				return err
			}
		case "conf-dir":
			if !filepath.IsAbs(value) || strings.Contains(value, ",") {
				return errDNSIdentity
			}
			directory, err := trustedDNSDirectory(value)
			if err != nil {
				return err
			}
			info, err := directory.Stat(".")
			if err != nil || info.Mode().Perm()&0o022 != 0 {
				_ = directory.Close()
				return errDNSIdentity
			}
			file, err := directory.Open(".")
			if err != nil {
				_ = directory.Close()
				return errDNSIdentity
			}
			entries, readErr := file.ReadDir(65)
			_ = file.Close()
			_ = directory.Close()
			if readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) > 64 {
				return errDNSIdentity
			}
			for _, entry := range entries {
				if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
					return errDNSIdentity
				}
				if err := checkDNSConfig(filepath.Join(value, entry.Name()), seen); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func inspectDNSIdentity(ctx context.Context) (DNSGuardIdentity, error) {
	var identity DNSGuardIdentity
	if os.Geteuid() != 0 {
		return identity, errDNSIdentity
	}
	passwd, err := trustedDNSFile("/etc/passwd", 256<<10)
	if err != nil {
		return identity, err
	}
	identity.UID, identity.GID, err = dnsAccount(passwd)
	if err != nil {
		return identity, err
	}
	for path, dst := range map[string]*string{dnsBinary: &identity.BinarySHA256, "/etc/init.d/dnsmasq": &identity.InitSHA256} {
		data, e := trustedDNSFile(path, 4<<20)
		if e != nil {
			return identity, e
		}
		sum := sha256.Sum256(data)
		*dst = hex.EncodeToString(sum[:])
	}
	versionCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	cmd := exec.CommandContext(versionCtx, dnsBinary, "--version")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	var version cappedPacketOutput
	cmd.Stdout = &version
	cmd.Stderr = &version
	err = cmd.Run()
	cancel()
	if err != nil || !strings.HasPrefix(version.String(), "Dnsmasq version 2.90  ") {
		return identity, errDNSIdentity
	}
	raw, err := (platform.ProductionRunner{}).Run(
		ctx,
		platform.UBusBinary(),
		[]string{"call", "service", "list", `{"name":"dnsmasq"}`},
		nil,
	)
	if err != nil {
		return identity, errDNSIdentity
	}
	var service map[string]struct {
		Instances map[string]struct {
			Running bool     `json:"running"`
			PID     int      `json:"pid"`
			Command []string `json:"command"`
		} `json:"instances"`
	}
	if json.Unmarshal(raw, &service) != nil || len(service["dnsmasq"].Instances) == 0 ||
		len(service["dnsmasq"].Instances) > 8 {
		return identity, errDNSIdentity
	}
	parents := map[int]bool{}
	for _, instance := range service["dnsmasq"].Instances {
		c := instance.Command
		if !instance.Running || instance.PID < 1 || len(c) != 6 || c[0] != dnsBinary ||
			c[1] != "-C" ||
			c[3] != "-k" ||
			c[4] != "-x" {
			return identity, errDNSIdentity
		}
		match := dnsConfigName.FindStringSubmatch(c[2])
		if len(match) != 2 || c[5] != "/var/run/dnsmasq/dnsmasq."+match[1]+".pid" {
			return identity, errDNSIdentity
		}
		if err := checkDNSConfig(c[2], map[string]bool{}); err != nil {
			return identity, err
		}
		parents[instance.PID] = true
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return identity, errDNSIdentity
	}
	if len(entries) > 8192 {
		return identity, errDNSIdentity
	}
	found := 0
	for _, entry := range entries {
		pid, e := strconv.Atoi(entry.Name())
		if e != nil || pid < 1 {
			continue
		}
		path := fmt.Sprintf("/proc/%d", pid)
		data, e := os.ReadFile(path + "/status")
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return identity, errDNSIdentity
		}
		uid, gid, ppid, e := dnsProcessStatus(data)
		if e != nil {
			return identity, e
		}
		exe, _ := os.Readlink(path + "/exe")
		if exe != dnsBinary && uid != identity.UID {
			continue
		}
		if exe != dnsBinary || uid != identity.UID || gid != identity.GID {
			return identity, errDNSIdentity
		}
		parent := pid
		for depth := 0; !parents[parent] && depth < 8; depth++ {
			if parent == pid {
				parent = ppid
				continue
			}
			status, e := os.ReadFile(fmt.Sprintf("/proc/%d/status", parent))
			if e != nil {
				return identity, errDNSIdentity
			}
			_, _, parent, e = dnsProcessStatus(status)
			if e != nil {
				return identity, e
			}
		}
		if !parents[parent] {
			return identity, errDNSIdentity
		}
		if err := checkDNSSocketUID(path, identity.UID); err != nil {
			return identity, err
		}
		found++
	}
	if found == 0 {
		return identity, errDNSIdentity
	}
	return identity, nil
}

func dnsProcessStatus(data []byte) (uint32, uint32, int, error) {
	var uid, gid uint32
	var ppid int
	seen := 0
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "Uid:" || fields[0] == "Gid:" {
			if len(fields) != 5 {
				return 0, 0, 0, errDNSIdentity
			}
			value, err := strconv.ParseUint(fields[1], 10, 32)
			if err != nil {
				return 0, 0, 0, errDNSIdentity
			}
			for _, item := range fields[2:] {
				if item != fields[1] {
					return 0, 0, 0, errDNSIdentity
				}
			}
			if fields[0] == "Uid:" {
				uid = uint32(value)
			} else {
				gid = uint32(value)
			}
			seen++
		}
		if fields[0] == "PPid:" {
			if len(fields) != 2 {
				return 0, 0, 0, errDNSIdentity
			}
			var err error
			ppid, err = strconv.Atoi(fields[1])
			if err != nil {
				return 0, 0, 0, errDNSIdentity
			}
			seen++
		}
	}
	if seen != 3 {
		return 0, 0, 0, errDNSIdentity
	}
	return uid, gid, ppid, nil
}

// Listening DNS/DHCP sockets can be opened before the privilege drop. Every
// upstream socket must be owned by the dedicated account; an idle service has
// no upstream sockets, so this check complements the audited 2.90 launch profile.
func checkDNSSocketUID(process string, uid uint32) error {
	entries, err := os.ReadDir(process + "/fd")
	if err != nil || len(entries) > 4096 {
		return errDNSIdentity
	}
	sockets := map[string]bool{}
	for _, entry := range entries {
		target, e := os.Readlink(process + "/fd/" + entry.Name())
		if e != nil {
			continue
		}
		if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			sockets[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
		}
	}
	for _, table := range []string{"udp", "udp6", "tcp", "tcp6"} {
		data, err := os.ReadFile(process + "/net/" + table)
		if err != nil || len(data) > 2<<20 {
			return errDNSIdentity
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 10 || !sockets[fields[9]] {
				continue
			}
			_, local, ok := strings.Cut(fields[1], ":")
			if !ok {
				return errDNSIdentity
			}
			_, remote, ok := strings.Cut(fields[2], ":")
			if !ok {
				return errDNSIdentity
			}
			if local == "0035" || local == "0043" || local == "0223" {
				continue
			}
			if strings.HasPrefix(table, "tcp") && remote != "0035" {
				continue
			}
			actual, err := strconv.ParseUint(fields[7], 10, 32)
			if err != nil || actual != uint64(uid) {
				return errDNSIdentity
			}
		}
	}
	return nil
}
