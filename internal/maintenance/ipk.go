package maintenance

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"
)

const (
	maxControlBytes  = 1 << 20
	maxExpandedBytes = 256 << 20
)

var (
	packageName         = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,79}$`)
	packageArchitecture = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_+.-]{0,63}$`)
	packageVersion      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127}$`)
	hexID               = regexp.MustCompile(`^[a-f0-9]{32}$`)
	hashID              = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type packageMetadata struct {
	Files     []PayloadFile `json:"files"`
	Conffiles []string      `json:"conffiles"`
	Package
	Depends       string `json:"depends,omitempty"`
	ExpandedBytes int64  `json:"expanded_bytes"`
}

// Package names, including dependency packages, are a fixed product boundary.
// A correctly signed unrelated system package is still not an API install target.
func allowedPackage(name string) bool {
	switch name {
	case "routeharbor",
		"routeharbor-guard",
		"routeharbor-node",
		"routeharbor-sing-box",
		"routeharbor-xray",
		"routeharbor-conntrack", "routeharbor-continuity",
		"sing-box",
		"xray-core",
		"conntrack",
		"libatomic1",
		"libstdcpp6",
		"libgcc1",
		"libmnl0",
		"libnfnetlink0",
		"libnetfilter-conntrack3",
		"libopenssl3",
		"libmbedtls21",
		"zlib",
		"kmod-nft-tproxy",
		"kmod-nft-socket",
		"kmod-nf-tproxy",
		"kmod-nf-socket",
		"kmod-inet-diag":
		return true
	default:
		return false
	}
}

func archivePath(name string) (string, error) {
	name = strings.TrimPrefix(name, "./")
	if name == "" || name == "." {
		return "", nil
	}
	if strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || len(name) > 240 ||
		strings.IndexFunc(name, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return "", errors.New("package_archive_path_rejected")
	}
	for part := range strings.SplitSeq(strings.TrimSuffix(name, "/"), "/") {
		if part == ".." || part == "." || part == "" {
			return "", errors.New("package_archive_path_rejected")
		}
	}
	return strings.TrimSuffix(name, "/"), nil
}

func controlFields(raw []byte) (map[string]string, error) {
	out := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 4096), 16<<10)
	previous := ""
	for scanner.Scan() {
		line := scanner.Text()
		if strings.ContainsRune(line, '\r') || strings.ContainsRune(line, '\x00') {
			return nil, errors.New("package_control_rejected")
		}
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if previous == "" {
				return nil, errors.New("package_control_rejected")
			}
			if previous == "Depends" {
				out[previous] += " " + strings.TrimSpace(line)
			}
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || key == "" || len(key) > 80 {
			return nil, errors.New("package_control_rejected")
		}
		if _, duplicate := out[key]; duplicate {
			return nil, errors.New("package_control_duplicate_field")
		}
		out[key] = strings.TrimSpace(value)
		previous = key
	}
	if scanner.Err() != nil {
		return nil, errors.New("package_control_rejected")
	}
	return out, nil
}

func inspectControl(r io.Reader) (packageMetadata, error) {
	var result packageMetadata
	compressed, err := gzip.NewReader(r)
	if err != nil {
		return result, errors.New("package_control_archive_rejected")
	}
	defer func() { _ = compressed.Close() }()
	limited := &io.LimitedReader{R: compressed, N: maxControlBytes + 1}
	reader := tar.NewReader(limited)
	seen := map[string]bool{}
	var control []byte
	var conffiles []byte
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return result, errors.New("package_control_archive_rejected")
		}
		name, err := archivePath(header.Name)
		if err != nil {
			return result, err
		}
		if name == "" && header.Typeflag == tar.TypeDir {
			continue
		}
		if seen[name] || len(seen) > 64 ||
			(header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeDir) {
			return result, errors.New("package_control_archive_rejected")
		}
		seen[name] = true
		if header.Size < 0 || header.Size > maxControlBytes {
			return result, errors.New("package_control_archive_rejected")
		}
		if name == "conffiles" {
			conffiles, err = io.ReadAll(io.LimitReader(reader, 64<<10+1))
			if err != nil || len(conffiles) > 64<<10 {
				return result, errors.New("package_conffiles_rejected")
			}
		}
		if name == "control" {
			control, err = io.ReadAll(io.LimitReader(reader, 64<<10+1))
			if err != nil || len(control) > 64<<10 {
				return result, errors.New("package_control_rejected")
			}
		}
	}
	if err := finishArchive(limited); err != nil {
		return result, err
	}
	if control == nil {
		return result, errors.New("package_control_missing")
	}
	fields, err := controlFields(control)
	if err != nil {
		return result, err
	}
	result.Name, result.Version, result.Architecture = fields["Package"], fields["Version"], fields["Architecture"]
	result.Depends = fields["Depends"]
	if result.Name != "routeharbor-guard" &&
		(strings.Contains(fields["Replaces"], "routeharbor-guard") || strings.Contains(fields["Conflicts"], "routeharbor-guard")) {
		return result, errors.New("maintenance_guard_relationship_rejected")
	}
	for line := range strings.SplitSeq(string(conffiles), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 1 {
			return result, errors.New("package_conffiles_rejected")
		}
		name, err := archivePath(strings.TrimPrefix(fields[0], "/"))
		if err != nil || name == "" {
			return result, errors.New("package_conffiles_rejected")
		}
		result.Conffiles = append(result.Conffiles, name)
	}
	if !packageName.MatchString(result.Name) || !allowedPackage(result.Name) ||
		!packageVersion.MatchString(result.Version) ||
		!packageArchitecture.MatchString(result.Architecture) ||
		len(result.Depends) > 8192 {
		return result, errors.New("package_identity_rejected")
	}
	if raw := fields["Installed-Size"]; raw != "" {
		size, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || size < 0 || size > maxExpandedBytes {
			return result, errors.New("package_size_rejected")
		}
	}
	return result, nil
}

func inspectData(r io.Reader) (int64, []PayloadFile, error) {
	compressed, err := gzip.NewReader(r)
	if err != nil {
		return 0, nil, errors.New("package_data_archive_rejected")
	}
	defer func() { _ = compressed.Close() }()
	limited := &io.LimitedReader{R: compressed, N: maxExpandedBytes + 1}
	reader := tar.NewReader(limited)
	var size int64
	var files []PayloadFile
	seen := map[string]bool{}
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, nil, errors.New("package_data_archive_rejected")
		}
		name, err := archivePath(header.Name)
		if err != nil {
			return 0, nil, err
		}
		if name == "" && header.Typeflag == tar.TypeDir {
			continue
		}
		if seen[name] || len(seen) > 16384 || header.Size < 0 ||
			header.Size > maxExpandedBytes-size {
			return 0, nil, errors.New("package_data_archive_rejected")
		}
		seen[name] = true
		size += header.Size
		entry := PayloadFile{Path: name, Mode: uint32(header.Mode) & 0o7777, Bytes: header.Size}
		if entry.Mode&0o6000 != 0 {
			return 0, nil, errors.New("package_privileged_mode_rejected")
		}
		switch header.Typeflag {
		case tar.TypeReg:
			entry.Type = "file"
			hash := sha256.New()
			count, err := io.Copy(hash, reader)
			if err != nil || count != header.Size {
				return 0, nil, errors.New("package_payload_rejected")
			}
			entry.SHA256 = hex.EncodeToString(hash.Sum(nil))
		case tar.TypeDir:
			entry.Type = "dir"
		case tar.TypeSymlink, tar.TypeLink:
			entry.Type = "symlink"
			if header.Typeflag == tar.TypeLink {
				entry.Type = "hardlink"
			}
			entry.Target = header.Linkname
			target := header.Linkname
			if strings.HasPrefix(target, "/") || strings.Contains(target, "\\") {
				return 0, nil, errors.New("package_link_rejected")
			}
			resolved := path.Clean(path.Join(path.Dir(name), target))
			if header.Typeflag == tar.TypeLink {
				resolved = path.Clean(target)
			}
			if _, err = archivePath(resolved); err != nil {
				return 0, nil, errors.New("package_link_rejected")
			}
		default:
			return 0, nil, errors.New("package_data_type_rejected")
		}
		files = append(files, entry)
	}
	if err := finishArchive(limited); err != nil {
		return 0, nil, err
	}
	return size, files, nil
}

// InspectIPK accepts the gzip/tar format emitted by the supported OpenWrt SDK.
// It never extracts paths, loads a library, or executes package-maintainer scripts.
func InspectIPK(r io.Reader) (packageMetadata, error) {
	var result packageMetadata
	compressed, err := gzip.NewReader(r)
	if err != nil {
		return result, errors.New("package_format_unsupported")
	}
	defer func() { _ = compressed.Close() }()
	limited := &io.LimitedReader{R: compressed, N: 128<<20 + 1}
	reader := tar.NewReader(limited)
	seen := map[string]bool{}
	var expanded int64
	var files []PayloadFile
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return result, errors.New("package_archive_rejected")
		}
		name, err := archivePath(header.Name)
		if err != nil {
			return result, err
		}
		if header.Typeflag != tar.TypeReg || seen[name] || header.Size < 0 ||
			header.Size > 128<<20 {
			return result, errors.New("package_archive_rejected")
		}
		seen[name] = true
		switch name {
		case "debian-binary":
			data, err := io.ReadAll(io.LimitReader(reader, 8))
			if err != nil || string(data) != "2.0\n" {
				return result, errors.New("package_format_unsupported")
			}
		case "control.tar.gz":
			result, err = inspectControl(reader)
			if err != nil {
				return result, err
			}
		case "data.tar.gz":
			expanded, files, err = inspectData(reader)
			if err != nil {
				return result, err
			}
		default:
			return result, errors.New("package_archive_member_rejected")
		}
	}
	if len(seen) != 3 || !seen["control.tar.gz"] || !seen["data.tar.gz"] || !seen["debian-binary"] {
		return result, errors.New("package_archive_incomplete")
	}
	if err := finishArchive(limited); err != nil {
		return result, err
	}
	result.ExpandedBytes = expanded
	result.Files = files
	if err := protectGuardPayload(result); err != nil {
		return result, err
	}
	return result, nil
}

// Drain the compressed member to verify its checksum and enforce the byte budget.
// Only zero tar padding may follow the archive terminator.
func finishArchive(reader *io.LimitedReader) error {
	var buffer [4096]byte
	for {
		n, err := reader.Read(buffer[:])
		for _, b := range buffer[:n] {
			if b != 0 {
				return errors.New("package_archive_trailing_data")
			}
		}
		if reader.N == 0 {
			return errors.New("package_archive_byte_limit")
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return errors.New("package_archive_checksum_rejected")
		}
	}
}

// Control-package identity alone does not prevent a misbuilt signed package
// from trying to overwrite retained guard state or its boot entry points.
func protectGuardPayload(metadata packageMetadata) error {
	if metadata.Name == "routeharbor-guard" {
		return nil
	}
	for _, file := range metadata.Files {
		if reservedGuardPath(file.Path, file.Type != "dir") {
			return errors.New("maintenance_guard_payload_rejected")
		}
		if file.Type == "symlink" || file.Type == "hardlink" {
			target := path.Clean(file.Target)
			if file.Type == "symlink" {
				target = path.Clean(path.Join(path.Dir(file.Path), file.Target))
			}
			if reservedGuardPath(target, true) {
				return errors.New("maintenance_guard_payload_rejected")
			}
		}
	}
	for _, name := range metadata.Conffiles {
		if reservedGuardPath(name, true) {
			return errors.New("maintenance_guard_payload_rejected")
		}
	}
	return nil
}

func reservedGuardPath(name string, includeAncestors bool) bool {
	roots := []string{
		"usr/libexec/routeharbor-helper",
		"etc/init.d/routeharbor-guard",
		"etc/routeharbor-helper",
		"etc/routeharbor-maintenance",
		"usr/share/nftables.d/ruleset-pre/90-routeharbor-guard.nft",
	}
	for _, root := range roots {
		if name == root || strings.HasPrefix(name, root+"/") ||
			(includeAncestors && strings.HasPrefix(root, name+"/")) {
			return true
		}
	}
	return (includeAncestors && name == "etc/rc.d") ||
		(strings.HasPrefix(name, "etc/rc.d/") && strings.HasSuffix(name, "routeharbor-guard"))
}
