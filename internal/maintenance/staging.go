package maintenance

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/release"
)

const maxBundleBytes int64 = 128 << 20

type bundleRecord struct {
	Schema         int               `json:"schema"`
	Summary        BundleSummary     `json:"summary"`
	Manifest       []byte            `json:"manifest"`
	Signature      []byte            `json:"signature"`
	KeyFingerprint string            `json:"key_fingerprint"`
	Metadata       []packageMetadata `json:"metadata"`
}

func trustedManifest(root *os.Root, raw, sig []byte) (release.Manifest, string, error) {
	var manifest release.Manifest
	key, fingerprint, err := trustedKey(root)
	if err != nil {
		return manifest, "", err
	}
	if len(raw) > 256<<10 || len(sig) != ed25519.SignatureSize || !ed25519.Verify(key, raw, sig) {
		return manifest, "", errors.New("maintenance_signature_rejected")
	}
	if err = adapter.StrictDecode(raw, &manifest); err != nil {
		return manifest, "", errors.New("maintenance_manifest_rejected")
	}
	if err = release.Validate(manifest); err != nil {
		return manifest, "", errors.New("maintenance_manifest_rejected")
	}
	return manifest, fingerprint, nil
}

func inputFile(root *os.Root, name string, limit int64) (*os.File, error) {
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > limit ||
		before.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("maintenance_input_rejected")
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		return nil, errors.New("maintenance_input_owner_rejected")
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("maintenance_input_rejected")
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		_ = f.Close()
		return nil, errors.New("maintenance_input_changed")
	}
	return f, nil
}

func readInput(root *os.Root, name string, limit int64) ([]byte, error) {
	f, err := inputFile(root, name, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("maintenance_input_rejected")
	}
	return raw, nil
}

// Stage is called only by trusted local administration, never by the public RPC.
// The existing root-owned trust.pub is independent of the incoming bundle.
func Stage(stateDir, sourceDir, architecture string) (BundleSummary, error) {
	var summary BundleSummary
	if !packageArchitecture.MatchString(architecture) {
		return summary, errors.New("maintenance_architecture_required")
	}
	root, err := openStateRoot(stateDir)
	if err != nil {
		return summary, err
	}
	defer func() { _ = root.Close() }()
	lock, err := stateLock(root, ".lock")
	if err != nil {
		return summary, err
	}
	defer stateUnlock(lock)
	before, err := os.Lstat(sourceDir)
	if err != nil || !filepath.IsAbs(sourceDir) || !before.IsDir() ||
		before.Mode()&os.ModeSymlink != 0 ||
		before.Mode().Perm()&0o022 != 0 {
		return summary, errors.New("maintenance_input_directory_rejected")
	}
	source, err := os.OpenRoot(sourceDir)
	if err != nil {
		return summary, err
	}
	defer func() { _ = source.Close() }()
	opened, err := source.Open(".")
	if err != nil {
		return summary, err
	}
	openedInfo, inspectErr := opened.Stat()
	_ = opened.Close()
	if inspectErr != nil || !os.SameFile(before, openedInfo) {
		return summary, errors.New("maintenance_input_directory_changed")
	}
	owner, ok := openedInfo.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return summary, errors.New("maintenance_input_directory_owner_rejected")
	}

	raw, err := readInput(source, "manifest.json", 256<<10)
	if err != nil {
		return summary, err
	}
	encoded, err := readInput(source, "manifest.sig", 1024)
	if err != nil {
		return summary, err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		return summary, errors.New("maintenance_signature_rejected")
	}
	manifest, fingerprint, err := trustedManifest(root, raw, sig)
	if err != nil {
		return summary, err
	}
	identity := sha256.New()
	_, _ = identity.Write(raw)
	_, _ = identity.Write(sig)
	_, _ = identity.Write([]byte(architecture + fingerprint))
	id := hex.EncodeToString(identity.Sum(nil)[:16])
	existing := false
	if _, err := readPrivate(root, "bundle-"+id+".json"); err == nil {
		existing = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return summary, err
	}
	entries, err := stateEntries(root)
	if err != nil {
		return summary, err
	}
	bundles := 0
	var stored int64
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "bundle-") && strings.HasSuffix(name, ".json") {
			bundles++
		}
		if strings.HasPrefix(name, "artifact-") && strings.HasSuffix(name, ".ipk") {
			info, err := entry.Info()
			if err != nil {
				return summary, err
			}
			stored += info.Size()
		}
	}
	if (!existing && bundles >= 4) || stored > 4*maxBundleBytes {
		return summary, errors.New("maintenance_storage_limit")
	}
	record := bundleRecord{Schema: 1, Manifest: raw, Signature: sig, KeyFingerprint: fingerprint}
	summary = BundleSummary{
		ID:           id,
		Version:      manifest.Version,
		Commit:       manifest.Commit,
		Architecture: architecture,
	}
	seen := map[string]bool{}
	var total int64
	for _, artifact := range manifest.Artifacts {
		if artifact.Architecture != architecture && artifact.Architecture != "all" {
			continue
		}
		if !strings.HasSuffix(artifact.Name, ".ipk") {
			continue
		}
		total += artifact.Bytes
		if total > maxBundleBytes || len(record.Metadata) >= 32 || stored+total > 4*maxBundleBytes {
			return summary, errors.New("maintenance_storage_limit")
		}
		metadata, err := copyArtifact(root, source, artifact)
		if err != nil {
			return summary, err
		}
		if metadata.Architecture != artifact.Architecture || seen[metadata.Name] {
			return summary, errors.New("maintenance_package_identity_rejected")
		}
		seen[metadata.Name] = true
		summary.Packages = append(summary.Packages, metadata.Package)
		record.Metadata = append(record.Metadata, metadata)
	}
	if len(summary.Packages) == 0 {
		return summary, errors.New("maintenance_no_matching_packages")
	}
	sort.Slice(
		summary.Packages,
		func(i, j int) bool { return summary.Packages[i].Name < summary.Packages[j].Name },
	)
	record.Summary = summary
	data, err := json.Marshal(record)
	if err != nil {
		return summary, err
	}
	if err = writePrivate(root, "bundle-"+id+".json", data); err != nil {
		return summary, err
	}
	return summary, nil
}

func copyArtifact(root, source *os.Root, artifact release.Artifact) (packageMetadata, error) {
	var metadata packageMetadata
	input, err := inputFile(source, artifact.Name, maxBundleBytes)
	if err != nil {
		return metadata, err
	}
	defer func() { _ = input.Close() }()
	incomingHash := sha256.New()
	incomingBytes, err := io.Copy(incomingHash, io.LimitReader(input, artifact.Bytes+1))
	if err != nil || incomingBytes != artifact.Bytes ||
		hex.EncodeToString(incomingHash.Sum(nil)) != artifact.SHA256 {
		return metadata, errors.New("maintenance_artifact_hash_rejected")
	}
	if _, err = input.Seek(0, io.SeekStart); err != nil {
		return metadata, err
	}
	name := "artifact-" + artifact.SHA256 + ".ipk"
	// Repair a torn regular destination only after the replacement has been
	// authenticated. A symlink or foreign-owned entry is never removed.
	if _, err = root.Lstat(name); err == nil {
		before, inspectErr := root.Lstat(name)
		if inspectErr != nil || !before.Mode().IsRegular() {
			return metadata, errors.New("maintenance_staging_destination_rejected")
		}
		file, openErr := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if openErr != nil {
			return metadata, openErr
		}
		after, statErr := file.Stat()
		if statErr != nil || !os.SameFile(before, after) {
			_ = file.Close()
			return metadata, errors.New("maintenance_staging_destination_changed")
		}
		privateErr := privateRegular(file)
		_ = file.Close()
		if privateErr != nil {
			return metadata, privateErr
		}
		if existing, inspectErr := inspectArtifact(root, artifact); inspectErr == nil {
			return existing, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return metadata, err
	}
	temporary := ".artifact-" + artifact.SHA256 + ".tmp"
	if info, inspectErr := root.Lstat(temporary); inspectErr == nil {
		if !info.Mode().IsRegular() {
			return metadata, errors.New("maintenance_staging_destination_rejected")
		}
		stale, openErr := root.OpenFile(
			temporary,
			os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,
			0,
		)
		if openErr != nil {
			return metadata, openErr
		}
		privateErr := privateRegular(stale)
		_ = stale.Close()
		if privateErr != nil {
			return metadata, privateErr
		}
		if err = root.Remove(temporary); err != nil {
			return metadata, err
		}
	} else if !errors.Is(inspectErr, os.ErrNotExist) {
		return metadata, inspectErr
	}
	output, err := root.OpenFile(
		temporary,
		os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return metadata, err
	}
	complete := false
	defer func() {
		_ = output.Close()
		if !complete {
			_ = root.Remove(temporary)
		}
	}()
	hash := sha256.New()
	count, err := io.Copy(io.MultiWriter(output, hash), io.LimitReader(input, artifact.Bytes+1))
	if err != nil || count != artifact.Bytes ||
		hex.EncodeToString(hash.Sum(nil)) != artifact.SHA256 {
		return metadata, errors.New("maintenance_artifact_hash_rejected")
	}
	if _, err = output.Seek(0, io.SeekStart); err != nil {
		return metadata, err
	}
	metadata, err = InspectIPK(output)
	if err != nil {
		return metadata, err
	}
	metadata.SHA256, metadata.Bytes = artifact.SHA256, artifact.Bytes
	if err = output.Sync(); err != nil {
		return metadata, err
	}
	if err = output.Close(); err != nil {
		return metadata, err
	}
	if err = root.Rename(temporary, name); err != nil {
		return metadata, err
	}
	directory, err := root.Open(".")
	if err != nil {
		return metadata, err
	}
	err = directory.Sync()
	_ = directory.Close()
	if err != nil {
		return metadata, err
	}
	complete = true
	return metadata, nil
}

func inspectArtifact(root *os.Root, artifact release.Artifact) (packageMetadata, error) {
	var metadata packageMetadata
	f, err := inputFile(root, "artifact-"+artifact.SHA256+".ipk", maxBundleBytes)
	if err != nil {
		return metadata, err
	}
	defer func() { _ = f.Close() }()
	if err = privateRegular(f); err != nil {
		return metadata, err
	}
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(f, artifact.Bytes+1))
	if err != nil || count != artifact.Bytes ||
		hex.EncodeToString(hash.Sum(nil)) != artifact.SHA256 {
		return metadata, errors.New("maintenance_artifact_hash_rejected")
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return metadata, err
	}
	metadata, err = InspectIPK(f)
	metadata.SHA256, metadata.Bytes = artifact.SHA256, artifact.Bytes
	return metadata, err
}

func readBundle(root *os.Root, id string) (bundleRecord, error) {
	var record bundleRecord
	if !hexID.MatchString(id) {
		return record, errors.New("maintenance_bundle_id_invalid")
	}
	raw, err := readPrivate(root, "bundle-"+id+".json")
	if err != nil {
		return record, err
	}
	if err = adapter.StrictDecode(
		raw,
		&record,
	); err != nil || record.Schema != 1 ||
		record.Summary.ID != id {
		return record, errors.New("maintenance_bundle_rejected")
	}
	manifest, key, err := trustedManifest(root, record.Manifest, record.Signature)
	if err != nil {
		return record, err
	}
	if key != record.KeyFingerprint || manifest.Version != record.Summary.Version ||
		manifest.Commit != record.Summary.Commit ||
		!packageArchitecture.MatchString(record.Summary.Architecture) {
		return record, errors.New("maintenance_bundle_rejected")
	}
	identity := sha256.New()
	_, _ = identity.Write(record.Manifest)
	_, _ = identity.Write(record.Signature)
	_, _ = identity.Write([]byte(record.Summary.Architecture + key))
	if hex.EncodeToString(identity.Sum(nil)[:16]) != id {
		return record, errors.New("maintenance_bundle_identity_rejected")
	}
	// The cache is an index only. Dependencies, payload hashes, permissions and
	// conffiles always come from the authenticated IPK, including after reboot.
	record.Metadata = nil
	record.Summary.Packages = nil
	seen := map[string]bool{}
	var total int64
	for _, artifact := range manifest.Artifacts {
		if (artifact.Architecture != record.Summary.Architecture && artifact.Architecture != "all") ||
			!strings.HasSuffix(artifact.Name, ".ipk") {
			continue
		}
		total += artifact.Bytes
		if total > maxBundleBytes || len(record.Metadata) >= 32 {
			return record, errors.New("maintenance_bundle_rejected")
		}
		metadata, err := inspectArtifact(root, artifact)
		if err != nil {
			return record, err
		}
		if metadata.Architecture != artifact.Architecture || seen[metadata.Name] {
			return record, errors.New("maintenance_package_identity_rejected")
		}
		seen[metadata.Name] = true
		record.Metadata = append(record.Metadata, metadata)
		record.Summary.Packages = append(record.Summary.Packages, metadata.Package)
	}
	if len(record.Metadata) == 0 {
		return record, errors.New("maintenance_bundle_rejected")
	}
	sort.Slice(
		record.Summary.Packages,
		func(i, j int) bool { return record.Summary.Packages[i].Name < record.Summary.Packages[j].Name },
	)
	return record, nil
}

func stateEntries(root *os.Root) ([]os.DirEntry, error) {
	f, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	entries, err := f.ReadDir(513)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > 512 {
		return nil, errors.New("maintenance_storage_limit")
	}
	return entries, nil
}

func trustedKey(root *os.Root) (ed25519.PublicKey, string, error) {
	encoded, err := readPrivate(root, "trust.pub")
	if err != nil {
		return nil, "", errors.New("maintenance_trust_unavailable")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, "", errors.New("maintenance_trust_invalid")
	}
	digest := sha256.Sum256(key)
	return ed25519.PublicKey(key), hex.EncodeToString(digest[:]), nil
}
