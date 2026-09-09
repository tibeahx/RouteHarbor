package maintenance

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/tibeahx/OpenRHP/internal/platform"
)

type Gate interface {
	AcquireMaintenance(context.Context, string, func() error) error
	ReleaseMaintenance(string) error
	ReacquireMaintenance(context.Context, string, func() error) error
	DecommissionMaintenance(context.Context, string, string) error
}

type OpkgBackend struct {
	StateDir     string
	Gate         Gate
	CheckPending func() error
}

func (b *OpkgBackend) binary() (string, error) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return "", errors.New("maintenance_requires_root_openwrt")
	}
	for _, name := range []string{"/bin/opkg", "/usr/bin/opkg"} {
		info, err := os.Lstat(name)
		if err != nil {
			continue
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
			continue
		}
		return name, nil
	}
	return "", errors.New("maintenance_package_manager_unsupported")
}

func (b *OpkgBackend) Inventory(ctx context.Context) (Inventory, error) {
	var result Inventory
	if _, err := b.binary(); err != nil {
		return result, err
	}
	report := platform.Detect(ctx)
	if report.Version == "" || report.PackageArch == "" {
		return result, errors.New("maintenance_openwrt_required")
	}
	result.Architecture = report.PackageArch
	file, err := os.OpenFile(
		"/usr/lib/opkg/status",
		os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,
		0,
	)
	if err != nil {
		return result, errors.New("maintenance_package_inventory_unavailable")
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return result, errors.New("maintenance_package_inventory_unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 2<<20+1))
	if err != nil || len(raw) > 2<<20 {
		return result, errors.New("maintenance_package_inventory_limit")
	}
	result.Packages = map[string]string{}
	for paragraph := range strings.SplitSeq(string(raw), "\n\n") {
		if strings.TrimSpace(paragraph) == "" {
			continue
		}
		fields, err := controlFields([]byte(paragraph))
		if err != nil {
			return result, errors.New("maintenance_package_inventory_invalid")
		}
		status := strings.Fields(fields["Status"])
		if len(status) != 3 {
			return result, errors.New("maintenance_package_inventory_invalid")
		}
		if status[2] == "not-installed" || status[2] == "config-files" {
			continue
		}
		if status[2] != "installed" {
			return result, errors.New("maintenance_package_database_interrupted")
		}
		name, version := fields["Package"], fields["Version"]
		if !packageName.MatchString(name) || !packageVersion.MatchString(version) ||
			result.Packages[name] != "" {
			return result, errors.New("maintenance_package_inventory_invalid")
		}
		result.Packages[name] = version
	}
	var space syscall.Statfs_t
	if err = syscall.Statfs(b.StateDir, &space); err != nil {
		return result, errors.New("maintenance_storage_unavailable")
	}
	result.AvailableBytes = int64(space.Bavail) * int64(space.Bsize)
	if result.AvailableBytes < 0 {
		return result, errors.New("maintenance_storage_unavailable")
	}
	return result, nil
}

func (b *OpkgBackend) run(ctx context.Context, args ...string) (int, error) {
	binary, err := b.binary()
	if err != nil {
		return -1, err
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(bounded, binary, args...)
	cmd.Env = b.environment()
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 2 * time.Second
	err = cmd.Run()
	if err == nil {
		return 0, nil
	}
	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		return exit.ExitCode(), nil
	}
	return -1, errors.New("maintenance_package_manager_unavailable")
}

func (b *OpkgBackend) Compare(ctx context.Context, a, operator, c string) (bool, error) {
	if !packageVersion.MatchString(a) || !packageVersion.MatchString(c) {
		return false, errors.New("maintenance_version_invalid")
	}
	switch operator {
	case "=", ">=", "<=", ">>", "<<", ">", "<":
	default:
		return false, errors.New("maintenance_version_operator_invalid")
	}
	status, err := b.run(ctx, "compare-versions", a, operator, c)
	if err != nil {
		return false, err
	}
	if status == 0 {
		return true, nil
	}
	if status == 1 {
		return false, nil
	}
	return false, errors.New("maintenance_version_comparison_failed")
}

func (b *OpkgBackend) arguments(plan Plan, paths []string, dry bool) ([]string, error) {
	root, err := openStateRoot(b.StateDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	// --conf alone still loads /etc/opkg/*.conf. OPKG_CONF_DIR and an empty
	// private lists directory jointly isolate the offline dependency closure.
	if strings.IndexFunc(b.StateDir, func(r rune) bool { return r <= 32 || r == 127 }) >= 0 {
		return nil, errors.New("maintenance_state_path_unsupported")
	}
	empty, err := openStateRoot(filepath.Join(b.StateDir, "empty-feeds"))
	if err != nil {
		return nil, err
	}
	entries, inspectErr := stateEntries(empty)
	_ = empty.Close()
	if inspectErr != nil || len(entries) != 0 {
		return nil, errors.New("maintenance_feed_directory_not_empty")
	}
	config := []byte(
		"dest root /\nlists_dir ext " + filepath.Join(
			b.StateDir,
			"empty-feeds",
		) + "\noption overlay_root /overlay\n",
	)
	if err = writePrivate(root, "opkg.conf", config); err != nil {
		return nil, err
	}
	args := []string{"--conf", filepath.Join(b.StateDir, "opkg.conf")}
	if dry {
		args = append(args, "--noaction")
	}
	if plan.Request.Action == "remove" {
		args = append(args, "remove")
		packages := append([]Package(nil), plan.Packages...)
		// opkg processes removals in argument order. Even one invocation must
		// remove wrappers before the controller/native packages they depend on.
		sort.SliceStable(packages, func(i, j int) bool {
			return removalPriority(packages[i].Name) < removalPriority(packages[j].Name)
		})
		for _, p := range packages {
			if !recoverablePackage(p.Name) {
				return nil, errors.New("maintenance_removal_unsupported")
			}
			args = append(args, p.Name)
		}
	} else {
		if len(paths) != len(plan.Packages) {
			return nil, errors.New("maintenance_artifact_count_invalid")
		}
		args = append(args, "install")
		for i, p := range plan.Packages {
			if !allowedPackage(p.Name) || p.Name == "openrhp-guard" || p.Name == "openrhp-node" ||
				!hashID.MatchString(p.SHA256) ||
				paths[i] != filepath.Join(b.StateDir, "artifact-"+p.SHA256+".ipk") {
				return nil, errors.New("maintenance_installation_unsupported")
			}
			args = append(args, paths[i])
		}
	}
	return args, nil
}

func removalPriority(name string) int {
	switch name {
	case "openrhp-sing-box", "openrhp-xray", "openrhp-conntrack":
		return 0
	default:
		return 1
	}
}

func (b *OpkgBackend) Check(ctx context.Context, plan Plan, paths []string) error {
	if b.Gate == nil {
		return errors.New("maintenance_guard_unavailable")
	}
	if len(plan.Packages) == 0 {
		return nil
	}
	args, err := b.arguments(plan, paths, true)
	if err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	status, err := b.run(bounded, args...)
	if err != nil {
		return err
	}
	if status != 0 {
		return errors.New("maintenance_offline_preflight_failed")
	}
	return nil
}

func (b *OpkgBackend) Acquire(ctx context.Context, id string) error {
	if b.Gate == nil {
		return errors.New("maintenance_guard_unavailable")
	}
	return b.Gate.AcquireMaintenance(ctx, id, b.CheckPending)
}

func (b *OpkgBackend) Release(id string) error {
	if b.Gate == nil {
		return errors.New("maintenance_guard_unavailable")
	}
	return b.Gate.ReleaseMaintenance(id)
}

func (b *OpkgBackend) Decommission(ctx context.Context, id, policy string) error {
	if b.Gate == nil {
		return errors.New("maintenance_guard_unavailable")
	}
	return b.Gate.DecommissionMaintenance(ctx, id, policy)
}

func (b *OpkgBackend) Execute(ctx context.Context, plan Plan, paths []string) error {
	if len(plan.Packages) == 0 {
		return nil
	}
	args, err := b.arguments(plan, paths, false)
	if err != nil {
		return err
	}
	status, err := b.run(ctx, args...)
	if err != nil {
		return err
	}
	if status != 0 {
		return errors.New("maintenance_package_manager_failed")
	}
	return nil
}

// Recover is reached only from durable, explicitly requested local recovery.
// Removing first allows same-version repair and rollback without force flags.
func (b *OpkgBackend) Recover(
	ctx context.Context,
	target Plan,
	remove []Package,
	paths []string,
) error {
	for _, p := range remove {
		if !recoverablePackage(p.Name) {
			return errors.New("maintenance_system_dependency_recovery_unsupported")
		}
	}
	removal := Plan{Request: Request{Action: "remove"}, Packages: remove}
	if err := b.Execute(ctx, removal, nil); err != nil {
		return err
	}
	if target.Request.Action == "remove" {
		return nil
	}
	if err := b.Check(ctx, target, paths); err != nil {
		return err
	}
	return b.Execute(ctx, target, paths)
}

func (b *OpkgBackend) environment() []string {
	return []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LC_ALL=C",
		"HOME=/root",
		"OPKG_CONF_DIR=" + filepath.Join(b.StateDir, "empty-feeds"),
	}
}

func (b *OpkgBackend) AcquireRecovery(ctx context.Context, id string) error {
	if b.Gate == nil {
		return errors.New("maintenance_guard_unavailable")
	}
	return b.Gate.ReacquireMaintenance(ctx, id, b.CheckPending)
}
