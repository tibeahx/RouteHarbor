#!/bin/sh
# Actual OpenWrt opkg and detached-worker tests in disposable containers.
# This is userland evidence, not full-boot or physical power-loss acceptance.
set -eu
cd "$(dirname "$0")/.."
GO=${GO:-go}
image=openrhp-maintenance-lab:24.10.7
mkdir -p test-results/maintenance
chmod 0755 test-results/maintenance
if ! docker image inspect "$image" >/dev/null 2>&1; then
 build_dir=$(mktemp -d)
 trap 'rm -rf "$build_dir"' EXIT HUP INT TERM
 curl --fail --silent --show-error --location --proto '=https' \
  https://downloads.openwrt.org/releases/24.10.7/targets/x86/64/openwrt-24.10.7-x86-64-rootfs.tar.gz \
  -o "$build_dir/rootfs.tar.gz"
 expected=862c25809a12356bdc051d144f53a4ebb6494bd0239a19e8c54cd9160db89b21
 if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$build_dir/rootfs.tar.gz" | cut -d ' ' -f 1)
 else
  actual=$(shasum -a 256 "$build_dir/rootfs.tar.gz" | cut -d ' ' -f 1)
 fi
 [ "$actual" = "$expected" ] || { echo "OpenWrt rootfs hash mismatch" >&2; exit 1; }
 cp docker/lab-maintenance/Dockerfile "$build_dir/Dockerfile"
 docker build --platform linux/amd64 --network none -t "$image" "$build_dir"
 rm -rf "$build_dir"
 trap - EXIT HUP INT TERM
fi
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO" test -c -o test-results/maintenance/opkg.test ./internal/maintenance
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO" test -c -o test-results/maintenance/helper.test ./internal/helper
chmod 0755 test-results/maintenance/opkg.test test-results/maintenance/helper.test
for suite in opkg worker; do
 log="test-results/maintenance/$suite.log"
 if docker run --rm --name "openrhp-maintenance-$suite-$$" --platform linux/amd64 --network none \
  -e OPENRHP_OPKG_LAB=1 -e OPENRHP_MAINTENANCE_LAB=1 \
  -v "$PWD/test-results/maintenance:/tests:ro" "$image" -eu -c '
   mkdir -p /usr/libexec
   cp /tests/helper.test /usr/libexec/openrhp-maintenance.test
   chmod 0755 /usr/libexec/openrhp-maintenance.test
   if [ "$1" = opkg ]; then
    /tests/opkg.test -test.run "^TestOpenWrtOpkgOffline$" -test.v -test.timeout 120s
   else
    /usr/libexec/openrhp-maintenance.test -test.run "^TestLinuxMaintenanceWorkerSurvivesControllerKill$" -test.v -test.timeout 30s
   fi
  ' lab "$suite" >"$log" 2>&1; then
  cat "$log"
 else
  cat "$log" >&2
  exit 1
 fi
done
