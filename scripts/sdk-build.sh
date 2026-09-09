#!/bin/sh
# Package with an already verified OpenWrt SDK. This script downloads nothing.
set -eu
[ "$#" -eq 2 ] || { echo 'Usage: scripts/sdk-build.sh /absolute/openwrt-sdk /absolute/go1.27.1/bin/go' >&2; exit 2; }
sdk_dir="$1"
go_binary="$2"
case "$sdk_dir:$go_binary" in /*:/*) ;; *) echo 'SDK and Go paths must be absolute.' >&2; exit 2 ;; esac
[ "$(uname -s)" = Linux ] || { echo 'Run the OpenWrt SDK on Linux, for example in an isolated container.' >&2; exit 1; }
[ -f "$sdk_dir/include/package.mk" ] && [ -f "$sdk_dir/rules.mk" ] || { echo 'This is not an extracted OpenWrt SDK.' >&2; exit 1; }
[ -x "$go_binary" ] || { echo 'Pinned Go executable not found.' >&2; exit 1; }
[ "$("$go_binary" version | cut -d ' ' -f 3)" = go1.27.1 ] || { echo 'Go 1.27.1 is required; verify it independently before building.' >&2; exit 1; }
source_dir="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
[ -f "$source_dir/LICENSE" ] || { echo 'Project license must be present.' >&2; exit 1; }
recipe="$sdk_dir/package/openrhp"
if [ -e "$recipe" ]; then
 [ -f "$recipe/.openrhp-owned" ] || { echo 'Refusing to replace an existing foreign SDK package directory.' >&2; exit 1; }
 rm -rf "$recipe"
fi
mkdir -p "$recipe"
printf '%s\n' 'OpenRHP SDK staging directory' > "$recipe/.openrhp-owned"
cp -R "$source_dir/packaging/openwrt/openrhp/." "$recipe/"
# Fresh SDK defaults otherwise select every available package and kernel module.
# Initialize only a new SDK configuration; preserve an operator's existing config.
if [ ! -f "$sdk_dir/.config" ]; then
 printf '%s\n' '# CONFIG_ALL is not set' '# CONFIG_ALL_KMODS is not set' '# CONFIG_ALL_NONSHARED is not set' \
  'CONFIG_PACKAGE_openrhp=m' 'CONFIG_PACKAGE_openrhp-guard=m' 'CONFIG_PACKAGE_openrhp-node=m' \
  'CONFIG_PACKAGE_openrhp-conntrack=m' 'CONFIG_PACKAGE_openrhp-sing-box=m' 'CONFIG_PACKAGE_openrhp-xray=m' > "$sdk_dir/.config"
fi
# The SDK, not filename guessing, chooses ipk/opkg or apk packaging and arch names.
make -C "$sdk_dir" defconfig
# External source files are not part of the SDK's downloaded-source stamp. Clear
# only this owned package so every invocation packages the current source tree.
make -C "$sdk_dir" package/openrhp/clean NO_DEPS=1 V=s
# These pure-Go binaries have no SDK package build dependencies. Avoid recursively
# rebuilding runtime dependencies (notably the SDK's fixed all-kmod selection).
# NO_DEPS is the SDK's supported build-graph switch; package DEPENDS metadata stays
# intact, and the target package manager must install/check runtime dependencies.
make -C "$sdk_dir" package/openrhp/compile NO_DEPS=1 V=s CONFIG_PACKAGE_openrhp-conntrack=m OPENRHP_SOURCE="$source_dir" OPENRHP_GO="$go_binary"
# Inspect the actual six current IPKs. In particular, SDK stripping must not
# corrupt already stripped Go ELF sections or their authoritative build metadata.
GO="$go_binary" python3 "$source_dir/packaging/tests/check_ipk_elf.py" --sdk "$sdk_dir" --recipe "$recipe/Makefile"
printf '%s\n' 'SDK packages are in the SDK bin/packages and bin/targets trees. These are development artifacts, not a signed release.'
