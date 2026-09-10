#!/bin/sh
set -eu
umask 077
version=2.13.2
system=$(uname -s)
machine=$(uname -m)
case "$system/$machine" in
  Darwin/arm64) release=darwin-arm64; digest=f4bf83f0b64f055c42b28fc9a38861839f69c096e61c788e72dfaae412011789 ;;
  Darwin/x86_64) release=darwin-amd64; digest=8a13aaf9cbbb1dee52824e862cf0d0720e5bb97c1f4260d1e51623a09492b57b ;;
  Linux/x86_64) release=linux-amd64; digest=2277d43b98ec0054280f2ac26b53268bae97682444678a59a657dd565da021d6 ;;
  Linux/aarch64|Linux/arm64) release=linux-arm64; digest=a2a4e0065aa41be71f7c5ac90f271b61751331e5d04314e62afe4027855f0893 ;;
  *) echo "No verified golangci-lint archive is pinned for $system/$machine" >&2; exit 1 ;;
esac
tool_root=${ROUTEHARBOR_TOOLS_DIR:-"$(pwd)/.local/tools"}
mkdir -p "$tool_root/golangci-lint-$version-$release"
tool_dir=$(cd "$tool_root/golangci-lint-$version-$release" && pwd)
archive="$tool_dir/archive.tar.gz"
if [ ! -f "$archive" ]; then
  download=$(mktemp "$tool_dir/download.XXXXXX")
  trap 'rm -f "$download"' EXIT HUP INT TERM
  curl --fail --silent --show-error --location --proto '=https' --retry 3 \
    "https://github.com/golangci/golangci-lint/releases/download/v$version/golangci-lint-$version-$release.tar.gz" -o "$download"
  mv "$download" "$archive"
  trap - EXIT HUP INT TERM
fi
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$archive" | cut -d ' ' -f 1)
else
  actual=$(shasum -a 256 "$archive" | cut -d ' ' -f 1)
fi
[ "$actual" = "$digest" ] || { echo 'golangci-lint archive checksum mismatch; nothing was executed.' >&2; exit 1; }
# Extract afresh from the verified archive, so a stale cached executable is never trusted.
tar -xzf "$archive" -C "$tool_dir" --strip-components=1 "golangci-lint-$version-$release/golangci-lint"
printf '%s\n' "$tool_dir/golangci-lint"
