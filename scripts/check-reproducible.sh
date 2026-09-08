#!/bin/sh
# Compare the same source from different absolute paths with empty separate caches.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${GO:=go}"
check_tmp=$(mktemp -d)
trap 'rm -rf "$check_tmp"' EXIT HUP INT TERM
mkdir -p "$check_tmp/source-first" "$check_tmp/source-second"
# Freeze the input once so concurrent workspace edits cannot change one build only.
cp -R "$root/go.mod" "$root/api" "$root/cmd" "$root/internal" "$check_tmp/source-first/"
cp -R "$check_tmp/source-first/." "$check_tmp/source-second/"
for pass in first second; do
  source_dir="$check_tmp/source-$pass"
  (cd "$source_dir" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=local GOCACHE="$check_tmp/cache-$pass" "$GO" build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$check_tmp/$pass" ./cmd/openrhp)
done
cmp "$check_tmp/first" "$check_tmp/second"
printf '%s\n' 'PASS: Linux amd64 controller is byte-identical across source paths and empty build caches.'
