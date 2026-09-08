#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$1" != --fix ]; }; then
  echo 'Usage: scripts/lint.sh [--fix]' >&2
  exit 2
fi
go_binary=${GO:-go}
go_directory=$(dirname "$(command -v "$go_binary")")
PATH="$go_directory:$PATH"
export PATH
linter=$(sh scripts/install-golangci-lint.sh)
"$linter" version
host_os=$("$go_binary" env GOHOSTOS)
host_arch=$("$go_binary" env GOHOSTARCH)
printf 'Linting host source and tests (%s/%s)\n' "$host_os" "$host_arch"
status=0
CGO_ENABLED=0 GOOS="$host_os" GOARCH="$host_arch" "$linter" run --config .golangci.yml "$@" ./... || status=1
if [ "$host_os/$host_arch" != linux/amd64 ]; then
  printf '%s\n' 'Linting Linux source and tests (linux/amd64)'
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$linter" run --config .golangci.yml "$@" ./... || status=1
fi
exit "$status"
