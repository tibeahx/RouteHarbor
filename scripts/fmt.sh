#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$1" != --check ]; }; then
  echo 'Usage: scripts/fmt.sh [--check]' >&2
  exit 2
fi
go_binary=${GO:-go}
go_directory=$(dirname "$(command -v "$go_binary")")
PATH="$go_directory:$PATH"
export PATH
formatter=$(sh scripts/install-golangci-lint.sh)
if [ "$#" -eq 0 ]; then
  "$formatter" fmt --config .golangci.yml ./...
else
  report=$(mktemp "${TMPDIR:-/tmp}/openrhp-format.XXXXXX")
  trap 'rm -f "$report"' EXIT HUP INT TERM
  "$formatter" fmt --config .golangci.yml --diff ./... > "$report"
  if [ -s "$report" ]; then
    cat "$report"
    echo 'Go formatting differs; run make fmt and review the result.' >&2
    exit 1
  fi
fi
