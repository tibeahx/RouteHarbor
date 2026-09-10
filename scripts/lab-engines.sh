#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
command -v docker >/dev/null || { echo 'Docker is required.' >&2; exit 1; }
: "${GO:=go}"
command -v "$GO" >/dev/null || { echo 'The pinned Go toolchain is required.' >&2; exit 1; }
arch=$(docker info --format '{{.Architecture}}')
case "$arch" in aarch64|arm64) go_arch=arm64;; x86_64|amd64) go_arch=amd64;; *) echo 'Native engine lab supports amd64 and arm64 only.' >&2; exit 1;; esac
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
(cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH="$go_arch" "$GO" test -c -o "$tmp/adapter.test" ./internal/adapter)
docker build -t routeharbor-path-lab:local -f "$root/docker/lab-paths/Dockerfile" "$root/docker/lab-paths"
docker build -t routeharbor-engine-lab:local -f "$root/docker/lab-engines/Dockerfile" "$root/docker/lab-engines"
docker run --rm --network none --entrypoint /tests/adapter.test -e ROUTEHARBOR_ENGINE_LAB=1 --mount "type=bind,src=$tmp,dst=/tests,readonly" routeharbor-engine-lab:local -test.v -test.run TestPinnedNativeEngine
