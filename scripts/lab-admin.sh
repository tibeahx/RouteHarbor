#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
build_dir=$(mktemp -d /tmp/routeharbor-admin-lab.XXXXXX)
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM
arch=$(docker info --format '{{.Architecture}}')
case "$arch" in aarch64|arm64) go_arch=arm64;; x86_64|amd64) go_arch=amd64;; *) echo "Unsupported Docker test architecture: $arch" >&2; exit 1;; esac
CGO_ENABLED=0 GOOS=linux GOARCH="$go_arch" go build -o "$build_dir/routeharbor" ./cmd/routeharbor
cp docker/lab-admin/test.py "$build_dir/test.py"
if ! docker image inspect routeharbor-path-lab:local >/dev/null 2>&1; then
  docker build -t routeharbor-path-lab:local docker/lab-paths
fi
docker build -f "$PWD/docker/lab-admin/Dockerfile" -t routeharbor-admin-lab:local "$build_dir"
docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,nodev,size=32m \
  --tmpfs /etc/routeharbor:rw,nosuid,nodev,size=32m,mode=0700 \
  --tmpfs /root/test-private:rw,nosuid,nodev,size=32m,mode=0700 routeharbor-admin-lab:local
