#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p test-results
arch=$(docker info --format '{{.Architecture}}')
case "$arch" in aarch64|arm64) go_arch=arm64;; x86_64|amd64) go_arch=amd64;; *) echo "Unsupported Docker test architecture: $arch" >&2; exit 1;; esac
CGO_ENABLED=0 GOOS=linux GOARCH="$go_arch" go test -c -o test-results/node-link.test ./internal/node
if ! docker image inspect routeharbor-path-lab:local >/dev/null 2>&1; then
  docker build -t routeharbor-path-lab:local docker/lab-paths
fi
docker run --rm --network none --cap-add NET_ADMIN --cap-add NET_RAW --read-only --tmpfs /tmp:rw,nosuid,nodev,size=32m \
  -e ROUTEHARBOR_NODE_LINK_LAB=1 -v "$PWD/test-results:/work/test-results:ro" \
  --entrypoint /work/test-results/node-link.test routeharbor-path-lab:local -test.run '^TestLinuxVethNodeLinkTelemetry$' -test.v
