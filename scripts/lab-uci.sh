#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p test-results
arch=$(docker info --format '{{.Architecture}}')
case "$arch" in aarch64|arm64) go_arch=arm64;; x86_64|amd64) go_arch=amd64;; *) echo "Unsupported Docker test architecture: $arch" >&2; exit 1;; esac
CGO_ENABLED=0 GOOS=linux GOARCH="$go_arch" go test -c -o test-results/node-uci.test ./internal/node
CGO_ENABLED=0 GOOS=linux GOARCH="$go_arch" go test -c -o test-results/gateway-uci.test ./internal/coverage
if ! docker image inspect routeharbor-path-lab:local >/dev/null 2>&1; then
  docker build -t routeharbor-path-lab:local docker/lab-paths
fi
docker build -f docker/lab-uci/Dockerfile -t routeharbor-uci-lab:local .
docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,nodev,size=64m -v "$PWD/test-results:/work/test-results:ro" routeharbor-uci-lab:local
docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,nodev,size=64m -v "$PWD/test-results:/work/test-results:ro" routeharbor-uci-lab:local /work/test-results/gateway-uci.test -test.run "TestGateway.*RealUCI" -test.v
