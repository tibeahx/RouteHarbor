#!/bin/sh
# Offline release/staging checks; never calls a package manager or changes traffic.
set -eu
cd "$(dirname "$0")/.."
GO=${GO:-go}
mkdir -p test-results/release
chmod 0755 test-results/release
arch=$(docker info --format '{{.Architecture}}')
case "$arch" in aarch64|arm64) go_arch=arm64;; x86_64|amd64) go_arch=amd64;; *) echo "Unsupported Docker architecture: $arch" >&2; exit 1;; esac
CGO_ENABLED=0 GOOS=linux GOARCH="$go_arch" "$GO" test -c -o test-results/release/release-cli.test ./cmd/openrhp-release
CGO_ENABLED=0 GOOS=linux GOARCH="$go_arch" "$GO" test -c -o test-results/release/release-core.test ./internal/release
chmod 0755 test-results/release/release-cli.test test-results/release/release-core.test
if ! docker image inspect openrhp-path-lab:local >/dev/null 2>&1; then
 docker build -t openrhp-path-lab:local docker/lab-paths
fi
for binary in release-cli release-core; do
 docker run --rm --network none --read-only --cap-drop ALL \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m \
  -v "$PWD/test-results/release:/work:ro" \
  --entrypoint /usr/bin/timeout openrhp-path-lab:local -k 5s 150s \
  "/work/$binary.test" -test.v -test.timeout 120s
done
