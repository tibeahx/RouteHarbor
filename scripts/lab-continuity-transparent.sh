#!/bin/sh
# Real transparent LAN traffic; all interfaces live in a disposable container.
set -eu
cd "$(dirname "$0")/.."
: "${GO:=go}"
: "${ROUTEHARBOR_CONTINUITY_LAB_IMAGE:=routeharbor-path-lab:local}"
mkdir -p test-results/continuity-transparent
lab_arch=$(docker image inspect "$ROUTEHARBOR_CONTINUITY_LAB_IMAGE" --format '{{.Architecture}}')
case "$lab_arch" in arm64|amd64) ;; *) echo 'Unsupported Linux lab architecture' >&2; exit 1;; esac
CGO_ENABLED=0 GOOS=linux GOARCH="$lab_arch" "$GO" test -c \
  -o test-results/continuity-transparent/helper.test ./internal/helper
CGO_ENABLED=0 GOOS=linux GOARCH="$lab_arch" "$GO" build \
  -o test-results/continuity-transparent/routeharbor-helper ./cmd/routeharbor-helper
CGO_ENABLED=0 GOOS=linux GOARCH="$lab_arch" "$GO" build \
  -o test-results/continuity-transparent/routeharbor-continuity ./cmd/routeharbor-continuity
# Privilege is confined to the disconnected container: the test creates nested
# network namespaces, nftables rules and typed transparent sockets. Its only
# host mount contains the freshly built executables and is read-only.
docker run --rm --network none --privileged --memory 512m --pids-limit 256 \
  --mount "type=bind,src=$PWD/test-results/continuity-transparent,dst=/lab,readonly" \
  -e ROUTEHARBOR_NET_LAB=1 --entrypoint /bin/sh "$ROUTEHARBOR_CONTINUITY_LAB_IMAGE" -ec '
    install -d -m 0755 /usr/libexec
    install -m 0755 /lab/routeharbor-helper /usr/libexec/routeharbor-helper
    install -m 0755 /lab/routeharbor-continuity /usr/libexec/routeharbor-continuity
    /lab/helper.test -test.v -test.run "^TestLinuxContinuityTransparentE2E$" -test.timeout 90s
  '
