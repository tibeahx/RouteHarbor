#!/bin/sh
# Root-owned receipt storage tests; this does not generate device verification.
set -eu
cd "$(dirname "$0")/.."
: "${GO:=go}"
lab_build=$(mktemp -d)
trap 'rm -rf "$lab_build"' EXIT HUP INT TERM
lab_arch=$(docker image inspect openrhp-path-lab:local --format '{{.Architecture}}')
CGO_ENABLED=0 GOOS=linux GOARCH="$lab_arch" "$GO" test -c -o "$lab_build/wireless.test" ./internal/wireless
# This directory contains only a test executable. On native Linux the bind mount
# retains the host UID; the capability-free container must be able to traverse it.
chmod 0755 "$lab_build" "$lab_build/wireless.test"
docker run --rm --network none --read-only --cap-drop ALL --cap-add CHOWN \
  --tmpfs /tmp:rw,nosuid,nodev,size=16m \
  --mount "type=bind,source=$lab_build,target=/lab,readonly" \
  --entrypoint /lab/wireless.test openrhp-path-lab:local -test.v
