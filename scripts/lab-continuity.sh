#!/bin/sh
# Real Linux, isolated carrier failures. This never attaches to a physical WAN.
set -eu
cd "$(dirname "$0")/.."
: "${GO:=go}"
: "${OPENRHP_CONTINUITY_LAB_IMAGE:=openrhp-path-lab:local}"
: "${OPENRHP_CONTINUITY_SWITCHES:=1000}"
mkdir -p test-results/continuity
lab_arch=$(docker image inspect "$OPENRHP_CONTINUITY_LAB_IMAGE" --format '{{.Architecture}}')
case "$lab_arch" in arm64|amd64) ;; *) echo 'Unsupported Linux lab architecture' >&2; exit 1;; esac
CGO_ENABLED=0 GOOS=linux GOARCH="$lab_arch" "$GO" test -c -o test-results/continuity/continuity.test ./internal/continuity
docker run --rm --network none --read-only --cap-drop ALL --cap-add NET_ADMIN \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m --memory 512m --pids-limit 128 \
  --mount "type=bind,src=$PWD/test-results/continuity,dst=/tests,readonly" \
  --entrypoint /tests/continuity.test \
  -e OPENRHP_CONTINUITY_LAB=1 -e "OPENRHP_CONTINUITY_SWITCHES=$OPENRHP_CONTINUITY_SWITCHES" \
  "$OPENRHP_CONTINUITY_LAB_IMAGE" -test.v -test.run '^TestLinuxContinuityQualification$' -test.timeout 15m
