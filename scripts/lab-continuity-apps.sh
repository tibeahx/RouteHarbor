#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
: "${GO:=go}"
: "${ROUTEHARBOR_CONTINUITY_APP_IMAGE:=routeharbor-continuity-app-lab:local}"
mkdir -p test-results/continuity
if ! docker image inspect "$ROUTEHARBOR_CONTINUITY_APP_IMAGE" >/dev/null 2>&1; then
  docker build -t "$ROUTEHARBOR_CONTINUITY_APP_IMAGE" docker/lab-continuity-apps
fi
lab_arch=$(docker image inspect "$ROUTEHARBOR_CONTINUITY_APP_IMAGE" --format '{{.Architecture}}')
case "$lab_arch" in arm64|amd64) ;; *) echo 'Unsupported Linux lab architecture' >&2; exit 1;; esac
CGO_ENABLED=0 GOOS=linux GOARCH="$lab_arch" "$GO" test -c -o test-results/continuity/applications.test ./internal/continuity
docker run --rm --network none --read-only --cap-drop ALL --cap-add NET_ADMIN \
  --cap-add SETUID --cap-add SETGID --cap-add SYS_CHROOT --cap-add CHOWN \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m --tmpfs /run:rw,nosuid,nodev,size=8m \
  --memory 512m --pids-limit 128 \
  --mount "type=bind,src=$PWD/test-results/continuity,dst=/tests,readonly" \
  --entrypoint /tests/applications.test -e ROUTEHARBOR_CONTINUITY_APP_LAB=1 \
  "$ROUTEHARBOR_CONTINUITY_APP_IMAGE" -test.v -test.run '^TestLinuxContinuityApplications$' -test.timeout 3m
