#!/bin/sh
# Native detector/classifier and selective relay composition; no external WAN.
set -eu
cd "$(dirname "$0")/.."
: "${GO:=go}"
: "${OPENRHP_ENGINE_LAB_IMAGE:=openrhp-engine-lab:local}"
lab_build="$(mktemp -d "${TMPDIR:-/tmp}/openrhp-selective-acceptance.XXXXXX")"
trap 'rm -rf "$lab_build"' EXIT HUP INT TERM
lab_arch="$(docker image inspect "$OPENRHP_ENGINE_LAB_IMAGE" --format '{{.Architecture}}')"
CGO_ENABLED=0 GOOS=linux GOARCH="$lab_arch" "$GO" test -c -o "$lab_build/acceptance.test" ./internal/continuityrun
for test in TestLinuxSelectiveLearnsThroughActualTLSAndHotRules TestLinuxSelectiveRelaySwitchAndFailurePreserveDirect; do
 docker run --rm --network none --privileged --memory 512m --memory-swap 512m --pids-limit 256 \
  --mount "type=bind,source=$lab_build,target=/lab,readonly" \
  --env OPENRHP_SELECTIVE_ACCEPTANCE_LAB=1 --entrypoint /lab/acceptance.test \
  "$OPENRHP_ENGINE_LAB_IMAGE" -test.v -test.run "^$test$" -test.timeout 120s
done
