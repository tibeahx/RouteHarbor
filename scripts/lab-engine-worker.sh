#!/bin/sh
# Native engine privilege boundary and owner-lifetime checks in an isolated VM.
set -eu
cd "$(dirname "$0")/.."
: "${GO:=go}"
: "${OPENRHP_ENGINE_LAB_IMAGE:=openrhp-engine-lab:local}"
lab_build="$(mktemp -d "${TMPDIR:-/tmp}/openrhp-engine-worker.XXXXXX")"
trap 'rm -rf "$lab_build"' EXIT HUP INT TERM
lab_arch="$(docker image inspect "$OPENRHP_ENGINE_LAB_IMAGE" --format '{{.Architecture}}')"
CGO_ENABLED=0 GOOS=linux GOARCH="$lab_arch" "$GO" test -c -o "$lab_build/helper.test" ./internal/helper
CGO_ENABLED=0 GOOS=linux GOARCH="$lab_arch" "$GO" build -trimpath -o "$lab_build/openrhp-helper" ./cmd/openrhp-helper
docker run --rm --network none --privileged \
 --mount "type=bind,source=$lab_build,target=/lab,readonly" \
 --env OPENRHP_NET_LAB=1 --env OPENRHP_ENGINE_WORKER_LAB=1 \
 --entrypoint /bin/sh "$OPENRHP_ENGINE_LAB_IMAGE" -eu -c '
 mkdir -p /usr/libexec
 cp /lab/openrhp-helper /usr/libexec/openrhp-helper
 chown root:root /usr/libexec/openrhp-helper
 chmod 0755 /usr/libexec/openrhp-helper
 /lab/helper.test -test.v -test.run "^TestLinuxManagedEngine(WorkerPrivilegesAndCleanup|RPCUnprivilegedAPIAndCrashCleanup|AfterHelperSIGKILL)$"
 '
