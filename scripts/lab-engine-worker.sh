#!/bin/sh
# Native engine privilege boundary and owner-lifetime checks in an isolated VM.
set -eu
cd "$(dirname "$0")/.."
: "${GO:=go}"
: "${ROUTEHARBOR_ENGINE_LAB_IMAGE:=routeharbor-engine-lab:local}"
lab_build="$(mktemp -d "${TMPDIR:-/tmp}/routeharbor-engine-worker.XXXXXX")"
trap 'rm -rf "$lab_build"' EXIT HUP INT TERM
lab_arch="$(docker image inspect "$ROUTEHARBOR_ENGINE_LAB_IMAGE" --format '{{.Architecture}}')"
CGO_ENABLED=0 GOOS=linux GOARCH="$lab_arch" "$GO" test -c -o "$lab_build/helper.test" ./internal/helper
CGO_ENABLED=0 GOOS=linux GOARCH="$lab_arch" "$GO" build -trimpath -o "$lab_build/routeharbor-helper" ./cmd/routeharbor-helper
docker run --rm --network none --privileged \
 --mount "type=bind,source=$lab_build,target=/lab,readonly" \
 --env ROUTEHARBOR_NET_LAB=1 --env ROUTEHARBOR_ENGINE_WORKER_LAB=1 \
 --entrypoint /bin/sh "$ROUTEHARBOR_ENGINE_LAB_IMAGE" -eu -c '
 mkdir -p /usr/libexec
 cp /lab/routeharbor-helper /usr/libexec/routeharbor-helper
 # The host mktemp directory is 0700. An unprivileged fixture must not execute
 # through that bind mount; copy the public test binary to a traversable path.
 cp /lab/helper.test /usr/libexec/routeharbor-lab-helper.test
 chown root:root /usr/libexec/routeharbor-helper /usr/libexec/routeharbor-lab-helper.test
 chmod 0755 /usr/libexec/routeharbor-helper /usr/libexec/routeharbor-lab-helper.test
 /usr/libexec/routeharbor-lab-helper.test -test.v -test.run "^TestLinuxManagedEngine(WorkerPrivilegesAndCleanup|RPCUnprivilegedAPIAndCrashCleanup|AfterHelperSIGKILL)$"
 '
