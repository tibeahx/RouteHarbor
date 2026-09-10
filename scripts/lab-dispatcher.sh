#!/bin/sh
# Pinned sing-box schema and actual LAN dispatch in an isolated Linux namespace.
set -eu
cd "$(dirname "$0")/.."
: "${GO:=go}"
: "${OPENRHP_ENGINE_LAB_IMAGE:=openrhp-engine-lab:local}"
lab_build="$(mktemp -d "${TMPDIR:-/tmp}/openrhp-dispatcher-lab.XXXXXX")"
trap 'rm -rf "$lab_build"' EXIT HUP INT TERM
lab_arch="$(docker image inspect "$OPENRHP_ENGINE_LAB_IMAGE" --format '{{.Architecture}}')"
CGO_ENABLED=0 GOOS=linux GOARCH="$lab_arch" "$GO" test -c -o "$lab_build/dispatch.test" ./internal/dispatch
docker run --rm --network none --privileged \
 --mount "type=bind,source=$lab_build,target=/lab,readonly" \
 --env OPENRHP_DISPATCH_LAB=1 --entrypoint /bin/sh "$OPENRHP_ENGINE_LAB_IMAGE" -eu -c '
 /lab/dispatch.test -test.v -test.run "^TestDispatcher(NativeConfigChecks|SameIPDomainIsolation)$"
 '
