#!/bin/sh
# Production helper RPC, privilege drop, inherited FD, DNS and owner lifetime.
# All sockets and processes run in a disposable disconnected Linux container.
set -eu
cd "$(dirname "$0")/.."
: "${GO:=go}"
: "${OPENRHP_ENGINE_LAB_IMAGE:=openrhp-engine-lab:local}"
: "${OPENRHP_DISPATCHER_LAB_MEMORY:=512m}"
lab_build="$(mktemp -d "${TMPDIR:-/tmp}/openrhp-dispatcher-worker.XXXXXX")"
trap 'rm -rf "$lab_build"' EXIT HUP INT TERM
lab_arch="$(docker image inspect "$OPENRHP_ENGINE_LAB_IMAGE" --format '{{.Architecture}}')"
case "$lab_arch" in arm64|amd64) ;; *) echo 'Unsupported Linux lab architecture' >&2; exit 1;; esac
CGO_ENABLED=0 GOOS=linux GOARCH="$lab_arch" "$GO" test -c -o "$lab_build/helper.test" ./internal/helper
CGO_ENABLED=0 GOOS=linux GOARCH="$lab_arch" "$GO" build -trimpath -o "$lab_build/openrhp-helper" ./cmd/openrhp-helper
scale_fixture=
if [ -n "${OPENRHP_DISPATCHER_SCALE_DOMAINS:-}" ]; then
 cp "$OPENRHP_DISPATCHER_SCALE_DOMAINS" "$lab_build/domains.lst"
 chmod 0644 "$lab_build/domains.lst"
 scale_fixture=/lab/domains.lst
fi
docker run --rm --network none --privileged --memory "$OPENRHP_DISPATCHER_LAB_MEMORY" \
 --memory-swap "$OPENRHP_DISPATCHER_LAB_MEMORY" --pids-limit 256 \
 --mount "type=bind,source=$lab_build,target=/lab,readonly" \
 --env OPENRHP_NET_LAB=1 --env OPENRHP_DISPATCHER_WORKER_LAB=1 \
 --env "OPENRHP_DISPATCHER_SCALE_DOMAINS=$scale_fixture" \
 --env "OPENRHP_DISPATCHER_SCALE_WORKERS=${OPENRHP_DISPATCHER_SCALE_WORKERS:-1}" \
 --entrypoint /bin/sh "$OPENRHP_ENGINE_LAB_IMAGE" -eu -c '
 mkdir -p /usr/libexec
 cp /lab/openrhp-helper /usr/libexec/openrhp-helper
 cp /lab/helper.test /usr/libexec/openrhp-lab-helper.test
 chown root:root /usr/libexec/openrhp-helper /usr/libexec/openrhp-lab-helper.test
 chmod 0755 /usr/libexec/openrhp-helper /usr/libexec/openrhp-lab-helper.test
 ip address add 11.0.0.2/32 dev lo
 ip address add 11.0.0.53/32 dev lo
 lab_status=0
 /usr/libexec/openrhp-lab-helper.test -test.v -test.run "^TestLinuxDispatcherWorkerRPCPrivilegesDNSAndOwnerCleanup$" -test.timeout 150s || lab_status=$?
 if [ -r /sys/fs/cgroup/memory.peak ]; then
  printf "container memory peak bytes: "
  cat /sys/fs/cgroup/memory.peak
 fi
 if [ -r /sys/fs/cgroup/memory.events ]; then cat /sys/fs/cgroup/memory.events; fi
 exit "$lab_status"
 '
