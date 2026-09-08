#!/bin/sh
# Real nftables, policy routes, ownership refusal and SIGKILL watchdog recovery
# inside an isolated Docker Linux VM container. Never joins the host network.
set -eu
cd "$(dirname "$0")/.."
: "${GO:=go}"
: "${OPENRHP_LAB_IMAGE:=openrhp-path-lab:local}"
lab_build="$(mktemp -d "${TMPDIR:-/tmp}/openrhp-network-lab.XXXXXX")"
trap 'rm -rf "$lab_build"' EXIT HUP INT TERM
lab_arch="$(docker image inspect "$OPENRHP_LAB_IMAGE" --format '{{.Architecture}}')"
CGO_ENABLED=0 GOOS=linux GOARCH="$lab_arch" "$GO" test -c -o "$lab_build/helper.test" ./internal/helper
CGO_ENABLED=0 GOOS=linux GOARCH="$lab_arch" "$GO" build -trimpath -o "$lab_build/openrhp-helper" ./cmd/openrhp-helper
docker run --rm --network none --privileged \
 --mount "type=bind,source=$lab_build,target=/lab,readonly" \
 --env OPENRHP_NET_LAB=1 --env OPENRHP_PACKET_LAB=1 --entrypoint /bin/sh "$OPENRHP_LAB_IMAGE" -eu -c '
 mkdir -p /usr/libexec
 cp /lab/openrhp-helper /usr/libexec/openrhp-helper
 cp /lab/helper.test /usr/libexec/openrhp-helper.test
 chown root:root /usr/libexec/openrhp-helper
 chown root:root /usr/libexec/openrhp-helper.test
 chmod 0755 /usr/libexec/openrhp-helper
 chmod 0755 /usr/libexec/openrhp-helper.test
 /usr/libexec/openrhp-helper.test -test.v -test.run "^(TestLinux(RealNFTAndRoutes|ConntrackResetPreservesCurrentAndForeignFlows|ForeignDefaultPriorityRefused|IndependentWatchdogAfterHelperSIGKILL|GatewayWatchdogAfterManagerSIGKILL|LifecyclePersistedGuardAndRemoval|RollbackRetainsGuardOwnership|BootGuardCrashRecovery|PacketSupervisorAfterManagerSIGKILL|FirstUseNativeProbeRegistration)|TestNativePacketLifecycle)$"
 '
