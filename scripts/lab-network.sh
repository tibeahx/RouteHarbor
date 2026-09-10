#!/bin/sh
# Real nftables, policy routes, ownership refusal and SIGKILL watchdog recovery
# inside an isolated Docker Linux VM container. Never joins the host network.
set -eu
cd "$(dirname "$0")/.."
: "${GO:=go}"
: "${ROUTEHARBOR_LAB_IMAGE:=routeharbor-path-lab:local}"
lab_build="$(mktemp -d "${TMPDIR:-/tmp}/routeharbor-network-lab.XXXXXX")"
trap 'rm -rf "$lab_build"' EXIT HUP INT TERM
lab_arch="$(docker image inspect "$ROUTEHARBOR_LAB_IMAGE" --format '{{.Architecture}}')"
CGO_ENABLED=0 GOOS=linux GOARCH="$lab_arch" "$GO" test -c -o "$lab_build/helper.test" ./internal/helper
CGO_ENABLED=0 GOOS=linux GOARCH="$lab_arch" "$GO" build -trimpath -o "$lab_build/routeharbor-helper" ./cmd/routeharbor-helper
docker run --rm --network none --privileged \
 --mount "type=bind,source=$lab_build,target=/lab,readonly" \
 --env ROUTEHARBOR_NET_LAB=1 --env ROUTEHARBOR_PACKET_LAB=1 --entrypoint /bin/sh "$ROUTEHARBOR_LAB_IMAGE" -eu -c '
 mkdir -p /usr/libexec
 cp /lab/routeharbor-helper /usr/libexec/routeharbor-helper
 cp /lab/helper.test /usr/libexec/routeharbor-helper.test
 chown root:root /usr/libexec/routeharbor-helper
 chown root:root /usr/libexec/routeharbor-helper.test
 chmod 0755 /usr/libexec/routeharbor-helper
 chmod 0755 /usr/libexec/routeharbor-helper.test
 /usr/libexec/routeharbor-helper.test -test.v -test.run "^(TestLinux(RealNFTAndRoutes|ConntrackResetPreservesCurrentAndForeignFlows|ForeignDefaultPriorityRefused|IndependentWatchdogAfterHelperSIGKILL|GatewayWatchdogAfterManagerSIGKILL|LifecyclePersistedGuardAndRemoval|RollbackRetainsGuardOwnership|BootGuardCrashRecovery|EarlyBootGuardBeforeNetworkDevices|BridgeIngressGuard|DNSGuardSurvivesNFTFlushAndPreservesOtherUID|DNSUnsafeSourceProfiles|PacketSupervisorAfterManagerSIGKILL|FirstUseNativeProbeRegistration)|TestNativePacketLifecycle)$"
 '
