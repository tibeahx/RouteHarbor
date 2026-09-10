#!/bin/sh
# Real selective nft and route guards in a network-isolated Linux container.
set -eu
cd "$(dirname "$0")/.."
: "${GO:=go}"
: "${ROUTEHARBOR_LAB_IMAGE:=routeharbor-path-lab:local}"
lab_build="$(mktemp -d "${TMPDIR:-/tmp}/routeharbor-selective-lab.XXXXXX")"
trap 'rm -rf "$lab_build"' EXIT HUP INT TERM
lab_arch="$(docker image inspect "$ROUTEHARBOR_LAB_IMAGE" --format '{{.Architecture}}')"
CGO_ENABLED=0 GOOS=linux GOARCH="$lab_arch" "$GO" test -c -o "$lab_build/helper.test" ./internal/helper
CGO_ENABLED=0 GOOS=linux GOARCH="$lab_arch" "$GO" build -trimpath -o "$lab_build/routeharbor-helper" ./cmd/routeharbor-helper
docker run --rm --network none --privileged \
 --mount "type=bind,source=$lab_build,target=/lab,readonly" \
 --env ROUTEHARBOR_NET_LAB=1 --entrypoint /bin/sh "$ROUTEHARBOR_LAB_IMAGE" -eu -c '
 mkdir -p /usr/libexec
 cp /lab/routeharbor-helper /usr/libexec/routeharbor-helper
 chown root:root /usr/libexec/routeharbor-helper
 chmod 0755 /usr/libexec/routeharbor-helper
 /lab/helper.test -test.v -test.run "^TestLinuxSelective(EmergencyAndNativeGuards|DetachedWatchdogAfterHelperDeath|MigrationRemovesLegacyGlobalBlackhole|DecommissionPreservesClosedAcrossBoot|CompletedEmergencyRepairsPolicyReset)$"
 '
