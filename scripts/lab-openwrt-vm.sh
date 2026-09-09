#!/bin/sh
# Boot the already verified OpenWrt image under QEMU TCG in an isolated Docker VM.
# No downloads, host networking, published ports, physical NICs or block devices.
set -eu
cd "$(dirname "$0")/.."
[ "$#" -eq 4 ] || { echo 'Usage: scripts/lab-openwrt-vm.sh /absolute/verified-image-directory /absolute/private-state-directory /absolute/sdk-packages /absolute/verified-dependencies' >&2; exit 2; }
for path in "$@"; do
 case "$path" in /*) ;; *) echo 'All lab input/state paths must be absolute.' >&2; exit 2 ;; esac
 [ -d "$path" ] && [ ! -L "$path" ] || { echo 'Lab input/state directories must exist and not be symbolic links.' >&2; exit 2; }
done
lab_name=openrhp-openwrt-boot-lab
lab_control=/lab/vmctl.py
case "${OPENRHP_VM_PROFILE:-x86-64}" in
 x86-64) ;;
 x86-generic) lab_name=openrhp-openwrt-i386-lab; lab_control=/lab/vmctl-i386.py ;;
 *) echo 'Only the pinned x86-64 and x86-generic VM profiles are supported.' >&2; exit 2 ;;
esac
lab_image=${OPENRHP_VM_IMAGE:-openrhp-openwrt-vm:24.10.7}
if docker container inspect "$lab_name" >/dev/null 2>&1; then
 [ "$(docker inspect --format '{{ index .Config.Labels "org.openrhp.lab" }}' "$lab_name")" = full-boot ] || { echo 'Container name belongs to another task.' >&2; exit 1; }
 [ "$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$lab_name")" = none ] || { echo 'The lab must use Docker network none.' >&2; exit 1; }
 [ "$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/state"}}{{.Source}}{{end}}{{end}}' "$lab_name")" = "$2" ] || { echo 'Stop the existing lab before selecting another private state directory.' >&2; exit 1; }
else
 docker run --detach --rm --name "$lab_name" --label org.openrhp.lab=full-boot --network none --privileged \
  --mount "type=bind,source=$1,target=/inputs,readonly" \
  --mount "type=bind,source=$2,target=/state" \
  --mount "type=bind,source=$3,target=/packages,readonly" \
  --mount "type=bind,source=$4,target=/dependencies,readonly" \
  --mount "type=bind,source=$(pwd)/docker/lab-openwrt-vm,target=/lab,readonly" "$lab_image"
fi
docker exec "$lab_name" python3 "$lab_control" up
