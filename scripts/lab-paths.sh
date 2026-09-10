#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
command -v docker >/dev/null || { echo 'Docker is required for the isolated Linux path lab.' >&2; exit 1; }
docker build -t routeharbor-path-lab:local -f "$root/docker/lab-paths/Dockerfile" "$root/docker/lab-paths"
# Privileges apply only to the disposable Docker VM container. No host network or mounts are used.
docker run --rm --privileged --network none routeharbor-path-lab:local
