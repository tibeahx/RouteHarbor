#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
GO=${GO:-go}
OUT=${OUT:-dist}
mkdir -p "$OUT"
printf 'binary,target,goarch,abi,bytes\n' > "$OUT/build-matrix.csv"
for target in amd64 386 armv5 armv6 armv7 arm64 mips-softfloat mipsle-softfloat mips64-softfloat mips64le-softfloat riscv64; do
  arch=$target
  arm=7
  case "$target" in
    armv*) arch=arm; arm=${target#armv} ;;
    mips*-*) arch=${target%-*} ;;
  esac
  if [ "${PROTOTYPE:-0}" = 1 ]; then programs=prototype; else programs="routeharbor routeharbor-helper routeharbor-node routeharbor-release routeharbor-continuity routeharbor-relay"; fi
  for program in $programs; do
  if [ "$program" = prototype ]; then entry=./scripts/prototypes/minimal.go; else entry=./cmd/$program; fi
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOARM="$arm" GOMIPS=softfloat GOMIPS64=softfloat "$GO" build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$OUT/$program-linux-$target" "$entry"
  bytes=$(wc -c < "$OUT/$program-linux-$target" | tr -d ' ')
  printf '%s,%s,%s,%s,%s\n' "$program" "$target" "$arch" "$target" "$bytes" >> "$OUT/build-matrix.csv"
  done
done
cat "$OUT/build-matrix.csv"
