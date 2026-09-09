#!/bin/sh
# User-mode CPU emulation only: not OpenWrt kernel, package ABI, or physical hardware acceptance.
set -eu
cd "$(dirname "$0")/.."
GO=${GO:-go}
targets='armv5 armv6 armv7 mips-softfloat mipsle-softfloat mips64-softfloat mips64le-softfloat 386 riscv64'
output=test-results/abi
if [ "$#" -gt 0 ]; then
 targets="$*"
 label=
 for target in "$@"; do
  case "$target" in
   armv5|armv6|armv7|mips-softfloat|mipsle-softfloat|mips64-softfloat|mips64le-softfloat|386|riscv64) ;;
   *) printf 'Unsupported ABI target: %s\n' "$target" >&2; exit 2 ;;
  esac
  label="${label}${label:+-}${target}"
 done
 # Targeted follow-ups never overwrite the original complete-run evidence.
 output="test-results/abi-$label"
fi
mkdir -p "$output"
chmod 0755 "$output"
if ! docker image inspect openrhp-path-lab:local >/dev/null 2>&1; then
 docker build -t openrhp-path-lab:local docker/lab-paths
fi
docker build -t openrhp-abi-lab:local docker/lab-abi
{
 "$GO" version
 git rev-parse HEAD
 git status --short
 docker image inspect openrhp-abi-lab:local --format '{{.Id}}'
 docker run --rm --network none --read-only --cap-drop ALL openrhp-abi-lab:local \
  /bin/sh -c 'uname -sm; dpkg-query -W qemu-user-static; qemu-mips64-static --version'
} > "$output/environment.txt"
failed=0
printf 'target,package,emulator,cpu,result\n' > "$output/results.csv"
for target in $targets; do
 arch=$target
 arm=7
 cpu=max
 case "$target" in
  armv5) arch=arm; arm=5; emulator=qemu-arm-static; cpu=arm926 ;;
  armv6) arch=arm; arm=6; emulator=qemu-arm-static; cpu=arm1176 ;;
  armv7) arch=arm; arm=7; emulator=qemu-arm-static; cpu=cortex-a9 ;;
  mips-softfloat) arch=mips; emulator=qemu-mips-static; cpu=24Kc ;;
  mipsle-softfloat) arch=mipsle; emulator=qemu-mipsel-static; cpu=24Kc ;;
  mips64-softfloat) arch=mips64; emulator=qemu-mips64-static; cpu=5Kc ;;
  mips64le-softfloat) arch=mips64le; emulator=qemu-mips64el-static; cpu=5Kc ;;
  386) emulator=qemu-i386-static; cpu=qemu32 ;;
  riscv64) emulator=qemu-riscv64-static; cpu=rv64 ;;
 esac
 for suite in selection config release; do
  package=./internal/$suite
  if [ "$suite" = release ]; then package=./cmd/openrhp-release; fi
  binary="$target-$suite.test"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOARM="$arm" GOMIPS=softfloat GOMIPS64=softfloat \
   "$GO" test -c -o "$output/$binary" "$package"
  chmod 0755 "$output/$binary"
  printf 'Executing %s on %s (%s)\n' "$suite" "$target" "$cpu"
  if docker run --rm --network none --read-only --cap-drop ALL \
   --tmpfs /tmp:rw,nosuid,nodev,size=64m \
   -v "$PWD/$output:/work:ro" \
   openrhp-abi-lab:local /usr/bin/timeout -k 5s 180s "/usr/bin/$emulator" -cpu "$cpu" "/work/$binary" \
   -test.timeout 120s > "$output/$target-$suite.log" 2>&1; then
   printf '%s,%s,%s,%s,PASS\n' "$target" "$suite" "$emulator" "$cpu" >> "$output/results.csv"
  else
   printf '%s,%s,%s,%s,FAIL\n' "$target" "$suite" "$emulator" "$cpu" >> "$output/results.csv"
   cat "$output/$target-$suite.log"
   failed=1
  fi
 done
done
printf 'target,emulator,cpu,result\n' > "$output/stdlib-results.csv"
# No project imports: separate emulator/runtime failures from application behavior.
controls=
case " $targets " in *' mips64-softfloat '*) controls="$controls mips64-first mips64-second" ;; esac
case " $targets " in *' 386 '*) controls="$controls 386-first 386-second" ;; esac
for variant in $controls; do
 case "$variant" in
  mips64-first) arch=mips64; emulator=qemu-mips64-static; cpu=5Kc ;;
  mips64-second) arch=mips64; emulator=qemu-mips64-static; cpu=MIPS64R2-generic ;;
  386-first) arch=386; emulator=qemu-i386-static; cpu=qemu32 ;;
  386-second) arch=386; emulator=qemu-i386-static; cpu=max ;;
 esac
 CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOMIPS64=softfloat \
  "$GO" build -o "$output/stdlib-$arch" ./scripts/testdata/abi-netpoll
 chmod 0755 "$output/stdlib-$arch"
 if docker run --rm --network none --read-only --cap-drop ALL \
  --tmpfs /tmp:rw,nosuid,nodev,size=16m -v "$PWD/$output:/work:ro" \
  openrhp-abi-lab:local /usr/bin/timeout -k 2s 30s "/usr/bin/$emulator" \
  -cpu "$cpu" "/work/stdlib-$arch" > "$output/stdlib-$variant.log" 2>&1; then
  printf '%s,%s,%s,PASS\n' "$arch" "$emulator" "$cpu" >> "$output/stdlib-results.csv"
 else
  printf '%s,%s,%s,FAIL\n' "$arch" "$emulator" "$cpu" >> "$output/stdlib-results.csv"
  failed=1
 fi
done
cat "$output/results.csv"
cat "$output/stdlib-results.csv"
exit "$failed"
