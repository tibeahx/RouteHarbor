#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
: "${GO:=go}"
browser_tmp=$(mktemp -d)
server_pid=
trap 'if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi; rm -rf "$browser_tmp"' EXIT HUP INT TERM
"$GO" build -trimpath -o "$browser_tmp/routeharbor" ./cmd/routeharbor
export ROUTEHARBOR_TEST_URL=http://127.0.0.1:8787
# Each suite gets a fresh real API, credentials, state and rate-limit bucket.
# Fast browser clocks must not consume another suite's real-time request budget.
for spec in tests/browser/*.spec.js; do
  suite=$(basename "$spec" .spec.js)
  suite_tmp="$browser_tmp/$suite"
  mkdir -m 0700 "$suite_tmp"
  "$browser_tmp/routeharbor" bootstrap --state "$suite_tmp/state" --token-file "$suite_tmp/admin.token"
  "$browser_tmp/routeharbor" serve --state "$suite_tmp/state" --runtime "$suite_tmp/runtime" --listen 127.0.0.1:8787 > "$suite_tmp/server.log" 2>&1 &
  server_pid=$!
  export ROUTEHARBOR_TEST_TOKEN_FILE="$suite_tmp/admin.token"
  node -e 'const http=require("http"); let attempts=0; const check=()=>http.get(process.env.ROUTEHARBOR_TEST_URL,r=>{r.resume();process.exit(0)}).on("error",()=>{if(++attempts>=50)process.exit(1);setTimeout(check,100)});check()'
  npm --prefix tests/browser test -- "$(basename "$spec")"
  kill "$server_pid"
  wait "$server_pid" 2>/dev/null || true
  server_pid=
done
