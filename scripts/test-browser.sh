#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
: "${GO:=go}"
browser_tmp=$(mktemp -d)
server_pid=
trap 'if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi; rm -rf "$browser_tmp"' EXIT HUP INT TERM
"$GO" build -trimpath -o "$browser_tmp/openrhp" ./cmd/openrhp
"$browser_tmp/openrhp" bootstrap --state "$browser_tmp/state" --token-file "$browser_tmp/admin.token"
"$browser_tmp/openrhp" serve --state "$browser_tmp/state" --runtime "$browser_tmp/runtime" --listen 127.0.0.1:8787 > "$browser_tmp/server.log" 2>&1 &
server_pid=$!
export OPENRHP_TEST_TOKEN_FILE="$browser_tmp/admin.token"
export OPENRHP_TEST_URL=http://127.0.0.1:8787
node -e 'const http=require("http"); let attempts=0; const check=()=>http.get(process.env.OPENRHP_TEST_URL,r=>{r.resume();process.exit(0)}).on("error",()=>{if(++attempts>=50)process.exit(1);setTimeout(check,100)});check()'
npm --prefix tests/browser test
