#!/bin/sh
# Development only: no formatter or Node runtime is installed on routers.
set -eu
cd "$(dirname "$0")/.."
mode=--write
if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$1" != --check ]; }; then
  echo 'Usage: scripts/format-web.sh [--check]' >&2
  exit 2
fi
[ "$#" -eq 0 ] || mode=--check
formatter=tests/browser/node_modules/.bin/prettier
[ -x "$formatter" ] || {
  echo 'Install development tools first: npm ci --prefix tests/browser --ignore-scripts' >&2
  exit 1
}
[ "$("$formatter" --version)" = 3.9.6 ] || {
  echo 'Prettier 3.9.6 is required; reinstall from the committed package lock.' >&2
  exit 1
}
exec "$formatter" "$mode" --config .prettierrc.json \
  'internal/web/assets/*.{js,css,html,svg}' \
  'tests/browser/*.{js,json}' .prettierrc.json
