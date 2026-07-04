#!/bin/sh
set -eu

BASE_URL="${HINCYRAY_URL:-http://127.0.0.1:8088}"
OUT="${1:-/tmp/hincyray-doctor.json}"

api() {
  method="$1"
  path="$2"
  body="${3:-}"
  if [ "$method" = "POST" ]; then
    curl -fsS --max-time 20 -X POST -H 'Content-Type: application/json' -d "$body" "$BASE_URL$path"
  else
    curl -fsS --max-time 20 "$BASE_URL$path"
  fi
}

json_quote() {
  sed 's/\\/\\\\/g; s/"/\\"/g; s/$/\\n/' | tr -d '\n'
}

tmp="/tmp/hincyray-doctor.$$"
mkdir -p "$tmp"
trap 'rm -rf "$tmp"' EXIT

for item in \
  health:GET:/api/health \
  status:GET:/api/status \
  system:GET:/api/system \
  memory_guard:GET:/api/memory-guard \
  dns:GET:/api/diagnostics/dns \
  udp_quic:GET:/api/diagnostics/udp-quic \
  subscriptions:GET:/api/subscriptions/refresh-report \
  validate_config:POST:/api/mihomo-config/validate \
  metrics:GET:/metrics
do
  name=${item%%:*}
  rest=${item#*:}
  method=${rest%%:*}
  path=${rest#*:}
  if [ "$method" = "POST" ]; then
    api "$method" "$path" '{}' >"$tmp/$name" 2>"$tmp/$name.err" || true
  else
    api "$method" "$path" >"$tmp/$name" 2>"$tmp/$name.err" || true
  fi
done

{
  printf '{\n'
  first=1
  for file in "$tmp"/*; do
    case "$file" in *.err) continue;; esac
    name=$(basename "$file")
    [ "$first" = 1 ] || printf ',\n'
    first=0
    if [ -s "$file.err" ]; then
      printf '  "%s": {"ok": false, "error": "%s", "body": "%s"}' "$name" "$(cat "$file.err" | json_quote)" "$(cat "$file" | json_quote)"
    elif grep -q '^[[:space:]]*{' "$file" 2>/dev/null; then
      printf '  "%s": %s' "$name" "$(cat "$file")"
    else
      printf '  "%s": {"raw": "%s"}' "$name" "$(cat "$file" | json_quote)"
    fi
  done
  printf '\n}\n'
} >"$OUT"

echo "doctor report: $OUT"
