#!/bin/sh
set -eu

BASE_URL="${HINCYRAY_URL:-http://127.0.0.1:8088}"

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing command: $1" >&2; exit 2; }
}

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

need curl

echo "== HincyRay router E2E: $BASE_URL =="
api GET /api/health >/tmp/hincyray-e2e-health.json
api GET /api/status >/tmp/hincyray-e2e-status.json
api GET /api/system >/tmp/hincyray-e2e-system.json
api GET /api/memory-guard >/tmp/hincyray-e2e-memory.json
api GET /api/diagnostics/dns >/tmp/hincyray-e2e-dns.json
api GET /api/diagnostics/udp-quic >/tmp/hincyray-e2e-udp.json
api POST /api/mihomo-config/validate '{}' >/tmp/hincyray-e2e-validate.json
api GET /metrics >/tmp/hincyray-e2e-metrics.txt

grep -q 'hincyray_up 1' /tmp/hincyray-e2e-metrics.txt
echo "health:     $(cat /tmp/hincyray-e2e-health.json)"
echo "validator:  $(cat /tmp/hincyray-e2e-validate.json)"
echo "memory:     $(cat /tmp/hincyray-e2e-memory.json)"
echo "dns:        $(cat /tmp/hincyray-e2e-dns.json)"
echo "udp/quic:   $(cat /tmp/hincyray-e2e-udp.json)"
echo "metrics:    ok"
echo "router e2e ok"
