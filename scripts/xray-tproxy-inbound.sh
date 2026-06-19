#!/bin/sh
# Adds a dokodemo-door TPROXY inbound to the HincyRay-generated Xray config.
#
# HincyRay generates a SOCKS-only config for 127.0.0.1:10808. For transparent
# WiFi routing via TPROXY, Xray also needs a dokodemo-door inbound on 0.0.0.0:10810.
# This script patches the generated config in-place using jq.
#
# Run on the router after selecting an active profile via HincyRay API:
#   sh /opt/etc/hincyray/scripts/xray-tproxy-inbound.sh
#
# Then restart the core:
#   curl -X POST http://127.0.0.1:8088/api/core/restart

set -eu

CONFIG="${HINCYRAY_XRAY_CONFIG:-/opt/etc/hincyray/xray-client.json}"

if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required but not found. Install with: opkg install jq"
    exit 1
fi

# Check if dokodemo-door inbound already exists
if jq -e '.inbounds[] | select(.protocol == "dokodemo-door")' "$CONFIG" >/dev/null 2>&1; then
    echo "dokodemo-door inbound already present in $CONFIG, skipping."
    exit 0
fi

TMP="${CONFIG}.tmp"
jq '.inbounds += [{
    "listen": "0.0.0.0",
    "port": 10810,
    "protocol": "dokodemo-door",
    "settings": {
        "network": "tcp,udp",
        "followRedirect": true
    },
    "streamSettings": {
        "sockopt": {
            "tproxy": "tproxy"
        }
    },
    "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"]
    }
}] | .log.loglevel = "warning"' "$CONFIG" > "$TMP"
mv "$TMP" "$CONFIG"

echo "Added dokodemo-door TPROXY inbound on port 10810 to $CONFIG"
echo "Restart core: curl -X POST http://127.0.0.1:8088/api/core/restart"
