#!/bin/sh
# HincyRay TPROXY rollback.
#
# Removes all TPROXY rules for 192.168.2.0/24.
# After rollback, HincyRay-VPN WiFi routes direct (no VPN).
#
# Run on the router as root:
#   sh /opt/etc/hincyray/scripts/tproxy-rollback.sh

set -eu

TPROXY_MARK=0x111
TPROXY_TABLE=111
VPN_SUBNET=192.168.2.0/24

echo "Removing HincyRay TPROXY rules for ${VPN_SUBNET}..."

iptables -t mangle -D PREROUTING -s "${VPN_SUBNET}" -j HINCYRAY 2>/dev/null || true
iptables -t mangle -F HINCYRAY 2>/dev/null || true
iptables -t mangle -X HINCYRAY 2>/dev/null || true

ip rule del fwmark "${TPROXY_MARK}" lookup "${TPROXY_TABLE}" 2>/dev/null || true
ip route flush table "${TPROXY_TABLE}" 2>/dev/null || true

echo "TPROXY rules removed. HincyRay-VPN now routes direct (no VPN)."
echo "To disable HincyRay-VPN WiFi entirely:"
echo "  ndmc -c 'interface WifiMaster0/AccessPoint1 down'"
echo "  ndmc -c 'interface WifiMaster1/AccessPoint1 down'"
