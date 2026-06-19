#!/bin/sh
# HincyRay TPROXY setup for Keenetic Entware.
#
# Routes traffic from 192.168.2.0/24 (HincyRay-VPN WiFi segment) through
# Xray via TPROXY. Does NOT touch 192.168.1.0/24 (Home/main network).
#
# Prerequisites:
#   - HincyRay daemon running with Xray core (SOCKS on 127.0.0.1:10808)
#   - Xray config must include a dokodemo-door TPROXY inbound on port 10810
#   - WiFi segment HincyRay-VPN on 192.168.2.0/24 already created via ndmc
#   - Kernel modules xt_TPROXY, xt_socket loaded (Keenetic has them built-in)
#
# Run on the router as root:
#   sh /opt/etc/hincyray/scripts/tproxy-setup.sh
#
# Rollback:
#   sh /opt/etc/hincyray/scripts/tproxy-rollback.sh

set -eu

TPROXY_PORT=10810
TPROXY_MARK=0x111
TPROXY_TABLE=111
VPN_SUBNET=192.168.2.0/24

echo "HincyRay TPROXY setup for ${VPN_SUBNET}"

# Create mangle chain
iptables -t mangle -N HINCYRAY 2>/dev/null || true

# Avoid duplicates: remove and re-add jump rule
iptables -t mangle -D PREROUTING -s "${VPN_SUBNET}" -j HINCYRAY 2>/dev/null || true
iptables -t mangle -A PREROUTING -s "${VPN_SUBNET}" -j HINCYRAY

# Clear and rebuild chain rules
iptables -t mangle -F HINCYRAY

# Skip local/multicast/broadcast
iptables -t mangle -A HINCYRAY -d 192.168.0.0/16 -j RETURN
iptables -t mangle -A HINCYRAY -d 224.0.0.0/4 -j RETURN
iptables -t mangle -A HINCYRAY -d 255.255.255.255/32 -j RETURN

# TPROXY TCP and UDP to Xray dokodemo-door
iptables -t mangle -A HINCYRAY -p tcp -j TPROXY --on-port "${TPROXY_PORT}" --tproxy-mark "${TPROXY_MARK}/0xffffffff"
iptables -t mangle -A HINCYRAY -p udp -j TPROXY --on-port "${TPROXY_PORT}" --tproxy-mark "${TPROXY_MARK}/0xffffffff"

# Policy routing for TPROXY-marked packets
ip rule del fwmark "${TPROXY_MARK}" lookup "${TPROXY_TABLE}" 2>/dev/null || true
ip route flush table "${TPROXY_TABLE}" 2>/dev/null || true
ip route add local default dev lo table "${TPROXY_TABLE}"
ip rule add fwmark "${TPROXY_MARK}" lookup "${TPROXY_TABLE}"

echo "TPROXY rules installed for ${VPN_SUBNET} -> port ${TPROXY_PORT}"
echo "Verify: iptables -t mangle -S HINCYRAY"
echo "Verify: ip rule show | grep ${TPROXY_MARK}"
