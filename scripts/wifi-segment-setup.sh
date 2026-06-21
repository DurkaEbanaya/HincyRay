#!/bin/sh
# Creates the HincyRay-VPN WiFi segment on Keenetic via ndmc.
#
# This creates a separate bridge on 192.168.2.0/24 with a guest WiFi SSID
# "HincyRay-VPN" on both 2.4GHz and 5GHz. The main network (Home/192.168.1.0/24)
# is not touched.
#
# Run on the router as root:
#   sh /opt/etc/hincyray/scripts/wifi-segment-setup.sh
#
# After running, enable split routing in the HincyRay web panel
# (http://192.168.1.1:8088/) and click Apply — the daemon handles
# tun2socks, iproute2, and iptables setup automatically.
# Config is NOT saved automatically — reboot restores previous state.
# To save: ndmc -c "system configuration save"

set -eu

WIFI_PASSWORD="${HINCYRAY_WIFI_PASSWORD:-HincyRayVPN2026}"
SSID="${HINCYRAY_WIFI_SSID:-HincyRay-VPN}"
SUBNET="${HINCYRAY_WIFI_SUBNET:-192.168.2.0/24}"
GATEWAY="${HINCYRAY_WIFI_GATEWAY:-192.168.2.1}"
DHCP_START="${HINCYRAY_DHCP_START:-192.168.2.10}"
DHCP_END="${HINCYRAY_DHCP_END:-192.168.2.100}"

echo "Creating HincyRay-VPN WiFi segment on ${SUBNET}..."

# Create bridge/segment
ndmc -c "interface Bridge1" 2>&1 || true
ndmc -c "interface Bridge1 rename HincyRay" 2>&1 || true
ndmc -c "interface Bridge1 description HincyRay-VPN" 2>&1 || true
ndmc -c "interface Bridge1 security-level private" 2>&1 || true
ndmc -c "interface Bridge1 ip address ${GATEWAY} 255.255.255.0" 2>&1 || true
ndmc -c "interface Bridge1 include GuestWiFi" 2>&1 || true
ndmc -c "interface Bridge1 include GuestWiFi_5G" 2>&1 || true
ndmc -c "interface Bridge1 ip dhcp client dns-routes" 2>&1 || true
ndmc -c "interface Bridge1 up" 2>&1 || true

# 2.4GHz guest AP
ndmc -c "interface WifiMaster0/AccessPoint1 ssid ${SSID}" 2>&1 || true
ndmc -c "interface WifiMaster0/AccessPoint1 encryption enable" 2>&1 || true
ndmc -c "interface WifiMaster0/AccessPoint1 encryption wpa2" 2>&1 || true
ndmc -c "interface WifiMaster0/AccessPoint1 authentication wpa-psk ${WIFI_PASSWORD}" 2>&1 || true
ndmc -c "interface WifiMaster0/AccessPoint1 up" 2>&1 || true

# 5GHz guest AP
ndmc -c "interface WifiMaster1/AccessPoint1 ssid ${SSID}" 2>&1 || true
ndmc -c "interface WifiMaster1/AccessPoint1 encryption enable" 2>&1 || true
ndmc -c "interface WifiMaster1/AccessPoint1 encryption wpa2" 2>&1 || true
ndmc -c "interface WifiMaster1/AccessPoint1 authentication wpa-psk ${WIFI_PASSWORD}" 2>&1 || true
ndmc -c "interface WifiMaster1/AccessPoint1 up" 2>&1 || true

# DHCP pool
ndmc -c "ip dhcp pool _HINCYRAY" 2>&1 || true
ndmc -c "ip dhcp pool _HINCYRAY range ${DHCP_START} ${DHCP_END}" 2>&1 || true
ndmc -c "ip dhcp pool _HINCYRAY lease 25200" 2>&1 || true
ndmc -c "ip dhcp pool _HINCYRAY bind HincyRay" 2>&1 || true
ndmc -c "ip dhcp pool _HINCYRAY enable" 2>&1 || true

echo ""
echo "WiFi segment created:"
echo "  SSID: ${SSID}"
echo "  Password: ${WIFI_PASSWORD}"
echo "  Gateway: ${GATEWAY}"
echo "  DHCP: ${DHCP_START} - ${DHCP_END}"
echo ""
echo "Next steps:"
echo "  1. Open the HincyRay web panel: http://192.168.1.1:8088/"
echo "  2. Enable 'Split routing' in the Routing section and click Apply"
echo "  3. The daemon will automatically start tun2socks and install"
echo "     iproute2/iptables rules for the ${SUBNET} subnet"
echo "  4. Test: connect a device to ${SSID}, verify exit IP at 2ip.ru"
echo ""
echo "NOT saved to flash. To save: ndmc -c 'system configuration save'"
echo "To rollback WiFi: ndmc -c 'interface WifiMaster0/AccessPoint1 down' && ndmc -c 'interface WifiMaster1/AccessPoint1 down'"
