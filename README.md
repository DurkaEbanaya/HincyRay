# HincyRay v0.12.0

[English](README.md) | [Русский](README.ru.md)

---

HincyRay is a lightweight VPN/proxy client for Keenetic routers. It ships a router daemon (`hincyray`) that reuses the parser and quality scoring from the `XrayVpnTest` desktop tool, and exposes an embedded web panel on the router LAN.

The daemon uses **Mihomo (Clash.Meta)** as the single proxy core, supporting VLESS (Reality/xhttp), VMess, Trojan, Shadowsocks, Hysteria2 (port hopping), WireGuard, and TUIC. Transparent proxying via iptables NAT REDIRECT (TCP) + TPROXY (UDP) — no tun2socks, no TUN device.

## How it works

```
Device on Keenetic "HincyRay" policy
         |
         v
  iptables nat PREROUTING
  (match by policy connmark)
         |
    +----+----+
    v         v
  TCP       UDP
    |         |
  REDIRECT  TPROXY
  ->10810   ->10811
    |         |
    v         v
  Mihomo redir/tproxy inbounds
  (redir-in TCP 10810, tproxy-in UDP 10811)
         |
         v
  Active outbound (VLESS/VMess/Trojan/SS/Hy2/WG/TUIC)
         |
         v
  Internet
```

Devices not assigned to the policy keep their normal route — no interference with the main network.

### ndm firewall reload survival

Keenetic's `ndm` daemon recreates all iptables chains on config changes, WAN events, and DHCP renewals. HincyRay installs a hook script at `/opt/etc/ndm/netfilter.d/hincyray.sh` that **ndm itself calls** after every firewall reload, reinstalling all rules atomically. A 10-second watchdog acts as a safety net.

## Features

### v0.12.0

- **Hysteria2 port hopping**: `mport`/`ports` and `hopInterval`/`hop_interval` query params parsed from share links, emitted as Mihomo `ports` + `hop-interval` fields.
- **Profile CRUD API**: `POST /api/profiles/add` (parse share link), `POST /api/profiles/delete` (remove by ID, re-index), `POST /api/profiles/update` (rename, toggle block_quic). Backend-only, UI pending redesign.
- **Auto-refresh subscriptions**: watchdog Phase 7 refreshes all subscriptions on a configurable interval. Disabled by default. If the active profile is removed during refresh, auto-selects the best available.
- **Traffic statistics**: cumulative upload/download byte counters persisted in state. Real-time speed via Mihomo `/traffic` API. `GET /api/traffic`, `GET /api/mihomo-api/traffic`, `GET /api/mihomo-api/memory`.
- **Connection log**: persisted log of connections seen through the proxy (host, source IP, chain, rule, upload/download). Cap 500 entries. `GET /api/connection-log`.
- **Speed test API**: `POST /api/mihomo-api/speed-test` downloads a 10MB file through the SOCKS proxy and returns Mbps, elapsed time, and bytes. Default URL: Cloudflare.
- **Per-device routing**: route specific devices (by IP) to a different target (DIRECT, active proxy, specific profile). Implemented as `SRC-IP-CIDR` rules emitted before general routing rules. ARP scan for device discovery. `GET /api/device-routes`, `POST /api/device-routes`, `POST /api/device-routes/delete`, `GET /api/devices`, `POST /api/device-routes/apply`.

### v0.11.0

- **Mihomo parity pack**: DOMAIN-KEYWORD rules, IP-SUFFIX/SRC-IP-CIDR/SRC-IP-SUFFIX rules, SRC-PORT/IN-PORT rules, ws-opts early-data, grpc-opts advanced, mTLS certificate/private-key, ECH query-server-name, nameserver-policy, include-all/include-all-proxies for proxy groups, raw AND/OR/NOT logic rules.

### v0.10.0

- **WireGuard + TUIC protocol support**: `wireguard://`/`wg://` and `tuic://` share link parsing. Mihomo outbounds with private key, public key, allowed-ips, reserved, MTU (WG) and uuid, password, congestion controller, udp-relay-mode (TUIC).
- **ECH (Encrypted Client Hello)**: `ech` query param parsed from VLESS/Trojan links and VMess JSON. Emits `ech-opts` with enable + optional base64 config + query-server-name.
- **xhttp advanced**: no-grpc-header, x-padding-*, uplink-http-method, session-*, seq-*, uplink-data-*, sc-max-each-post-bytes, sc-min-posts-interval-ms, XMUX reuse settings.
- **Sub-rules**: named rule groups via `SubRuleConfig`. `GET/POST /api/mihomo-features` includes sub-rule configuration.
- **GEOIP/IP-ASN rules**: `geoip:`, `geoip-asn:`/`ip-asn:`, `src-geoip:`, `src-ip-asn:` prefixes in routing rules. `reality-opts.support-x25519mlkem768`.

### v0.9.1

- **External Controller API integration**: `mihomo_api_get()`, `mihomo_api_get_json()`, `mihomo_api_delay()` client functions. `GET /api/mihomo-api/proxies`, `GET /api/mihomo-api/connections`, `POST /api/mihomo-api/delay` proxy endpoints.
- **Proxy group filtering**: `filter`, `exclude_filter`, `exclude_type`, `include_all_providers` for node selection in large profile sets. `tcp_concurrent` (connect all IPs, first wins).
- **Watchdog 3-mode failover**: (1) proxy_group enabled — delegates to Mihomo native; (2) external controller — uses API delay test; (3) fallback — SOCKS curl health check.
- **Web UI "Proxy Status"**: live group health, connections, delay test.

### v0.9.0

- **Advanced Mihomo features**: `MihomoFeatures` master struct. Proxy groups (url-test/fallback/load-balance/select), external controller (REST API), NTP, proxy/rule providers, smux, DNS enhancements (cache-algorithm=arc, prefer-h3, respect-rules), sniffer enhancements, experimental, per-proxy defaults, tunnels, hosts, authentication. `GET/POST /api/mihomo-features`. `domain_rule()` supports `regex:` and `wildcard:` prefixes.

### v0.8.0

- **Mihomo migration**: replaces Xray + sing-box as the single proxy core. All protocols handled by one binary. Sniffer enabled, fake-ip DNS mode. Config generated as YAML.
- **Mihomo auto-update**: checks GitHub releases through the SOCKS proxy, downloads and installs new binaries automatically. Backup `.bak`, rollback on failure.
- **Transparent proxy fixes**: DNS always enabled, TPROXY port 10811, `geo-auto-update: false`, `geoip.metadb` required, stdout to log file.

### v0.7.0

- **NAT REDIRECT + TPROXY**: iptables transparent proxy via Keenetic traffic policy connmarks. No tun2socks, no TUN device. 9-35x faster than tun2socks.
- **Keenetic RCI integration**: queries policy connmark, auto-creates policy if not found.
- **ndm hook script**: auto-generated, called by ndm after every firewall reload.
- **QUIC mode toggle**: Block (default) or Proxy (via TPROXY).
- **Kernel module auto-loading**: `xt_TPROXY`, `xt_socket`, `xt_comment`.

### v0.6.0–v0.6.1

- **Always-on watchdog**: core restart with exponential backoff, firewall rule monitoring.
- **Health-check failover**: 3 consecutive failures → switch to next-best profile.
- **Auto-benchmark + auto-select**: scheduled benchmark, switch to highest-scoring profile.
- **Graceful shutdown**: SIGTERM/SIGINT stops core, removes iptables, persists state.
- **State corruption recovery**: corrupted `state.json` → backup, fresh state.
- **System monitoring**: CPU/RAM/temp/load/uptime via `/proc` + `/sys`.
- **Interactive atomic installer**: `scripts/hincyray-install.sh`.

### v0.1–v0.5

- **Protocol support**: VLESS (Reality/TLS/xhttp), VMess (base64-JSON, WS/gRPC/TCP), Trojan, Shadowsocks, Hysteria2, WireGuard, TUIC.
- **HWID fingerprint**: configurable device identity for Happ subscription fetches.
- **DNS anti-leak**: remote DNS through proxy, local DNS for direct domains.
- **Port routing**: all / allow_list / deny_list modes.
- **GeoIP/GeoSite**: configurable asset path.
- **WiFi traffic split**: routing rules match geosite, domains, IP/CIDR, geoip, ports, network type.
- **Benchmark/stats/favorites/subscriptions**: TCP/HEAD/GET benchmark methods, per-profile metrics, subscription refresh.

## Prerequisites

### Router (Keenetic Giga KN-1012 or similar ARM64)

- Entware with `curl`, `jq`, `mihomo`
- `geoip.metadb` file in the geo directory (Mihomo requires it; cannot download from blocked GitHub)
- Kernel modules: `xt_TPROXY.ko`, `xt_socket.ko`, `xt_comment.ko`
- A Keenetic traffic policy (auto-created by HincyRay or manually in Keenetic Web UI)
- `iptables` with `connmark`, `REDIRECT`, `TPROXY`, `socket`, `comment` match/target support

### Desktop (macOS)

- `sing-box` and `xray` in `PATH` (`brew install sing-box xray`)

## Build

### Router daemon

```bash
cargo zigbuild --release --no-default-features --bin hincyray --target aarch64-unknown-linux-gnu.2.27
patchelf --set-interpreter /opt/lib/ld-linux-aarch64.so.1 --set-rpath /opt/lib \
  target/aarch64-unknown-linux-gnu/release/hincyray
```

### Desktop diagnostics

```bash
cargo build --release --bin xray-vpn-test
```

### Quality gates

```bash
cargo fmt
cargo test          # 254 tests
cargo clippy --all-targets --all-features   # 0 warnings
```

## Installation

Use the interactive atomic installer:

```bash
sh scripts/hincyray-install.sh
```

The installer checks for kernel modules, creates the ndm hook directory, installs the binary, init script, and default state. Staging → backup → atomic `mv` → verify → commit/rollback.

See [`docs/hincyray-entware-install.md`](docs/hincyray-entware-install.md) for manual installation.

## Web panel

```
http://<router-ip>:8088/
```

Status, profiles, benchmark, import, subscriptions, routing rules, per-device routing, firewall controls, DNS, HWID, system monitor, Mihomo update, Mihomo features, proxy status, traffic & connections, logs — all in one page. Auto-refreshes every 5 seconds. No external CDN or build step.

### Environment overrides

| Variable | Default |
|---|---|
| `HINCYRAY_LISTEN` | `0.0.0.0:8088` |
| `HINCYRAY_STATE` | `/opt/etc/hincyray/state.json` (Entware) |
| `HINCYRAY_MIHOMO_CONFIG` | `mihomo-config.yaml` next to state file |

## HTTP API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Embedded web panel |
| `GET` | `/api/health` | Service health + version |
| `GET` | `/api/status` | Active profile, core status, split routing, DNS, HWID, mihomo_version, update_available_version, proxy_group_enabled, ec_enabled |
| `GET` | `/api/profiles` | Imported profiles |
| `POST` | `/api/profiles/import` | Import share links / subscription URL / Xray JSON |
| `POST` | `/api/profiles/add` | Add a single profile from a raw share link |
| `POST` | `/api/profiles/delete` | Delete a profile by ID |
| `POST` | `/api/profiles/update` | Update profile name and/or block_quic |
| `POST` | `/api/profiles/block-quic` | Toggle block_quic flag on a profile |
| `POST` | `/api/active-profile` | Set active profile, regenerate config, restart core |
| `GET` | `/api/mihomo-config` | Generated Mihomo config |
| `POST` | `/api/core/start` | Start Mihomo core |
| `POST` | `/api/core/stop` | Stop Mihomo core |
| `POST` | `/api/core/restart` | Restart Mihomo core |
| `GET` | `/api/bench/status` | Benchmark job status |
| `POST` | `/api/bench/start` | Start benchmark (tcp/head/get) |
| `POST` | `/api/bench/stop` | Cancel benchmark |
| `GET` | `/api/stats` | Per-profile metrics |
| `POST` | `/api/favorites/toggle` | Toggle favorite |
| `GET` | `/api/favorites` | List favorites |
| `GET` | `/api/subscriptions` | Saved subscriptions |
| `POST` | `/api/subscriptions/refresh` | Refresh all subscriptions |
| `POST` | `/api/subscriptions/refresh-one` | Refresh a single subscription by URL |
| `POST` | `/api/subscriptions/delete` | Delete a subscription and its profiles |
| `GET` | `/api/routing` | Routing settings + rules + catalog |
| `POST` | `/api/routing/settings` | Save routing settings |
| `POST` | `/api/routing/rules` | Save routing rules |
| `POST` | `/api/routing/apply` | Regenerate config + restart core + restart firewall |
| `GET` | `/api/routing/firewall-status` | Firewall/iptables/ndm-hook health check |
| `POST` | `/api/routing/firewall-start` | Start firewall |
| `POST` | `/api/routing/firewall-stop` | Stop firewall |
| `GET` | `/api/device-routes` | List per-device routing rules |
| `POST` | `/api/device-routes` | Add/update a device route (upsert by IP) |
| `POST` | `/api/device-routes/delete` | Delete a device route by IP |
| `GET` | `/api/devices` | Scan LAN devices via `/proc/net/arp` |
| `POST` | `/api/device-routes/apply` | Regenerate config + restart core |
| `GET` | `/api/dns` | DNS anti-leak settings |
| `POST` | `/api/dns` | Save DNS settings |
| `GET` | `/api/dns/leak-test` | DNS leak test |
| `GET` | `/api/logs` | Mihomo log tail (last 200 lines) |
| `GET` | `/api/system` | CPU/RAM/temp/load/uptime |
| `GET` | `/api/auto-settings` | Auto-select, auto-switch, auto-benchmark, auto-refresh settings |
| `POST` | `/api/auto-settings` | Save auto-settings |
| `GET` | `/api/hwid` | HWID fingerprint config |
| `POST` | `/api/hwid` | Save HWID fingerprint |
| `GET` | `/api/update/status` | Mihomo version, available update, auto-update settings |
| `POST` | `/api/update/check` | Check GitHub releases for a newer Mihomo version |
| `POST` | `/api/update/apply` | Download and install the available Mihomo update |
| `POST` | `/api/update/settings` | Save auto-update enabled / interval |
| `GET` | `/api/mihomo-features` | MihomoFeatures config (proxy groups, EC, NTP, providers, etc.) |
| `POST` | `/api/mihomo-features` | Save MihomoFeatures config |
| `GET` | `/api/mihomo-api/proxies` | Forward `GET /proxies` to Mihomo REST API |
| `GET` | `/api/mihomo-api/connections` | Forward `GET /connections` to Mihomo REST API |
| `POST` | `/api/mihomo-api/delay` | Test proxy delay via Mihomo API |
| `GET` | `/api/mihomo-api/traffic` | Forward `GET /traffic` to Mihomo REST API |
| `GET` | `/api/mihomo-api/memory` | Forward `GET /memory` to Mihomo REST API |
| `POST` | `/api/mihomo-api/speed-test` | Download 10MB through SOCKS proxy, return Mbps |
| `GET` | `/api/traffic` | Cumulative + real-time traffic statistics |
| `GET` | `/api/connection-log` | Persisted connection log (cap 500 entries) |

## WiFi VPN segment (optional)

- `scripts/wifi-segment-setup.sh` — creates the `HincyRay-VPN` SSID on `192.168.2.0/24` via Keenetic `ndmc`.
- Assign every device that must use the VPN to the Keenetic "HincyRay" traffic policy. **The SSID/subnet alone is not enough**: HincyRay matches packets by the policy connmark.
- The daemon handles all transparent proxying internally via `FirewallManager`:
  1. Queries the policy connmark from Keenetic RCI API.
  2. Installs iptables nat HINCYRAY chain (TCP REDIRECT to port 10810) matching the connmark.
  3. Installs iptables mangle HINCYRAY_UDP chain (UDP TPROXY to port 10811) if TPROXY is available.
  4. Installs DNS DNAT rules (port 53 → 127.0.0.1:1053).
  5. Generates ndm hook script for firewall reload survival.
  6. Watchdog reinstalls rules if missing.

### Per-device routing

Devices assigned to the HincyRay policy can be individually routed to a different target (DIRECT, active proxy, or a specific profile). Rules are emitted as `SRC-IP-CIDR,<ip>/32,<target>` before general routing rules, ensuring device-specific rules match first.

Use the web panel's "Per-Device Routing" section:
1. Click "Scan devices (ARP)" to discover LAN devices.
2. Add a route: select device IP, name, and target.
3. Click "Apply Mihomo config" to activate.

## Documentation

- [`docs/benchmark-tun2socks-vs-redirect.md`](docs/benchmark-tun2socks-vs-redirect.md) — tun2socks vs NAT REDIRECT benchmark (9-35x improvement).
- [`docs/hincyray-entware-install.md`](docs/hincyray-entware-install.md) — Entware install runbook.
- [`docs/hincyray-v0.1-status.md`](docs/hincyray-v0.1-status.md) — version status.
- [`docs/keenetic-client-roadmap.md`](docs/keenetic-client-roadmap.md) — product roadmap.

## State migration

Existing `state.json` from any prior version is automatically migrated:
- v0.7→v0.8: `xray_path`→`mihomo_path`, `singbox_path` removed, auto-update fields added.
- v0.8→v0.9: `mihomo_features` added with defaults.
- v0.9→v0.10: No state changes (new protocol support only).
- v0.10→v0.11: `dns_nameserver_policy`, `raw_rules` added to MihomoFeatures.
- v0.11→v0.12: `auto_refresh_enabled`, `auto_refresh_interval_hours`, `last_auto_refresh_unix`, `traffic_total_up_bytes`, `traffic_total_down_bytes`, `connection_log`, `device_routes` added with defaults.

No manual intervention required.

## License

MIT
