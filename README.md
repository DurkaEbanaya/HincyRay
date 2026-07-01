# HincyRay v0.8.0

[English](README.md) | [Русский](README.ru.md)

---

HincyRay is a lightweight VPN/proxy client for Keenetic routers. It ships a router daemon (`hincyray`) that reuses the parser and quality scoring from the `XrayVpnTest` desktop tool, and exposes an embedded web panel on the router LAN.

**v0.8 replaces Xray + sing-box with Mihomo (Meta)** as the single proxy core on the router. Mihomo handles all protocols (VLESS/VMess/Trojan/Shadowsocks/Hysteria2), sniffing, fake-ip DNS, and transparent proxy inbounds in one binary. No more Xray or sing-box on the router.

**v0.8 also adds Mihomo auto-update** via the GitHub releases API through the SOCKS proxy (GitHub is blocked from the router), and fixes five transparent-proxy bugs found via end-to-end testing with a Pixel 6a.

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
  Active VLESS/VMess/Trojan/SS/Hysteria2 outbound
         |
         v
  Internet
```

Devices not assigned to the policy keep their normal route -- no interference with the main network.

### ndm firewall reload survival

Keenetic's `ndm` daemon recreates all iptables chains on config changes, WAN events, and DHCP renewals. HincyRay installs a hook script at `/opt/etc/ndm/netfilter.d/hincyray.sh` that **ndm itself calls** after every firewall reload, reinstalling all rules atomically. A 10-second watchdog acts as a safety net.

## Features

- **v0.8 Mihomo migration**: Mihomo (Meta) replaces Xray + sing-box as the single proxy core on the router. All protocols (VLESS/VMess/Trojan/SS/Hysteria2) handled by one binary. Sniffer enabled (HTTP/TLS/QUIC), fake-ip DNS mode. Config generated as YAML via `src/mihomo_config.rs` (`build_mihomo_config()` for simple SOCKS, `build_mihomo_router_config()` for transparent proxy). `src/singbox_config.rs` deleted; `src/xray_config.rs` kept only for the desktop tester.
- **v0.8 Mihomo auto-update**: checks GitHub releases through the SOCKS proxy (GitHub blocked from router), downloads and installs new binaries automatically. Binary replacement via unlink + copy (avoids ETXTBSY), backup `.bak`, rollback on failure. State tracks `mihomo_version`, `update_available_version`, `auto_update_enabled`, `auto_update_interval_hours`, `last_update_check_unix`. Watchdog Phase 6 runs scheduled checks and auto-installs. Web UI shows version cards, check/apply buttons, and an auto-update toggle.
- **v0.8 transparent proxy fixes (Pixel 6a E2E)**: DNS always enabled in router config (firewall unconditionally DNATs DNS to port 1053). TPROXY listener moved to port 10811 (was 10810, conflicted with redir TCP bind). `geo_dir_from_state` returns the directory itself (was returning parent). `geo-auto-update: false` + `geoip.metadb` required (Mihomo hangs trying to download from blocked GitHub). Mihomo stdout redirected to log file (was `/dev/null`, logs were empty).
- **v0.7 NAT REDIRECT + TPROXY**: iptables transparent proxy via Keenetic traffic policy connmarks. TCP via `nat REDIRECT`, UDP via `mangle TPROXY`. No tun2socks, no TUN device.
- **v0.7 Keenetic RCI integration**: queries `localhost:79/rci/show/ip/policy` for the policy connmark. Auto-creates the policy if not found.
- **v0.7 ndm hook script**: auto-generated at `/opt/etc/ndm/netfilter.d/hincyray.sh`, called by ndm after every firewall reload. Rules survive ndm restarts.
- **v0.7 QUIC mode toggle**: `Block` (default -- forces TCP fallback) or `Proxy` (via TPROXY). Configurable per-rule and globally in the web UI.
- **v0.7 kernel module auto-loading**: `xt_TPROXY`, `xt_socket`, `xt_comment` loaded at startup. TPROXY unavailable -> TCP-only REDIRECT + QUIC blocked.
- **v0.6 always-on watchdog**: monitors the core and restarts it with exponential backoff (10s -> 300s max). Also monitors firewall rules and reinstalls them if missing.
- **v0.6 health-check failover**: probes the SOCKS tunnel every 10 seconds. After 3 consecutive failures, switches to the next-best profile by score.
- **v0.6 auto-benchmark**: schedules a TCP benchmark on all profiles every N hours.
- **v0.6 auto-select**: after a benchmark, switches to the highest-scoring profile.
- **v0.6 graceful shutdown**: SIGTERM/SIGINT stops the core, removes iptables rules, truncates ndm hook, persists state.
- **v0.6 state corruption recovery**: corrupted `state.json` -> backup to `.corrupt`, fresh state created.
- **v0.5 protocol support**: VLESS (Reality/TLS/XHTTP), VMess (base64-JSON, WS/gRPC/TCP), Trojan (TLS), Shadowsocks. Hysteria2/WireGuard rejected with a clear error.
- **v0.5 HWID fingerprint**: configurable device identity for Happ subscription fetches.
- **v0.5 DNS anti-leak**: remote DNS through proxy, local DNS for direct domains. `GET /api/dns/leak-test` to verify.
- **v0.5 port routing**: `all` / `allow_list` / `deny_list` modes with per-rule port and network (TCP/UDP) matching.
- **v0.5 GeoIP/GeoSite**: configurable asset path.
- **v0.3 WiFi traffic split**: routing rules match `geosite:*`, domains, IP/CIDR, `geoip:*`, ports, network type. Targets: `direct`, active, best, or fixed profile.
- **v0.2 benchmark/stats/favorites/subscriptions**: TCP/HEAD/GET benchmark methods, per-profile metrics, favorites by raw link, subscription refresh.

## Prerequisites

### Router (Keenetic Giga KN-1012 or similar ARM64)

- Entware with `curl`, `jq`, `mihomo`
- `geoip.metadb` file in the geo directory (Mihomo requires it; cannot download from blocked GitHub)
- Kernel modules: `xt_TPROXY.ko`, `xt_socket.ko`, `xt_comment.ko` (usually in `/lib/modules/$(uname -r)/`)
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
cargo test
cargo clippy --all-targets --all-features
```

## Installation

Use the interactive atomic installer:

```bash
sh scripts/hincyray-install.sh
```

The installer checks for kernel modules, creates the ndm hook directory, installs the binary, init script, and default state. Staging -> backup -> atomic `mv` -> verify -> commit/rollback.

See [`docs/hincyray-entware-install.md`](docs/hincyray-entware-install.md) for manual installation.

## Web panel

```
http://<router-ip>:8088/
```

Status, profiles, benchmark, import, subscriptions, routing rules, firewall controls, DNS, HWID, system monitor, Mihomo update, logs -- all in one page. Auto-refreshes every 5 seconds. No external CDN or build step.

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
| `GET` | `/api/status` | Active profile, core status, split routing, DNS, HWID, mihomo_version, update_available_version |
| `GET` | `/api/profiles` | Imported profiles |
| `POST` | `/api/profiles/import` | Import share links / subscription URL / Xray JSON |
| `POST` | `/api/active-profile` | Set active profile, regenerate config, restart Mihomo core, persist state |
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
| `GET` | `/api/routing` | Routing settings + rules + catalog |
| `POST` | `/api/routing/settings` | Save routing settings (quic_mode, port_mode, etc.) |
| `POST` | `/api/routing/rules` | Save routing rules |
| `POST` | `/api/routing/apply` | Regenerate config + restart core + restart firewall |
| `GET` | `/api/routing/firewall-status` | Firewall/iptables/ndm-hook health check |
| `POST` | `/api/routing/firewall-start` | Start firewall (install iptables rules + ndm hook) |
| `POST` | `/api/routing/firewall-stop` | Stop firewall (remove rules + truncate ndm hook) |
| `GET` | `/api/dns` | DNS anti-leak settings |
| `POST` | `/api/dns` | Save DNS settings |
| `GET` | `/api/dns/leak-test` | DNS leak test |
| `GET` | `/api/hwid` | HWID fingerprint config |
| `POST` | `/api/hwid` | Save HWID fingerprint |
| `GET` | `/api/auto-settings` | Auto-select, auto-switch, auto-benchmark interval |
| `POST` | `/api/auto-settings` | Save auto-settings |
| `GET` | `/api/update/status` | Mihomo version, available update, auto-update settings |
| `POST` | `/api/update/check` | Check GitHub releases for a newer Mihomo version |
| `POST` | `/api/update/apply` | Download and install the available Mihomo update |
| `POST` | `/api/update/settings` | Save auto-update enabled / interval |
| `GET` | `/api/logs` | Mihomo log tail (last 200 lines) |
| `GET` | `/api/system` | CPU/RAM/temp/load/uptime |

## WiFi VPN segment (optional)

- `scripts/wifi-segment-setup.sh` -- creates the `HincyRay-VPN` SSID on `192.168.2.0/24` via Keenetic `ndmc`.
- Assign every device that must use the VPN to the Keenetic "HincyRay" / "XKeen" traffic policy. **The SSID/subnet alone is not enough**: HincyRay matches packets by the policy connmark that Keenetic writes for `ip hotspot` hosts assigned to that policy.
- The daemon handles all transparent proxying internally via `FirewallManager`:
  1. Queries the policy connmark from Keenetic RCI API.
  2. Installs iptables nat HINCYRAY chain (TCP REDIRECT to port 10810) matching the connmark.
  3. Installs iptables mangle HINCYRAY_UDP chain (UDP TPROXY to port 10811) if TPROXY is available.
  4. Installs DNS DNAT rules (port 53 -> 127.0.0.1:1053).
  5. Generates ndm hook script for firewall reload survival.
  6. Watchdog reinstalls rules if missing.

### Required Keenetic policy assignment

Transparent WiFi routing works only for hosts that Keenetic marks with the traffic-policy connmark. A client connected to `HincyRay-VPN` but left on `conform` / default policy will bypass HincyRay completely; `HINCYRAY` iptables counters will stay at zero.

Assign the client in the Keenetic Web UI, or through `ndmc`:

```bash
# Replace with the real client MAC address.
ndmc -c 'ip hotspot host <client-mac> policy Policy0'
ndmc -c 'system configuration save'
```

`Policy0` is the internal name Keenetic used in testing for the policy whose description is `XKeen`. Verify the actual policy name/mark on your router:

```bash
curl -s localhost:79/rci/show/ip/policy
```

Verify that the host is marked correctly:

```bash
ndmc -c 'show running-config' | grep -i '<client-mac>'
iptables -t mangle -L _NDM_HOTSPOT_PREROUTING_MANGL -n -v | grep -i '<client-mac>'
iptables -t nat -L HINCYRAY -n -v
```

Expected result for a VPN-routed host:

```text
host <client-mac> policy Policy0
MARK set 0xffffaaa
CONNMARK save
HINCYRAY ... REDIRECT ... packet counters increase when the client opens a site
```

If the host shows `conform` instead of `policy Policy0`, Keenetic will emit a plain `RETURN` rule for that MAC and HincyRay will not see the traffic.

## Documentation

- [`docs/benchmark-tun2socks-vs-redirect.md`](docs/benchmark-tun2socks-vs-redirect.md) -- tun2socks vs NAT REDIRECT benchmark (9-35x improvement).
- [`docs/hincyray-entware-install.md`](docs/hincyray-entware-install.md) -- Entware install runbook.
- [`docs/hincyray-v0.1-status.md`](docs/hincyray-v0.1-status.md) -- version status.
- [`docs/keenetic-client-roadmap.md`](docs/keenetic-client-roadmap.md) -- product roadmap.

## State migration (v0.7 -> v0.8)

Existing `state.json` with Xray fields is automatically migrated:
- `xray_path` -> `mihomo_path`
- `xray_config_path` -> `mihomo_config_path`
- `singbox_path` -> removed
- `auto_update_enabled`, `auto_update_interval_hours`, `last_update_check_unix`, `update_available_version`, `mihomo_version` -> added with defaults
- `dns_settings.enabled` forced `true` when `split_routing.enabled`

No manual intervention required.

## License

MIT
