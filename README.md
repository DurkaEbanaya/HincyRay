# HincyRay v0.15.6

[English](README.md) | [Русский](README.ru.md)

---

HincyRay is a lightweight VPN/proxy client for Keenetic routers. It ships a router daemon (`hincyray`) that reuses the parser and quality scoring from the `XrayVpnTest` desktop tool, and exposes an embedded web panel on the router LAN.

The daemon uses **Mihomo (Clash.Meta)** as the single proxy core, supporting VLESS (Reality/xhttp), VMess, Trojan, Shadowsocks, ShadowsocksR, Snell, HTTP, SOCKS, AnyTLS, Hysteria v1/v2 (port hopping), WireGuard, TUIC, SSH, MASQUE, OpenVPN, and Tailscale. Transparent proxying via iptables NAT REDIRECT (TCP) + TPROXY (UDP) — no tun2socks, no TUN device.

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

### v0.16.0

- **MATCH toggle**: the final `MATCH` rule is now visible as an immutable first row in the rules table. Toggle between `MATCH,proxy` (everything through VPN) and `MATCH,direct` (everything direct, rules decide what goes through VPN). Locked to `proxy` when no rules exist.
- **Inline cell editing**: click any cell in the rules table to edit it in place — name, domains/IPs, target (active/direct/reject/best), ports (with include/exclude mode), and protocol (any/tcp/udp). No separate edit form needed.
- **Per-rule port mode**: each rule can specify ports as "only these" (`DST-PORT`) or "except these" (`AND` with `NOT,DST-PORT`). Generates correct Mihomo AND-rules.
- **AND rule composition**: when a rule combines domains/IPs + ports + network, they are ANDed together (`AND,((DOMAIN-SUFFIX,example.com),(DST-PORT,443),(NETWORK,udp)),target`) instead of emitting separate OR-style rules.
- **QUIC block is now a regular rule**: the old "Block QUIC globally" checkbox and "QUIC mode" dropdown are removed from settings. QUIC blocking is now a visible, editable rule in the table (`network=udp, ports=443, target=reject`). Migrated automatically from old state.
- **Geo provider management**: new "Геобаза" card with provider selection (MetaCubeX/Loyalsoldier/v2fly), file status (size/exists), and one-click download through the SOCKS proxy. `GET /api/geo/providers`, `POST /api/geo/download`, `GET /api/geo/status`.
- **Preset target override**: clicking a preset chip now shows a target selector (active/direct/reject) — apply "RU Direct" with target `active` to route Russian IPs through VPN instead of direct.
- **Routing conflict detection**: `GET /api/routing` returns `conflicts` array with warnings when per-rule ports clash with global PortMode (AllowList/DenyList). Shown as auto-hiding toast notifications.
- **"Сеть" → "Протокол"**: renamed the "Network" column/field to "Protocol" throughout the UI.
- 323 tests, 0 clippy warnings.

### v0.15.6

- **RU Direct**: route Russian domains direct before `MATCH,proxy`. Two modes: `.ru`/`.рф` TLD suffixes or `GEOSITE,category-ru` (includes `vk.com`, `yandex.com`). Exceptions list for domains that should go through VPN anyway (e.g. `2ip.ru`). Rule order: user rules > QUIC block > RU Direct exceptions (→proxy) > RU Direct main (→DIRECT) > port-mode > MATCH.
- **Unified rules UI**: merged Domains + IPs into single textarea with auto-classification. Expanded service catalog to 23 services + 3 domain zones. Click-to-append chips. Edit (✎) button for inline rule editing.
- **Chain-check `info` status**: informational nodes (GEOIP runtime, no active connection) are `info` not `warn`; overall status is `ok` when only info nodes exist.
- **Routing rules CRUD fixed**: delete/toggle/add/preset-apply all call API then reload from server. Custom select sync fixed (initCustomSelects before refreshDashboard).
- **`network=any` fix**: no longer emits `NETWORK,any` which crashes Mihomo. Two-layer normalization at daemon + config generator.
- 313 tests, 0 clippy warnings.

### v0.15.5

- **Routing chain diagnostics**: new `/api/routing/chain-check` endpoint and Web UI metro-line visualization for split routing, policy marks, firewall/DNS/TCP/UDP interception, Mihomo core, active proxy, geo assets, device overrides, port mode, routing rules, and observed Mihomo connections.
- **Safer routing presets on Keenetic**: router rejects known OOM-heavy `geosite:category-ads-all` rules before applying config, preventing Mihomo from crashing during matcher construction.
- **Unlock checks improved**: backend accepts both `service` and `services`; each result now includes direct and proxy probes so the UI can show whether VPN actually unlocks the target.
- **Local connection country flags**: `/api/mihomo-api/connections` enriches Mihomo connection metadata from local `geoip.metadb`, including Meta-geoip0 databases used by Mihomo.
- **UDP TPROXY capability restored**: firewall startup now loads `xt_TPROXY`/`xt_socket` before capability detection and the ndm hook reloads them before reinstalling UDP rules. Verified on Keenetic Giga: `tproxy_available=true`, `tproxy-in` listener on 10811, `HINCYRAY_UDP` mangle rules installed, chain-check UDP node OK.
- **Subscription/profile UI fixes**: refresh/delete group actions use saved subscription URLs; provider card cancel buttons remove the correct card; added “Без пресетов / Всё VPN” preset.
- 306 tests, 0 clippy warnings.

### v0.15.4

- **Systematic Web UI button audit (~40 buttons fixed)**: every action button now has a proper handler with success toast and optional auto-reload. `apiAction(method, path, body, successMsg, reloadFn)` wrapper standardises all action calls. Background polling uses `api(silent=true)` — no more error toast spam every 5 seconds when External Controller is disabled. Error toasts auto-hide after 5s.
  - **Save/load functions**: `saveAutoSettings()` (15 fields), `saveSubStore()`, `saveFeatures()` (GET→merge→POST→apply — doesn't clobber unexposed fields), `saveRoutingSettings()` (12 fields), `saveAuth()` — all with success toasts.
  - **Result modals**: `showConfig()` (YAML config), `checkUpdate()` (version info), `speedTest()` (Mbps/bytes/elapsed), `doTrace()` (decision/name/reason/source/target/candidates), `loadLogs()` (log viewer).
  - **Speed test UI**: service selector (Cloudflare/OVH/Google/Custom URL), mode selector, timeout input. Shows download speed, bytes, elapsed time. Upload/jitter/packet-loss honestly omitted (no compatible upload endpoint).
  - **Human-readable EC error**: "External Controller is disabled. Enable it in Mihomo → Settings…" instead of raw 502 JSON.
  - ID attributes added to ~50 form fields. ~40 new i18n entries (RU/EN).
- **Benchmark details**: collapsible `<details>` with per-server results table (ID, profile, status, latency, jitter, speed, packet loss, error). `renderBenchResults()` populates both the benchmark section and the overview Tests section.
- **Overview "Tests" section**: new sidebar nav item with speed/delay/benchmark quick buttons, traffic/memory cards, compact top-20 bench results table.
- **Mihomo memory procfs fallback**: `read_process_rss_kb(pid)` reads `VmRSS` from `/proc/<pid>/status` when EC is disabled or returns `inuse:0`. Verified: `{"inuse":35724,"oslimit":0,"source":"procfs"}`.
- **Device routing UI clarity**: split into two tables — "Detected LAN devices" (shows all scanned devices including those without override) and "Individual override routes" (only explicit per-device rules). Warning text: override routes have priority above domain/GEO rules. Default target changed from `direct` to `active`. `loadDevices()` auto-loads on page init (silent, no toast).
- 301 tests, 0 clippy warnings.

### v0.15.3

- **DNS section fixed**: Save button now sends all fields (remote/local servers, strategy, enabled) with success toast. Leak test and Diagnostics buttons now display results in a modal — structured table with status badges, iptables rule checks, proxy exit IP, DNS resolver comparison, nslookup output, Mihomo EC DNS query, Cloudflare trace.
- **DNS diagnostics on BusyBox**: replaced `nslookup` (which doesn't support custom ports on BusyBox) with pure-Rust DNS-over-TCP query (`dns_query_tcp`) — no external tools needed.
- 301 tests, 0 clippy warnings.

### v0.15.2

- **Profile sorting by column click**: click any sortable header (Балл, Задержка, Скорость, EWMA, etc.) to sort ascending ▲, click again for descending ▼. State persists across 5s refresh.
- **Collapsed group persistence**: profile group collapse state saved to `localStorage` — survives page reload.
- **Favorites table**: full compact table with all metrics and inline Select/Rename/Delete buttons, replacing the old text-only list.
- **Profile ID/group fix**: `normalizeProfiles` merges profiles + stats endpoints — IDs show correctly (0, 1, 2…) and group names show friendly names instead of raw subscription URLs.
- **Compact profile table**: reduced padding and font size; column reordered (Балл and action buttons near start, Адрес at end).
- **Traffic/memory live updates**: proxy status cards now fetch real data from `/api/traffic` and `/api/mihomo-api/memory` every 5s.
- **Delay test fix**: empty POST body no longer causes "invalid JSON" error — daemon falls back to defaults.
- **WebDAV wiring**: upload/download buttons now read from input fields and send JSON body.

### v0.15.1

- **Fluent/Acrylic Web UI**: new embedded web panel (`src/webui/index.html`) compiled via `include_str!`. 7 navigation groups, 24 sidebar items, 16 Mihomo Features sub-sections, custom Acrylic dropdowns, RU/EN i18n (~180 pairs), light/dark theme with brightness slider, tooltips, login overlay, confirm modal, toast notifications, responsive bottom-nav for mobile, real `fetch()` API helper with Bearer-token auth, production data loaders for all 87 daemon endpoints, data-URI logo (no external asset dependency).
- **EC streaming fix**: `first_stream_json()` parses the first JSON snapshot from Mihomo infinite-stream endpoints (`/traffic`, `/memory`), succeeding even when `curl --max-time` exits with code 28 (timeout on infinite stream).
- **Optional EC endpoints**: `/api/mihomo-api/configs/geo` and `/api/mihomo-api/rules/disable` now return `{"supported":false}` (200) when Mihomo EC responds 405, instead of 502 transport error.
- **UI flicker fix**: `updateStatusUI` split into `updateStatusCards` (core/profile/version cards) and `updateRoutingForm` (routing form fields) — prevents `loadRouting()` from overwriting status cards with partial data.

### v0.15.0

- **10 new outbound protocols**: ShadowsocksR, Snell, HTTP proxy, SOCKS, AnyTLS, Hysteria v1, SSH, MASQUE, OpenVPN, Tailscale. Share-link parsing in `profiles.rs` + Mihomo YAML builders in `mihomo_config.rs`.
- **Relay proxy groups**: `ProxyGroupType::Relay` for chain proxy groups.
- **DNS parity fields**: `fake-ip-filter-mode`, `fake-ip-ttl`, `use-hosts`, `use-system-hosts`, `default-nameserver`, `proxy-server-nameserver-policy`, `direct-nameserver-follow-policy`, `ecs`, `ecs-override`, `disable-ipv4/6`, `disable-qtype-N`.
- **Typed rules**: `MihomoRuleConfig` struct for `IN-NAME`, `IN-USER`, `PROCESS-*`, `UID`, `DSCP`, `RULE-SET` and other Mihomo rule types — emitted before raw rules.
- **EC API parity endpoints**: `GET /api/mihomo-api/version`, `/configs`, `/configs/geo`, `/rules`, `/providers/proxies`, `/providers/rules`; `POST /api/mihomo-api/cache/fakeip/flush`, `/cache/dns/flush`, `/rules/disable`.
- **Hysteria v1 mapping**: `hysteria://` / `hy://` now maps to `Protocol::Hysteria` (v1); `hysteria2://` / `hy2://` remains `Protocol::Hysteria2`.

### v0.14.0

- **Rule Trace**: `POST /api/routing/trace` explains local routing decisions for host/IP/port/protocol/source IP requests. Runtime-owned `geosite:*`, `geoip:*`, and `rule-set:*` matches are reported as Mihomo evaluation candidates instead of being guessed locally.
- **Sub-Store Lite**: lightweight parsed-profile cleanup with include/exclude filters, rename rules, dedup by protocol/address/port, sorting by name/group/protocol/address/score/latency, and backup-before-apply. `GET/POST /api/substore-lite`, `POST /api/substore-lite/apply`.
- **Smart Auto-Select 2.0**: EWMA score/latency/download metrics, minimum-success gating, failure penalty, and cooldown for failing profiles. Configured through `/api/auto-settings`.
- **Backups and WebDAV**: local state backups with create/list/restore/delete plus WebDAV upload/download. Restore validates state JSON, creates a pre-restore backup, then regenerates runtime config safely.
- **Diagnostics & Recovery**: web panel section for rule trace, DNS diagnostics, unlock checks, Sub-Store Lite, backups, WebDAV, and connection closing.
- **Unlock checker + DNS diagnostics**: `POST /api/unlock-check` probes common services; `GET /api/dns/diagnostics` checks local resolver behavior and Mihomo DNS/API availability.
- **Scheduled maintenance**: watchdog can periodically create backups, refresh subscriptions, restart Mihomo, and close connections.
- **Connection control**: `POST /api/mihomo-api/connections/close` closes all connections or filters by connection id, host, or source IP.
- **External Controller wildcard fix**: daemon dials loopback for wildcard EC binds (`0.0.0.0`, `[::]`, `:port`). RU Direct presets now use `geoip:RU` only to avoid missing `geosite:ru` datasets.

### v0.13.0

- **REJECT routing target**: block matching domains, IPs, ports, or device routes with Mihomo `REJECT`.
- **Routing presets**: RU Direct, Ad Block, Only Web VPN, Block Social, RU Direct + Ad Block. `GET /api/routing-presets`, `POST /api/routing-presets/apply`.
- **Web UI authentication**: login/password settings with in-memory session tokens and Bearer auth support.
- **Mihomo desktop benchmark backend**: desktop diagnostics use Mihomo for all supported protocols, including WireGuard and TUIC.

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

- `mihomo` in `PATH` for desktop benchmarking.

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
cargo fmt --all
cargo check --all-targets --all-features
cargo test --all-targets --all-features   # 301 tests
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

Fluent/Acrylic design with 7 navigation groups, 24 sidebar items, RU/EN i18n, light/dark theme. Status, profiles, benchmark, import, subscriptions, routing rules, per-device routing, firewall controls, DNS, diagnostics, backups, HWID, system monitor, Mihomo update, Mihomo features, proxy status, traffic & connections, logs — all in one page. Auto-refreshes every 5 seconds. No external CDN or build step.

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
| `GET` | `/api/routing-presets` | Built-in routing presets |
| `POST` | `/api/routing-presets/apply` | Apply a routing preset |
| `POST` | `/api/routing/trace` | Explain local routing decision for a host/IP/port/source request |
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
| `GET` | `/api/dns/diagnostics` | Resolver + Mihomo DNS diagnostics |
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
| `POST` | `/api/mihomo-api/connections/close` | Close all/filter-matched Mihomo connections |
| `POST` | `/api/mihomo-api/delay` | Test proxy delay via Mihomo API |
| `GET` | `/api/mihomo-api/traffic` | Forward `GET /traffic` to Mihomo REST API |
| `GET` | `/api/mihomo-api/memory` | Forward `GET /memory` to Mihomo REST API |
| `GET` | `/api/mihomo-api/version` | Forward `GET /version` to Mihomo REST API |
| `GET` | `/api/mihomo-api/configs` | Forward `GET /configs` to Mihomo REST API |
| `GET` | `/api/mihomo-api/configs/geo` | Forward `GET /configs/geo` to Mihomo REST API |
| `GET` | `/api/mihomo-api/rules` | Forward `GET /rules` to Mihomo REST API |
| `GET` | `/api/mihomo-api/providers/proxies` | Forward `GET /providers/proxies` to Mihomo REST API |
| `GET` | `/api/mihomo-api/providers/rules` | Forward `GET /providers/rules` to Mihomo REST API |
| `POST` | `/api/mihomo-api/cache/fakeip/flush` | Flush Mihomo fake-ip cache |
| `POST` | `/api/mihomo-api/cache/dns/flush` | Flush Mihomo DNS cache |
| `POST` | `/api/mihomo-api/rules/disable` | Disable a Mihomo rule by index |
| `POST` | `/api/mihomo-api/speed-test` | Download 10MB through SOCKS proxy, return Mbps |
| `POST` | `/api/unlock-check` | Probe common service unlock/connectivity through proxy path |
| `GET` | `/api/substore-lite` | Sub-Store Lite settings |
| `POST` | `/api/substore-lite` | Save Sub-Store Lite settings |
| `POST` | `/api/substore-lite/apply` | Apply Sub-Store Lite cleanup with backup |
| `GET` | `/api/backups` | List state backups |
| `POST` | `/api/backups/create` | Create state backup |
| `POST` | `/api/backups/restore` | Restore a state backup |
| `POST` | `/api/backups/delete` | Delete a state backup |
| `POST` | `/api/backups/webdav-upload` | Upload backup to WebDAV |
| `POST` | `/api/backups/webdav-download` | Download and restore backup from WebDAV |
| `POST` | `/api/auth/login` | Create Web UI session token |
| `POST` | `/api/auth/logout` | Destroy Web UI session token |
| `GET` | `/api/auth-settings` | Web UI authentication settings |
| `POST` | `/api/auth-settings` | Save Web UI authentication settings |
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
- v0.12→v0.13: `web_ui_auth` added with disabled default; routing targets accept `reject`.
- v0.13→v0.14: `sub_store_lite`, `smart_select`, `maintenance`, and EWMA/cooldown profile stats added with defaults.
- v0.14→v0.15: New `Protocol` variants (ShadowsocksR, Snell, Http, Socks, AnyTls, Hysteria, Ssh, Masque, OpenVpn, Tailscale), `ProxyGroupType::Relay`, DNS parity fields (`dns_fake_ip_filter_mode`, `dns_fake_ip_ttl`, `dns_use_hosts`, `dns_use_system_hosts`, `dns_default_nameserver`, `dns_proxy_server_nameserver_policy`, `dns_direct_nameserver_follow_policy`, `dns_ecs`, `dns_ecs_override`, `dns_disable_ipv4`, `dns_disable_ipv6`, `dns_disable_qtypes`), `typed_rules` (Vec<MihomoRuleConfig>) added to MihomoFeatures with defaults.

No manual intervention required.

## License

MIT
