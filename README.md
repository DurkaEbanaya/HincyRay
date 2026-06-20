# HincyRay v0.4

HincyRay is a lightweight VPN/proxy client for Keenetic Homebrew routers. v0.4 ships a router daemon (`hincyray`) that reuses the parser, Xray config generator, and quality scoring originally developed for the `XrayVpnTest` desktop tool, and exposes an embedded web panel on the router LAN. v0.4 replaces the TPROXY-based WiFi VPN routing with tun2socks (TUN device + iproute2 policy routing), eliminating iptables mangle chain dependency and surviving Keenetic ndm reloads with zero downtime. v0.3 added WiFi-only traffic split (per-domain/per-IP/per-service routing), a per-server QUIC/UDP 443 toggle, and a live service catalog refresh. Earlier versions added the v0.1.1 opt-in WiFi VPN segment and v0.2 benchmark/stats/favorites/subscription refresh.

The desktop app `xray-vpn-test` is still built from this crate behind the `desktop` feature, but its role is now diagnostics and benchmarking only &mdash; it is not the shipped product. See [`docs/hincyray-v0.1-status.md`](docs/hincyray-v0.1-status.md) for the version status and [`docs/keenetic-client-roadmap.md`](docs/keenetic-client-roadmap.md) for the longer plan.

## Features

- Router daemon `hincyray` runs on Keenetic Giga KN-1012 (Entware aarch64) and exposes a JSON HTTP API plus an embedded web panel.
- Web panel at `http://<router-ip>:8088/` for status, subscription import, profile selection, Xray core start/stop/restart, ping/benchmark, stats/rating, favorites, subscription refresh, WiFi traffic split rules, and per-server QUIC toggle &mdash; no external CDN or build step required.
- Accepts direct `vless://`, `hysteria2://`/`hy2://` share links, HTTPS subscription URLs, and Xray-style JSON configs with `outbounds`.
- Loads Happ/TutNet-style subscriptions that require Android-like request headers, with automatic retry using the Happ `User-Agent` and `X-*` headers.
- Parses Happ/TutNet Xray-style JSON that carries DNS-over-HTTPS URLs by falling back to Xray `outbounds` parsing when no direct profiles are found, so embedded DNS URLs are not mistaken for subscriptions.
- Generates Xray client configs for VLESS Reality/TLS and VLESS XHTTP/Satellite via the shared `xray_config` module.
- Persists state, profiles, active profile, generated Xray config, saved subscription sources, favorites, per-profile stats, split-routing rules, and per-server QUIC flags under `/opt/etc/hincyray/` on Entware.
- **v0.2 background benchmark**: `POST /api/bench/start` with method `tcp`/`head`/`get` runs as a background job. TCP probes `address:port` directly (no Xray). HEAD/GET spin up a temporary Xray SOCKS per VLESS profile on a random local port, run `curl` through it, then tear it down &mdash; the active core is never touched. GET additionally does a short (max 3 s) ranged download for speed. Hysteria2 is rejected for HEAD/GET with a clear error. `POST /api/bench/stop` requests cancellation; `GET /api/bench/status` reports running/completed/current/last results.
- **v0.2 stats and ratings**: `GET /api/stats` returns per-profile latest latency/jitter/speed/success/fail/score/last error/last checked, sorted by score descending. Uses the shared `scoring::quality_score` formula. Stats survive daemon restarts and are capped at the latest 1000 history samples.
- **v0.2 favorites**: `POST /api/favorites/toggle` with `{ "profile_id": N }` toggles a favorite by raw share link (stable across renumbering). `GET /api/favorites` lists them.
- **v0.2 subscription refresh**: `POST /api/subscriptions/refresh` re-fetches every saved subscription source, merges new profiles by raw link, and updates per-source `last_loaded`/`last_error`/`profile_count`. Failed refreshes do not delete existing profiles. `GET /api/subscriptions` lists saved sources.
- **v0.4 TUN-based WiFi VPN routing via tun2socks**: `tun2socks` creates a TUN device (`tun0`) and forwards WiFi VPN traffic (192.168.2.0/24) to Xray's second SOCKS inbound (127.0.0.1:10810) via iproute2 policy routing. iptables mangle MARK + fwmark rule is used for source-based routing (source-based ip rule alone does not work for forwarded traffic on Keenetic). FORWARD ACCEPT rules allow br1↔tun0 forwarding. A 10-second watchdog reinstalls any iptables rules wiped by ndm. No TPROXY, no dokodemo-door, no mangle redirect — just a MARK + TUN + SOCKS chain.
- **Opt-in WiFi VPN segment**: `scripts/wifi-segment-setup.sh` creates a separate `HincyRay-VPN` SSID on `192.168.2.0/24` via Keenetic `ndmc`. The daemon handles all routing internally via tun2socks and iproute2; no manual iptables scripts needed.
- **v0.3 WiFi traffic split**: in the web panel, define routing rules scoped to the tun2socks SOCKS inbound. Rules can match `geosite:*` categories, custom domains, IP/CIDR, or `geoip:*` and target `direct`, the active server, the best server, or a fixed profile. SOCKS clients are unaffected.
- **v0.3 service catalog**: choose a rule source project (`MetaCubeX`, `Loyalsoldier`, `v2fly/domain-list-community`, `blackmatrix7/ios_rule_script`) and click **Refresh service catalog** to pull live category lists from GitHub; the panel turns them into checkboxes. Catalog refresh uses the same direct-then-local-SOCKS fallback as subscription refresh, so it works on isolated routers.
- **v0.3 per-server QUIC toggle**: each profile row has a `⊘ QUIC` button. When enabled for a server, HincyRay adds a `block UDP 443` rule before any WiFi traffic that would exit through that server (active fallback or fixed target), forcing services like YouTube to fall back to TCP.
- **v0.4 TUN controls**: the web panel shows live TUN status (tun2socks process, TUN interface, mangle MARK chain, FORWARD rules, ip rule, SOCKS port, Xray core) and offers **Start** and **Stop** buttons for the tun2socks process.
- Desktop `xray-vpn-test` remains available as the macOS diagnostics surface (feature `desktop`) for benchmarking nodes through `sing-box` and `xray`.

## Safe SOCKS-only MVP (default)

v0.1 is intentionally narrow to avoid breaking the workstation that manages the router:

- The daemon only starts Xray with a local SOCKS listener on the router at `127.0.0.1:10808`.
- It does **not** install `iptables` / `ip rule` / `nftables` rules, Keenetic routing hooks, or any system-wide policy routing. (The v0.1.1 WiFi VPN segment is **opt-in and manual**: you must run `scripts/` yourself; see [WiFi VPN segment (v0.1.1, opt-in)](#wifi-vpn-segment-v011-opt-in) below.)
- It does **not** change your main workstation IP or default route. Validation is done by curling through the router-local SOCKS proxy from the router itself.
- It does **not** autostart policy routing or transparent proxying by default. The opt-in WiFi segment is the only shipped routing path; per-device/per-domain rules are post-MVP.

## Current limitations

- **No automatic routing installed by the daemon by default.** The v0.4 WiFi VPN segment uses tun2socks (TUN + iproute2 + mangle MARK) for `192.168.2.0/24` only; automatic failover and auto-select are still post-MVP. The v0.3 split-routing engine only applies to the tun2socks WiFi segment, not to the main `192.168.1.0/24` network or SOCKS clients.
- **Hysteria2 is not supported by the Xray backend.** Selecting a Hysteria2 profile returns a clear 400 error from `/api/active-profile`. Hysteria2 is also rejected by the HEAD/GET benchmark with `unsupported by xray benchmark`; use the TCP method to probe `address:port` for Hysteria2 nodes. A future sing-box or Mihomo backend is planned.
- **Router internet may require manual artifact copy.** The Entware router is often isolated or has restricted direct downloads. The Xray binary, HincyRay binary, and `geoip.dat`/`geosite.dat` assets may need to be fetched on a workstation and copied via `scp`. See [`docs/hincyray-entware-install.md`](docs/hincyray-entware-install.md).
- **Benchmark HEAD/GET requires `curl` in PATH.** Entware ships curl; if it is missing, HEAD/GET methods return a clear `curl spawn` error. The TCP method does not need curl.
- **Benchmark runs one profile at a time.** HEAD/GET spin up and tear down a temporary Xray child per profile so the router is never overloaded; this is intentional and not a benchmark parallelism bug.
- **Auto-select is a flag, not an active loop.** The `Auto switch servers` toggle exists in state and UI, but the daemon does not yet continuously benchmark or switch the active profile on failure. That is post-v0.3.

## Build

Requirements:

- Rust 2024 toolchain.
- For the desktop diagnostics build: macOS SDK / Xcode command line tools, plus `sing-box` and `xray` in `PATH` for runtime checks.

### Router daemon (HincyRay v0.4)

Build only the `hincyray` binary with desktop features disabled so `eframe`, `egui_extras`, and `arboard` are not pulled in. This is the build that ships to Keenetic Entware:

```bash
cargo build --release --no-default-features --bin hincyray
```

The binary will be at:

```text
target/release/hincyray
```

For local debugging on a desktop machine you can also build it with default features:

```bash
cargo build --bin hincyray
./target/debug/hincyray
```

### Desktop diagnostics (XrayVpnTest)

The desktop GUI binary `xray-vpn-test` requires the `desktop` feature and is skipped by `--no-default-features`:

```bash
cargo build --release --bin xray-vpn-test   # default features include "desktop"
cargo build --release --target x86_64-apple-darwin --bin xray-vpn-test
```

The macOS binary will be at:

```text
target/release/xray-vpn-test
target/x86_64-apple-darwin/release/xray-vpn-test
```

Runtime benchmarking on macOS needs external proxy cores in `PATH`:

```bash
brew install sing-box
brew install xray
```

### Quality gates

```bash
cargo fmt
cargo test
cargo test --no-default-features --lib
cargo clippy --all-targets --all-features
```

## Web panel

Once `hincyray` is running on the router, open the embedded panel from any device on the same LAN:

```text
http://<router-ip>:8088/
```

The page is served inline from `index_html()` and talks to the JSON API over `fetch`. No external CDN or build step is required.

Environment overrides:

- `HINCYRAY_LISTEN` &mdash; bind address, default `0.0.0.0:8088`.
- `HINCYRAY_STATE` &mdash; state file path. Auto-detected otherwise: `/opt/etc/hincyray/state.json` (Entware), `/etc/hincyray/state.json` (OpenWrt), `$HOME/.config/hincyray/state.json`, or `./hincyray-state.json`.
- `HINCYRAY_XRAY_CONFIG` &mdash; generated Xray client config path. Defaults to `xray-client.json` next to the state file.

## HTTP API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Embedded web panel (status cards, import, profile table, benchmark controls, stats/rating, favorites, subscriptions, core controls). LAN URL: `http://<router-ip>:8088/`. |
| `GET` | `/api/health` | `{ "ok": true, "service": "hincyray", "version": ... }`. |
| `GET` | `/api/status` | Active profile, profile count, listen info, xray paths, core status. |
| `GET` | `/api/profiles` | Imported profiles with id/name/protocol/transport/address/port/active/group/block_quic. |
| `POST` | `/api/profiles/import` | Body: share links, Xray JSON config, or subscription URL. Loads subscriptions synchronously, merges by raw link, and persists subscription sources for later refresh. |
| `POST` | `/api/profiles/block-quic` | Body: `{ "profile_id": N, "block_quic": true|false }`. Toggle per-server QUIC/UDP 443 block. |
| `POST` | `/api/active-profile` | Body: `{ "profile_id": N }` (or `{ "id": N }`). Generates Xray config and persists state. Returns 400 if Xray does not support the protocol (e.g. Hysteria2). |
| `GET` | `/api/xray/config` | Generated Xray client config for the active profile (400 if none/unsupported). |
| `POST` | `/api/core/start` | Start `xray run -format json -c <xray config path>` as a child process. |
| `POST` | `/api/core/stop` | Stop the running Xray child, if any. |
| `POST` | `/api/core/restart` | Stop then start. |
| `GET` | `/api/bench/status` | Live benchmark job: `{ running, method, total, completed, current_profile_id, current_profile_name, last_updated, cancel_requested, results, summary }`. |
| `POST` | `/api/bench/start` | Body: `{ "method": "tcp"\|"head"\|"get", "profile_ids": [..]? , "probe_url"?, "download_url"? }`. Starts a background job. Returns 409 if a job is already running. |
| `POST` | `/api/bench/stop` | Requests cancellation of the running job (the in-flight profile finishes first). |
| `GET` | `/api/stats` | Per-profile latest metrics + aggregates: latency, jitter, speed, success/fail counts, score, favorite, active, last error, last checked. Sorted by score descending. |
| `POST` | `/api/favorites/toggle` | Body: `{ "profile_id": N }`. Toggles favorite by raw share link (stable across renumbering). |
| `GET` | `/api/favorites` | List favorite profiles. |
| `GET` | `/api/subscriptions` | List saved subscription sources with `last_loaded`/`last_error`/`profile_count`. |
| `POST` | `/api/subscriptions/refresh` | Re-fetch every saved subscription, merge new profiles by raw link, update per-source metadata. Failed refreshes do not delete existing profiles. |
| `GET` | `/api/routing` | Split-routing settings, rules, curated service catalog, and available source projects. |
| `POST` | `/api/routing/settings` | Body: `{ "enabled": bool, "auto_switch": bool, "block_quic_global": bool, "rule_source": "..." }`. Save split-routing settings. |
| `POST` | `/api/routing/rules` | Body: `{ "rules": [...] }`. Save WiFi-only routing rules (domains/IPs/services/target). |
| `POST` | `/api/routing/catalog/refresh` | Body: `{ "source": "v2fly-dlc"|"blackmatrix7"|... }`. Pull live service category list from the selected GitHub project (direct or via local SOCKS fallback). |
| `POST` | `/api/routing/apply` | Regenerate Xray config with the current rules and restart the core if running. |
| `GET` | `/api/routing/tun-status` | Returns `{ enabled, tun_running, core_running, iface_exists, rule_exists, mangle_exists, forward_exists, socks_listening, tun_device, tun_socks_port }`. |
| `POST` | `/api/routing/tun-start` | Start the tun2socks process and install iproute2 + iptables rules. |
| `POST` | `/api/routing/tun-stop` | Stop tun2socks and remove all routing rules. |

Request bodies are limited to 1 MiB. No async runtime or web framework is used; the daemon runs on `std::net::TcpListener` with one thread per connection. The benchmark worker is a separate `std::thread`; the active Xray `CoreManager` child is never touched by benchmarks.

### Example session

```bash
# Import a share link
curl -sS -X POST http://127.0.0.1:8088/api/profiles/import \
  --data-binary 'vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&sni=www.example.com&type=tcp&fp=chrome&pbk=KEY&sid=abcd#Demo'

# Pick the first profile as active
curl -sS -X POST http://127.0.0.1:8088/api/active-profile \
  -H 'Content-Type: application/json' --data '{"profile_id":0}'

# Start the Xray core
curl -sS -X POST http://127.0.0.1:8088/api/core/start

# Validate through router-local SOCKS (does NOT change client routes)
curl -sS --socks5-hostname 127.0.0.1:10808 https://api.ipify.org

# v0.2: ping all imported profiles over TCP (no Xray needed)
curl -sS -X POST http://127.0.0.1:8088/api/bench/start \
  -H 'Content-Type: application/json' --data '{"method":"tcp"}'

# Poll the live job
curl -sS http://127.0.0.1:8088/api/bench/status

# Read aggregated stats/ratings
curl -sS http://127.0.0.1:8088/api/stats

# Mark profile 0 as favorite
curl -sS -X POST http://127.0.0.1:8088/api/favorites/toggle \
  -H 'Content-Type: application/json' --data '{"profile_id":0}'

# Refresh all saved subscriptions
curl -sS -X POST http://127.0.0.1:8088/api/subscriptions/refresh

# v0.3: enable WiFi split routing, create a "RU direct" rule, and apply
curl -sS -X POST http://127.0.0.1:8088/api/routing/settings \
  -H 'Content-Type: application/json' --data '{"enabled":true,"block_quic_global":false,"rule_source":"metacubex-lite"}'
curl -sS -X POST http://127.0.0.1:8088/api/routing/rules \
  -H 'Content-Type: application/json' \
  --data '{"rules":[{"enabled":true,"name":"RU direct","target":"direct","domains":["geosite:ru"],"ips":["geoip:ru"],"services":["ru"]}]}'
curl -sS -X POST http://127.0.0.1:8088/api/routing/apply

# v0.3: toggle QUIC block for profile 0
curl -sS -X POST http://127.0.0.1:8088/api/profiles/block-quic \
  -H 'Content-Type: application/json' --data '{"profile_id":0,"block_quic":true}'
```

## WiFi VPN segment (v0.4, tun2socks)

v0.4 routes a separate WiFi segment through Xray using tun2socks — no TPROXY, no dokodemo-door, no mangle redirect:

- `scripts/wifi-segment-setup.sh` &mdash; creates the `HincyRay-VPN` SSID on `192.168.2.0/24` via Keenetic `ndmc` (2.4 GHz + 5 GHz, DHCP pool).
- The daemon handles all routing internally via `TunManager`:
  1. `tun2socks` creates a TUN device (`tun0`) and forwards traffic to Xray's second SOCKS inbound (`127.0.0.1:10810`).
  2. iptables mangle MARK chain (`HINCYRAY_TUN`) marks packets from `192.168.2.0/24` with fwmark `0x111`.
  3. iproute2 `ip rule fwmark 0x111 lookup 111` + `ip route default dev tun0 table 111` routes marked packets through the TUN.
  4. iptables FORWARD ACCEPT rules allow br1↔tun0 forwarding (ndm default FORWARD policy is DROP).
  5. A 10-second watchdog checks all components and reinstalls any iptables rules wiped by ndm.

Only `192.168.2.0/24` is steered through Xray; `192.168.1.0/24` keeps the main uplink. The TUN interface and iproute2 rules survive ndm reloads; only iptables chains need watchdog reinstallation. Tested: `kill -HUP ndm` &mdash; zero downtime, VPN stays up.

## Documentation

- [`docs/hincyray-v0.1-status.md`](docs/hincyray-v0.1-status.md) &mdash; what is implemented, what is validated on KN-1012, what is not implemented, next milestones.
- [`docs/hincyray-entware-install.md`](docs/hincyray-entware-install.md) &mdash; concrete install/runbook for Keenetic Entware, including manual artifact copy, init script, subscription import in isolated networks, SOCKS validation, and rollback.
- [`docs/keenetic-client-roadmap.md`](docs/keenetic-client-roadmap.md) &mdash; longer product roadmap and post-MVP scope.

## Notes

- VLESS XHTTP is not supported by `sing-box`, so the desktop diagnostics app tests XHTTP/Satellite profiles through `xray`. The router daemon uses `xray` exclusively for v0.4.
- The quality score is a pragmatic composite of short download speed, latency, jitter, and failures. It is shared between the desktop app and the daemon via `scoring::quality_score`. The v0.3 daemon uses it for `/api/stats` and the rating table.
- v0.3 benchmark cleanup: temporary Xray children are wrapped in a `Drop` guard, so even on early return, cancel, or error the child is killed and reaped. The active core (held by `CoreManager`) is never touched by the benchmark worker.
- Neither the daemon nor the desktop app modifies system VPN settings by default; checks and the router MVP run through a local SOCKS proxy. The v0.4 WiFi VPN segment uses tun2socks managed by the daemon's `TunManager`.
- v0.4 split routing only applies to the tun2socks WiFi inbound (`192.168.2.0/24` by default). SOCKS clients always use the active profile.
- v0.4 requires `tun2socks` binary at `/opt/sbin/tun2socks` (or path specified in `SplitRoutingSettings.tun2socks_path`). Download from [xjasonlyu/tun2socks releases](https://github.com/xjasonlyu/tun2socks/releases) — the `tun2socks-linux-arm64` build is a statically linked Go binary (~10 MB).
- Subscription bodies and rule catalog bodies are tried as plain text and common base64 variants.
- Do not put real subscription URLs or tokens into bug reports or docs; use the placeholder `https://provider.example/sub/<token>`.
