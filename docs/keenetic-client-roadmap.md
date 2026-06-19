# Keenetic VPN Client Roadmap

> v0.1 is shipped as the `hincyray` router daemon. See [`hincyray-v0.1-status.md`](hincyray-v0.1-status.md) for the implemented / validated / not-implemented snapshot, and [`hincyray-entware-install.md`](hincyray-entware-install.md) for the install runbook. The desktop `xray-vpn-test` is the diagnostics surface behind the `desktop` feature.

## Goal

Build a lightweight VPN/proxy client for Keenetic Homebrew routers, starting with Keenetic Giga KN-1012, using the current XrayVpnTest project as the parser, benchmark, and diagnostics foundation.

The desktop application is the diagnostics surface. The shipped router product is `hincyray` v0.1: a router-installed daemon with a web panel that accepts Happ/TutNet-style subscriptions and direct configs, lets the user choose a server manually, and exposes a local SOCKS listener through Xray. The v0.1.1 add-on in `scripts/` adds an opt-in WiFi VPN segment via TPROXY for `192.168.2.0/24` (manual setup, main network untouched). Automatic server selection, per-device/per-domain policy routing, and Hysteria2 remain post-MVP.

## Target Device

- Primary router: Keenetic Giga KN-1012.
- Runtime environment: Keenetic Homebrew / Entware-style userspace.
- Preferred implementation language: Rust, to minimize memory use and keep one codebase for parsing, scoring, API, and UI backend.
- Proxy core: Xray first, with Mihomo considered for rule-engine features if needed.

## User-Facing Requirements

- Web UI available from the router LAN.
- Paste/import subscriptions and direct profile links from providers that normally target Happ or Incy.
- Parse VLESS, VLESS XHTTP, Hysteria2, and Xray-style JSON configs.
- Show available servers with protocol, transport, country/name, latency, stability, speed, and last error.
- Allow manual server selection.
- Allow automatic server selection based on measured quality.
- Allow rules such as specific devices, SSIDs, domains, or IP ranges to use the proxy while other traffic remains direct.
- Support a dedicated Wi-Fi/network segment that exits through the selected VPN/proxy server.
- Keep main configuration in the web UI, not only in terminal config files.
- Expose logs and copyable error messages for debugging.

## Proposed Architecture

- `xray-vpn-test` desktop app remains the macOS diagnostics UI and test harness.
- Shared Rust library modules handle subscription loading, provider fallbacks, profile normalization, and quality scoring.
- A new router daemon manages state, subscriptions, selected profiles, generated core configs, process lifecycle, and routing rules.
- A small web UI talks to the daemon over local HTTP API.
- Xray runs as the main execution core for VLESS Reality/TLS and XHTTP/Satellite compatibility.
- Mihomo may be added later if its rule system is required, but should not be the first dependency unless it simplifies real Keenetic routing.

## Router Integration Questions

These must be verified on the actual Keenetic Homebrew environment before final design:

- CPU architecture and available Rust target triple for KN-1012.
- Available init/service manager and persistent storage paths.
- Whether `iptables`, `ip rule`, `ip route`, `nftables`, or Keenetic-specific routing hooks are available.
- How separate Wi-Fi/guest networks are exposed to Homebrew userspace.
- Whether transparent proxying is reliable, or whether the first MVP should expose HTTP/SOCKS proxy and document router UI integration.
- Whether Xray can run within available RAM/CPU limits under real traffic.

## MVP Scope

- Cross-compile or build a small Rust daemon for Keenetic Homebrew.
- Package installable artifact from GitHub Releases.
- Include or download a compatible Xray binary, depending on licensing and size constraints.
- Provide web UI for subscription import, server list, manual selection, and benchmark run.
- Generate Xray config for the selected profile.
- Start/stop/restart Xray from the daemon.
- Expose a local SOCKS/HTTP proxy endpoint on the router.
- Persist settings and benchmark history.

### Current MVP Status (HincyRay daemon)

A first MVP of the daemon is now in-tree as a separate binary, `hincyray`, sharing `src/profiles.rs`, `src/scoring.rs`, and `src/xray_config.rs` with the desktop app. The desktop GUI (`xray-vpn-test`) is unchanged.

The canonical v0.1 status (implemented, validated on KN-1012, not implemented, next milestones) lives in [`hincyray-v0.1-status.md`](hincyray-v0.1-status.md); the install runbook lives in [`hincyray-entware-install.md`](hincyray-entware-install.md). The implementation details below are kept here as a source-tree reference.

Implemented:

- `src/bin/hincyray.rs` binary entrypoint calling `xray_vpn_test::hincyray::run()`.
- `src/hincyray.rs` library module: sync `std::net::TcpListener` HTTP server, no async runtime, no web framework. One thread per connection, 15 s read/write timeouts, 1 MiB request body cap.
- Bind default `0.0.0.0:8088`, override via `HINCYRAY_LISTEN`.
- State path auto-detection: `HINCYRAY_STATE` env → `/opt/etc/hincyray/state.json` (Entware) → `/etc/hincyray/state.json` (OpenWrt) → `$HOME/.config/hincyray/state.json` → `./hincyray-state.json`. Atomic save via temp file + rename.
- Xray config path: `HINCYRAY_XRAY_CONFIG` env → `xray-client.json` next to state.
- JSON state: profiles, active_profile_id, auto_select, listen_host (default `127.0.0.1`), socks_port (default `10808`), http_port (default `10809`, reserved for later), xray_path (default `xray`), metrics_history placeholder, routing_rules placeholder.
- HTTP API: `GET /`, `GET /api/health`, `GET /api/status`, `GET /api/profiles`, `POST /api/profiles/import`, `POST /api/active-profile`, `GET /api/xray/config`, `POST /api/core/start|stop|restart`.
- `CoreManager` with one in-memory `Child`, status detection via `try_wait`, idempotent stop. Xray is spawned with `stdout`/`stderr` set to `Stdio::null()` so the long-lived child cannot block on a buffered pipe that nothing reads.
- The daemon can be built without the desktop feature: `cargo build --release --no-default-features --bin hincyray` skips `eframe`/`egui_extras`/`arboard` so the Entware/OpenWrt artifact stays small and free of GUI dependencies. Shared modules (`profiles`, `scoring`, `xray_config`, `tester`, `hincyray`) remain available; `app`/`theme`/`run()` are gated behind the `desktop` feature.
- Xray config generation reuses `xray_config::build_xray_config` (VLESS only; Hysteria2 returns a 400 with a clear message).
- Tests for xray_config (VLESS XHTTP Reality fields, Hysteria2 rejection, Unknown protocol rejection, TCP Reality), storage round-trip with defaults, import/dedup, active-profile activation and config write, edge-case HTTP responses.
- v0.1.1 opt-in WiFi VPN segment via TPROXY: `scripts/wifi-segment-setup.sh`, `scripts/xray-tproxy-inbound.sh`, `scripts/tproxy-setup.sh`, `scripts/tproxy-rollback.sh`. Creates `HincyRay-VPN` SSID on `192.168.2.0/24`, patches the generated Xray config with a `dokodemo-door` TPROXY inbound on port `10810`, and installs `iptables` mangle TPROXY rules + a policy-routing table that steer only `192.168.2.0/24` through Xray. The main `192.168.1.0/24` network is untouched. Manual setup only; the daemon stays SOCKS-only by default. Validated on KN-1012: a phone on `HincyRay-VPN` got the proxy exit IP and YouTube worked, while `192.168.1.0/24` kept its direct IP.

Not yet implemented (post-MVP, tracked below):

- Router-side policy routing installed/managed by the daemon itself. The v0.1.1 WiFi VPN segment ships an opt-in, script-driven TPROXY path for `192.168.2.0/24`, but per-device / per-domain rules and daemon-managed install/rollback are still pending.
- Automatic server selection using `scoring::quality_score` and recent metrics.
- Health checks with automatic failover.
- Full web UI (only an endpoint-listing index page is shipped).
- Cross-compilation pipeline and Homebrew package artifact.
- Hysteria2 backend (Xray does not support it; sing-box or Mihomo integration is the planned path).

## Post-MVP Scope

- Automatic server selector using quality score, recent failures, and preferred country/provider.
- Policy routing for selected clients, SSIDs, domains, or IP ranges (v0.1.1 delivers an opt-in per-subnet WiFi segment via `scripts/`; per-client/per-domain rules and daemon-managed install/rollback remain).
- Health checks with automatic failover.
- Export/import full router-client configuration.
- Optional Mihomo backend for advanced rule-based routing if Xray routing is insufficient.

## Non-Goals For The First Router MVP

- Full replacement of every Happ/Incy feature.
- Kernel-level VPN implementation.
- Complex terminal-only Mihomo workflows as the primary UX.
- Supporting every router model before KN-1012 is validated.

## Development Strategy

1. Keep all current parsing and benchmarking tests passing on macOS.
2. Refactor shared parser/scoring code only when needed by the router daemon.
3. Build the router daemon and API as a separate binary, not by overloading the desktop UI.
4. Validate Xray config generation on macOS first, then on Keenetic.
5. Add router routing features incrementally after a local proxy MVP works reliably.
