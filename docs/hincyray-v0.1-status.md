# HincyRay v0.1 status

Version: **0.1.0** (crate version in `Cargo.toml`).

This document records what is implemented, what was validated on real hardware, what is intentionally not implemented, and the next milestones. It is the authoritative v0.1 status snapshot; the long-form plan lives in [`keenetic-client-roadmap.md`](keenetic-client-roadmap.md).

## Implemented

- **Router daemon binary `hincyray`** built from the same crate as the desktop diagnostics tool, sharing `src/profiles.rs`, `src/scoring.rs`, `src/xray_config.rs`. Built without the desktop feature: `cargo build --release --no-default-features --bin hincyray` (skips `eframe` / `egui_extras` / `arboard`).
- **Sync HTTP server** on `std::net::TcpListener`, no async runtime, no web framework. One thread per connection, 15 s read/write timeouts, 1 MiB request body cap.
- **Default bind** `0.0.0.0:8088`, overridable via `HINCYRAY_LISTEN`.
- **State persistence** with auto-detected path: `HINCYRAY_STATE` &rarr; `/opt/etc/hincyray/state.json` (Entware) &rarr; `/etc/hincyray/state.json` (OpenWrt) &rarr; `$HOME/.config/hincyray/state.json` &rarr; `./hincyray-state.json`. Atomic save via temp file + rename.
- **Generated Xray config path**: `HINCYRAY_XRAY_CONFIG` &rarr; `xray-client.json` next to state.
- **JSON state** with profiles, `active_profile_id`, `auto_select`, `listen_host` (default `127.0.0.1`), `socks_port` (default `10808`), `http_port` (default `10809`, reserved), `xray_path` (default `xray`), `metrics_history` placeholder, `routing_rules` placeholder.
- **HTTP API**: `GET /`, `GET /api/health`, `GET /api/status`, `GET /api/profiles`, `POST /api/profiles/import`, `POST /api/active-profile`, `GET /api/xray/config`, `POST /api/core/start|stop|restart`.
- **Embedded web panel** served inline from `index_html()` at `http://<router-ip>:8088/`: status cards, subscription/profile import box, profile table with activation, Xray config preview, and core start/stop/restart buttons. No external CDN or build step.
- **Subscription import** accepting direct `vless://` / `hysteria2://` / `hy2://` links, HTTPS subscription URLs, plain/base64/base64url subscription bodies, and Xray-style JSON configs with `outbounds`. Profiles merge by raw link (dedup).
- **Happ/TutNet subscription loading** with automatic retry using the Happ `User-Agent: Happ/3.22.1` and `X-HWID`, `X-Ver-OS`, `X-Bundle-ID`, `X-Device-model`, `X-Device-OS`, `X-API-Version` headers when the first `sing-box`-style fetch returns no profiles.
- **Happ/TutNet Xray-JSON fallback**: when a body contains DNS-over-HTTPS URLs but no direct profile candidates, the parser falls back to `outbounds` parsing so embedded DNS URLs are not mistaken for subscriptions.
- **Xray config generation** for VLESS Reality/TLS and VLESS XHTTP/Satellite via the shared `xray_config::build_xray_config`. Hysteria2 returns an explicit error from `/api/active-profile` (HTTP 400 with a clear message).
- **Core lifecycle**: `CoreManager` holds one in-memory Xray `Child`, status via `try_wait`, idempotent stop, restart = stop + start. Xray is spawned with `stdout`/`stderr` set to `Stdio::null()` so the long-lived child cannot block on a buffered pipe.
- **Safe SOCKS-only MVP**: the daemon starts Xray with a local SOCKS listener at `127.0.0.1:10808` on the router. It does **not** install any routing hooks.
- **Desktop diagnostics surface `xray-vpn-test`** remains built behind the `desktop` feature for macOS benchmarking of VLESS/Hysteria2/XHTTP nodes via `sing-box` and `xray`.
- **Tests**: xray_config (VLESS XHTTP Reality fields, TCP Reality, Hysteria2 rejection, Unknown protocol rejection), profiles (direct links, RTF candidates, Xray JSON outbounds, DNS-URL fallback, XHTTP settings preservation), scoring (perfect/median/terrible bands, loss-only), hincyray (state round-trip with defaults, import + dedup, active-profile activation + config write, Hysteria2 400, missing profile 404, legacy `id` field, root HTML, health, status defaults, core stop idempotency, 404 routing), tester (VLESS Reality/TLS/XHTTP, Hysteria2 sing-box config validity).

## Validated on Keenetic Giga KN-1012

The following was confirmed on a Keenetic Giga KN-1012 running Keenetic Homebrew / Entware (aarch64):

- HincyRay daemon built with `--no-default-features --bin hincyray` runs on the router and serves `http://<router-ip>:8088/`.
- Manual Xray install using the official XTLS/Xray-core ARM64 binary at `/opt/etc/hincyray/xray`, with symlink `/opt/sbin/xray`, and `geoip.dat` / `geosite.dat` in `/opt/etc/hincyray/`.
- Init script `/opt/etc/init.d/S99hincyray` starts/stops the daemon; state at `/opt/etc/hincyray/state.json`; generated config at `/opt/etc/hincyray/xray-client.json`; log redirected to `/opt/var/log/hincyray/hincyray.log`.
- Old `xkeen` / `xray_s` / `mihomo_s` packages were removed before installing HincyRay.
- A TutNet subscription was imported (Happ/TutNet JSON with DNS-over-HTTPS URLs parsed via the `outbounds` fallback), the active profile `Satellite` was selected, and the Xray core was started through the daemon.
- Validation was router-local SOCKS only:
  - Workstation direct IP (not through SOCKS): `<workstation-public-ip>` &mdash; **unchanged** before and after starting the core.
  - Router `curl --socks5-hostname 127.0.0.1:10808 https://2ip.io/` (or `https://api.ipify.org`): `<proxy-exit-ip>` &mdash; the proxy exit IP, distinct from the workstation's direct IP.
- No `iptables` / `ip rule` / `nftables` / Keenetic routing hooks were installed or enabled. The workstation's main IP and default route were not affected.

## Not implemented (intentionally, for v0.1 safe MVP)

- **No system-wide policy routing.** No `iptables`, `ip rule`, `nftables`, or Keenetic-specific routing hooks are installed or enabled. Only the router-local SOCKS listener at `127.0.0.1:10808` is exposed.
- **No transparent proxy / per-device / per-SSID / per-domain steering.** The `routing_rules` field exists in state as a placeholder for future migration but is not consumed.
- **No automatic server selection.** `scoring::quality_score` exists and is shared with the desktop app, but the daemon does not run benchmarks or pick a profile automatically. `auto_select` is a state field only.
- **No automatic health checks or failover.** The daemon does not probe the active profile or switch profiles on failure.
- **No Hysteria2 backend.** Xray does not speak Hysteria2; selecting a Hysteria2 profile returns HTTP 400 from `/api/active-profile`. A future sing-box or Mihomo backend is the planned path.
- **No HTTP proxy listener.** `http_port` defaults to `10809` but is reserved; only SOCKS is wired through Xray in v0.1.
- **No Xray log capture.** Xray `stdout`/`stderr` are discarded to avoid blocked pipes; if you need Xray logs, run `xray` manually with the generated config.
- **No packaged Homebrew/opkg artifact or signed release pipeline.** Install is manual (workstation build + `scp`), as documented in [`hincyray-entware-install.md`](hincyray-entware-install.md).
- **No cross-compilation pipeline in CI.** Cross-compile instructions are documentation-level only.

## Next milestones (post-v0.1)

1. **Automatic server selection**: run a short benchmark through the active core, score with `scoring::quality_score`, and switch to the best profile on a schedule or on failure.
2. **Health checks with failover**: periodic router-local SOCKS probes; switch active profile when the current one fails N times in a window.
3. **Hysteria2 backend**: integrate `sing-box` or Mihomo as a second core so Hysteria2 profiles can be activated and used.
4. **Policy routing opt-in**: add an explicit, off-by-default flag that installs `iptables`/`nftables` rules to steer selected client/SSID/domain traffic through the SOCKS listener. Keep the safe SOCKS-only mode as the default.
5. **Packaged Entware artifact**: produce an installable archive and an init script template that can be shipped from GitHub Releases, so the manual `scp` flow becomes optional.
6. **Web panel polish**: profile detail view, metrics history charts, log viewer, error copy buttons.
7. **Xray log capture**: route Xray `stderr` to a rotating file under `/opt/var/log/hincyray/` without blocking the child.

These are tracked in [`keenetic-client-roadmap.md`](keenetic-client-roadmap.md) under Post-MVP Scope.
