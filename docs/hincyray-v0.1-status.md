# HincyRay v0.1 status

> **v0.2 update**: as of crate version `0.2.0`, the daemon also ships background ping/benchmark (`/api/bench/*`), per-profile stats and ratings (`/api/stats`), favorites (`/api/favorites/*`), and subscription refresh (`/api/subscriptions/*`). The v0.1 baseline described below is unchanged; see the [README](../README.md) for the v0.2 API table and the web panel's benchmark/stats/favorites/subscriptions controls.

Version: **0.1.0** (crate version in `Cargo.toml`). The **v0.1.1 add-on** shipped in `scripts/` introduces an opt-in WiFi VPN segment via TPROXY; the crate version is not bumped yet, so the daemon still reports `0.1.0` on `/api/health`.

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
- **Safe SOCKS-only MVP (default)**: the daemon starts Xray with a local SOCKS listener at `127.0.0.1:10808` on the router. By default it does **not** install any routing hooks.
- **Opt-in WiFi VPN segment via TPROXY (v0.1.1 add-on)**: optional shell scripts in `scripts/` create a separate `HincyRay-VPN` WiFi segment on `192.168.2.0/24` via Keenetic `ndmc`, patch the generated Xray config with a `dokodemo-door` TPROXY inbound on port `10810`, and install `iptables` mangle TPROXY rules + a policy-routing table that steer **only** `192.168.2.0/24` through Xray. The main `192.168.1.0/24` network is untouched. Nothing is installed automatically by the daemon; the user must run the scripts explicitly, and changes are not saved to flash until `ndmc -c "system configuration save"` is run. See [WiFi VPN segment via TPROXY (v0.1.1 add-on)](#wifi-vpn-segment-via-tproxy-v011-add-on) below.
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
- No `iptables` / `ip rule` / `nftables` / Keenetic routing hooks were installed or enabled by the daemon. The workstation's main IP and default route were not affected.
- **WiFi VPN segment via TPROXY (v0.1.1)**: after running `scripts/wifi-segment-setup.sh`, `scripts/xray-tproxy-inbound.sh` (followed by `POST /api/core/restart`), and `scripts/tproxy-setup.sh`, a phone connected to the `HincyRay-VPN` SSID on `192.168.2.0/24` received the proxy exit IP and YouTube worked, while devices on the main `192.168.1.0/24` network kept their direct IP and default route. Running `scripts/tproxy-rollback.sh` restored direct routing for `192.168.2.0/24` without rebooting.

## WiFi VPN segment via TPROXY (v0.1.1 add-on)

v0.1.1 ships an **opt-in, manual** path to route a separate WiFi segment through Xray. It is implemented entirely as shell scripts under `scripts/`; the daemon itself remains SOCKS-only by default and does not install or remove routing rules.

Flow:

1. `scripts/wifi-segment-setup.sh` &mdash; creates a `HincyRay-VPN` SSID on `192.168.2.0/24` (2.4 GHz + 5 GHz) via Keenetic `ndmc`, with a DHCP pool. The main `192.168.1.0/24` network is not touched. Run this **before** the TPROXY scripts.
2. `scripts/xray-tproxy-inbound.sh` &mdash; patches the HincyRay-generated Xray config in place (needs `jq`) to add a `dokodemo-door` TPROXY inbound on `0.0.0.0:10810`. Restart the core after this: `curl -X POST http://127.0.0.1:8088/api/core/restart`. Idempotent: it skips if the inbound already exists.
3. `scripts/tproxy-setup.sh` &mdash; installs an `iptables` mangle `HINCYRAY` chain, a `PREROUTING` jump that matches **only** `-s 192.168.2.0/24`, TPROXY TCP/UDP rules pointing at port `10810`, and a policy-routing table (`fwmark 0x111`, table `111`) with `local default dev lo`. Traffic from `192.168.1.0/24` never enters the chain.
4. `scripts/tproxy-rollback.sh` &mdash; removes the `iptables` rules, the `HINCYRAY` chain, and the policy-routing table. After rollback, `192.168.2.0/24` routes direct again without rebooting.

Invariants:

- Only `192.168.2.0/24` is steered through Xray; `192.168.1.0/24` keeps the main uplink.
- Nothing is saved to flash automatically. Run `ndmc -c "system configuration save"` to persist the WiFi segment; the `iptables` rules are **not** persisted, so re-run `tproxy-setup.sh` after every reboot.
- All four scripts are idempotent and safe to re-run.

The step-by-step runbook, including how to test and how to roll back, lives in [`hincyray-entware-install.md`](hincyray-entware-install.md) under [WiFi VPN segment setup (v0.1.1, opt-in)](hincyray-entware-install.md#wifi-vpn-segment-setup-v011-opt-in).

## Not implemented (intentionally, for v0.1 safe MVP)

- **No automatic policy routing installed by the daemon.** By default the daemon still only starts Xray with a local SOCKS listener at `127.0.0.1:10808` and does **not** install `iptables`, `ip rule`, `nftables`, or Keenetic routing hooks. The v0.1.1 WiFi VPN segment is **opt-in and manual**: the user must run `scripts/wifi-segment-setup.sh`, `scripts/xray-tproxy-inbound.sh`, and `scripts/tproxy-setup.sh` on the router, and nothing is saved to flash until `ndmc -c "system configuration save"` is run explicitly.
- **No per-device / per-domain steering yet.** The v0.1.1 TPROXY path steers one whole WiFi subnet (`192.168.2.0/24`) through Xray. Per-device, per-SSID-as-rule-target, and per-domain steering are still post-MVP. The `routing_rules` field exists in state as a placeholder for future migration but is not consumed.
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
4. **Policy routing opt-in (partially delivered in v0.1.1)**: WiFi-subnet TPROXY steering is now shipped as opt-in `scripts/` (see [WiFi VPN segment via TPROXY (v0.1.1 add-on)](#wifi-vpn-segment-via-tproxy-v011-add-on)). Remaining work: per-device / per-domain rules, daemon-managed install/rollback, and persistence of the `iptables` rules across reboots. Keep the safe SOCKS-only mode as the default.
5. **Packaged Entware artifact**: produce an installable archive and an init script template that can be shipped from GitHub Releases, so the manual `scp` flow becomes optional.
6. **Web panel polish**: profile detail view, metrics history charts, log viewer, error copy buttons.
7. **Xray log capture**: route Xray `stderr` to a rotating file under `/opt/var/log/hincyray/` without blocking the child.

These are tracked in [`keenetic-client-roadmap.md`](keenetic-client-roadmap.md) under Post-MVP Scope.
