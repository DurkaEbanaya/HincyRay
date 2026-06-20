# HincyRay v0.1 status

> **v0.4 update**: as of crate version `0.4.0`, the daemon replaced TPROXY with tun2socks (TUN device + iproute2 policy routing + mangle MARK). WiFi VPN traffic from `192.168.2.0/24` is routed through a TUN device (`tun0`) to Xray's second SOCKS inbound (`127.0.0.1:10810`) via `tun2socks`. A 10-second watchdog checks tun2socks process, TUN interface, Xray core, mangle MARK chain, and FORWARD rules — reinstalls any wiped by ndm. TUN interfaces and iproute2 rules survive ndm reloads; only iptables chains need watchdog reinstallation. Earlier versions added v0.3 WiFi-only traffic split, per-server QUIC blocking, live service catalog, and v0.2 background benchmark, stats, favorites, and subscription refresh. The v0.1 baseline described below is unchanged; see the [README](../README.md) for the v0.4 API table and the web panel's TUN controls.

Version: **0.1.0** (crate version in `Cargo.toml`). The crate version was later bumped to `0.4.0`, and the daemon reports `0.4.0` on `/api/health`.

This document records what is implemented, what was validated on real hardware, what is intentionally not implemented, and the next milestones. It is the authoritative v0.1 status snapshot; the long-form plan lives in [`keenetic-client-roadmap.md`](keenetic-client-roadmap.md).

## Implemented

- **Router daemon binary `hincyray`** built from the same crate as the desktop diagnostics tool, sharing `src/profiles.rs`, `src/scoring.rs`, `src/xray_config.rs`. Built without the desktop feature: `cargo build --release --no-default-features --bin hincyray` (skips `eframe` / `egui_extras` / `arboard`).
- **Sync HTTP server** on `std::net::TcpListener`, no async runtime, no web framework. One thread per connection, 15 s read/write timeouts, 1 MiB request body cap.
- **Default bind** `0.0.0.0:8088`, overridable via `HINCYRAY_LISTEN`.
- **State persistence** with auto-detected path: `HINCYRAY_STATE` &rarr; `/opt/etc/hincyray/state.json` (Entware) &rarr; `/etc/hincyray/state.json` (OpenWrt) &rarr; `$HOME/.config/hincyray/state.json` &rarr; `./hincyray-state.json`. Atomic save via temp file + rename.
- **Generated Xray config path**: `HINCYRAY_XRAY_CONFIG` &rarr; `xray-client.json` next to state.
- **JSON state** with profiles, `active_profile_id`, `auto_select`, `listen_host` (default `127.0.0.1`), `socks_port` (default `10808`), `http_port` (default `10809`, reserved), `xray_path` (default `xray`), `metrics_history`, `routing_rules`, `split_routing`, and per-profile `block_quic`.
- **HTTP API**: `GET /`, `GET /api/health`, `GET /api/status`, `GET /api/profiles`, `POST /api/profiles/import`, `POST /api/profiles/block-quic`, `POST /api/active-profile`, `GET /api/xray/config`, `POST /api/core/start|stop|restart`, `GET|POST /api/bench/*`, `GET /api/stats`, `POST /api/favorites/toggle`, `GET /api/favorites`, `GET|POST /api/subscriptions/*`, `GET /api/routing`, `POST /api/routing/settings`, `POST /api/routing/rules`, `POST /api/routing/catalog/refresh`, `POST /api/routing/apply`, `GET /api/routing/tun-status`, `POST /api/routing/tun-start`, `POST /api/routing/tun-stop`.
- **Embedded web panel** served inline from `index_html()` at `http://<router-ip>:8088/`: status cards, subscription/profile import box, profile table with activation, Xray config preview, and core start/stop/restart buttons. No external CDN or build step.
- **Subscription import** accepting direct `vless://` / `hysteria2://` / `hy2://` links, HTTPS subscription URLs, plain/base64/base64url subscription bodies, and Xray-style JSON configs with `outbounds`. Profiles merge by raw link (dedup).
- **Happ/TutNet subscription loading** with automatic retry using the Happ `User-Agent: Happ/3.22.1` and `X-HWID`, `X-Ver-OS`, `X-Bundle-ID`, `X-Device-model`, `X-Device-OS`, `X-API-Version` headers when the first `sing-box`-style fetch returns no profiles.
- **Happ/TutNet Xray-JSON fallback**: when a body contains DNS-over-HTTPS URLs but no direct profile candidates, the parser falls back to `outbounds` parsing so embedded DNS URLs are not mistaken for subscriptions.
- **Xray config generation** for VLESS Reality/TLS and VLESS XHTTP/Satellite via the shared `xray_config::build_xray_config`. Hysteria2 returns an explicit error from `/api/active-profile` (HTTP 400 with a clear message).
- **Core lifecycle**: `CoreManager` holds one in-memory Xray `Child`, status via `try_wait`, idempotent stop, restart = stop + start. Xray is spawned with `stdout`/`stderr` set to `Stdio::null()` so the long-lived child cannot block on a buffered pipe.
- **Safe SOCKS-only MVP (default)**: the daemon starts Xray with a local SOCKS listener at `127.0.0.1:10808` on the router. By default it does **not** install any routing hooks.
- **Opt-in WiFi VPN segment via tun2socks (v0.4)**: the daemon manages a `TunManager` that creates a TUN device (`tun0`) via `tun2socks`, forwards WiFi VPN traffic from `192.168.2.0/24` to Xray's second SOCKS inbound (`127.0.0.1:10810`), and installs iproute2 policy routing (fwmark `0x111`, table `111`) + iptables mangle MARK chain + FORWARD ACCEPT rules. A 10-second watchdog reinstalls any iptables rules wiped by ndm. The main `192.168.1.0/24` network is untouched. The WiFi segment SSID is created by `scripts/wifi-segment-setup.sh`; all routing is handled internally by the daemon.
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
- **WiFi VPN segment via tun2socks (v0.4)**: after running `scripts/wifi-segment-setup.sh` and enabling split routing in the web panel, a phone connected to the `HincyRay-VPN` SSID on `192.168.2.0/24` received the proxy exit IP and YouTube worked, while devices on the main `192.168.1.0/24` network kept their direct IP. `kill -HUP ndm` (simulating ndm reload) was tested: TUN interface survived, tun2socks stayed alive, VPN continued working with zero downtime. The 10-second watchdog successfully reinstalled FORWARD rules that were wiped by ndm.

## WiFi VPN segment via tun2socks (v0.4)

v0.4 routes a separate WiFi segment through Xray using tun2socks. The daemon manages the entire routing chain internally via `TunManager`; no manual iptables scripts are needed.

Flow:

1. `scripts/wifi-segment-setup.sh` &mdash; creates a `HincyRay-VPN` SSID on `192.168.2.0/24` (2.4 GHz + 5 GHz) via Keenetic `ndmc`, with a DHCP pool. The main `192.168.1.0/24` network is not touched. Run this once before enabling split routing.
2. The daemon's `TunManager` starts `tun2socks` with `-device tun://tun0 -proxy socks5://127.0.0.1:10810 -mtu 1400`, which creates the TUN device and forwards traffic to Xray's second SOCKS inbound.
3. iptables mangle MARK chain (`HINCYRAY_TUN`) marks packets from `192.168.2.0/24` with fwmark `0x111` (excluding local/multicast destinations).
4. iproute2 `ip rule fwmark 0x111 lookup 111` + `ip route add default dev tun0 table 111` routes marked packets through the TUN.
5. iptables FORWARD ACCEPT rules allow br1↔tun0 forwarding (ndm default FORWARD policy is DROP).
6. A 10-second watchdog checks all components and reinstalls any iptables rules wiped by ndm.

Invariants:

- Only `192.168.2.0/24` is steered through Xray; `192.168.1.0/24` keeps the main uplink.
- TUN interface and iproute2 rules survive ndm reloads; only iptables chains need watchdog reinstallation.
- All routing is managed by the daemon &mdash; no manual scripts beyond the initial WiFi segment setup.

## Not implemented (intentionally, for v0.1 safe MVP)

- **No automatic policy routing installed by the daemon.** By default the daemon only starts Xray with a local SOCKS listener at `127.0.0.1:10808` and does **not** install `iptables`, `ip rule`, or Keenetic routing hooks. The v0.4 WiFi VPN segment is managed by `TunManager` when split routing is enabled in the web panel.
- **Per-device steering is still post-MVP.** The v0.3 split-routing engine supports per-domain / per-IP / per-service steering for the tun2socks WiFi segment (`192.168.2.0/24`), but per-device or per-SSID rules are still future work.
- **No automatic server selection loop.** `scoring::quality_score` exists and is shared with the desktop app, and the v0.3 UI exposes an `auto_switch` toggle, but the daemon does not continuously benchmark or switch the active profile on failure.
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
4. **Policy routing (delivered in v0.4)**: WiFi-subnet routing is now managed by the daemon's `TunManager` using tun2socks (TUN + iproute2 + mangle MARK). v0.3 added per-domain / per-IP / per-service split rules. Remaining work: per-device / per-SSID rules. Keep the safe SOCKS-only mode as the default.
5. **Packaged Entware artifact**: produce an installable archive and an init script template that can be shipped from GitHub Releases, so the manual `scp` flow becomes optional.
6. **Web panel polish**: profile detail view, metrics history charts, log viewer, error copy buttons.
7. **Xray log capture**: route Xray `stderr` to a rotating file under `/opt/var/log/hincyray/` without blocking the child.

These are tracked in [`keenetic-client-roadmap.md`](keenetic-client-roadmap.md) under Post-MVP Scope.
