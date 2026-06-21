# Project: HincyRay v0.6.1 (crate `xray-vpn-test`)

Rust crate shipping two binaries: the `hincyray` router daemon (Keenetic Giga KN-1012 / Entware aarch64, safe SOCKS-only MVP by default, with an opt-in WiFi VPN segment added in v0.1.1, WiFi-only traffic split added in v0.3, tun2socks-based WiFi VPN routing replacing TPROXY in v0.4, HWID/protocol/port/DNS/geo features in v0.5, reliability/failover/auto-switch in v0.6, and system monitoring + interactive installer in v0.6.1) and the `xray-vpn-test` desktop diagnostics app (macOS, feature `desktop`). Both reuse `src/profiles.rs`, `src/scoring.rs`, and `src/xray_config.rs`.

Tech stack: Rust 2024, Cargo, `eframe/egui` desktop GUI (feature-gated), `reqwest` blocking client for subscription loading, external `sing-box` and `xray` binaries for protocol execution, `tun2socks` for TUN-based WiFi VPN routing on the router.

## Workspace Overview

* `src/main.rs` - thin binary entrypoint only.
* `src/bin/hincyray.rs` - thin binary entrypoint for the Keenetic router daemon.
* `src/lib.rs` - public module map and `eframe` startup wiring.
* `src/app.rs` - GUI state, user actions, table sorting, benchmark progress display.
* `src/profiles.rs` - profile/subscription parsing and subscription HTTP loading. Supports VLESS, VMess, Trojan, Shadowsocks, Hysteria2. `HwidConfig` for hardcoded device fingerprint. `decode_vmess_json` for base64-JSON vmess:// links.
* `src/scoring.rs` - shared `quality_score` formula reused by `tester.rs` and `hincyray.rs`.
* `src/xray_config.rs` - shared Xray client config generation for VLESS (Reality + xhttpSettings), VMess, Trojan, Shadowsocks. Hysteria2/WireGuard return explicit errors. `RouterExtra` for DNS anti-leak, port routing, geo asset paths. `PortMode` (All/AllowList/DenyList). `DnsSettings`. Also exposes `query_value`/`percent_decode`/`extract_ss_credentials` to `tester.rs`.
* `src/tester.rs` - benchmark result model, sing-box config generation (VLESS/VMess/Trojan/Shadowsocks/Hysteria2), proxy probes, and short download test. Uses `scoring::quality_score` and `xray_config::build_xray_config`.
* `src/hincyray.rs` - HincyRay router daemon: sync `TcpListener` HTTP API, state persistence with corruption recovery, `CoreManager` for Xray process lifecycle (with `XRAY_LOCATION_ASSET` env, stderr to log file), `TunManager` for tun2socks process lifecycle, WiFi-only split routing via tun2socks, per-server QUIC toggle, port routing, DNS anti-leak, HWID fingerprint, TUN controls in web UI, graceful shutdown (SIGTERM/SIGINT), watchdog with core restart + exponential backoff, health-check failover, auto-benchmark scheduling, auto-select best profile, Xray/tun2socks log viewer in web UI, auto-refresh status every 5s, dynamic bridge resolution, system monitoring (CPU/RAM/temp/load/uptime via `/proc` + `/sys`), `CpuTimes` delta computation for CPU usage.
* `src/theme.rs` - Fluent/Acrylic-inspired egui styling.
* `scripts/wifi-segment-setup.sh` - v0.1.1 opt-in WiFi VPN segment: create the `HincyRay-VPN` SSID on `192.168.2.0/24` via Keenetic `ndmc`.
* `scripts/hincyray-install.sh` - v0.6.1 interactive atomic installer (archinstall-style): staging → backup → atomic `mv` → verify → commit/rollback.

## Architectural Invariants

* Keep `main.rs` free of app logic; route new behavior through library modules.
* UI should not know protocol internals beyond display fields and benchmark results.
* Real protocol execution belongs behind `tester.rs`; keep UI changes independent from sing-box/xray implementation details.
* Profile parsing must accept both direct share links and HTTPS subscription URLs; examples may come from RTF/plain text paste buffers.
* Do not fold router-daemon behavior into the desktop GUI; Keenetic work should become a separate binary/API using shared parsing/scoring modules.
* WiFi VPN routing uses tun2socks (TUN device + iproute2 `ip rule`/`ip route`) — never iptables TPROXY. iproute2 rules survive Keenetic ndm reloads; iptables mangle chains do not.
* HWID fingerprint must be consistent: HWID, OS version, device model, and User-Agent must all agree so the server's cross-check passes.

## Development Practices

* Build/check: `cargo check`
* Format: `cargo fmt`
* Lint: `cargo clippy --all-targets --all-features`
* Test: `cargo test`
* Run GUI: `cargo run`
* Release build: `cargo build --release`

## Notes

* Runtime benchmarking requires `sing-box` and `xray` in `PATH`; on macOS `sing-box` can be installed with `brew install sing-box`.
* Subscription bodies are tried as plain text and common base64 variants.
* Happ/TutNet Xray-style JSON with DNS-over-HTTPS URLs is parsed via the `outbounds` fallback when no direct profiles are found.
* Do not add OS-specific APIs unless guarded behind a cross-platform boundary.
* v0.5 adds: VMess/Trojan/Shadowsocks parsing + Xray/sing-box outbound generation; HWID `HwidConfig` with configurable fingerprint; DNS anti-leak `DnsSettings` (remote/local DNS, queryStrategy); port routing `PortMode` (All/AllowList/DenyList) with `proxy_ports`/`bypass_ports`; GeoIP/GeoSite asset path (`XRAY_LOCATION_ASSET` env); per-rule `ports` and `network` fields in `RoutingRule`.
* v0.6 adds: watchdog always runs (not just split routing); Xray/tun2socks stderr captured to rotating log files (`/opt/var/log/hincyray/xray.log`, `tun2socks.log`); state corruption recovery (backup to `.corrupt`, log error); graceful shutdown via SIGTERM/SIGINT (stops children, cleans iptables/TUN, persists state); health-check failover (SOCKS probe, 3 consecutive failures → switch to next-best profile by score); auto-benchmark scheduling (`auto_bench_interval_hours`); auto-select best profile after benchmark; benchmark supports VMess/Trojan/SS (not just VLESS); dynamic VPN bridge resolution (not hardcoded `br1`); web UI auto-refresh every 5s; auto-settings and logs sections in web UI; `GET /api/logs`, `GET/POST /api/auto-settings` endpoints.
* v0.6.1 adds: system monitoring (`GET /api/system` — CPU model/cores/features/temp/usage per-core, RAM total/free/available/usage, load average, uptime, kernel, hostname, model via `/proc` + `/sys`); `CpuTimes` delta computation stored in `DaemonInner`; web UI System section with progress bars (CPU/RAM/temp) auto-refreshed every 5s; interactive atomic installer script (`scripts/hincyray-install.sh`, archinstall-style: staging → backup → atomic `mv` → verify → commit/rollback).
* v0.4 replaces TPROXY with tun2socks: `tun2socks` creates a TUN device and forwards WiFi VPN traffic (192.168.2.0/24) to Xray's second SOCKS inbound (127.0.0.1:10810) via iproute2 policy routing. iptables mangle MARK + FORWARD ACCEPT needed; watchdog reinstalls after ndm wipes.
* v0.1 status: `docs/hincyray-v0.1-status.md`. Entware install runbook: `docs/hincyray-entware-install.md`. Longer plan: `docs/keenetic-client-roadmap.md`.
* Never put real subscription URLs or tokens in docs, tests, or commits; use the placeholder `https://provider.example/sub/<token>`.
