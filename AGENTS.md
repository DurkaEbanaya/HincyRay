# Project: HincyRay v0.4 (crate `xray-vpn-test`)

Rust crate shipping two binaries: the `hincyray` router daemon (Keenetic Giga KN-1012 / Entware aarch64, safe SOCKS-only MVP by default, with an opt-in WiFi VPN segment added in v0.1.1, WiFi-only traffic split added in v0.3, and tun2socks-based WiFi VPN routing replacing TPROXY in v0.4) and the `xray-vpn-test` desktop diagnostics app (macOS, feature `desktop`). Both reuse `src/profiles.rs`, `src/scoring.rs`, and `src/xray_config.rs`.

Tech stack: Rust 2024, Cargo, `eframe/egui` desktop GUI (feature-gated), `reqwest` blocking client for subscription loading, external `sing-box` and `xray` binaries for protocol execution, `tun2socks` for TUN-based WiFi VPN routing on the router.

## Workspace Overview

* `src/main.rs` - thin binary entrypoint only.
* `src/bin/hincyray.rs` - thin binary entrypoint for the Keenetic router daemon.
* `src/lib.rs` - public module map and `eframe` startup wiring.
* `src/app.rs` - GUI state, user actions, table sorting, benchmark progress display.
* `src/profiles.rs` - profile/subscription parsing and subscription HTTP loading.
* `src/scoring.rs` - shared `quality_score` formula reused by `tester.rs` and `hincyray.rs`.
* `src/xray_config.rs` - shared Xray client config generation for VLESS (Reality + xhttpSettings). Hysteria2 returns an explicit error. Also exposes `query_value`/`percent_decode` to `tester.rs`.
* `src/tester.rs` - benchmark result model, sing-box config generation, proxy probes, and short download test. Uses `scoring::quality_score` and `xray_config::build_xray_config`.
* `src/hincyray.rs` - HincyRay router daemon: sync `TcpListener` HTTP API, state persistence, `CoreManager` for Xray process lifecycle, `TunManager` for tun2socks process lifecycle, WiFi-only split routing via tun2socks (TUN + iproute2, no iptables), per-server QUIC toggle, TUN controls in web UI.
* `src/theme.rs` - Fluent/Acrylic-inspired egui styling.
* `scripts/wifi-segment-setup.sh` - v0.1.1 opt-in WiFi VPN segment: create the `HincyRay-VPN` SSID on `192.168.2.0/24` via Keenetic `ndmc`. The daemon handles all routing internally via tun2socks and iproute2; no iptables/TPROXY scripts needed (removed in v0.4).

## Architectural Invariants

* Keep `main.rs` free of app logic; route new behavior through library modules.
* UI should not know protocol internals beyond display fields and benchmark results.
* Real protocol execution belongs behind `tester.rs`; keep UI changes independent from sing-box/xray implementation details.
* Profile parsing must accept both direct share links and HTTPS subscription URLs; examples may come from RTF/plain text paste buffers.
* Do not fold router-daemon behavior into the desktop GUI; Keenetic work should become a separate binary/API using shared parsing/scoring modules.
* WiFi VPN routing uses tun2socks (TUN device + iproute2 `ip rule`/`ip route`) — never iptables. iproute2 rules survive Keenetic ndm reloads; iptables mangle chains do not.

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
* v0.4 replaces TPROXY with tun2socks: `tun2socks` creates a TUN device and forwards WiFi VPN traffic (192.168.2.0/24) to Xray's second SOCKS inbound (127.0.0.1:10810) via iproute2 policy routing. No iptables/mangle/TPROXY needed. The watchdog checks tun2socks process + TUN interface + Xray core, not iptables chains.
* v0.1 status: `docs/hincyray-v0.1-status.md`. Entware install runbook (incl. WiFi VPN segment setup): `docs/hincyray-entware-install.md`. Longer plan: `docs/keenetic-client-roadmap.md` (roadmap, not currently shipped behavior beyond v0.4).
* Never put real subscription URLs or tokens in docs, tests, or commits; use the placeholder `https://provider.example/sub/<token>`.
