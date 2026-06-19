# Project: HincyRay v0.1 (crate `xray-vpn-test`)

Rust crate shipping two binaries: the `hincyray` router daemon (Keenetic Giga KN-1012 / Entware aarch64, safe SOCKS-only MVP by default, with an opt-in WiFi VPN segment added in v0.1.1) and the `xray-vpn-test` desktop diagnostics app (macOS, feature `desktop`). Both reuse `src/profiles.rs`, `src/scoring.rs`, and `src/xray_config.rs`.

Tech stack: Rust 2024, Cargo, `eframe/egui` desktop GUI (feature-gated), `reqwest` blocking client for subscription loading, external `sing-box` and `xray` binaries for protocol execution.

## Workspace Overview

* `src/main.rs` - thin binary entrypoint only.
* `src/bin/hincyray.rs` - thin binary entrypoint for the Keenetic router daemon.
* `src/lib.rs` - public module map and `eframe` startup wiring.
* `src/app.rs` - GUI state, user actions, table sorting, benchmark progress display.
* `src/profiles.rs` - profile/subscription parsing and subscription HTTP loading.
* `src/scoring.rs` - shared `quality_score` formula reused by `tester.rs` and `hincyray.rs`.
* `src/xray_config.rs` - shared Xray client config generation for VLESS (Reality + xhttpSettings). Hysteria2 returns an explicit error. Also exposes `query_value`/`percent_decode` to `tester.rs`.
* `src/tester.rs` - benchmark result model, sing-box config generation, proxy probes, and short download test. Uses `scoring::quality_score` and `xray_config::build_xray_config`.
* `src/hincyray.rs` - HincyRay router daemon: sync `TcpListener` HTTP API, state persistence, `CoreManager` for Xray process lifecycle.
* `src/theme.rs` - Fluent/Acrylic-inspired egui styling.
* `scripts/wifi-segment-setup.sh`, `scripts/xray-tproxy-inbound.sh`, `scripts/tproxy-setup.sh`, `scripts/tproxy-rollback.sh` - v0.1.1 opt-in WiFi VPN segment via TPROXY: create the `HincyRay-VPN` SSID on `192.168.2.0/24` via Keenetic `ndmc`, patch the generated Xray config with a `dokodemo-door` TPROXY inbound on port `10810`, install `iptables` mangle TPROXY rules + a policy-routing table that steer only `192.168.2.0/24` through Xray, and roll them back. The daemon itself stays SOCKS-only; these scripts are run manually and are not saved to flash without `ndmc -c "system configuration save"`.

## Architectural Invariants

* Keep `main.rs` free of app logic; route new behavior through library modules.
* UI should not know protocol internals beyond display fields and benchmark results.
* Real protocol execution belongs behind `tester.rs`; keep UI changes independent from sing-box/xray implementation details.
* Profile parsing must accept both direct share links and HTTPS subscription URLs; examples may come from RTF/plain text paste buffers.
* Do not fold router-daemon behavior into the desktop GUI; Keenetic work should become a separate binary/API using shared parsing/scoring modules.

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
* v0.1 is a safe SOCKS-only MVP by default: router-local `127.0.0.1:10808` only, no `iptables`/`ip rule`/`nftables`/Keenetic routing hooks installed by the daemon. The v0.1.1 add-on in `scripts/` adds an opt-in WiFi VPN segment via TPROXY for `192.168.2.0/24` only (manual setup, not installed by the daemon).
* v0.1 status: `docs/hincyray-v0.1-status.md`. Entware install runbook (incl. WiFi VPN segment setup): `docs/hincyray-entware-install.md`. Longer plan: `docs/keenetic-client-roadmap.md` (roadmap, not currently shipped behavior beyond v0.1 / v0.1.1).
* Never put real subscription URLs or tokens in docs, tests, or commits; use the placeholder `https://provider.example/sub/<token>`.
