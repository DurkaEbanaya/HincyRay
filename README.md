# HincyRay v0.1

HincyRay is a lightweight VPN/proxy client for Keenetic Homebrew routers. v0.1 ships a router daemon (`hincyray`) that reuses the parser, Xray config generator, and quality scoring originally developed for the `XrayVpnTest` desktop tool, and exposes an embedded web panel on the router LAN. The **v0.1.1 add-on** in `scripts/` introduces an opt-in WiFi VPN segment that routes a separate `HincyRay-VPN` SSID on `192.168.2.0/24` through Xray via TPROXY, leaving the main `192.168.1.0/24` network untouched.

The desktop app `xray-vpn-test` is still built from this crate behind the `desktop` feature, but its role is now diagnostics and benchmarking only &mdash; it is not the shipped product. See [`docs/hincyray-v0.1-status.md`](docs/hincyray-v0.1-status.md) for the version status and [`docs/keenetic-client-roadmap.md`](docs/keenetic-client-roadmap.md) for the longer plan.

## Features

- Router daemon `hincyray` runs on Keenetic Giga KN-1012 (Entware aarch64) and exposes a JSON HTTP API plus an embedded web panel.
- Web panel at `http://<router-ip>:8088/` for status, subscription import, profile selection, and Xray core start/stop/restart &mdash; no external CDN or build step required.
- Accepts direct `vless://`, `hysteria2://`/`hy2://` share links, HTTPS subscription URLs, and Xray-style JSON configs with `outbounds`.
- Loads Happ/TutNet-style subscriptions that require Android-like request headers, with automatic retry using the Happ `User-Agent` and `X-*` headers.
- Parses Happ/TutNet Xray-style JSON that carries DNS-over-HTTPS URLs by falling back to Xray `outbounds` parsing when no direct profiles are found, so embedded DNS URLs are not mistaken for subscriptions.
- Generates Xray client configs for VLESS Reality/TLS and VLESS XHTTP/Satellite via the shared `xray_config` module.
- Persists state, profiles, active profile, and generated Xray config under `/opt/etc/hincyray/` on Entware.
- **Opt-in WiFi VPN segment via TPROXY (v0.1.1 add-on)**: shell scripts under `scripts/` create a separate `HincyRay-VPN` SSID on `192.168.2.0/24`, patch the generated Xray config with a `dokodemo-door` TPROXY inbound on port `10810`, and install `iptables` mangle TPROXY rules that steer **only** `192.168.2.0/24` through Xray. The main `192.168.1.0/24` network is untouched. Nothing is installed automatically by the daemon.
- Desktop `xray-vpn-test` remains available as the macOS diagnostics surface (feature `desktop`) for benchmarking nodes through `sing-box` and `xray`.

## Safe SOCKS-only MVP (default)

v0.1 is intentionally narrow to avoid breaking the workstation that manages the router:

- The daemon only starts Xray with a local SOCKS listener on the router at `127.0.0.1:10808`.
- It does **not** install `iptables` / `ip rule` / `nftables` rules, Keenetic routing hooks, or any system-wide policy routing. (The v0.1.1 WiFi VPN segment is **opt-in and manual**: you must run `scripts/` yourself; see [WiFi VPN segment (v0.1.1, opt-in)](#wifi-vpn-segment-v011-opt-in) below.)
- It does **not** change your main workstation IP or default route. Validation is done by curling through the router-local SOCKS proxy from the router itself.
- It does **not** autostart policy routing or transparent proxying by default. The opt-in WiFi segment is the only shipped routing path; per-device/per-domain rules are post-MVP.

## Current limitations

- **No automatic routing installed by the daemon.** By default only the router-local SOCKS endpoint is exposed. The v0.1.1 WiFi VPN segment is opt-in and script-driven (TPROXY for `192.168.2.0/24` only); per-device/per-domain steering and automatic failover are still post-MVP.
- **Hysteria2 is not supported by the Xray backend.** Selecting a Hysteria2 profile returns a clear 400 error from `/api/active-profile`. A future sing-box or Mihomo backend is planned.
- **Router internet may require manual artifact copy.** The Entware router is often isolated or has restricted direct downloads. The Xray binary, HincyRay binary, and `geoip.dat`/`geosite.dat` assets may need to be fetched on a workstation and copied via `scp`. See [`docs/hincyray-entware-install.md`](docs/hincyray-entware-install.md).
- **Automatic server selection is not wired up.** The shared `scoring::quality_score` exists, but the daemon does not yet run benchmarks or pick the best profile.
- **Web panel is MVP scope.** It covers status cards, import, profile table, and core controls; advanced UI is post-MVP.

## Build

Requirements:

- Rust 2024 toolchain.
- For the desktop diagnostics build: macOS SDK / Xcode command line tools, plus `sing-box` and `xray` in `PATH` for runtime checks.

### Router daemon (HincyRay v0.1)

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
| `GET` | `/` | Embedded web panel (status cards, import, profile table, core controls). LAN URL: `http://<router-ip>:8088/`. |
| `GET` | `/api/health` | `{ "ok": true, "service": "hincyray", "version": ... }`. |
| `GET` | `/api/status` | Active profile, profile count, listen info, xray paths, core status. |
| `GET` | `/api/profiles` | Imported profiles with id/name/protocol/transport/address/port/active. |
| `POST` | `/api/profiles/import` | Body: share links, Xray JSON config, or subscription URL. Loads subscriptions synchronously and merges by raw link. |
| `POST` | `/api/active-profile` | Body: `{ "profile_id": N }` (or `{ "id": N }`). Generates Xray config and persists state. Returns 400 if Xray does not support the protocol (e.g. Hysteria2). |
| `GET` | `/api/xray/config` | Generated Xray client config for the active profile (400 if none/unsupported). |
| `POST` | `/api/core/start` | Start `xray run -format json -c <xray config path>` as a child process. |
| `POST` | `/api/core/stop` | Stop the running Xray child, if any. |
| `POST` | `/api/core/restart` | Stop then start. |

Request bodies are limited to 1 MiB. No async runtime or web framework is used; the daemon runs on `std::net::TcpListener` with one thread per connection.

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
```

## WiFi VPN segment (v0.1.1, opt-in)

The four shell scripts in `scripts/` add an opt-in path to route a separate WiFi segment through Xray:

- `scripts/wifi-segment-setup.sh` &mdash; creates the `HincyRay-VPN` SSID on `192.168.2.0/24` via Keenetic `ndmc` (2.4 GHz + 5 GHz, DHCP pool).
- `scripts/xray-tproxy-inbound.sh` &mdash; patches the generated Xray config with a `dokodemo-door` TPROXY inbound on `0.0.0.0:10810` (needs `jq`).
- `scripts/tproxy-setup.sh` &mdash; installs `iptables` mangle TPROXY rules + a policy-routing table for `192.168.2.0/24` only.
- `scripts/tproxy-rollback.sh` &mdash; removes the above; `192.168.2.0/24` then routes direct again.

Only `192.168.2.0/24` is steered through Xray; `192.168.1.0/24` keeps the main uplink. Nothing is installed automatically, and changes are not saved to flash unless you run `ndmc -c "system configuration save"`. The `iptables` rules are not persisted, so re-run `tproxy-setup.sh` after every reboot. The step-by-step runbook (run, test, rollback, save) is in [`docs/hincyray-entware-install.md`](docs/hincyray-entware-install.md).

## Documentation

- [`docs/hincyray-v0.1-status.md`](docs/hincyray-v0.1-status.md) &mdash; what is implemented, what is validated on KN-1012, what is not implemented, next milestones.
- [`docs/hincyray-entware-install.md`](docs/hincyray-entware-install.md) &mdash; concrete install/runbook for Keenetic Entware, including manual artifact copy, init script, subscription import in isolated networks, SOCKS validation, and rollback.
- [`docs/keenetic-client-roadmap.md`](docs/keenetic-client-roadmap.md) &mdash; longer product roadmap and post-MVP scope.

## Notes

- VLESS XHTTP is not supported by `sing-box`, so the desktop diagnostics app tests XHTTP/Satellite profiles through `xray`. The router daemon uses `xray` exclusively for v0.1.
- The quality score is a pragmatic composite of short download speed, latency, jitter, and failures. It is shared between the desktop app and the daemon via `scoring::quality_score`.
- Neither the daemon nor the desktop app modifies system VPN settings in v0.1; checks and the router MVP run through a local SOCKS proxy.
- Subscription bodies are tried as plain text and common base64 variants.
- Do not put real subscription URLs or tokens into bug reports or docs; use the placeholder `https://provider.example/sub/<token>`.
