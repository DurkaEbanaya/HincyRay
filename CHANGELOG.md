# Changelog

## v0.14.0 - 2026-07-02

### Added

- Rule Trace API (`POST /api/routing/trace`) to explain which local routing/device/port rule would match a candidate request, while explicitly marking Mihomo-owned geo/rule-set evaluation as runtime-only.
- Sub-Store Lite (`GET/POST /api/substore-lite`, `POST /api/substore-lite/apply`) for parsed-profile cleanup: include/exclude filters, rename rules, protocol/address/port deduplication, sorting, and backup-before-apply.
- Smart Auto-Select 2.0 with EWMA score/latency/download metrics, minimum-success gating, failure penalty, and cooldown for repeatedly failing profiles.
- State backup/restore APIs (`GET /api/backups`, `POST /api/backups/create`, `/restore`, `/delete`) with traversal-safe backup names and pre-restore backups.
- WebDAV backup upload/download endpoints for remote state backup transport.
- Diagnostics & Recovery web panel with unlock checks, DNS diagnostics, rule trace, Sub-Store Lite controls, backup controls, and connection closing.
- Unlock checker (`POST /api/unlock-check`) for common services through the router proxy path.
- DNS diagnostics (`GET /api/dns/diagnostics`) with local resolver checks, Mihomo DNS query support where available, and routing trace context.
- Scheduled maintenance in watchdog: optional backup, subscription refresh, core restart, and connection close on a configurable UTC interval.
- Connection control (`POST /api/mihomo-api/connections/close`) to close all connections or filter by connection id, host, or source IP.

### Changed

- Mihomo External Controller client now dials loopback when the configured bind address is wildcard (`0.0.0.0`, `[::]`, or `:port`).
- RU Direct routing presets now use `geoip:RU` only; they no longer emit `geosite:ru`, which is absent from some router GeoSite datasets and can prevent Mihomo startup.
- `/api/status` and `/api/auto-settings` now include Smart Auto-Select and scheduled maintenance settings.

### Verified

- Local gates: `cargo fmt --all`, `cargo check --all-targets --all-features`, `cargo clippy --all-targets --all-features`, `cargo test --all-targets --all-features` (288 tests).
- Router E2E on Keenetic Giga KN-1012: health/status, auto-settings, rule trace, Sub-Store Lite, backup create/list/restore, filtered connection close, DNS diagnostics, unlock check, WebDAV validation, final Mihomo EC health.

## v0.13.0 - 2026-07-02

### Added

- REJECT routing target for rules and per-device routes.
- Routing presets: RU Direct, Ad Block, Only Web VPN, Block Social, RU Direct + Ad Block.
- Web UI authentication with login/password and in-memory session tokens.
- Mihomo backend for desktop benchmarking, replacing sing-box/xray execution and covering WireGuard/TUIC.

### Verified

- 280 tests, 0 clippy warnings.

## v0.12.0 - 2026-07-01

### Added

- Hysteria2 port hopping.
- Profile CRUD API.
- Auto-refresh subscriptions.
- Traffic statistics and persisted connection log.
- Speed test API.
- Per-device routing with `SRC-IP-CIDR` rules.

### Verified

- 280 tests, 0 clippy warnings.
