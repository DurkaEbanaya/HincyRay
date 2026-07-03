# Changelog

## v0.15.1 - 2026-07-03

### Added

- New Fluent/Acrylic Web UI (`src/webui/index.html`) embedded at compile time via `include_str!`, replacing the old inline HTML raw string. Features: 7 navigation groups, 24 sidebar items, 16 Mihomo Features sub-sections, custom Acrylic dropdowns, RU/EN i18n (~180 pairs), light/dark theme, brightness slider, tooltips toggle, login overlay, confirm modal, toast notifications, responsive bottom-nav for mobile, real `fetch()` API helper with Bearer-token auth, production data loaders for all 87 daemon endpoints, data-URI logo (no external asset dependency).
- `first_stream_json()` helper for parsing Mihomo streaming endpoints (`/traffic`, `/memory`) — extracts and validates the first JSON snapshot from a multi-object stream.
- `mihomo_api_get_response()` and `mihomo_api_post_response()` helpers returning `(status, body)` for callers that need to inspect HTTP status codes.
- `handle_mihomo_api_optional_forward_get()` and `handle_mihomo_api_optional_forward_post()` for EC endpoints that may return 405 on some Mihomo versions — normalizes to `{"ok":false,"supported":false,"mihomo_status":405}` instead of 502 transport error.
- 2 new tests: `stream_parser_uses_first_json_snapshot`, `stream_parser_rejects_empty_or_invalid_stream`.

### Changed

- `index_html()` now returns `include_str!("webui/index.html")` instead of a 2300-line inline raw string. Old UI removed entirely from `hincyray.rs` (−2345 lines).
- `/api/mihomo-api/configs/geo` and `/api/mihomo-api/rules/disable` now use optional forward handlers — return 200 with `{"supported":false}` when Mihomo EC responds 405, instead of 502.
- `mihomo_api_stream_get()` now succeeds when `curl --max-time` receives a valid first JSON snapshot even if curl exits with code 28 (timeout on infinite stream). Previously treated as error.
- Root endpoint test assertion updated from `"HincyRay daemon"` to `"HincyRay — Панель управления Mihomo"`.
- Web UI `updateStatusUI` split into `updateStatusCards` (core/profile/version cards) and `updateRoutingForm` (routing form fields). `loadRouting()` now calls only `updateRoutingForm`, preventing partial-data overwrites that caused status cards to flicker to `'—'` on every 5-second refresh.

### Verified

- Local gates: `cargo fmt --all`, `cargo check --all-targets --all-features`, `cargo clippy --all-targets --all-features`, `cargo test --all-targets --all-features` (294 tests, 0 clippy warnings).
- Router E2E on Keenetic Giga KN-1012 (64/64 passed): new WebUI root (title, data-uri logo, real fetch helper, no mock-token, old UI removed), health/status/system/profiles/stats/favorites/subscriptions/routing/dns/logs/hwid/update/features/config, Mihomo EC proxies/connections/version/configs/configs-geo/rules/providers/traffic/memory, routing trace, unlock check, update check, EC delay/fakeip-flush/dns-flush/rules-disable/connections-close, speed test, benchmark start/status/stop, backup create/delete, save-same for DNS/routing/auto-settings/mihomo-features/substore/auth-settings.
- Pixel 6a ADB: router ping OK, HincyRay API health OK via `nc`, browser launch OK. Transparent proxy path not testable (Android default network selection prefers wlan1 over HincyRay wlan0 segment).
- Post-flicker-fix E2E on Keenetic Giga (17/17 passed): health, status cards stable across refresh, routing form load/save, Mihomo features, benchmark, backup create, save-same for DNS/auto-settings/auth-settings.

## v0.15.0 - 2026-07-02

### Added

- 10 new outbound protocols for Mihomo config generation: ShadowsocksR, Snell, HTTP proxy, SOCKS, AnyTLS, Hysteria v1, SSH, MASQUE, OpenVPN, Tailscale. Share-link parsing in `profiles.rs` + Mihomo YAML builders in `mihomo_config.rs`.
- `ProxyGroupType::Relay` — deprecated by upstream but supported for config parity. Emits `type: relay` proxy group.
- DNS parity fields in `MihomoFeatures`: `fake-ip-filter-mode`, `fake-ip-ttl`, `use-hosts`, `use-system-hosts`, `default-nameserver`, `proxy-server-nameserver-policy`, `direct-nameserver-follow-policy`, `ecs`, `ecs-override`, `disable-ipv4`, `disable-ipv6`, `disable-qtype-N`.
- First-class typed rules (`MihomoRuleConfig` struct + `typed_rules` field) for `IN-NAME`, `IN-USER`, `PROCESS-*`, `UID`, `DSCP`, `RULE-SET` and other Mihomo rule types — emitted before raw rules in both simple and router configs.
- EC API parity endpoints: `GET /api/mihomo-api/version`, `/configs`, `/configs/geo`, `/rules`, `/providers/proxies`, `/providers/rules`; `POST /api/mihomo-api/cache/fakeip/flush`, `/cache/dns/flush`, `/rules/disable`. All use allowlisted static paths — no arbitrary URL forwarding.
- `mihomo_api_post` helper for POST requests to Mihomo EC, with empty-body → `{"ok":true}` normalization.
- Shared TLS/auth/bandwidth helper functions (`apply_tls_common`, `apply_user_password`, `copy_optional_*`, `split_csv`) for new protocol builders.
- Targeted tests: new outbound protocols type verification, relay group YAML emission, DNS parity fields, typed rules ordering.

### Changed

- `Protocol::from_scheme`: `hysteria://` / `hy://` now maps to `Protocol::Hysteria` (v1); `hysteria2://` / `hy2://` remains `Protocol::Hysteria2`. Prevents v1 links from being silently treated as v2.
- HTTP proxy profiles use `mihomo+http://` / `mihomo+https://` / `http-proxy://` / `https-proxy://` schemes to avoid collision with subscription URL detection (`http://` / `https://` remain subscription sources).
- `tester.rs` and `xray_config.rs` match arms explicitly return unsupported errors for new Mihomo-only protocols instead of falling through to `Unknown`.
- `mihomo_api_post` returns `{"ok":true}` when Mihomo responds with empty body (e.g. cache flush endpoints).

### Verified

- Local gates: `cargo fmt --all`, `cargo check --all-targets --all-features`, `cargo clippy --all-targets --all-features`, `cargo test --all-targets --all-features` (292 tests, 0 clippy warnings).
- Router E2E on Keenetic Giga KN-1012 (28/28 passed): health, status (core running, EC enabled, failover 0), EC API parity (/version, /configs, /configs/geo, /rules, /providers/proxies, /providers/rules, cache flush fakeip/dns), relay proxy group config generation, DNS parity fields in config (fake-ip-filter-mode, use-hosts, use-system-hosts, default-nameserver), typed DSCP rule in config, features reset, core restart, final health/connections.

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
