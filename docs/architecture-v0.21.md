# HincyRay v0.21 Architecture and Operational Contracts

Status: implemented contracts, 2026-07-15. Full Rust gates, Playwright result, cross-build, and router deployment remain pending until the final report.

## 1. Operational Model

HincyRay remains a synchronous Rust router daemon supervising Mihomo and Keenetic firewall integration:

```text
Keenetic traffic policy connmark
  -> iptables NAT REDIRECT for TCP on 10810
  -> iptables mangle TPROXY for UDP on 10811
  -> DNS interception on 1053
  -> Mihomo routing and outbound selection
```

There is no TUN device or tun2socks process. Mihomo config is generated output; persisted HincyRay state and the applied GeoBase snapshot are authoritative inputs.

## 2. Module Boundaries

| Module | Contract |
|---|---|
| `hincyray` | Composition root: HTTP dispatch, persisted state, activation, core/firewall/watchdog orchestration |
| `hincyray_api` | Typed bounded API DTOs for onboarding, routing, connection pages, memory report, safe mode, and `/api/contracts` |
| `hincyray_security` | Argon2id hashing, password verification, CSPRNG tokens, session expiry/cap, login throttling |
| `hincyray_webui` | Embedded Web UI asset boundary; HTTP routing does not know the asset filesystem layout |
| `mihomo_config` | Typed Mihomo YAML and routing rule generation; no process or HTTP ownership |
| `geobase` | Revisioned desired/applied manifests, artifact validation, quotas, and garbage collection |
| `profiles` / `scoring` / `benchmark` | Parsing, shared scoring, and benchmark execution independent of daemon transport |

`src/main.rs` and `src/bin/hincyray.rs` remain thin entrypoints. Shared modules compile in the no-default-features router build; desktop modules remain feature-gated.

## 3. Security Contract

Implemented behavior:

- Persist only an Argon2id PHC password hash with random salt; legacy plaintext is migrated on state load and not serialized again.
- Generate 256-bit cryptographically random Bearer tokens.
- Enforce 30-minute idle and 12-hour absolute session expiry, with at most 32 sessions.
- Throttle a source IP after five failed logins in five minutes for 15 minutes.
- Invalidate sessions when username, password, or auth-enabled state changes.
- Reject cross-origin state-changing requests when `Origin` does not match `Host`.
- Bound request bodies and reject malformed length or invalid UTF-8.
- Keep the browser token in `sessionStorage`; stale `localStorage.hincyray_token` is removed on page load.
- Redact secrets from both `GET /api/mihomo-config` and `GET /api/mihomo-config/preview`.

Public routes remain limited to the UI document, health, login, and reading auth settings. Other routes require a valid Bearer session when authentication is enabled.

## 4. Contract Discovery and Onboarding

### `GET /api/contracts`

Returns contract version `1`, the bounded endpoint list, `state_changing_requires_same_origin`, and auth scheme `argon2id-password+cSPRNG-bearer-expiry`.

### `GET /api/onboarding/status`

Returns:

```json
{
  "ready": false,
  "version": "0.21.0",
  "checks": [
    {
      "id": "mihomo",
      "label": "Mihomo binary",
      "status": "error",
      "detail": "/opt/sbin/mihomo unavailable",
      "remediation": "Install Mihomo or correct mihomo_path"
    }
  ]
}
```

Checks cover Mihomo, active profile, `geoip.metadb`, core, transparent firewall/TPROXY state, and the Keenetic ndm hook. `ready` is true only when every check is `ok`; failed checks include remediation text.

## 5. Routing Contracts

### `GET /api/routing/summary`

Returns transparent-routing and safe-mode state, match target, total/enabled user rules, device routes, managed rules, server count, conflicts, and whether the desired GeoBase generation requires apply.

### `GET /api/routing/connection-context`

Returns the bounded server projection used by the connection routing UI: stable `ref`, profile id, name, protocol, address, group, and active state. Raw share links and credentials are not included.

### `GET /api/routing/preview`

Builds the desired config without mutating runtime and compares its SHA-256 with the applied config file. The response reports `requires_apply`, whether core restart/firewall reload would occur, desired/applied hashes, changes, and routing conflict warnings. It does not persist state, replace the live config, restart Mihomo, reload firewall, or advance the applied GeoBase generation.

The separate `GET /api/mihomo-config/preview` returns redacted desired YAML.

### `POST /api/routing/explain`

Accepts `resource` or `host`, with optional `source_ip`, `port`, and `network`. The resource is normalized as a routable domain or IP and evaluated through the existing trace engine. The response includes the normalized resource, kind, local routing decision/candidates, and safe-mode state. Mihomo-owned GEOSITE/GEOIP/RULE-SET evaluation remains identified as runtime-owned rather than guessed locally.

`POST /api/routing/trace` and `GET/POST /api/routing/chain-check` remain compatible lower-level diagnostics.

## 6. Memory Report and Safe Mode

### `GET /api/memory-estimate`

Despite the compatibility name, this endpoint is a factual current-state report, not a speculative allocator forecast. It returns:

- `rule_source_bytes`: measured bytes of enabled local rule-provider and applied GeoBase artifacts on disk.
- `current_mihomo_rss_kb`: current Mihomo RSS from procfs when running.
- `available_memory_kb`: current `MemAvailable`.
- User-rule, rule-provider, and applied GeoBase entry counts.
- RKN bypass and safe-mode state.
- `risk`: `observed-ok` or `observed-warning`, derived from configured Memory Guard thresholds.
- `reasons`: observed threshold violations.

It does not claim an estimated incremental or peak memory allocation.

### `GET /api/safe-mode`

Returns enabled state, core/firewall status, and the heavy optional features suppressed by safe mode: RKN bypass, managed GeoBases, proxy/rule providers, sub-rules, raw/typed rules, tunnels, and smux.

### `POST /api/safe-mode`

Accepts:

```json
{"enabled":true,"apply":true}
```

The state change is persisted with an undo snapshot. With `apply:false`, only state changes. With `apply:true` (default), the normal transactional activation path validates and applies the desired config and firewall state. Activation failure restores the previous policy state and reports rollback status. Safe mode suppresses heavy generated features without purging profiles, subscriptions, source artifacts, backups, or history.

## 7. Bounded Connections

### `POST /api/mihomo-api/connections/page`

Request:

```json
{"query":"🇷🇺 chatgpt.com","offset":0,"limit":50}
```

Response:

```json
{
  "total": 120,
  "filtered": 1,
  "offset": 0,
  "limit": 50,
  "connections": []
}
```

`limit` defaults to 100 and is clamped to 1–500. Filtering occurs before `offset`/`limit` and covers host, sniffed host, destination/remote/source IP, destination country, rule, rule payload, and chains. Local GeoIP enrichment is applied before filtering. `GET /api/mihomo-api/connections` remains the legacy full snapshot for compatibility.

The Web UI uses the paged endpoint for active-connection views and combines it with `/api/routing/connection-context`. Its aggregate search index includes the exact rendered flag-plus-host label, fixing searches such as `🇷🇺 chatgpt.com`.

## 8. Transactional Activation and Persistence

Config activation is serialized by an apply lock:

1. Clone authoritative state and select desired/applied GeoBase projection.
2. Generate and validate Mihomo YAML.
3. Save previous config bytes and atomically write the candidate.
4. Restart/start Mihomo and observe process plus External Controller readiness.
5. Apply firewall state when requested.
6. Commit desired GeoBase generation only after successful activation.
7. Restore previous config, core state, firewall state, and policy state on failure.

`state.json` stores durable configuration and counters. Sessions, login limiter, undo snapshots, live jobs, sampled metrics, and the bounded 500-entry connection log are transient. `quality-history.json` and the revisioned GeoBase store remain separate from the main state.

## 9. Responsive Web UI

The Web UI remains one embedded HTML document with no CDN or frontend build step.

- Desktop uses the full sidebar and tables.
- Tablet/mobile navigation uses compact rail, tabs, bottom navigation, and mobile sheets.
- `enhanceResponsiveTables()` assigns `data-label` from table headers; at mobile widths each row becomes a labelled card.
- Profile rename uses an in-page form dialog with keyboard Enter/Escape behavior, never `window.prompt`.
- Native connection route selects remain native and usable on touch devices.
- Background polling remains limited to lightweight status/system loops; the removed periodic full-dashboard refresh is not restored.

## 10. Browser Smoke and Release Gates

The fixture-backed Playwright smoke suite covers page boot without JavaScript errors, exact `🇷🇺 chatgpt.com` search, native connection route action payload, and profile rename dialog behavior.

```bash
npm ci
npm run test:browser
```

The complete required release commands are:

```bash
cargo fmt --all --check
cargo check --all-targets --all-features
cargo clippy --all-targets --no-default-features --bin hincyray -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
python3 scripts/frontend-contract-test.py
npm ci
npm run test:browser
git diff --check
```

This document records the implemented contracts only. Final command results, a no-default-features aarch64 artifact, SHA verification, and router E2E/deployment evidence remain pending until the final report.
