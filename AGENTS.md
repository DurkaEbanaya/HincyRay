# HincyRay v0.22.0 (`xray-vpn-test`)

Rust 2024 crate shipping two binaries: `hincyray` for Keenetic/Entware aarch64 and the feature-gated `xray-vpn-test` desktop diagnostics app. Router mode uses Mihomo with iptables NAT REDIRECT (TCP 10810) and mangle TPROXY (UDP 10811); there is no TUN/tun2socks path.

## Code map

- `src/main.rs`, `src/bin/hincyray.rs` — thin entrypoints only.
- `src/profiles.rs` — profile/share-link parsing and subscription loading. Plain HTTP(S) is a subscription URL; HTTP proxy profiles use `mihomo+http(s)://`.
- `src/benchmark.rs` — shared Mihomo benchmark plus native YouTube and Telegram Quick Test orchestration.
- `src/telegram_probe.rs` — serialized Telegram login/session/media probe; secrets and SQLite session stay outside `state.json`.
- `src/scoring.rs` — shared quality scoring.
- `src/mihomo_config.rs` — router and benchmark Mihomo YAML generation and protocol builders.
- `src/hincyray.rs` — daemon composition root: persisted state, lifecycle identity, HTTP handlers, transactional activation, watchdog, core/firewall orchestration, Deep Bench, and Dead Servers.
- `src/geobase.rs` — managed GeoBase storage/generation.
- `src/hincyray_api.rs` — typed bounded API contracts/OpenAPI.
- `src/hincyray_mihomo_api.rs` — Mihomo External Controller transport.
- `src/hincyray_routing.rs` — routing-resource normalization.
- `src/hincyray_security.rs` — password/session/login security.
- `src/hincyray_webui.rs`, `src/webui/index.html` — embedded Web UI boundary and asset.
- `src/tester.rs`, `src/xray_config.rs` — desktop diagnostics; `xray_config.rs` is not used by the router daemon.
- `scripts/hincyray-install.sh` — transactional installer with lifecycle lock, PID/executable identity checks, and rollback.
- `scripts/frontend-contract-test.py` — static Web UI/API contract.
- `scripts/installer-lifecycle-contract-test.py` — installer/init lifecycle contract.
- `tests/browser/` — fixture-backed Playwright smoke tests.
- `scripts/router-e2e.sh` — live router smoke suite.

## Architectural invariants

- Keep entrypoints free of application logic. Router behavior belongs behind daemon/library modules; desktop UI must not own router protocol execution.
- `Profile.group` is subscription/manual provenance only. Dead Servers is a virtual lifecycle projection; never encode dead state by rewriting profile groups.
- Routing and lifecycle identities are separate contracts:
  - routing targets use `server:srv-v1-…` and resolve through `server_route_registry`;
  - Dead Servers, Deep Bench selectors, and quality history use canonical `srv-v2-…` lifecycle refs;
  - never parse, substitute, or expose one contract as the other.
- Lifecycle canonicalization removes display identity but preserves connection identity. Startup migration converts raw and resolvable current-profile v1 lifecycle values to v2; legacy orphan v1 Trash entries remain restorable.
- Manual and automatic Dead Servers transitions share the serialized `mutate_dead_server_membership()` boundary. Validate the whole batch before mutation; active profiles cannot be moved; persistence/dataplane failures must roll lifecycle fields back without erasing unrelated state.
- Automatic/all/subscription scopes exclude dead profiles. Explicit diagnostic requests may include them. Enabled pinned routes preserve intent and use active fallback while their target is dead.
- Router DNS is always present because firewall rules unconditionally redirect port 53 to Mihomo on 1053. `dns.enabled` is a desktop-Xray concept.
- DIRECT routes use configured local DNS servers by default so their name resolution does not depend on VPN upstream health.
- Router geo assets are MetaCubeX `geosite.dat` + `geoip.metadb`; legacy `geoip.dat` and the oversized RKN bypass list are not runtime inputs.
- Quick Test is sequential. YouTube uses a narrow Innertube direct-format probe with Rust + `curl`; do not add Python/yt-dlp/JS runtime. Telegram uses one private SQLite session and must not be opened by concurrent clients.
- Redir and TPROXY listeners must stay on separate ports. The ndm hook is the primary firewall-reload mechanism; watchdog reinstall is a safety net.
- `geoip.metadb` must be present locally and `geo-auto-update: false`; router startup must not depend on blocked GitHub downloads.
- Mihomo fallback group `proxy` is the canonical upstream-health decider. The daemon reads its state; do not add duplicate periodic upstream probes.
- Keep request/response bodies bounded and structurally redact secrets. Never place real subscription URLs, tokens, private keys, or credentials in source/docs/tests; use `https://provider.example/sub/<token>`.
- Guard OS-specific APIs behind platform boundaries.

## Required gates

Run all before commit/release:

```sh
cargo fmt --all --check
cargo check --all-targets --all-features
cargo clippy --all-targets --no-default-features --bin hincyray -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
python3 scripts/frontend-contract-test.py
python3 scripts/installer-lifecycle-contract-test.py
npm run test:browser
git diff --check
```

Runtime benchmarking requires `mihomo` in `PATH`. Router E2E after deploy:

```sh
HINCYRAY_URL=http://127.0.0.1:8088 scripts/router-e2e.sh
```

Noisy Cargo/tests/router commands must write full output to a temp log and print only a bounded summary.

## Keenetic operations

Target: Keenetic Giga KN-1012, Entware aarch64. SSH is `root@192.168.1.1:222`; use the established `expect` password pattern because key auth is unreliable. SCP requires `-O`.

| Purpose | Value |
|---|---|
| Binary | `/opt/sbin/hincyray` |
| Init script | `/opt/etc/init.d/S99hincyray` |
| State | `/opt/etc/hincyray/state.json` |
| Quality history | `/opt/etc/hincyray/quality-history.json` |
| Mihomo config / geo dir | `/opt/etc/hincyray/mihomo-config.yaml` / `/opt/etc/hincyray` |
| Logs | `/opt/var/log/hincyray/` |
| Daemon API | `http://127.0.0.1:8088` |
| Mihomo EC | `127.0.0.1:9090` |
| SOCKS / mixed / redir / TPROXY | `10808` / `10809` / `10810` / `10811` |

Use `/opt/etc/init.d/S99hincyray start|stop|restart|status` exclusively. Never stop HincyRay with `pgrep -f`, `pkill -f`, `killall`, `pidof`, or argv/name scans; the init script owns the PID file and verifies `/proc/<pid>/exe`.

Router BusyBox lacks `python3`, `bc`, `timeout`, `iw`, and `iwconfig`; its `jq` has no regex/ONIGURUMA support. Use `curl --max-time`, bounded projections, and BusyBox-compatible syntax.

## Build and deploy

```sh
cargo zigbuild --release --no-default-features --bin hincyray \
  --target aarch64-unknown-linux-gnu.2.27
patchelf --set-interpreter /opt/lib/ld-linux-aarch64.so.1 \
  --set-rpath /opt/lib target/aarch64-unknown-linux-gnu/release/hincyray
shasum -a 256 target/aarch64-unknown-linux-gnu/release/hincyray
```

Before replacing the live binary:

1. Verify staged and local SHA256 match.
2. Stop through the init script, then snapshot binary, `state.json`, `quality-history.json`, and generated Mihomo config as one rollback set.
3. Install and verify remote SHA before start.
4. Start through the init script and wait for both the expected `/api/health` version and `core_status=running`; core startup is asynchronous after init returns.
5. Verify active profile, fallback group, firewall/TPROXY, and router E2E.
6. On any failure restore the complete rollback set and verify the previous version health.

Release artifact SHA256: `6a99122d61e75d039b0147c6b87789d2f0713b18f350a0dd88838f49cafe5e24`. Live verification and release evidence are recorded in `docs/releases/v0.22.0.md`.

## Release

- `Cargo.toml`, first-party `Cargo.lock`, README EN/RU, CHANGELOG, installer download version, installer contract, and `docs/releases/vX.Y.Z.md` must agree.
- The GitHub repository is private. Installer downloads must use a local `HINCYRAY_BIN_PATH` or authenticated API resolution with `HINCYRAY_GITHUB_TOKEN`; never assume a public `releases/download` URL or expose the token in URLs/logs.
- Inspect status/diff/log and stage only intended files. Never stage user-owned scratch documents or secrets.
- GitHub Release tag must target the pushed release commit and attach the hash-verified aarch64 `hincyray` artifact.
- Detailed history belongs in `CHANGELOG.md` and `docs/releases/`, not this file.
