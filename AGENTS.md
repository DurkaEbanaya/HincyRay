# HincyRay v1.2.1 (`xray-vpn-test`)

Rust 2024 crate shipping two binaries: `hincyray` for Keenetic/Entware aarch64 and the feature-gated `xray-vpn-test` desktop diagnostics app. Router mode uses Mihomo with iptables NAT REDIRECT (TCP 10810) and mangle TPROXY (UDP 10811); there is no TUN/tun2socks path.

## Code map

- `src/main.rs`, `src/bin/hincyray.rs` — thin entrypoints only.
- `src/profiles.rs` — profile/share-link parsing and subscription loading. Plain HTTP(S) is a subscription URL; HTTP proxy profiles use `mihomo+http(s)://`.
- `src/benchmark.rs` — shared Mihomo benchmark plus native YouTube, Telegram, and AI Studio Quick Test orchestration.
- `src/telegram_probe.rs` — serialized Telegram login/session/media probe; secrets and SQLite session stay outside `state.json`.
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
- Routing-rule deletions are desired-state safe: activation failure leaves the deletion persisted and pending apply; additions and edits retain transactional rollback.
- Automatic/all/subscription scopes exclude dead profiles. Explicit diagnostic requests may include them. Enabled pinned routes preserve intent and use active fallback while their target is dead.
- Router DNS is always present because firewall rules unconditionally redirect port 53 to Mihomo on 1053. `dns.enabled` is a desktop-Xray concept.
- DIRECT routes use configured local DNS servers by default so their name resolution does not depend on VPN upstream health.
- Router geo assets are MetaCubeX `geosite.dat` + `geoip.metadb`; legacy `geoip.dat` and the oversized RKN bypass list are not runtime inputs.
- Quick/Full server workers are bounded to 1–6. YouTube uses a serialized narrow Innertube direct-format probe with Rust + `curl`; Telegram serializes access to its one private SQLite session. AI Studio uses the bounded ipregion Google-region + published-region-list method. The legacy direct AI Studio request remains disabled. Do not add Python/yt-dlp/JS runtime; ipregion has no Telegram check.
- Redir and TPROXY listeners must stay on separate ports. The ndm hook is the primary firewall-reload mechanism; watchdog reinstall is a safety net.
- `geoip.metadb` must be present locally and `geo-auto-update: false`; router startup must not depend on blocked GitHub downloads.
- Mihomo fallback group `proxy` is the canonical upstream-health decider. The daemon reads its state; do not add duplicate periodic upstream probes.
- Keep request/response bodies bounded and structurally redact secrets. Never place real subscription URLs, tokens, private keys, or credentials in source/docs/tests; use `https://provider.example/sub/<token>`.
- Subscription loading separates network-path fallback from client/content compatibility. Retry Happ identity only after an HTTP/content rejection; transport failures advance to the next path. Keep compressed and decoded bodies bounded.
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

Router BusyBox lacks `python3`, `bc`, `timeout`, `install`, `iw`, and `iwconfig`; its `jq` has no regex/ONIGURUMA support. Use `curl --max-time`, bounded projections, and BusyBox-compatible syntax.

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

Use this repeatable live-update sequence; do not improvise a different installer path:

1. `scp -O` the patched binary to `/opt/etc/hincyray/hincyray.stage` while the daemon is running, then verify its SHA256 remotely.
2. Create one timestamped rollback directory under `/opt/etc/hincyray/` containing `/opt/sbin/hincyray`, `state.json`, `quality-history.json`, and `mihomo-config.yaml` when present.
3. Arm a shell `trap` that stops via `S99hincyray`, restores that complete set with BusyBox `cp -p`, runs `chmod 0755 /opt/sbin/hincyray`, and starts via `S99hincyray` on any failure.
4. Stop via `S99hincyray`; replace the binary with `cp` plus `chmod 0755` (BusyBox has no `install`); verify installed SHA; start via `S99hincyray`.
5. Poll bounded `/api/health` and `/api/safe-mode` until the expected version, `core_status=running`, and `firewall_status=running`; only then disarm the trap and remove the staged file.
6. Verify active profile, fallback group, routing/firewall, the changed live behavior, and bounded router E2E. Keep the rollback directory and report its path.

Release artifact SHA256: `e809d1a3541b2bebd23400f71406f0d87716db206d1df977f99f9309c68cf720`. Live verification and release evidence are recorded in `docs/releases/v1.2.1.md`.

## Release

- `Cargo.toml`, first-party `Cargo.lock`, README EN/RU, CHANGELOG, installer download version, installer contract, and `docs/releases/vX.Y.Z.md` must agree.
- The GitHub repository is public. Installer downloads use the exact versioned `releases/download` asset; local `HINCYRAY_BIN_PATH` remains the offline path.
- Inspect status/diff/log and stage only intended files. Never stage user-owned scratch documents or secrets.
- GitHub Release tag must target the pushed release commit and attach the hash-verified aarch64 `hincyray` artifact.
- Detailed history belongs in `CHANGELOG.md` and `docs/releases/`, not this file.
