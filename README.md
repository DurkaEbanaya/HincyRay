# HincyRay v1.3.28

Local v1.3.28, dated 2026-09-25, shows green/red connection indicators for Keenetic devices in “Zигануть Vсеми руками” and keeps disconnected devices in a collapsed list while preserving MAC selection. Details: [v1.3.28](docs/releases/v1.3.28.md). The versioned GitHub Release artifact has not been published.

[English](README.md) | [Русский](README.ru.md)

---

HincyRay is a lightweight VPN/proxy client for Keenetic routers. It ships a router daemon (`hincyray`) that reuses the parser and benchmark engine from the `XrayVpnTest` desktop tool, and exposes an embedded web panel on the router LAN.

The daemon uses **Mihomo (Clash.Meta)** as the single proxy core, supporting VLESS (Reality/xhttp), VMess, Trojan, Shadowsocks, ShadowsocksR, Snell, HTTP, SOCKS, AnyTLS, Hysteria v1/v2 (port hopping), WireGuard, TUIC, SSH, MASQUE, OpenVPN, and Tailscale. Transparent proxying via iptables NAT REDIRECT (TCP) + TPROXY (UDP) — no tun2socks, no TUN device.

## How it works

v1.3.12 is a verified, deployed local correction: explicit **Check Services** actions attempt YouTube, Telegram, and AI Studio for the chosen scope instead of inheriting global Find N/short-circuit settings. All final gates passed (674 Rust / 88 browser tests / 131 frontend routes). A real complete-service test passed all three on active profile 88; read-only live Chromium confirmed its green indicators and profile 431's existing red results. [YouTube previews](docs/youtube-availability.md) remain contract 1, not video playback or Mihomo health.

Final artifact, rollback, router E2E, service smoke, and live UI evidence are in [the v1.3.12 record](docs/releases/v1.3.12.md). Historical v1.3.7-v1.3.11 evidence remains unchanged. GitHub publication remains pending and unauthorized; no v1.3.12 asset availability is claimed. `HINCYRAY_BIN_PATH` remains the offline artifact path.

```
Device on Keenetic "HincyRay" policy
         |
         v
  iptables nat PREROUTING
  (match by policy connmark)
         |
    +----+----+
    v         v
  TCP       UDP
    |         |
  REDIRECT  TPROXY
  ->10810   ->10811
    |         |
    v         v
  Mihomo redir/tproxy inbounds
  (redir-in TCP 10810, tproxy-in UDP 10811)
         |
         v
  Active outbound (VLESS/VMess/Trojan/SS/Hy2/WG/TUIC)
         |
         v
  Internet
```

Devices not assigned to the policy keep their normal route — no interference with the main network.

### ndm firewall reload survival

Keenetic's `ndm` daemon recreates all iptables chains on config changes, WAN events, and DHCP renewals. HincyRay installs a hook script at `/opt/etc/ndm/netfilter.d/hincyray.sh` that **ndm itself calls** after every firewall reload, reinstalling all rules atomically. A 10-second watchdog acts as a safety net.

## Features

### v1.3.24

The status cards include a Direct availability check. It runs bounded direct requests, without SOCKS or HTTP proxy, to Google, VK, ya.ru, and YouTube in parallel and shows each result independently.

### v1.3.23

Results ordering is the initial profile-table view. The chosen order, including Import order when explicitly selected, persists across page reloads. An accepted subscription Check Services start selects and saves Results order, so returning to the page shows the expected ranking without another click.

### v1.3.22

An accepted subscription Check Services run selects Results order. Within each subscription, profiles with more passed YouTube preview, Telegram, and AI checks appear first; ties use fresh ping, while untested/stale and unreachable entries remain distinct at the end. The Ping cell in this mode shows the same fresh measurement used for sorting.

### v1.3.21

Torrent SOCKS5 flows are labeled in both connection tables. Changing the Torrent SOCKS5 target reconnects only its inbound connections; changing applied general routing rules reconnects existing connections so they pick up the new route. A partial reconnect is reported instead of silently claiming success.

### v1.3.20

Torrent SOCKS5 now shows a live password byte count and explains that an empty New password field preserves only an already configured password. Invalid first-time and too-short passwords are rejected in the browser before applying unrelated routing settings.

### v1.3.19

Torrent SOCKS5 can be enabled while Web UI authentication is disabled, and panel authentication can be disabled without stopping an existing authenticated Torrent SOCKS5 listener. The separate SOCKS5 credentials remain required.

### v1.3.18

Server-target pickers in routing rules, connections, and Torrent SOCKS open as a centered searchable dialog. Refreshes defer while routing edits or dialogs are active, rule removal has a visible Undo action, and disabled Parovozik rules are hidden. The wagon list starts collapsed. The Steam memory incident and the limits of current evidence are recorded separately in the release note; no automatic memory recovery is enabled.

### v1.3.17

Torrent clients can use a dedicated authenticated SOCKS5 listener whose identity is routed independently of domains, ports, or encrypted BitTorrent payloads. TCP and client-supported SOCKS5 UDP share one listener in the existing Mihomo process; target changes do not require changing the client. Credentials are never returned by the API or config preview, and listener/state lifecycle changes are validated and rolled back transactionally.

### v1.3.16

The canonical `proxy` dataplane is now a selector over `proxy-active` and `REJECT`; a hidden isolated sensor measures the active VPN without directly changing routing. The watchdog counts only fresh URL-specific samples, uses three-failure/two-success hysteresis, preserves fail-closed state across reloads, restarts, updates, and rollback, and isolates slower pinned/Parovozik health namespaces. This prevents a saturated pinned transfer from turning one delayed 3-second probe into an immediate cross-VPN outage.

### v1.3.15

The canonical active, pinned-server, exact-current-server, and Parovozik VPN groups put `REJECT` first. Mihomo skips it while a VPN member is healthy, but its all-unhealthy first-member behavior now rejects locally instead of falling through to WAN or repeatedly dialing a dead upstream. Delay diagnostics test the raw active outbound rather than poisoning aggregate group state, and the UI renders rejected chains and unknown health conservatively.

### v1.3.14

Routing target selection now uses one wide searchable grouped picker for new and existing rules and connection actions. Entries show profile IDs, long names without clipping, and Dead Servers/fallback state. Connection polling pauses while the picker is open.

The typed resource-reload action serializes configuration mutation, applies desired routing, then closes matching Mihomo connections by sniffed host or destination IP with source, port, and network qualifiers. Closure is bounded and errors are redacted. GeoIP, GeoSite, and rule-set decisions remain Mihomo runtime decisions instead of being presented as a definite target. Persistence failures roll memory back, and device-route apply ensures the core is running before transparent routing is enabled.

### v1.3.13

Ordinary actions send `availability_full` with optional strict `service_checks`: ordered `youtube` (YT), `telegram` (YT+TG), or `ai`/`all` (YT+TG+AI), plus boolean `fail_fast`. Shared GUI choices apply across all scopes; All and fail-fast are selectable in ordinary and advanced modes. Missing/null policy retains shipped full/all defaults. Ordinary checks have no `search` or discovery preflight; only the separate explicit advanced global Find N action has a candidate target.

Explicit ordinary policy admits exactly `min(requested workers, candidates)` or rejects with HTTP 503 before reservation, preserving an existing job rather than silently reducing workers. The unchanged 80 MiB reserve + 48 MiB/worker estimate requires 272 MiB available for four; unknown/zero budgets reject. Legacy/adaptive caps and remaining-target bounds remain. Contract-1 thumbnail probes no longer wait for the native YouTube mutex: each worker owns private core/config/captures and bounded decoding with cancellation guards. Native contract-7 playback and the shared Telegram SQLite session remain serialized. Four actual concurrent successful router transfers are not yet proven; no native video, new authentication/runtime, generic health, or automatic lifecycle action is added.

The live four-candidate request was rejected before reservation with memory permitting three; the existing idle job was preserved. A subsequent ordinary `availability_full` request for `[88]`, concurrency four, and explicit YT/no-fail-fast policy admitted exactly one for one candidate (not memory-reduced four-candidate work), with no search/preflight. Contract-1 previews passed once; TG/AI were unrequested, not false-green passes. Durable lifecycle and desired routing/settings projections stayed unchanged, allowing expected cache/stats/traffic updates. Separate real desktop/mobile DOM confirmed enabled All/fail-fast controls, green/current YT and gray/skipped TG/AI on 88, and closed technical details without sidebar clutter, mobile overflow, or JS errors. Intercepted single/global builders received mock 503 without forwarding mutations; v1.3.13 All/TG/AI positives and dynamic fail-fast sequences remain unverified. Older full-service/live UI evidence below is historical.

### v1.3.12

All/global, subscription, group, single-profile, favorite, selected, and explicit Dead Servers lightning actions consistently mean **Check Services**. They send `availability_full` without `search`, attempt all three services, and bypass the generic discovery preflight. Persisted global target 5, Find N prefix, or fail-fast settings cannot silently change an explicit diagnostic. Find N is a separate opt-in advanced global action with collapsed parameters. Technical explanations live outside the sidebar in collapsed Profiles details; sidebar activity shows only name/count, Stop, and animation. Actual passes/failures show green/red, unknown stays amber, and gray means stale/no-attempt/skipped. Native contract-7/contract-6 history is not converted into thumbnail success.

The minimal Trash lookup fix canonicalizes profiles once, preserving first-alias and legacy-orphan behavior; the live 519-entry response now succeeds within a five-second request budget. Active profile 88 passed real channel/three-preview, authorized Telegram media, and AI region checks with matching public service timestamp/ref. Read-only live Chromium verified green/red states, collapsed details, no mobile overflow, and no JavaScript errors; it did not click a lightning action, so scope request transport is fixture coverage, not live-click evidence.

The prior direct full test of Obhod 10 primary 431 (old connection aliases 93/100) failed all three services. Its healthy pinned group selects active-88 fallback, not a repaired primary; provider/protocol/network cause remains unproven. The old Find N single-click did not test YouTube. No native video pass, automatic quality/Dead Servers/AutoSelect action, quantitative speedup, or full-state byte isolation is claimed. Details: [check semantics](docs/youtube-availability.md), [`CHANGELOG.md`](CHANGELOG.md), and [`docs/releases/v1.3.12.md`](docs/releases/v1.3.12.md).

### v1.3.11

Restores subscription/group header lightning actions for the whole selected scope and their table presentation. Every profile has fixed neutral YT/TG/AI indicators with explicit not-tested, stale, skipped, or current state. Fresh completed results overlay safely after profile loading only when canonical lifecycle-v2 ref and exact ID match; service freshness uses public `last_service_test_unix`, not generic health activity. Status exposes canonical `server_ref`, never private raw identity.

Preflight diagnostics preserve HTTP/curl errors and append fixed-category upstream deadline evidence from a private, bounded 64 KiB warning-log tail, without raw core addresses. TLS EOF before service testing is not "YouTube bad": 335 rejected preflights mean services were untested, not 335 proven false failures or dead servers. Sampled transport deadlines and an established TCP socket do not prove the credentials/server/network cause; a fresh reparse of profile 93 generated byte-identical config, with no observed persisted-field loss. Protocol, SNI, certificate verification, and timeouts are not changed without proof.

Complete scope retains per-candidate Quick YouTube/Telegram short-circuit or Full continued checking; Find N retains preflight, history ordering, and goals. Contract-1 previews remain weaker evidence without native promotion, automatic Dead Servers, AutoSelect, or generic health updates; native contract-7 API/history stay separate. Live profile 93 preserved TLS EOF and added `[deadline_exceeded]` without testing YouTube; the final active-profile-88 smoke reached target 1 with three decoded previews, matching canonical ref and public service timestamp. Lifecycle/order/dead and routing intent stayed unchanged. Browser overlay behavior passed fixture tests; actual live DOM was not exercised. See [semantics](docs/youtube-availability.md), [`CHANGELOG.md`](CHANGELOG.md), and [`docs/releases/v1.3.11.md`](docs/releases/v1.3.11.md). No quantitative speedup or playback repair is claimed.

### v1.3.10

All user-facing search scopes use **YouTube channel and previews**: validate the public MrBeast channel and successfully fetch/decode previews for three distinct videos. The new `availability_quick`/`availability_full` methods and `search_availability` results use `youtube_thumbnails` contract 1. Shared completion/failure policies and Find N prefixes remain available; search offers no alternate YouTube verification method.

This check makes no Innertube request, video download, cookie/session import, JavaScript execution, or authentication workaround. Preview success proves only page/image access, not playback or account access. Native contract-7 `quick`/`full` API/history remain separate for concrete shipped/persisted compatibility. Availability stores resource diagnostics, not generic EWMA health or native overall success, and never triggers native promotion, automatic Dead Servers movement, or AutoSelect.

All final-version gates passed (668 Rust / 67 browser tests / 131 UI routes); the hash-verified deployment passed router E2E. A live target-1 search on active profile 88 confirmed the MrBeast channel and three distinct decoded previews, reached the target without cancellation, and preserved active identity, order, and Dead Servers projections. Resources, search bookkeeping, and background traffic accounting may change; no full-state byte isolation, quantitative speedup, or traffic-cost comparison is claimed. See [bounds and evidence](docs/youtube-availability.md), [`CHANGELOG.md`](CHANGELOG.md), and [`docs/releases/v1.3.10.md`](docs/releases/v1.3.10.md).

### v1.3.9

v1.3.9 changes adaptive preflight to accept any completed HTTPS response with HTTP status 200-599 as transport reachability, retrying once on an alternate domain through the same isolated Mihomo core. This is not a YouTube pass. Private core files survive until child reap; status keeps at most 20 preflight diagnostics with redacted errors bounded to 2 KiB, without health/Dead Servers penalties.

The native YouTube probe uses direct VISIONOS Innertube without mandatory web watch/bootstrap or a JavaScript runtime. Only a successful video-MIME media transfer of at least 16 KiB can pass. Bot/login refusal, HTTP 429, and client-compatibility refusals are **inconclusive**: the UI shows amber/unknown, summaries do not turn unknown or stale legacy evidence into failure or success, and unknown evidence cannot drive promotion, Dead Servers, or AutoSelect. Unknown history stays unknown; native resource contract 7 makes contract-6 evidence stale, while the defaulted `inconclusive` field tolerates old saves.

Linux core spawning now uses a persistent bounded owner thread so HTTP-thread exit cannot trigger Mihomo's `PDEATHSIG`; daemon-death cleanup and actual child ownership remain intact. All required gates passed (649 Rust / 66 browser tests / 131 UI routes), and the hash-verified deployment passed router E2E. Live diagnostics kept bot refusal unknown, found no good server, and preserved active identity, order, and Dead Servers. Authorized manual clock correction did not resolve the bot refusal or the other candidate's TLS EOF. NTP was initially unsynchronized, then independently verified twice as accurate/synchronized via `pool.ntp.org` at 17:34 UTC, within one second of the host; reboot persistence remains unverified.

No anonymous media bytes, playback fix, blanket false-rejection result, or quantitative speedup is claimed. No cookie/session import, authentication workaround, captcha, JavaScript, or yt-dlp runtime is added. Details: [probe semantics](docs/adaptive-discovery.md), [`CHANGELOG.md`](CHANGELOG.md), and [`docs/releases/v1.3.9.md`](docs/releases/v1.3.9.md). `HINCYRAY_BIN_PATH` matches the offline artifact workflow; GitHub publication and future asset availability remain pending and unauthorized.

### v1.3.8

v1.3.8 unifies global, selected, subscription, group, and single-profile testing behind one action and browser-stored parameters. **Complete scope** uses all native service checks with either YouTube/Telegram failure short-circuiting (existing Quick internally) or continued checking (existing Full internally). **Find N** uses a target of 1-20 and a supported YouTube, YouTube+Telegram, or YouTube+Telegram+AI Studio prefix. Unsupported combinations are not offered; explicit Dead Servers diagnostics always complete their scope.

The scheduler now waits for temporary target slots instead of permanently retiring workers. Status distinguishes requested workers, effective workers, active work, and the admission limit, with memory, candidate-count, and target-slot reasons. Startup admission estimates an 80 MiB router reserve and 48 MiB per worker; an unknown budget or a known budget permitting zero workers returns HTTP 503. This is not a continuous memory-reserve guarantee. YouTube and Telegram remain serialized: requesting four workers does not mean four concurrent YouTube checks.

All required gates passed: 625 Rust tests, 63 browser tests, and a frontend contract covering 131 routes. The hash-verified artifact is deployed with core/firewall running and router E2E passed. Controlled three-candidate YouTube searches observed peak active work of three for target 3 and one for target 1, without changing active identity, profile order, or Dead Servers membership. These observations are not parallel YouTube checks or a quantified speedup.

Details and runtime coverage limits: [unified search and discovery](docs/adaptive-discovery.md), [`CHANGELOG.md`](CHANGELOG.md), and [`docs/releases/v1.3.8.md`](docs/releases/v1.3.8.md). GitHub publication is pending; no v1.3.8 download availability is claimed. The installer version matches the verified local artifact; `HINCYRAY_BIN_PATH` remains the offline installation path.

### v1.3.7

v1.3.7 adds **Find Servers** for all live profiles, a selection, or one subscription, with a target of 1-20 and YouTube, YouTube+Telegram, or YouTube+Telegram+AI Studio requirements. Fresh service history affects ordering only; every counted server is measured again. Canonical aliases count once, and endpoint/provenance diversification plus rotating exploration broadens coverage. Preflight rejection is not health or Dead Servers evidence, and discovery never activates, promotes, or moves profiles.

This version also preserves login blocks on throttle-table overflow, treats unavailable or malformed Mihomo controller observations as inconclusive without health penalties or failover, redacts benchmark status and safely remaps result identities, and prevents delayed navigation focus from stealing focus from an input. Details: [adaptive discovery](docs/adaptive-discovery.md), [`CHANGELOG.md`](CHANGELOG.md), and [`docs/releases/v1.3.7.md`](docs/releases/v1.3.7.md). Verified local artifact, gates, and router deployment evidence are recorded there; GitHub publication remains pending.

### v1.3.6

v1.3.6 adds opt-in Quick/Full Test automation: promote successful servers within their group by service tier and ping, and move completely unresponsive inactive servers to Dead Servers. Settings and profile order are persisted; cancelled tests do not apply these actions. Details: [`CHANGELOG.md`](CHANGELOG.md) and [`docs/releases/v1.3.6.md`](docs/releases/v1.3.6.md).

### v1.3.2

v1.3.2 restores sidebar scanner movement when the client OS or browser requests reduced motion. The scanner remains deliberately slower in that mode, while unrelated decorative animations stay disabled. Details: [`CHANGELOG.md`](CHANGELOG.md) and [`docs/releases/v1.3.2.md`](docs/releases/v1.3.2.md).

### v1.3.1

v1.3.1 adds editable XHTTP upload tuning to manual profile settings, reports real daemon stages while switching the active server, makes Quick Test cancellation interrupt in-flight benchmark-owned processes, and prevents repeated server selections from queueing configuration applies. Benchmark concurrency is now bounded by available router memory.

The sidebar activity indicators no longer use high-frequency JavaScript animation timers or overlapping status polls. Operation instances are tracked independently, stale responses cannot resurrect completed indicators, refresh fanout is coalesced, and benchmark rows rerender only when results change. Details: [`CHANGELOG.md`](CHANGELOG.md) and [`docs/releases/v1.3.1.md`](docs/releases/v1.3.1.md).

### v1.3.0

v1.3.0 adds an on-demand **Profile Logger** for reproducing unstable browsing and streaming through the active server. A bounded 1–5 minute session records only new connections from the explicitly selected LAN client IP, profile-relevant warning/error events, routing chains, traffic counters, memory/runtime context, the latest service diagnostics, and a structurally redacted configuration summary. The resulting bounded Markdown report is written for direct use in an AI support conversation and excludes share links, subscription URLs, authentication data, and keys.

Profiles now have a secure on-demand editor for the display name and complete manual share link, with parsed protocol, transport, address, port, lifecycle, and subscription provenance. Subscription-managed links remain read-only. The `No group` projection can locally reparse and validate all manual profiles as one atomic batch.

The Mihomo Parameters page was reduced to router-relevant runtime status and validated Expert controls. Unsupported or parallel configuration surfaces were removed, External Controller became a fixed loopback invariant, and parameter changes now validate, apply, persist, or roll back as one transaction.

This release also fixes orphan Mihomo split-brain processes and verifies that the tracked child owns every required listener, bounds and streamlines connection-table polling, supports Happ/Xray XHTTP `extra` options including header-based `GET` packet uplinks on Mihomo v1.19.29, and makes the benchmark concurrency selector persist and visibly run up to six workers. See [`CHANGELOG.md`](CHANGELOG.md) and [`docs/releases/v1.3.0.md`](docs/releases/v1.3.0.md).

### v1.2.2

v1.2.2 makes Quick and Full YouTube diagnostics use the same bounded playback policy, retries transient network failures once, and tries multiple direct media formats so a broken low-resolution CDN URL does not produce a false failure. Quick Test now performs the actual YouTube check whenever its temporary Mihomo runtime starts instead of deriving a YouTube result from unrelated ping diagnostics.

The benchmark concurrency field is a native accessible 1–6 selector again. After a successful active-profile switch, HincyRay closes existing Mihomo connections so applications reconnect through the new server rather than retaining the previous exit IP. See [`CHANGELOG.md`](CHANGELOG.md) and [`docs/releases/v1.2.2.md`](docs/releases/v1.2.2.md).

### v1.2.1

v1.2.1 makes the built-in Mihomo updater safe on memory-constrained Keenetic routers. Core releases are now decompressed directly into the staged file instead of being buffered in HincyRay memory, while the existing binary verification, backup, restart, and rollback flow remains intact. Subscription wrappers whose query value is another URL are also preserved as one source instead of being split at the nested scheme. See [`CHANGELOG.md`](CHANGELOG.md) and [`docs/releases/v1.2.1.md`](docs/releases/v1.2.1.md).

### v1.2.0

v1.2.0 replaces the legacy speed-oriented profile benchmark UI with explicit Quick and Full service tests. Both modes record ICMP, direct TCP, and end-to-end proxy HTTPS ping diagnostics plus YouTube, Telegram, and AI Studio availability. Quick Test stops a profile at the first failed stage; Full Test records every stage independently. Server-level concurrency is configurable from 1 to 6, while the shared Telegram session and anonymous YouTube boundary remain serialized.

The YouTube probe now carries its visitor cookies and matching client identity through the bounded media-range request, avoiding false CDN `403` results, and uses a realistic connect budget. Subscription compatibility also rejects unusable unspecified-address sentinels before the existing Happ fallback. See [`CHANGELOG.md`](CHANGELOG.md) and [`docs/releases/v1.2.0.md`](docs/releases/v1.2.0.md).

### v1.1.0

v1.1.0 adds the disabled-by-default **Паровозик** direct-first classifier. It only considers domains absent from enabled applied GeoBases, keeps learned `Паровозик Direct` and `Паровозик VPN` lists separate from user and GeoBase rules, and can try the current VPN followed by up to five selected live server routes. Its compact subscription-column UI excludes Dead Servers and preserves unsaved selections across status refreshes.

Quick Test now determines AI Studio availability with the bounded [`vernette/ipregion`](https://github.com/vernette/ipregion) region method. See [`CHANGELOG.md`](CHANGELOG.md) and [`docs/releases/v1.1.0.md`](docs/releases/v1.1.0.md).

### v1.0.0

v1.0.0 is the first stable public release. It promotes the hardened Keenetic/Mihomo runtime developed through v0.22.1 and ships a production Fluent/Acrylic Web UI with a restored HincyRay mark, responsive desktop/tablet profile grids, mobile navigation, bounded API-backed views, and visible progress feedback for long-running tests and apply/download operations.

The stable release includes transactional core/firewall activation, persistent ndm firewall recovery, TCP REDIRECT + UDP TPROXY, canonical routing and lifecycle identities, Dead Servers, Deep Bench, real Quick Test checks for YouTube/Telegram/AI Studio, secure Web UI sessions, structurally redacted diagnostics, managed GeoBase, backups, and a public release installer path. AI Studio availability follows the bounded Google-region method from [`vernette/ipregion`](https://github.com/vernette/ipregion); Telegram retains its authorized media probe because ipregion does not expose a Telegram check. See [`CHANGELOG.md`](CHANGELOG.md) and [`docs/releases/v1.0.0.md`](docs/releases/v1.0.0.md).

### v0.22.1

v0.22.1 fixes transparent-router outages that looked like dead VPN servers. DHCP limited broadcasts, link-local traffic, loopback, and every RFC1918 destination now bypass TCP REDIRECT and UDP TPROXY in both live firewall rules and the persistent ndm hook. Proxy hostnames bootstrap through configured local DNS servers instead of depending on the not-yet-established proxy itself, and the watchdog requires the `proxy-active` outbound—not only its aggregate fallback group—to report alive.

Quick Test service indicators (`YT`/`TG`/`AI`) now remain beside the profile name even when the optional latency column is hidden. Dead Servers also supports single/all Quick Test, restore-all, and atomic clear; profile quality is represented by raw latency/jitter/loss/speed rather than a synthetic score.

### v0.22.0

v0.22.0 turns Quick Test into real, per-profile service validation. YouTube uses a narrow native Innertube bootstrap and downloads a bounded 512 KiB `googlevideo.com` range through the tested profile; it needs only Rust, Mihomo, and `curl`—no Python, `yt-dlp`, JavaScript runtime, or TUN path. Telegram signs in through a dedicated Web UI flow and downloads one bounded chunk from a configured media message through the same temporary profile runtime.

Telegram API credentials and authorization state are kept outside `state.json`: private config and SQLite session files use mode `0600`, API responses never return the API hash, phone, login code, or 2FA password, and the Web UI provides an explicit revoke/delete action. Versioned `YT`/`TG` indicators discard obsolete smoke results, while the profile metric gear keeps wide diagnostic columns optional.

Routing is smaller and more predictable: the legacy oversized RKN bypass subsystem and router `geoip.dat` path are removed. Supported router geo assets are MetaCubeX `geosite.dat` and `geoip.metadb`; managed GeoBase avoids a redundant Active provider under `MATCH,proxy`, while static Active networks remain explicit.

### v0.21.7

v0.21.7 keeps DIRECT/RU routes usable when the VPN upstream is unavailable by resolving DIRECT destinations through the configured local DNS servers. It introduced the selected-server Quick Test entry point that v0.22.0 upgrades to end-to-end service validation.

Background auto-VPN learning no longer restarts Mihomo when it discovers a domain. Learned exceptions are persisted and applied on the next explicit routing apply or core restart, avoiding a router-wide connection interruption. The duplicate auto-switch controls now remain synchronized in the Web UI.

### v0.21.6

v0.21.6 adds a virtual Dead Servers lifecycle group with atomic bulk move/restore, preserves each profile's subscription/manual provenance, and excludes dead profiles from automatic selection while retaining explicit diagnostics. Routing keeps its `srv-v1` identity contract; lifecycle, Deep Bench, and quality history use canonical `srv-v2` references that survive display renames and equivalent URL serialization.

On upgrade, raw lifecycle values and resolvable current-profile `srv-v1` values migrate to `srv-v2` automatically. Legacy orphan `srv-v1` Trash entries remain restorable. Do not use lifecycle refs as `server:` routing targets: routing intentionally remains backed by `server_route_registry` and `srv-v1`.

### v0.21.5

v0.21.5 makes automatic failover evidence-based: benchmark history only orders candidates, while every replacement server must pass a fresh zero-loss HTTPS check through its real proxy protocol before HincyRay switches. Candidate identity is raw-link based and remains correct across subscription reindexing.

### v0.21.4

v0.21.4 preserves both stdout and stderr from every temporary Mihomo benchmark process. Early process exits now return the real startup/configuration diagnostic instead of an opaque exit code, preventing runner failures from being mistaken for bad proxy profiles.

### v0.21.3

v0.21.3 makes subscription refresh non-destructive: HTTP success without a supported proxy profile is reported as a content failure, and an empty refresh can never replace an existing subscription group. Removing a group remains an explicit user action.

### v0.21.2

v0.21.2 is a router hotfix for GeoBase Active routing: broad generated Active rule providers now use the Mihomo fallback group `proxy` instead of raw `proxy-active`, so upstream flaps fall back safely instead of breaking policy-marked clients.

### v0.21.1

v0.21.1 completes the remaining v0.21 control-plane contract work: full onboarding checks for policy mark, kernel modules, EC and DNS; generated OpenAPI/JSON schemas at `/api/openapi.json`; typed routing preview diffs; redacted log output; an explicit Connections “create/change rule” flow; expanded browser E2E for login, routing add/apply, DNS save/apply, profile import and mobile bottom navigation; and module extraction for Mihomo EC plus resource normalization.

### v0.21.0

v0.21 implements the hardening and operability contracts end to end. Authentication uses Argon2id password storage with legacy plaintext migration, cryptographically random bounded sessions, login throttling, same-origin mutation checks, and `sessionStorage` for the browser Bearer token. Generated applied and preview configs are redacted before they leave the daemon.

The versioned API surface is advertised by `GET /api/contracts`. Readiness/onboarding, routing summary/context/preview/explain, observed memory reporting, safe mode, and bounded connection pages are available at `/api/onboarding/status`, `/api/routing/summary`, `/api/routing/connection-context`, `/api/routing/preview`, `/api/routing/explain`, `/api/memory-estimate`, `GET/POST /api/safe-mode`, and `POST /api/mihomo-api/connections/page`. The memory report is factual: rule-source bytes on disk, current Mihomo RSS, available memory, rule/provider counts, and threshold-derived observed risk. It does not speculate about future peak allocation.

The Web UI adds responsive table-to-card layouts, mobile/tablet navigation, a profile rename dialog instead of `window.prompt`, and exact search support for rendered flag-plus-host labels such as `🇷🇺 chatgpt.com`. Module boundaries now include typed API DTOs in `hincyray_api`, auth policy in `hincyray_security`, and embedded UI ownership in `hincyray_webui`. The v0.21 release passed full Rust/frontend/browser gates, was cross-built for Keenetic/Entware aarch64, and was live-validated on Keenetic Giga. See [`docs/architecture-v0.21.md`](docs/architecture-v0.21.md) and [`docs/releases/v0.21.0.md`](docs/releases/v0.21.0.md).

### v0.20.0

Deep Bench adds a two-phase server quality workflow: quick benchmarking followed by stability samples, unlock checks, and sustained-download observation. Compact daily snapshots live in `quality-history.json`, and the 30-day history supports conservative Trash Bin promotion after repeated poor readings plus automatic or manual restore.

### v0.19.4

Fluent Reveal spotlight effect fixed (var() in radial-gradient was not resolving) and extended to buttons, chips, section headers, select triggers, and tabs. `/api/profiles/add` now accepts subscription URLs, not just share links — pasting a subscription URL fetches and imports all profiles instead of returning a parse error.

### v0.19.3

Emergency Web UI performance fix: periodic polling now uses only lightweight System/Status heartbeats. The heavyweight full-dashboard refresh loop was removed after it caused request storms and multi-second admin UI latency on Keenetic.

### v0.19.2

System UX hotfix: hardware/resource metrics now refresh through a lightweight 3-second heartbeat, and the Memory card opens a live breakdown with Linux memory summary, Mihomo/HincyRay RSS, top RSS processes, and Memory Guard warnings.

### v0.19.1

Hotfix: the System page now visibly renders hardware/resource metrics, the dead Hardware sidebar item is removed, and Mihomo config validation is bounded so a hung `mihomo -t` cannot block the daemon API.

### v0.19.0

Diagnostics and release-hardening:

- System page now includes hardware metrics directly: CPU/RAM/temp/load/uptime/host/core breakdown from `/api/system`.
- Added Mihomo config validator: `POST /api/mihomo-config/validate` runs the generated YAML through Mihomo test mode when supported.
- Added DNS diagnostics 2.0 (`GET /api/diagnostics/dns`) and UDP/QUIC diagnostics (`GET /api/diagnostics/udp-quic`).
- Added Memory Guard (`GET /api/memory-guard`) with Mihomo RSS and top RSS processes.
- Added Prometheus metrics at `GET /metrics`.
- Added subscription refresh reports, backend undo stack, bounded state compaction, global Web UI search, CLI commands, doctor script, router E2E script, frontend contract test, and CI with split clippy profiles.
- Tests: 348 passed.

### v0.18.0

Web UI sharing and audit hardening:

- Profile sharing APIs: `POST /api/profile-groups/share` shares a whole subscription/group (all servers in that group) and `POST /api/profiles/share` remains available for a single server profile.
- Web UI has **Share / QR** and delete actions on every subscription/group header in the profiles table, so URL-backed subscriptions and named imported groups are handled uniformly.
- Fixed profile add payload (`raw`), Sub-Store sorting (`sort_by`), EC raw response rendering, auto-update settings wiring, system metrics binding, and routing delete undo.
- Removed confusing per-server share/QUIC actions from the table row flow; subscription/group actions live on the group header, while QUIC remains controlled through routing rules.
- Added Web UI controls audit document.

### v0.17.0

- **Simplified routing lists**: the oversized legacy RKN list was removed in favor of managed GeoBase, GeoSite RU Direct, and the bounded Always VPN override list.
- **Reset to factory defaults**: one-click reset restores safe RU Direct, MATCH, and port-mode defaults and clears user/raw rules. The Web UI calls `POST /api/routing/reset` with `{"apply":true}`, so persistence, config regeneration, core restart, and rollback are one backend transaction.
- **Configurable sniffer override-destination**: toggle in the DNS section to control Mihomo's `override-destination` sniffer setting. Default `true` — ensures domain rules match even when clients use DoH/DoT (SNI is extracted into the destination field). `saveDns()` now calls `/api/routing/apply` after saving so DNS changes take effect immediately.
- 339 tests, 0 clippy warnings.
- Router E2E verified on Keenetic Giga: bypass list downloaded (24 MB, 744,070 rules, ~5s), Mihomo RSS 157 MB, toggle on/off verified in config, reset restores factory defaults.

### v0.16.0

- **MATCH toggle**: the final `MATCH` rule is now visible as an immutable first row in the rules table. Toggle between `MATCH,proxy` (everything through VPN) and `MATCH,direct` (everything direct, rules decide what goes through VPN). Locked to `proxy` when no rules exist.
- **Inline cell editing**: click any cell in the rules table to edit it in place — name, domains/IPs, target (active/direct/reject/best), ports (with include/exclude mode), and protocol (any/tcp/udp). No separate edit form needed.
- **Per-rule port mode**: each rule can specify ports as "only these" (`DST-PORT`) or "except these" (`AND` with `NOT,DST-PORT`). Generates correct Mihomo AND-rules.
- **AND rule composition**: when a rule combines domains/IPs + ports + network, they are ANDed together (`AND,((DOMAIN-SUFFIX,example.com),(DST-PORT,443),(NETWORK,udp)),target`) instead of emitting separate OR-style rules.
- **QUIC block is now a regular rule**: the old "Block QUIC globally" checkbox and "QUIC mode" dropdown are removed from settings. QUIC blocking is now a visible, editable rule in the table (`network=udp, ports=443, target=reject`). Migrated automatically from old state.
- **Geo provider management**: new "Геобаза" card with provider selection (MetaCubeX/Loyalsoldier/v2fly), file status (size/exists), and one-click download through the SOCKS proxy. `GET /api/geo/providers`, `POST /api/geo/download`, `GET /api/geo/status`.
- **Preset target override**: clicking a preset chip now shows a target selector (active/direct/reject) — apply "RU Direct" with target `active` to route Russian IPs through VPN instead of direct.
- **Routing conflict detection**: `GET /api/routing` returns `conflicts` array with warnings when per-rule ports clash with global PortMode (AllowList/DenyList). Shown as auto-hiding toast notifications.
- **"Сеть" → "Протокол"**: renamed the "Network" column/field to "Protocol" throughout the UI.
- 323 tests, 0 clippy warnings.

### v0.15.6

- **RU Direct**: route Russian domains direct before `MATCH,proxy`. Two modes: `.ru`/`.рф` TLD suffixes or `GEOSITE,category-ru` (includes `vk.com`, `yandex.com`). Exceptions list for domains that should go through VPN anyway (e.g. `2ip.ru`). Rule order: user rules > QUIC block > RU Direct exceptions (→proxy) > RU Direct main (→DIRECT) > port-mode > MATCH.
- **Unified rules UI**: merged Domains + IPs into single textarea with auto-classification. Expanded service catalog to 23 services + 3 domain zones. Click-to-append chips. Edit (✎) button for inline rule editing.
- **Chain-check `info` status**: informational nodes (GEOIP runtime, no active connection) are `info` not `warn`; overall status is `ok` when only info nodes exist.
- **Routing rules CRUD fixed**: delete/toggle/add/preset-apply all call API then reload from server. Custom select sync fixed (initCustomSelects before refreshDashboard).
- **`network=any` fix**: no longer emits `NETWORK,any` which crashes Mihomo. Two-layer normalization at daemon + config generator.
- 313 tests, 0 clippy warnings.

### v0.15.5

- **Routing chain diagnostics**: new `/api/routing/chain-check` endpoint and Web UI metro-line visualization for split routing, policy marks, firewall/DNS/TCP/UDP interception, Mihomo core, active proxy, geo assets, device overrides, port mode, routing rules, and observed Mihomo connections.
- **Safer routing presets on Keenetic**: router rejects known OOM-heavy `geosite:category-ads-all` rules before applying config, preventing Mihomo from crashing during matcher construction.
- **Unlock checks improved**: backend accepts both `service` and `services`; each result now includes direct and proxy probes so the UI can show whether VPN actually unlocks the target.
- **Local connection country flags**: `/api/mihomo-api/connections` enriches Mihomo connection metadata from local `geoip.metadb`, including Meta-geoip0 databases used by Mihomo.
- **UDP TPROXY capability restored**: firewall startup now loads `xt_TPROXY`/`xt_socket` before capability detection and the ndm hook reloads them before reinstalling UDP rules. Verified on Keenetic Giga: `tproxy_available=true`, `tproxy-in` listener on 10811, `HINCYRAY_UDP` mangle rules installed, chain-check UDP node OK.
- **Subscription/profile UI fixes**: refresh/delete group actions use saved subscription URLs; provider card cancel buttons remove the correct card; added “Без пресетов / Всё VPN” preset.
- 306 tests, 0 clippy warnings.

### v0.15.4

- **Systematic Web UI button audit (~40 buttons fixed)**: every action button now has a proper handler with success toast and optional auto-reload. `apiAction(method, path, body, successMsg, reloadFn)` wrapper standardises all action calls. Background polling uses `api(silent=true)` — no more error toast spam every 5 seconds when External Controller is disabled. Error toasts auto-hide after 5s.
  - **Save/load functions**: `saveAutoSettings()` (15 fields), `saveSubStore()`, `saveFeatures()` (GET→merge→POST→apply — doesn't clobber unexposed fields), `saveRoutingSettings()` (12 fields), `saveAuth()` — all with success toasts.
  - **Result modals**: `showConfig()` (YAML config), `checkUpdate()` (version info), `speedTest()` (Mbps/bytes/elapsed), `doTrace()` (decision/name/reason/source/target/candidates), `loadLogs()` (log viewer).
  - **Speed test UI**: service selector (Cloudflare/OVH/Google/Custom URL), mode selector, timeout input. Shows download speed, bytes, elapsed time. Upload/jitter/packet-loss honestly omitted (no compatible upload endpoint).
  - **Human-readable EC error**: "External Controller is disabled. Enable it in Mihomo → Settings…" instead of raw 502 JSON.
  - ID attributes added to ~50 form fields. ~40 new i18n entries (RU/EN).
- **Benchmark details**: collapsible `<details>` with per-server results table (ID, profile, status, latency, jitter, speed, packet loss, error). `renderBenchResults()` populates both the benchmark section and the overview Tests section.
- **Overview "Tests" section**: new sidebar nav item with speed/delay/benchmark quick buttons, traffic/memory cards, compact top-20 bench results table.
- **Mihomo memory procfs fallback**: `read_process_rss_kb(pid)` reads `VmRSS` from `/proc/<pid>/status` when EC is disabled or returns `inuse:0`. Verified: `{"inuse":35724,"oslimit":0,"source":"procfs"}`.
- **Device routing UI clarity**: split into two tables — "Detected LAN devices" (shows all scanned devices including those without override) and "Individual override routes" (only explicit per-device rules). Warning text: override routes have priority above domain/GEO rules. Default target changed from `direct` to `active`. `loadDevices()` auto-loads on page init (silent, no toast).
- 301 tests, 0 clippy warnings.

### v0.15.3

- **DNS section fixed**: Save button now sends all fields (remote/local servers, strategy, enabled) with success toast. Leak test and Diagnostics buttons now display results in a modal — structured table with status badges, iptables rule checks, proxy exit IP, DNS resolver comparison, nslookup output, Mihomo EC DNS query, Cloudflare trace.
- **DNS diagnostics on BusyBox**: replaced `nslookup` (which doesn't support custom ports on BusyBox) with pure-Rust DNS-over-TCP query (`dns_query_tcp`) — no external tools needed.
- 301 tests, 0 clippy warnings.

### v0.15.2

- **Profile sorting by column click**: click any sortable header (Балл, Задержка, Скорость, EWMA, etc.) to sort ascending ▲, click again for descending ▼. State persists across 5s refresh.
- **Collapsed group persistence**: profile group collapse state saved to `localStorage` — survives page reload.
- **Favorites table**: full compact table with all metrics and inline Select/Rename/Delete buttons, replacing the old text-only list.
- **Profile ID/group fix**: `normalizeProfiles` merges profiles + stats endpoints — IDs show correctly (0, 1, 2…) and group names show friendly names instead of raw subscription URLs.
- **Compact profile table**: reduced padding and font size; column reordered (Балл and action buttons near start, Адрес at end).
- **Traffic/memory live updates**: proxy status cards now fetch real data from `/api/traffic` and `/api/mihomo-api/memory` every 5s.
- **Delay test fix**: empty POST body no longer causes "invalid JSON" error — daemon falls back to defaults.
- **WebDAV wiring**: upload/download buttons now read from input fields and send JSON body.

### v0.15.1

- **Fluent/Acrylic Web UI**: embedded web panel (`src/webui/index.html`) compiled via `include_str!`, with desktop/tablet/mobile navigation, custom Acrylic controls, RU/EN i18n, light/dark theme, tooltips, login overlay, dialogs, toasts, adaptive profile grids, long-operation feedback, real `fetch()` API access with Bearer auth, and an inline HincyRay mark (no external asset dependency).
- **EC streaming fix**: `first_stream_json()` parses the first JSON snapshot from Mihomo infinite-stream endpoints (`/traffic`, `/memory`), succeeding even when `curl --max-time` exits with code 28 (timeout on infinite stream).
- **Optional EC endpoints**: `/api/mihomo-api/configs/geo` and `/api/mihomo-api/rules/disable` now return `{"supported":false}` (200) when Mihomo EC responds 405, instead of 502 transport error.
- **UI flicker fix**: `updateStatusUI` split into `updateStatusCards` (core/profile/version cards) and `updateRoutingForm` (routing form fields) — prevents `loadRouting()` from overwriting status cards with partial data.

### v0.15.0

- **10 new outbound protocols**: ShadowsocksR, Snell, HTTP proxy, SOCKS, AnyTLS, Hysteria v1, SSH, MASQUE, OpenVPN, Tailscale. Share-link parsing in `profiles.rs` + Mihomo YAML builders in `mihomo_config.rs`.
- **Relay proxy groups**: `ProxyGroupType::Relay` for chain proxy groups.
- **DNS parity fields**: `fake-ip-filter-mode`, `fake-ip-ttl`, `use-hosts`, `use-system-hosts`, `default-nameserver`, `proxy-server-nameserver-policy`, `direct-nameserver-follow-policy`, `ecs`, `ecs-override`, `disable-ipv4/6`, `disable-qtype-N`.
- **Typed rules**: `MihomoRuleConfig` struct for `IN-NAME`, `IN-USER`, `PROCESS-*`, `UID`, `DSCP`, `RULE-SET` and other Mihomo rule types — emitted before raw rules.
- **EC API parity endpoints**: `GET /api/mihomo-api/version`, `/configs`, `/configs/geo`, `/rules`, `/providers/proxies`, `/providers/rules`; `POST /api/mihomo-api/cache/fakeip/flush`, `/cache/dns/flush`, `/rules/disable`.
- **Hysteria v1 mapping**: `hysteria://` / `hy://` now maps to `Protocol::Hysteria` (v1); `hysteria2://` / `hy2://` remains `Protocol::Hysteria2`.

### v0.14.0

- **Rule Trace**: `POST /api/routing/trace` explains local routing decisions for host/IP/port/protocol/source IP requests. Runtime-owned `geosite:*`, `geoip:*`, and `rule-set:*` matches are reported as Mihomo evaluation candidates instead of being guessed locally.
- **Sub-Store Lite**: lightweight parsed-profile cleanup with include/exclude filters, rename rules, dedup by protocol/address/port, sorting by name/group/protocol/address/latency, and backup-before-apply. `GET/POST /api/substore-lite`, `POST /api/substore-lite/apply`.
- **Backups and WebDAV**: local state backups with create/list/restore/delete plus WebDAV upload/download. Restore validates state JSON, creates a pre-restore backup, then regenerates runtime config safely.
- **Diagnostics & Recovery**: web panel section for rule trace, DNS diagnostics, unlock checks, Sub-Store Lite, backups, WebDAV, and connection closing.
- **Unlock checker + DNS diagnostics**: `POST /api/unlock-check` probes common services; `GET /api/dns/diagnostics` checks local resolver behavior and Mihomo DNS/API availability.
- **Scheduled maintenance**: watchdog can periodically create backups, refresh subscriptions, restart Mihomo, and close connections.
- **Connection control**: `POST /api/mihomo-api/connections/close` closes all connections or filters by connection id, routable resource (`resource` host/IP), host, destination IP, or source IP.
- **External Controller wildcard fix**: daemon dials loopback for wildcard EC binds (`0.0.0.0`, `[::]`, `:port`). RU Direct presets now use `geoip:RU` only to avoid missing `geosite:ru` datasets.

### v0.13.0

- **REJECT routing target**: block matching domains, IPs, ports, or device routes with Mihomo `REJECT`.
- **Routing presets**: RU Direct, Ad Block, Only Web VPN, Block Social, RU Direct + Ad Block. `GET /api/routing-presets`, `POST /api/routing-presets/apply`.
- **Web UI authentication**: login/password settings with in-memory session tokens and Bearer auth support.
- **Mihomo desktop benchmark backend**: desktop diagnostics use Mihomo for all supported protocols, including WireGuard and TUIC.

### v0.12.0

- **Hysteria2 port hopping**: `mport`/`ports` and `hopInterval`/`hop_interval` query params parsed from share links, emitted as Mihomo `ports` + `hop-interval` fields.
- **Profile CRUD API**: `POST /api/profiles/add` (parse share link), `POST /api/profiles/delete` (remove by ID, re-index), `POST /api/profiles/update` (rename, toggle block_quic). The current Web UI exposes add/delete and dialog-based rename flows.
- **Auto-refresh subscriptions**: watchdog Phase 7 refreshes all subscriptions on a configurable interval. Disabled by default. If the active profile is removed during refresh, auto-selects the best available.
- **Provider-compatible subscription loading**: each network path uses bounded HTTP/content decoding before profile parsing, including gzip/deflate and nested base64 payloads. A Happ-compatible identity is retried for HTTP/content rejection, while DNS/TLS/timeout failures advance to the next direct/SOCKS/HTTP path instead of repeating the same failed transport.
- **Traffic statistics**: cumulative upload/download byte counters persisted in state. Real-time speed via Mihomo `/traffic` API. `GET /api/traffic`, `GET /api/mihomo-api/traffic`, `GET /api/mihomo-api/memory`.
- **Connection log**: persisted log of connections seen through the proxy (host, source IP, chain, rule, upload/download). Cap 500 entries. `GET /api/connection-log`.
- **Speed test API**: `POST /api/mihomo-api/speed-test` downloads a 10MB file through the SOCKS proxy and returns Mbps, elapsed time, and bytes. Default URL: Cloudflare.
- **Per-device routing**: route specific devices (by IP) to a different target (DIRECT, active proxy, specific profile). Implemented as `SRC-IP-CIDR` rules emitted before general routing rules. ARP scan for device discovery. `GET /api/device-routes`, `POST /api/device-routes`, `POST /api/device-routes/delete`, `GET /api/devices`, `POST /api/device-routes/apply`.

### v0.11.0

- **Mihomo parity pack**: DOMAIN-KEYWORD rules, IP-SUFFIX/SRC-IP-CIDR/SRC-IP-SUFFIX rules, SRC-PORT/IN-PORT rules, ws-opts early-data, grpc-opts advanced, mTLS certificate/private-key, ECH query-server-name, nameserver-policy, include-all/include-all-proxies for proxy groups, raw AND/OR/NOT logic rules.

### v0.10.0

- **WireGuard + TUIC protocol support**: `wireguard://`/`wg://` and `tuic://` share link parsing. Mihomo outbounds with private key, public key, allowed-ips, reserved, MTU (WG) and uuid, password, congestion controller, udp-relay-mode (TUIC).
- **ECH (Encrypted Client Hello)**: `ech` query param parsed from VLESS/Trojan links and VMess JSON. Emits `ech-opts` with enable + optional base64 config + query-server-name.
- **xhttp advanced**: no-grpc-header, x-padding-*, uplink-http-method, session-*, seq-*, uplink-data-*, sc-max-each-post-bytes, sc-min-posts-interval-ms, XMUX reuse settings.
- **Sub-rules**: named rule groups via `SubRuleConfig`. `GET/POST /api/mihomo-features` includes sub-rule configuration.
- **GEOIP/IP-ASN rules**: `geoip:`, `geoip-asn:`/`ip-asn:`, `src-geoip:`, `src-ip-asn:` prefixes in routing rules. `reality-opts.support-x25519mlkem768`.

### v0.9.1

- **External Controller API integration**: `mihomo_api_get()`, `mihomo_api_get_json()`, `mihomo_api_delay()` client functions. `GET /api/mihomo-api/proxies`, `GET /api/mihomo-api/connections`, `POST /api/mihomo-api/delay` proxy endpoints.
- **Proxy group filtering**: `filter`, `exclude_filter`, `exclude_type`, `include_all_providers` for node selection in large profile sets. `tcp_concurrent` (connect all IPs, first wins).
- **Watchdog 3-mode failover**: (1) proxy_group enabled — delegates to Mihomo native; (2) external controller — uses API delay test; (3) fallback — SOCKS curl health check.
- **Web UI "Proxy Status"**: live group health, connections, delay test.

### v0.9.0

- **Advanced Mihomo features**: `MihomoFeatures` master struct. Proxy groups (url-test/fallback/load-balance/select), external controller (REST API), NTP, proxy/rule providers, smux, DNS enhancements (cache-algorithm=arc, prefer-h3, respect-rules), sniffer enhancements, experimental, per-proxy defaults, tunnels, hosts, authentication. `GET/POST /api/mihomo-features`. `domain_rule()` supports `regex:` and `wildcard:` prefixes.

### v0.8.0

- **Mihomo migration**: replaces Xray + sing-box as the single proxy core. All protocols handled by one binary. Sniffer enabled, fake-ip DNS mode. Config generated as YAML.
- **Mihomo auto-update**: checks GitHub releases through the SOCKS proxy, downloads and installs new binaries automatically. Backup `.bak`, rollback on failure.
- **Transparent proxy fixes**: DNS always enabled, TPROXY port 10811, `geo-auto-update: false`, `geoip.metadb` required, stdout to log file.

### v0.7.0

- **NAT REDIRECT + TPROXY**: iptables transparent proxy via Keenetic traffic policy connmarks. No tun2socks, no TUN device. 9-35x faster than tun2socks.
- **Keenetic RCI integration**: queries policy connmark, auto-creates policy if not found.
- **ndm hook script**: auto-generated, called by ndm after every firewall reload.
- **QUIC mode toggle**: Block (default) or Proxy (via TPROXY).
- **Kernel module auto-loading**: `xt_TPROXY`, `xt_socket`, `xt_comment`.

### v0.6.0–v0.6.1

- **Always-on watchdog**: core restart with exponential backoff, firewall rule monitoring.
- **Health-check failover**: 3 consecutive failures → switch to next-best profile.
- **Auto-benchmark + auto-select**: scheduled benchmark, switch to the lowest-latency recently successful profile.
- **Graceful shutdown**: SIGTERM/SIGINT stops core, removes iptables, persists state.
- **State corruption recovery**: corrupted `state.json` → backup, fresh state.
- **System monitoring**: CPU/RAM/temp/load/uptime via `/proc` + `/sys`.
- **Interactive atomic installer**: `scripts/hincyray-install.sh`.

### v0.1–v0.5

- **Protocol support**: VLESS (Reality/TLS/xhttp), VMess (base64-JSON, WS/gRPC/TCP), Trojan, Shadowsocks, Hysteria2, WireGuard, TUIC.
- **HWID fingerprint**: configurable device identity for Happ subscription fetches.
- **DNS anti-leak**: remote DNS through proxy, local DNS for direct domains.
- **Port routing**: all / allow_list / deny_list modes.
- **GeoIP/GeoSite**: configurable asset path.
- **WiFi traffic split**: routing rules match geosite, domains, IP/CIDR, geoip, ports, network type.
- **Benchmark/stats/favorites/subscriptions**: TCP/HEAD/GET benchmark methods, per-profile metrics, subscription refresh.

## Prerequisites

### Router (Keenetic Giga KN-1012 or similar ARM64)

- Entware with `curl`, `jq`, `mihomo`
- `geoip.metadb` file in the geo directory (Mihomo requires it; cannot download from blocked GitHub)
- Kernel modules: `xt_TPROXY.ko`, `xt_socket.ko`, `xt_comment.ko`
- A Keenetic traffic policy (auto-created by HincyRay or manually in Keenetic Web UI)
- `iptables` with `connmark`, `REDIRECT`, `TPROXY`, `socket`, `comment` match/target support

### Desktop (macOS)

- `mihomo` in `PATH` for desktop benchmarking.

## Build

### Router daemon

```bash
cargo zigbuild --release --no-default-features --bin hincyray --target aarch64-unknown-linux-gnu.2.27
patchelf --set-interpreter /opt/lib/ld-linux-aarch64.so.1 --set-rpath /opt/lib \
  target/aarch64-unknown-linux-gnu/release/hincyray
```

### Desktop diagnostics

```bash
cargo build --release --bin xray-vpn-test
```

### Quality gates

```bash
cargo fmt --all --check
cargo check --all-targets --all-features
cargo clippy --all-targets --no-default-features --bin hincyray -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
python3 scripts/frontend-contract-test.py
python3 scripts/installer-lifecycle-contract-test.py
npm ci
npm run test:browser
git diff --check
```

The Playwright command runs the fixture-backed browser smoke suite. All final v1.3.13 gates passed (685 Rust / 92 browser tests / 131 routes), separately from pre-version development evidence; artifact/deployment, router E2E, live HTTP 503 preservation, and single-profile YT-only smoke are in [`docs/releases/v1.3.13.md`](docs/releases/v1.3.13.md). Separate deployed-page DOM and intercepted builder evidence is recorded there, not treated as accepted backend starts. Passed v1.3.12 gates (674 Rust / 88 browser tests / 131 frontend routes), artifact/deployment, full-service smoke, and read-only live UI remain unchanged in [`docs/releases/v1.3.12.md`](docs/releases/v1.3.12.md).

## Installation

Use the interactive atomic installer:

```bash
sh scripts/hincyray-install.sh
```

The installer checks for kernel modules, creates the ndm hook directory, installs the binary, init script, and default state. Staging → backup → atomic `mv` → verify → commit/rollback.

For the public release, the installer downloads the exact `hincyray` asset from GitHub Releases when no local binary is present. Offline installation remains available by copying the binary to `/tmp/hincyray` or setting `HINCYRAY_BIN_PATH`.

See [`docs/hincyray-entware-install.md`](docs/hincyray-entware-install.md) for manual installation.

## Web panel

```
http://<router-ip>:8088/
```

Embedded Fluent/Acrylic panel with RU/EN i18n, light/dark themes, desktop/sidebar, tablet, and mobile navigation. Profiles fill desktop and tablet width with an adaptive multi-column layout; mobile stays single-column. Long-running tests, downloads, and apply operations expose a moving activity indicator. Profile rename uses an in-page dialog, connection search matches exact rendered flag-plus-host labels, and the Bearer token is held in `sessionStorage`. Status, profiles, benchmark, import, subscriptions, routing, firewall, DNS, diagnostics, backups, HWID, system monitoring, Mihomo management, traffic, connections, and logs remain available without an external CDN or frontend build step. Lightweight status and system heartbeats are used instead of periodically refreshing the full dashboard.

### Environment overrides

| Variable | Default |
|---|---|
| `HINCYRAY_LISTEN` | `0.0.0.0:8088` |
| `HINCYRAY_STATE` | `/opt/etc/hincyray/state.json` (Entware) |
| `HINCYRAY_MIHOMO_CONFIG` | `mihomo-config.yaml` next to state file |

## HTTP API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Embedded web panel |
| `GET` | `/api/health` | Service health + version |
| `GET` | `/api/contracts` | Versioned bounded-endpoint and auth contract descriptor |
| `GET` | `/api/onboarding/status` | Readiness checks and remediation for Mihomo, profile, GeoIP, core, firewall, and ndm hook |
| `GET` | `/api/status` | Active profile, core status, split routing, DNS, HWID, mihomo_version, update_available_version, proxy_group_enabled, ec_enabled |
| `GET` | `/api/profiles` | Imported profiles |
| `POST` | `/api/profiles/import` | Import share links / subscription URL / Xray JSON |
| `POST` | `/api/profiles/add` | Add a single profile from a raw share link |
| `POST` | `/api/profiles/delete` | Delete a profile by ID |
| `POST` | `/api/profiles/update` | Update profile name and/or block_quic |
| `POST` | `/api/profiles/block-quic` | Toggle block_quic flag on a profile |
| `POST` | `/api/active-profile` | Set active profile, regenerate config, restart core |
| `GET` | `/api/trash` | List the virtual Dead Servers lifecycle projection |
| `POST` | `/api/trash/move` | Atomically move non-active lifecycle refs to Dead Servers |
| `POST` | `/api/trash/restore` | Atomically restore lifecycle refs, including legacy orphan v1 entries |
| `POST` | `/api/trash/purge-gone` | Purge Dead Servers entries no longer present in profiles |
| `GET` | `/api/mihomo-config` | Applied generated Mihomo config, with secrets redacted |
| `GET` | `/api/mihomo-config/preview` | Non-mutating preview of the desired generated config, with secrets redacted |
| `POST` | `/api/core/start` | Start Mihomo core |
| `POST` | `/api/core/stop` | Stop Mihomo core |
| `POST` | `/api/core/restart` | Restart Mihomo core |
| `GET` | `/api/bench/status` | Benchmark job status |
| `POST` | `/api/bench/start` | Start benchmark (tcp/head/get) |
| `POST` | `/api/bench/stop` | Cancel benchmark |
| `GET` | `/api/stats` | Per-profile metrics |
| `POST` | `/api/favorites/toggle` | Toggle favorite |
| `GET` | `/api/favorites` | List favorites |
| `GET` | `/api/subscriptions` | Saved subscriptions |
| `POST` | `/api/subscriptions/refresh` | Refresh all subscriptions |
| `POST` | `/api/subscriptions/refresh-one` | Refresh a single subscription by URL |
| `POST` | `/api/subscriptions/delete` | Delete a subscription and its profiles |
| `GET` | `/api/routing` | Routing settings + rules + catalog |
| `GET` | `/api/routing/summary` | Compact routing, safe-mode, rule, server, conflict, and GeoBase apply summary |
| `GET` | `/api/routing/connection-context` | Stable server references and active server context for connection routing UI |
| `GET` | `/api/routing/preview` | Non-mutating desired/applied config hash comparison and apply effects |
| `POST` | `/api/routing/explain` | Explain routing for a normalized host/IP resource with optional source/port/network context |
| `POST` | `/api/routing/settings` | Save routing settings; `{"apply":true}` saves + applies atomically |
| `POST` | `/api/routing/rules` | Save rules; failed apply rolls additions/edits back, while deletions remain saved with `requires_apply:true` |
| `POST` | `/api/routing/apply` | Regenerate config + restart core + restart firewall |
| `POST` | `/api/routing/resource-route` | Create/update a rule for observed host/IP resource, apply config, optionally close matching connections |
| `GET` | `/api/routing-presets` | Built-in routing presets |
| `POST` | `/api/routing-presets/apply` | Save a routing preset; `{"apply":true}` saves + applies atomically |
| `POST` | `/api/routing/trace` | Explain local routing decision for a host/IP/port/source request |
| `GET` | `/api/routing/firewall-status` | Firewall/iptables/ndm-hook health check |
| `POST` | `/api/routing/firewall-start` | Start firewall |
| `POST` | `/api/routing/firewall-stop` | Stop firewall |
| `GET` | `/api/device-routes` | List per-device routing rules |
| `POST` | `/api/device-routes` | Add/update a device route (upsert by IP) |
| `POST` | `/api/device-routes/delete` | Delete a device route by IP |
| `GET` | `/api/devices` | Scan LAN devices via `/proc/net/arp` |
| `POST` | `/api/device-routes/apply` | Regenerate config + restart core |
| `GET` | `/api/dns` | DNS anti-leak settings |
| `POST` | `/api/dns` | Save DNS settings |
| `GET` | `/api/dns/leak-test` | DNS leak test |
| `GET` | `/api/dns/diagnostics` | Resolver + Mihomo DNS diagnostics |
| `GET` | `/api/logs` | Mihomo log tail (last 200 lines) |
| `GET` | `/api/system` | CPU/RAM/temp/load/uptime |
| `GET` | `/api/memory-estimate` | Observed rule-source bytes, current Mihomo RSS, available memory, counts, and threshold risk |
| `GET` | `/api/safe-mode` | Safe-mode status and suppressed heavy features |
| `POST` | `/api/safe-mode` | Enable/disable safe mode, optionally applying through transactional activation |
| `GET` | `/api/auto-settings` | Auto-select, auto-switch, auto-benchmark, auto-refresh settings |
| `POST` | `/api/auto-settings` | Save auto-settings |
| `GET` | `/api/hwid` | HWID fingerprint config |
| `POST` | `/api/hwid` | Save HWID fingerprint |
| `GET` | `/api/update/status` | Mihomo version, available update, auto-update settings |
| `POST` | `/api/update/check` | Check GitHub releases for a newer Mihomo version |
| `POST` | `/api/update/apply` | Download and install the available Mihomo update |
| `POST` | `/api/update/settings` | Save auto-update enabled / interval |
| `GET` | `/api/mihomo-features` | MihomoFeatures config (proxy groups, EC, NTP, providers, etc.) |
| `POST` | `/api/mihomo-features` | Save MihomoFeatures config |
| `GET` | `/api/mihomo-api/proxies` | Forward `GET /proxies` to Mihomo REST API |
| `GET` | `/api/mihomo-api/connections` | Legacy full Mihomo connection snapshot |
| `POST` | `/api/mihomo-api/connections/page` | Filtered connection page with `query`, `offset`, and bounded `limit` (1–500) |
| `POST` | `/api/mihomo-api/connections/close` | Close all/filter-matched Mihomo connections (`scope`, `id`, `resource`, `host`, `destination_ip`, `source_ip`) |
| `POST` | `/api/mihomo-api/delay` | Test proxy delay via Mihomo API |
| `GET` | `/api/mihomo-api/traffic` | Forward `GET /traffic` to Mihomo REST API |
| `GET` | `/api/mihomo-api/memory` | Forward `GET /memory` to Mihomo REST API |
| `GET` | `/api/mihomo-api/version` | Forward `GET /version` to Mihomo REST API |
| `GET` | `/api/mihomo-api/configs` | Forward `GET /configs` to Mihomo REST API |
| `GET` | `/api/mihomo-api/configs/geo` | Forward `GET /configs/geo` to Mihomo REST API |
| `GET` | `/api/mihomo-api/rules` | Forward `GET /rules` to Mihomo REST API |
| `GET` | `/api/mihomo-api/providers/proxies` | Forward `GET /providers/proxies` to Mihomo REST API |
| `GET` | `/api/mihomo-api/providers/rules` | Forward `GET /providers/rules` to Mihomo REST API |
| `POST` | `/api/mihomo-api/cache/fakeip/flush` | Flush Mihomo fake-ip cache |
| `POST` | `/api/mihomo-api/cache/dns/flush` | Flush Mihomo DNS cache |
| `POST` | `/api/mihomo-api/rules/disable` | Disable a Mihomo rule by index |
| `POST` | `/api/mihomo-api/speed-test` | Download 10MB through SOCKS proxy, return Mbps |
| `POST` | `/api/unlock-check` | Probe common service unlock/connectivity through proxy path |
| `GET` | `/api/substore-lite` | Sub-Store Lite settings |
| `POST` | `/api/substore-lite` | Save Sub-Store Lite settings |
| `POST` | `/api/substore-lite/apply` | Apply Sub-Store Lite cleanup with backup |
| `GET` | `/api/backups` | List state backups |
| `POST` | `/api/backups/create` | Create state backup |
| `POST` | `/api/backups/restore` | Restore a state backup |
| `POST` | `/api/backups/delete` | Delete a state backup |
| `POST` | `/api/backups/webdav-upload` | Upload backup to WebDAV |
| `POST` | `/api/backups/webdav-download` | Download and restore backup from WebDAV |
| `POST` | `/api/auth/login` | Create Web UI session token |
| `POST` | `/api/auth/logout` | Destroy Web UI session token |
| `GET` | `/api/auth-settings` | Web UI authentication settings |
| `POST` | `/api/auth-settings` | Save Web UI authentication settings |
| `GET` | `/api/traffic` | Cumulative + real-time traffic statistics |
| `GET` | `/api/connection-log` | In-memory recent connection log (cap 500 entries; reset on daemon restart) |

## WiFi VPN segment (optional)

- `scripts/wifi-segment-setup.sh` — creates the `HincyRay-VPN` SSID on `192.168.2.0/24` via Keenetic `ndmc`.
- Assign every device that must use the VPN to the Keenetic "HincyRay" traffic policy. **The SSID/subnet alone is not enough**: HincyRay matches packets by the policy connmark.
- The daemon handles all transparent proxying internally via `FirewallManager`:
  1. Queries the policy connmark from Keenetic RCI API.
  2. Installs iptables nat HINCYRAY chain (TCP REDIRECT to port 10810) matching the connmark.
  3. Installs iptables mangle HINCYRAY_UDP chain (UDP TPROXY to port 10811) if TPROXY is available.
  4. Installs DNS DNAT rules (port 53 → 127.0.0.1:1053).
  5. Generates ndm hook script for firewall reload survival.
  6. Watchdog reinstalls rules if missing.

### Per-device routing

Devices assigned to the HincyRay policy can be individually routed to a different target (DIRECT, active proxy, or a specific profile). Rules are emitted as `SRC-IP-CIDR,<ip>/32,<target>` before general routing rules, ensuring device-specific rules match first.

Use the web panel's "Per-Device Routing" section:
1. Click "Scan devices (ARP)" to discover LAN devices.
2. Add a route: select device IP, name, and target.
3. Click "Apply Mihomo config" to activate.

## Documentation

- [`docs/benchmark-tun2socks-vs-redirect.md`](docs/benchmark-tun2socks-vs-redirect.md) — tun2socks vs NAT REDIRECT benchmark (9-35x improvement).
- [`docs/hincyray-entware-install.md`](docs/hincyray-entware-install.md) — Entware install runbook.
- [`docs/hincyray-v0.1-status.md`](docs/hincyray-v0.1-status.md) — version status.
- [`docs/keenetic-client-roadmap.md`](docs/keenetic-client-roadmap.md) — product roadmap.
- [`docs/architecture-v0.21.md`](docs/architecture-v0.21.md) — v0.21 module/API contracts and router operational model.
- [`docs/architecture-v0.22.md`](docs/architecture-v0.22.md) — Quick Test service contracts, Telegram secret/session boundary, and simplified routing assets.

## State migration

Existing `state.json` from any prior version is automatically migrated:
- v0.7→v0.8: `xray_path`→`mihomo_path`, `singbox_path` removed, auto-update fields added.
- v0.8→v0.9: `mihomo_features` added with defaults.
- v0.9→v0.10: No state changes (new protocol support only).
- v0.10→v0.11: `dns_nameserver_policy`, `raw_rules` added to MihomoFeatures.
- v0.11→v0.12: `auto_refresh_enabled`, `auto_refresh_interval_hours`, `last_auto_refresh_unix`, `traffic_total_up_bytes`, `traffic_total_down_bytes`, `connection_log`, `device_routes` added with defaults.
- v0.12→v0.13: `web_ui_auth` added with disabled default; routing targets accept `reject`.
- v0.13→v0.14: `sub_store_lite`, `smart_select`, `maintenance`, and EWMA/cooldown profile stats added with defaults.
- v0.14→v0.15: New `Protocol` variants (ShadowsocksR, Snell, Http, Socks, AnyTls, Hysteria, Ssh, Masque, OpenVpn, Tailscale), `ProxyGroupType::Relay`, DNS parity fields (`dns_fake_ip_filter_mode`, `dns_fake_ip_ttl`, `dns_use_hosts`, `dns_use_system_hosts`, `dns_default_nameserver`, `dns_proxy_server_nameserver_policy`, `dns_direct_nameserver_follow_policy`, `dns_ecs`, `dns_ecs_override`, `dns_disable_ipv4`, `dns_disable_ipv6`, `dns_disable_qtypes`), `typed_rules` (Vec<MihomoRuleConfig>) added to MihomoFeatures with defaults.
- v0.19→v0.20: Deep Bench and Trash Bin settings use serde defaults; quality history is stored separately from `state.json`.
- v0.20→v0.21: legacy plaintext Web UI passwords are converted to an Argon2id PHC hash on state load and are not serialized again; runtime sessions remain in memory only.

No manual intervention required.

## License

MIT
