# Changelog

## v1.3.28 - 2026-09-25

- Show Keenetic's `active` status as green/red connection indicators in the policy automation device list. Keep online devices visible and offline registered devices in a collapsed-by-default section, including previously selected MACs.

## v1.3.27 - 2026-09-25

- Removed Bing from Direct probes, status, and bot messages. Added the opt-in “Zигануть Vсеми руками” automation page with a global switch and per-device MAC selection.
- On scheduled five-minute samples, keep the current policy when both VK and ya.ru fail; otherwise assign Default Policy if Google passes, XKeen (Policy0) if Google fails. Validate Keenetic's policy/registered host, verify each assignment by rereading RCI, and leave unrelated devices alone. Existing bot pairing remains separate.

## v1.3.26 - 2026-09-25

- Removed Telegram from the Direct reachability checks, dashboard indicators and change notifications. The five remaining sites still check every five minutes; the Telegram bot continues delivering change-only notifications to its already paired private chat via the local SOCKS listener.

## v1.3.25 - 2026-09-25

- Extended lightweight Direct HTTPS availability checks to Telegram and YouTube, with a cached five-minute monitor.
- Added optional private bot pairing through `/start` and change-only six-site notifications; bot credentials stay outside regular state in a mode-0600 file.

## v1.3.24 - 2026-09-25

### Direct Availability Card

- Replaced the unused final status card with a Direct availability action and four independent site indicators: Google, Vk.ru, ya.ru, and bing.ru.
- Added a bounded read-only daemon endpoint that runs the four direct `curl` probes in parallel with no SOCKS/HTTP proxy, redirects limited to three, and errors/statuses kept per site.
- Added fixture/browser coverage for the endpoint request and independent green/red results.

## v1.3.23 - 2026-09-24

### Persistent Results View

- Fixed a gap in v1.3.22: a newly opened page restored Import order, even when completed subscription checks had produced ranked service evidence. Results is now the default profile order; accepted subscription checks select and persist Results. Explicit manual choices, including Import order, persist across reloads.
- Exercise the accepted subscription start, terminal result ranking, reload, and manual Import choice in fixture-backed browser tests. The prior ranking contract and no-mutation live verification remain separate.

## v1.3.22 - 2026-09-24

### Subscription Check Results Ordering

- After an accepted subscription Check Services run, select Results ordering for profile tables. Rank current YouTube thumbnail, Telegram, and AI passes first, then fresh reachable ping; unknown/stale evidence is not treated as a failed check, and confirmed unreachable profiles come last.
- Display the same fresh ping used for ordering in the Ping column while Results ordering is selected; preserve import and manual column-order options. A fixture-backed browser regression covers the subscription button, sorted rows, and stale/unreachable cases.

## v1.3.21 - 2026-09-23

### Connection Identity and Immediate Rule Application

- Label connections from the dedicated `torrent-socks-in` inbound in both the active-connection list and grouped connections table, including mixed-site counts.
- After successful Torrent SOCKS5 target/listener updates, close only existing connections from that inbound so the torrent client reconnects through the new target. After applied general routing changes, close existing Mihomo connections so new sessions re-evaluate the rules. Reconnection occurs only after successful activation; errors are returned as a separate bounded status and surfaced in the UI.
- Cover exact inbound filtering, real mock controller GET/DELETE behavior, routing scope, and UI labels with regression tests. The release record is in [`docs/releases/v1.3.21.md`](docs/releases/v1.3.21.md). GitHub publication remains unauthorized.

## v1.3.20 - 2026-09-23

### Torrent SOCKS5 Password Guidance

- Added a live UTF-8 byte counter and explicit first-password instructions to the Torrent SOCKS5 card. The browser now rejects an empty first password or a supplied password outside the existing 12–512-byte/control-free contract before sending any routing settings.
- Kept blank-as-preserve semantics for already configured credentials. Browser regression exercises missing, 11-byte, and 12-byte first passwords through a deferred routing refresh; the SOCKS credential policy itself is unchanged.

All final gates passed (705 Rust tests / 104 browser tests / 132 frontend routes); local, staged, and installed ARM64 SHA256 agreed at `51940d29a69c9ca3aa336f80d7a683572e5043cc78dbb93a21de0f6180237b33`. Transactional deployment, complete rollback, router E2E, and read-only live UI evidence are recorded in [`docs/releases/v1.3.20.md`](docs/releases/v1.3.20.md). GitHub publication remains unauthorized.

## v1.3.19 - 2026-09-23

### Independent Torrent SOCKS5 Authentication

- Removed the requirement to enable Web UI authentication before activating Torrent SOCKS5, and allowed disabling panel authentication while the SOCKS5 listener remains enabled.
- Preserved mandatory per-listener SOCKS5 username/password, private/loopback IPv4 binding, listener collision checks, and transactional state/core activation. Updated the Web UI hint and regression coverage.

All final gates passed (705 Rust tests / 103 browser tests / 132 frontend routes); local, staged, and installed ARM64 SHA256 agreed at `e9c4d14df558d0aa8b9ee812b237a2e372e3bd32fea5f784b86738290da41059`. Transactional deployment, complete rollback, router E2E, disabled-listener proof, and unchanged durable projections are recorded in [`docs/releases/v1.3.19.md`](docs/releases/v1.3.19.md). GitHub publication remains unauthorized.

## v1.3.18 - 2026-09-22

### Stable Routing Editors

- Moved searchable grouped server-target menus into a centered, wide, viewport-bound dialog shared by routing rules, connection actions, and Torrent SOCKS. Navigation, Escape, or removal of the originating editor closes the dialog.
- Deferred background routing/connection refresh while an edit or target picker is active, including responses arriving after editing begins; unrelated unsaved settings survive a forced rule-table reload.
- Made rule deletion visible with a named Delete action and escaped Undo notice. Disabled Parovozik projections are hidden, and its wagon list starts collapsed.
- Captured read-only evidence of Mihomo memory pressure during Steam downloads for a separate diagnosis; no load reproduction, automatic core restart, or routing mutation was used to claim a memory fix.

All final gates passed (703 Rust tests / 103 browser tests / 132 frontend routes); local, staged, and installed ARM64 SHA256 matched at `9b13359c1fc40dbd1baad6aeb4d610fa41b31a50af89da60b9a9cde56b1a5b3f`. Transactional deployment, complete rollback, router E2E, and read-only desktop/mobile live UI verification are recorded in [`docs/releases/v1.3.18.md`](docs/releases/v1.3.18.md). GitHub publication remains pending and unauthorized.

## v1.3.17 - 2026-09-22

### Dedicated Torrent SOCKS5 Identity

- Added an optional authenticated SOCKS5 listener in the existing Mihomo process so a cooperating torrent client can identify all traffic it sends through the listener without heuristic BitTorrent DPI. Listener-scoped routing supports explicit DIRECT, canonical active VPN, REJECT, Parovozik, and fixed-server targets.
- Added strict private-listener, credential, port-collision, target, Web UI authentication, and TCP+UDP socket-ownership contracts. The listener is disabled by default; clients must proxy peers, trackers, and DNS and disable direct fallback. DHT/uTP require SOCKS5 UDP support in the client.
- Integrated fixed torrent targets with routing registry retention, profile identity migration, deletion/subscription-refresh protection, pinned observation, and Dead Servers dataplane transitions.
- Added typed routing settings/OpenAPI, a grouped searchable target picker, password-preserve and explicit credential-clear flows, and structural secret redaction. State, Mihomo config, validation, corrupt-state, and local backup files use Unix mode `0600`; WebDAV requires HTTPS without redirects.
- Made settings activation and local/WebDAV restore transactional across state, generated config, core/firewall runtime, selector intent, and candidate/rollback socket contracts. Invalid restore/auth/listener states are rejected before persistence.

All final gates passed (703 Rust tests / 97 browser tests / 132 frontend routes); local, staged, and installed ARM64 SHA256 agreed at `9348d5a5bc4401c7436f73f2c185408c1dd410f79dd39aa2f9cc43aced33afa6`. Transactional deployment, the retained complete rollback, disabled-listener proof, private file modes, fail-closed selector evidence, router E2E, and unchanged durable projections are recorded in [`docs/releases/v1.3.17.md`](docs/releases/v1.3.17.md). No credentials were invented and no torrent traffic was generated. GitHub publication remains pending and unauthorized.

## v1.3.16 - 2026-09-21

### Isolated Health Hysteresis

- Replaced the canonical health-driven fallback with a fail-closed selector `[proxy-active, REJECT]` and a hidden `proxy-health` sensor. One Mihomo URL-test result can no longer change the main dataplane directly.
- Count only fresh main-namespace health samples: three consecutive failures select `REJECT`, while two consecutive successes restore `proxy-active`. The observation is one `/proxies` snapshot serialized against config apply and scoped to core generation plus canonical active identity.
- Isolated pinned and Parovozik health namespaces and reduced their interval to 60 seconds; main health remains 10 seconds with an 8-second timeout. This prevents auxiliary checks from overwriting main state or creating synchronized probe storms.
- Preserved selector intent across hot reloads, full restarts, profile-switch rollback, and manual/automatic Mihomo updates. Runtime selector shape is validated exactly; unverifiable restart or rollback stops the tracked core instead of leaving an unknown dataplane.
- Updated the Web UI to hide the sensor, derive canonical health from the exact main URL state, and prioritize REJECT over pinned labels.

The incident was reconstructed without an intentional load reproduction. Profile 202 was already unhealthy, so its Hugging Face route fell back to the same active VPN. Parallel transfer load delayed the shared 3-second health probe just beyond its deadline, and v1.3.15's one-sample fallback immediately selected REJECT for all new VPN connections while explicit DIRECT remained available. All final gates passed (693 Rust tests / 96 browser tests / 132 frontend routes); local, staged, and installed ARM64 SHA256 agreed at `3a261c99eba8b33917322bf93d34efe8420622e25bf4aba1417b56d402f87eb5`. Transactional deployment, exact selector/sensor evidence, isolated REJECT/no-IP proof, router E2E, unchanged durable projections, and the complete rollback are recorded in [`docs/releases/v1.3.16.md`](docs/releases/v1.3.16.md).

## v1.3.15 - 2026-09-20

### Fail-Closed VPN Routing

- Replaced the canonical `[proxy-active, DIRECT]` group with Mihomo-safe `[REJECT, proxy-active]`. Mihomo skips the unhealthy local reject member while VPN is healthy and selects it when every member is unhealthy, preventing transient active-profile health failures from exposing the direct WAN address.
- Applied the same REJECT-first contract to pinned-server and Parovozik VPN groups. A route explicitly targeting the current active server now uses the canonical fail-closed group instead of bypassing it through the raw outbound.
- Made watchdog recovery depend on the selected `proxy-active` member and its raw health rather than a separately mutable aggregate `alive` value. Default delay diagnostics now probe `proxy-active`, avoiding aggregate health poisoning.
- Made the Web UI prioritize REJECT chains and treat missing/non-boolean proxy health as unhealthy. Explicit DIRECT rules, direct GeoBase/RU routes, configured port bypasses, and local destination firewall bypasses remain intentional direct-routing policy.

The incident was captured live: the daemon repeatedly logged Mihomo fallback to DIRECT during 95-371 ms active-profile health flaps, while direct WAN and VPN egress were distinct. Immediate containment was hot-reloaded before this release. An isolated installed-Mihomo test then proved `[REJECT, dead-proxy]` selected REJECT after the health interval and returned no public IP. Final gates passed (**692 Rust tests**, **96 browser tests**, **132 frontend routes**); local, staged, and installed ARM64 SHA256 agreed at `d18d27e4837b632962177e337e8a9ab418c6e21162ad8025d3f64d65659f25b0`. Transactional deployment, router E2E, post-deployment group/delay/outage proof, and complete rollback are recorded in [`docs/releases/v1.3.15.md`](docs/releases/v1.3.15.md).

## v1.3.14 - 2026-09-19

### Routing Target and Reconnect Corrections

- Replaced narrow native route-target selects with one wide searchable grouped picker across new rules, inline rule editing, connection actions, and the connection rule editor. Server entries include profile IDs and explicit Dead Servers/fallback state, and connection polling pauses while a picker is open.
- Added a typed atomic resource-reload action that serializes routing mutations, applies current desired routing before closing matching Mihomo connections, and matches sniffed host, source IP, destination port, and network. Runtime GeoIP/GeoSite/rule-set decisions are reported as runtime-evaluated rather than as a fabricated target.
- Preserved Dead Servers routing intent while making active fallback explicit. Connection closure is bounded to 20 IDs with bounded redacted errors, and partial closure remains visible to the UI.
- Made routing settings, rules, resource routes, resets, presets, and device routes share the apply lock. Persistence failures now restore in-memory state, and device-route apply starts the core before enabling transparent routing.
- Added strict Xray VLESS `pcs`/`vcn` compatibility: one SHA-256 certificate pin maps to Mihomo `fingerprint`, and one certificate verification name maps to `name-cert-verify`, without disabling TLS verification. This restores Quattro profiles that use private pinned certificate chains.

Local v1.3.14 is deployed and verified. All final-version gates passed (**692 Rust tests**, **95 browser tests**, **132 frontend routes**); final local, staged, and installed ARM64 SHA256 agreed at `1ea0fb4073d2c98f0c630e46cb6135f94231f46c9065813fb3c637524be4e2af`. Health, core/firewall readiness, DNS/REDIRECT/TPROXY/table 111, and router E2E passed after the real resource reload and certificate-pin hotfix. Quattro LTE 86 passed an isolated daemon benchmark at 359 ms/0% loss and a real active switch with a 92 ms healthy leaf before profile 88 was restored. BeautifulVPN Obhod 11 retained its old identity but showed an upstream certificate-name mismatch, so it was not altered. The saved `us.aws.cdn.hf.co` rule remained on Dead Server profile 23 and the routing response correctly reported active fallback. Desktop/mobile live UI found profile 431, rendered Dead Servers fallback, had no overflow or JavaScript errors, and sent no mutation beyond the existing read-only connections-page query. Complete rollback and evidence are in [`docs/releases/v1.3.14.md`](docs/releases/v1.3.14.md). GitHub publication remains unauthorized.

## v1.3.13 - 2026-09-17

### Shared Service Policy and Exact Worker Admission

- Added optional strict `service_checks` to ordinary availability requests: required ordered prefix `all`/`youtube`/`telegram`/`ai` and boolean `fail_fast`, rejecting unknown fields/invalid values and combination with `search`. Missing/null retains shipped method defaults, including full/all continued checking for `availability_full`.
- Applied shared GUI prefix/fail-fast choices to ordinary `availability_full` across all/global, subscription, group, single, favorite, selected, and explicit Dead Servers scopes. All and fail-fast are selectable in ordinary and advanced modes; only the separate explicit advanced global Find N action owns a candidate target. Ordinary checks do not use search/preflight.
- Required exact ordinary explicit-policy admission of `min(requested workers, candidates)` or HTTP 503 before reservation, preserving the existing job. No silent worker reduction or memory bypass: reserve 80 MiB + 48 MiB/worker, estimated 272 MiB available for four, unknown/zero budgets rejected. Legacy/adaptive memory caps and remaining-target limits remain.
- Removed the native YouTube mutex from candidate-local contract-1 thumbnail probes, with independent private core/config/captures, per-worker HTML/image/decoder bounds, and cancellation/reaping guards. Native contract-7 Innertube and the shared Telegram SQLite session remain serialized.
- Kept previews separate from native playback/history, generic health, and automatic promotion/Dead Servers/AutoSelect. Added no authentication, native video, cookies, JavaScript/yt-dlp runtime, or protocol/security/timeout workaround.

Local v1.3.13 is deployed and verified: all final-version gates passed (685 Rust / 92 browser tests / 131 frontend routes), separately from verified development gates; local/staged/installed SHA agreed and router E2E passed. Simulated budget-four admission and budget-three rejection preserving a job remain fixture evidence. The four-thread local SOCKS-failure regression proves native Innertube mutex independence, not four successful router transfers.

Actual four-distinct-candidate/four-worker YT-only admission returned HTTP 503 with memory permitting three before reservation, preserving the existing idle job. A subsequent ordinary `availability_full` request for active `[88]`, concurrency four, explicit YT/no-fail-fast policy, and no search/preflight admitted exactly one worker for one candidate and passed real MrBeast identity/three decoded previews (contract 1). TG/AI were unrequested, native YouTube absent; all three ping checks passed. Desired routing/settings and durable lifecycle projections stayed unchanged, with expected cache/stats/service/traffic updates allowed. Final SHA, retained complete rollback, private proof, and exact smoke evidence are in [`docs/releases/v1.3.13.md`](docs/releases/v1.3.13.md). Separate actual LAN desktop/mobile DOM confirmed enabled ordinary/advanced All/fail-fast controls, browser-local label toggle, YT green/current and TG/AI gray/skipped on 88, collapsed details, no sidebar technical nodes/mobile overflow, and zero JS errors. Single/global builders received intercepted mock 503 with zero forwarded mutations, not backend acceptance or global All success. New v1.3.13 All/TG/AI positives and dynamic fail-fast sequences, actual backend clicks across all scopes, four positive concurrent router transfers, peak/continuous memory, cancellation under load, and reboot persistence remain unverified. No profile-431 repair or parameter guess is claimed. This documentation finalization performs no commands, credential handling, native clock/PC power action, or GitHub operation. Publication remains pending and unauthorized; v1.3.12 (674 Rust / 88 browser tests) and all older release evidence remain unchanged.

## v1.3.12 - 2026-09-17

### Explicit complete-service actions

- Made all/global, subscription, group, single, favorite, selected, and explicit Dead Servers lightning actions consistently Check Services: `availability_full`, no `search`, all YouTube/Telegram/AI checks, and no generic discovery preflight gate.
- Isolated opt-in advanced global Find N parameters so stored target/prefix/fail-fast values cannot turn an explicit diagnostic into partial discovery or skip later service checks. Advanced checkbox/help labels are global-only; Find N policy itself is unchanged.
- Moved technical explanations into collapsed Profiles check details; sidebar activity retains only name/count, Stop, and animation. Current conclusive results use red/green; unknown stays amber, and gray means stale/no-attempt/skipped rather than a fabricated failure. Native contract-7/contract-6 history is not converted into thumbnail success.
- Kept thumbnail contract 1, service timestamp/ref matching, bounded diagnostics, saved native compatibility settings, and exclusions from generic health, native promotion, automatic Dead Servers, and AutoSelect unchanged.
- Fixed the minimal Trash-list performance bug by canonicalizing all profiles once into a first-alias HashMap instead of repeating the scan for 519 dead refs across 433 profiles under the daemon lock. Added first-alias/restorable-legacy-orphan regression coverage without database or broader strategy changes; live `/api/trash` returned 519 entries within a five-second request budget.

The pre-update v1.3.11 direct `availability_full` test of Obhod 10 primary 431 (old aliases 93/100) failed all three services; its alive pinned group selected active-88 fallback. Primary forwarding is not repaired, and endpoint TCP/group health do not prove it. The old single-click Find N did not test YouTube; no private-builder field loss or cause for all 335 original rejects is established. Initial Astra consultation completed successfully and its advice was implemented; a follow-up encountered transient network failure, not a new verdict. No additional consultation occurs here.

Final v1.3.12 is deployed and verified: all gates passed (674 Rust / 88 browser tests / 131 frontend routes), final artifact hashes matched local/staged/installed, and router E2E passed. Actual `availability_full` without `search` passed YouTube previews, authorized Telegram media, and AI region checks on active 88. Read-only live Chromium confirmed three green indicators on 88 and three red existing results on 431, collapsed advanced details, no mobile overflow, and zero JavaScript errors; no live lightning click was made. Desired routing/settings and durable lifecycle projections stayed unchanged, allowing expected resource/accounting updates. Final SHA, retained rollback, build/deploy chronology, full-service and live UI evidence are in [`docs/releases/v1.3.12.md`](docs/releases/v1.3.12.md). No anonymous video playback, quantitative speedup, native network/time/power action, or parameter guess is claimed. Historical evidence is unchanged; GitHub publication remains pending and unauthorized.

## v1.3.11 - 2026-09-17

### Corrective UI and service evidence

- Restored subscription/group header lightning actions for whole-scope testing and table presentation after the v1.3.10 regression.
- Rendered fixed neutral YT/TG/AI indicators for every profile with not-tested, stale, skipped, and current states rather than treating absent/skipped evidence as service failure.
- Matched fresh result overlays after profile load using canonical lifecycle-v2 `server_ref` plus exact profile ID. Exposed an independent public `last_service_test_unix` for service freshness, not generic health timestamps; private raw connection identity stays out of status.
- Classified a bounded 64 KiB private temporary-core warning-log tail into fixed diagnostic categories without exposing raw core addresses/logs. Preserved HTTP/curl errors and appended upstream deadline evidence, distinguishing preflight transport failure from an actual YouTube check.
- Kept complete-scope Quick YouTube/Telegram short-circuit and Full continue policy, Find N preflight/history ordering/goals, thumbnail contract 1, and separate legacy native contract-7 API/history unchanged. Weak availability evidence still cannot drive generic health, native promotion, automatic Dead Servers, or AutoSelect.

Sampled profile 88 forwarded gstatic HTTP 204 and YouTube HTTP 200; profiles 93 WebSocket/TLS, 91 gRPC/Reality, and 118 Hysteria2 reached 5-second upstream deadlines. Profile 91 had an owned TCP socket established without a completed protocol stream; cause remains unproven. Reparsed profile-93 fields generated byte-identical config, with no observed persistence loss. No protocol/SNI/certificate-verification/timeout change is justified by these observations, and 335 preflight rejects mean services untested, not 335 proven false failures or dead servers.

Local corrective v1.3.11 is deployed and verified: all final gates passed (673 Rust / 84 browser tests / 131 frontend routes), local/staged/installed hashes matched, and router E2E passed. The negative profile-93 smoke preserved TLS EOF/curl 35 with fixed `[deadline_exceeded]`, zero service tests, and no raw core output. The final positive active-profile-88 smoke confirmed three decoded previews and reached target 1 with matching canonical ref/public service timestamp. Lifecycle/order/dead, profile provenance, and pinned/device routing intent stayed unchanged; other accounting/bookkeeping may change. Actual live browser DOM was not exercised; embedded markers and fixture browser behavior were verified separately. Artifact, complete rollback, and logs are recorded in [`docs/releases/v1.3.11.md`](docs/releases/v1.3.11.md). No clock/NTP change or quantitative speedup/playback repair is claimed. Historical release evidence is unchanged; GitHub publication remains pending and unauthorized.

## v1.3.10 - 2026-09-16

### YouTube channel and preview availability

- Made the public MrBeast channel page plus three successfully decoded previews for distinct videos the only YouTube check in every user-facing search scope. Completion/short-circuit policy, Find N prefixes, and explicit Dead Servers diagnostic scopes remain separate.
- Added `availability_quick`/`availability_full` methods and `search_availability` results with `youtube_thumbnails` contract 1. Preserved native contract-7 `quick`/`full` API/history separately for shipped API and persisted-data compatibility; preview evidence cannot become native playback evidence or consume old native success as a preview pass.
- Persisted resource diagnostics without generic EWMA health or overall native Quick/Full success. Availability searches never run native promotion, automatic Dead Servers movement, or AutoSelect, including completed scopes; compatibility controls/help remain separate.
- Bounded HTML to 2 MiB/20 seconds and each image to 128 KiB/8 seconds; pinned previews to HTTPS `i.ytimg.com:443` without credentials/redirects, actual JPEG/PNG/WebP decode, 1024-pixel dimensions, and 16 MiB decoder allocation. YouTube remains serialized, with existing cancellation and 80 MiB reserve/48 MiB worker startup estimates unchanged.
- Added no Innertube/video request, cookies/session import, JavaScript runtime, login, or authentication workaround to this availability method. Success means page/previews access, not playback, account access, or strong server health.

v1.3.10 is deployed and verified: all final-version gates passed before build (668 Rust / 67 browser tests / 131 UI routes), local/staged/installed artifact hashes agreed, and router E2E passed. The production `availability_quick` target-1 search on active profile 88 confirmed MrBeast and three distinct decoded previews, returned contract-1 `youtube_thumbnails` success, and reached the target without cancellation. Active identity/order/dead projections stayed unchanged; resource/search bookkeeping and background accounting may change. This is a page/preview pass on one profile, not playback or Mihomo health evidence; native post-actions remain excluded. Full artifact, complete rollback set, and logs are in [`docs/releases/v1.3.10.md`](docs/releases/v1.3.10.md). The earlier isolated ten-endpoint experiment is historical, not a ten-endpoint production release result. No lower-byte-cost or quantitative speedup claim is made. Clock/NTP were unchanged; historical v1.3.9 evidence remains intact. GitHub publication remains pending and unauthorized.

## v1.3.9 - 2026-09-16

### Reachability and native outcome honesty

- Accepted completed adaptive HTTPS preflights with any HTTP status 200-599 as transport reachability only, retrying once on an alternate domain through the same isolated core. This is not YouTube playback evidence; rejection still carries no persisted health/Dead Servers penalty.
- Retained the private temporary core home/config/log until child reap and bounded status to the last 20 preflight diagnostics with redacted errors up to 2 KiB.
- Replaced the obsolete ANDROID_VR 1.65.10 path with native direct VISIONOS Innertube without mandatory web watch/bootstrap. A pass requires successful video-MIME media transfer of at least 16 KiB, not a player response or reachability sample.
- Classified bot/login refusal, HTTP 429, and HTTP client-compatibility refusals as inconclusive instead of server failure or pass. Amber/unknown UI and summaries exclude false failures and stale legacy successes; unknown evidence/history cannot drive promotion, Dead Servers, or AutoSelect.
- Documented native resource contract 7: contract-6 evidence is stale, unknown history stays unknown, and a serde-defaulted `inconclusive` field tolerates old saves. No authentication/cookie/session workaround, captcha, JavaScript, or yt-dlp runtime is introduced.

### Core creator lifetime

- Fixed Linux `PDEATHSIG` killing Mihomo when its short-lived creator HTTP thread exited. A persistent spawn-owner thread uses a 256 KiB stack and queue bound 1, retains actual `Child` ownership, and preserves daemon-death kill/pre-exec behavior without an optional runtime path.
- Passed 10 caller-exit regression iterations and 10/10 rollback iterations. The owner adds one baseline daemon thread; the fresh live daemon had three threads after diagnostics.

v1.3.9 is deployed and verified with matching local/staged/installed SHA, all required gates passed (649 Rust / 66 browser tests / 131 UI routes), and router E2E passed before and after authorized manual clock correction. Controlled two-candidate YouTube searches remained exhausted with zero passes/failures and one inconclusive native result: bot refusal stayed unknown, while the other candidate failed TLS preflight. Active identity/order/Dead Servers stayed unchanged. Clock correction did not resolve either outcome. Initial 17:23 UTC observations were unsynchronized/manual; independent 17:34 UTC checks twice confirmed automatic NTP synchronization (`accurate=yes`, `synchronized=yes`, `usertime=no`, server `pool.ntp.org`) within one second of the host. Causes of the initial failure and later success are not established, and reboot persistence remains unverified without a system-wide configuration save. Full artifact, rollback, logs, and chronology are recorded in [`docs/releases/v1.3.9.md`](docs/releases/v1.3.9.md). No anonymous media playback, blanket explanation for the original 335 rejects, or quantitative speedup is claimed. GitHub publication remains pending and unauthorized.

## v1.3.8 - 2026-09-16

### Unified server search

- Unified global, selected, subscription, group, and single-profile actions behind shared browser-stored parameters: complete scope or find N.
- Complete scope uses all native services with a YouTube/Telegram failure short-circuit policy (existing Quick internally) or continued checking (existing Full internally). Find N retains targets 1-20 and supported YouTube, YouTube+Telegram, or YouTube+Telegram+AI Studio prefixes; unsupported combinations are not offered.
- Kept explicit Dead Servers diagnostics in complete scope, even when browser parameters select find N. Discovery continues to exclude dead candidates and never runs profile post-actions.
- Exposed requested/effective/active workers, admission limits, and memory-cap, candidate-count, and target-slot reasons without implying concurrent native YouTube/Telegram probes.

### Worker retention and memory admission

- Fixed temporary discovery target-slot saturation permanently retiring workers: workers now wait and can resume when rejected or failed candidates release slots.
- Rejected temporary-core starts with HTTP 503 when the memory budget is unknown or allows zero workers, using an 80 MiB router reserve and 48 MiB per-worker startup estimate instead of forcing one worker.
- Kept bounded cancellation and serialized native YouTube/Telegram probes. The memory guard is a startup admission estimate, not a continuous reserve guarantee; requesting four workers does not mean four simultaneous YouTube checks.

v1.3.8 is a verified local router update: all required gates passed (625 Rust / 63 browser tests / 131 UI routes), local/staged/installed artifact hashes agreed, and core/firewall plus router E2E were verified. Controlled three-candidate YouTube searches observed peak active work of three at target 3 and one at target 1 with lifecycle/order/dead membership unchanged. Worker retention after failed reservations is covered by injected Rust tests, not proven by these live traces. Artifact SHA256, complete rollback path, logs, and runtime coverage limits are recorded in [`docs/releases/v1.3.8.md`](docs/releases/v1.3.8.md). GitHub publication remains pending; no available release asset or quantified speedup is claimed.

## v1.3.7 - 2026-09-16

### Adaptive discovery

- Added Find Servers for all live profiles, selected profiles, or one subscription, with a target of 1-20 unique lifecycle identities and required prefixes YouTube, YouTube+Telegram, or YouTube+Telegram+AI Studio.
- Used current-contract service history younger than six hours for ordering only; every counted server must pass a fresh measurement. Deduplicated canonical aliases, interleaved endpoint/provenance buckets, and rotated exploration of unknown candidates.
- Added bounded real-protocol HTTPS preflight in temporary Mihomo, reusing successful cores for requested native service probes. Rejected preflights skip media work without persisted health failures or Dead Servers evidence.
- Stopped admission at the requested target within existing memory/concurrency bounds; distinguished target reached, exhausted, and cancelled outcomes. Requested-prefix success is not an exhaustive Quick pass, and discovery never activates profiles or runs Quick/Full promotion/dead-movement post-actions.

### Security and control-plane safety

- Retained existing login-throttle blocks when the bounded source table overflows instead of clearing them.
- Treated unavailable or malformed local Mihomo controller observations as inconclusive, resetting the consecutive-failure streak without penalizing the active profile or initiating failover. The canonical fallback group remains the upstream-health authority.
- Omitted raw connection credentials from benchmark status, redacted diagnostic strings, safely remapped result identities to current profile IDs, and excluded results whose identities no longer resolve.
- Prevented delayed navigation focus from stealing focus from an input on the next animation frame.

The verified local artifact SHA256, passed gates, and live router deployment evidence are recorded in [`docs/releases/v1.3.7.md`](docs/releases/v1.3.7.md). GitHub publication remains pending; historical evidence is not reused as v1.3.8 verification.

## v1.3.6 - 2026-09-16

### Profile test automation

- Added persisted, default-disabled test settings to promote successful servers and move completely unresponsive inactive servers to Dead Servers after completed Quick/Full tests.
- Ranked promoted profiles within their provenance group by Ping+YouTube+Telegram+AI, then without AI, then without Telegram, with lower ping first within equal tiers.
- Kept automatic Dead Servers transitions behind the shared transactional lifecycle boundary, skipped active and already-dead profiles, and required all ping checks to fail with no successful response. Responsive canonical aliases prevent automatic dead movement.
- Preserved active connection identity during profile renumbering and remapped completed benchmark results to current profile IDs. Cancelled or partial tests do not run post-actions.
- Added bounded typed benchmark settings contracts and retained both GET and POST operations for shared OpenAPI paths.
- Added regression coverage for settings persistence and validation, ranking, active identity after deletion, canonical aliases, completion callbacks, cancellation, and RU/EN Web UI controls.

## v1.3.5 - 2026-09-15

### Router resource safety

- Replaced unbounded per-connection HTTP thread creation with 32 fallible bounded workers, smaller worker stacks, and strict pre-auth request-line, header-size, header-count, and aggregate large-body limits.
- Bounded active Mihomo logs during runtime and changed `/api/logs` to read only a limited tail, preventing concurrent requests from loading a multi-megabyte or larger active log in full.
- Streamed or capped speed-test, WebDAV, Mihomo controller, GitHub API, and asset responses; serialized memory-heavy backup operations and capped detached DNS resolver workers.
- Pruned live Parovozik probe metadata and removed internal timestamp caches from routing responses. Periodic status polling no longer serializes or reapplies the complete routing form.

### Lifecycle and diagnostics

- Enforced the 1-15 minute Deep Bench stability window in persisted settings and API requests, while defensively bounding duration-derived sample allocations.
- Made Deep Bench downloads and unlock probes cancellation-aware, added parent-death protection to temporary Mihomo children, and coordinated benchmark and watchdog shutdown without blocking service cleanup.
- Added regression coverage for HTTP/resource permits, bounded streams and logs, routing projections, Deep Bench validation, log cursor generations, and live metadata pruning.

## v1.3.4 - 2026-09-01

### Routing and connections

- Canonicalized leading-dot domain zones such as `.ai` to `ai` before persistence and Mihomo rule generation, including startup migration for existing rules.
- Recognized the full Mihomo fake-IP block `198.18.0.0/15`, prevented synthetic addresses from becoming persistent routing resources, and exposed recovered host metadata in the connection view.
- Refreshed the routing server catalog after bulk subscription updates so stale opaque `srv-v1` references are not submitted after profile identities change.

### XHTTP and router memory

- Added measured 4/8/16/32 KiB `scMaxEachPostBytes` choices for manual XHTTP profiles while preserving unknown `extra` keys and existing custom values.
- Upload benchmarks now reject deadline-censored `curl` results instead of reporting the exact timeout boundary as measured throughput.
- Limited glibc allocator arenas and periodically returned unused pages after transient router work, reducing retained HincyRay RSS on the 512 MiB/no-swap target.

## v1.3.3 - 2026-08-20

### Web UI

- Removed the raw EC API controls from Proxy Status while retaining the bounded proxy, connection, traffic, and memory views.
- Added persistent subscription-group ordering with arrows on subscription headers. One click moves against the adjacent visible subscription, skipping hidden empty sources, and the pending button prevents duplicate operations.
- Sidebar benchmark, server-switch, and long-operation indicators now navigate to their owning section.
- Moved GeoData/GeoBase and the default-collapsed Split Routing controls to the bottom of the Xkeen routing page.

### Diagnostics

- Fixed DNS Diagnostics rendering of the structured TCP DNS listener response and removed the unsupported Mihomo EC `/dns/query` check.
- YouTube Unlock Check now uses the same bounded Innertube and media-range playback probe as Quick Test instead of `youtube.com/generate_204`.

### Documentation

- Added `docs/android-version-options.md` with the evaluated ClashMetaForAndroid fork strategy, GPLv3 implications, architecture boundary, phases, and risks.

## v1.3.2 - 2026-08-19

- Restored sidebar scanner movement under `prefers-reduced-motion: reduce`. The accessibility mode keeps a slower 3.4-second scanner cycle while continuing to suppress unrelated decorative animations.
- Added a Playwright regression assertion for the computed scanner animation name and duration in reduced-motion mode.

## v1.3.1 - 2026-08-19

### Profiles and activation

- Added structured XHTTP upload tuning for manual VLESS XHTTP profiles in the profile editor. `scMaxEachPostBytes` and `scMinPostsIntervalMs` remain inside the existing share-link `extra` object, preserve unrelated keys, and can be removed to restore Mihomo defaults.
- Added bounded active-profile apply status with real preparation, generation, validation, write, core apply/readiness, persistence, connection-close, and rollback stages.
- Repeated active-profile clicks no longer queue configuration applies: the UI disables competing selection controls and the daemon returns `409` when another apply owns the lock.

### Benchmark cancellation and memory

- Quick Test cancellation now interrupts and reaps its current benchmark-owned `ping`, `curl`, and temporary Mihomo processes; Telegram and serialized YouTube waits also observe cancellation. Cancelled profile results are not persisted.
- The stop endpoint waits for the benchmark worker to finish instead of reporting completion after only setting a flag.
- Temporary-core benchmark concurrency is reduced according to `MemAvailable`, preserving an 80 MiB router reserve and avoiding multi-Mihomo memory pressure on 512 MiB Keenetic hardware.

### Web UI responsiveness

- Replaced 30 ms JavaScript scanner timers with compositor-friendly CSS animation.
- Made active-profile and benchmark status polling single-flight and self-scheduling. Late responses cannot resurrect completed indicators, and completed benchmark progress is hidden after a bounded terminal display.
- Long operations now use unique instance tokens, so concurrent calls to the same endpoint finish independently instead of orphaning or prematurely hiding the sidebar indicator.
- Added request timeouts, coalesced dashboard/system/status refreshes, and avoided benchmark table rerenders when cumulative results are unchanged.

## v1.3.0 - 2026-08-18

### Profile diagnostics

- Added a transient, daemon-owned Profile Logger for the active server. Sessions run for 1–5 minutes and require an explicit LAN client IP so unrelated devices and pre-existing connections are excluded.
- Capture is bounded to 256 new `proxy-active` connections, 256 source-correlated warning/error events, a 4 MiB controller snapshot, a 64 KiB structurally redacted config summary, and a 256 KiB report.
- Reports include safe profile metadata, routing rules/chains, destination and traffic summaries, process/system memory, core/firewall identity, the latest service result, truncation markers, and finalization reason.
- Added a repeatable 15-minute JSON/Markdown report designed for direct AI troubleshooting, with typed API contracts, session-ID matching, manual stop/discard, timeout, and automatic finalization on profile or core-generation changes.
- Hardened report privacy with fail-closed source baselining, semantic IPv4/IPv6 matching, generated connection IDs, allowlisted config fields, URL stripping, recursive output redaction, and broad credential-key canaries. Share links, subscription URLs, tokens, passwords, cookies, private keys, and authorization values are excluded.

### Profiles and subscriptions

- Replaced the rename-only action with an on-demand profile editor that exposes the complete manual share link only in the detail endpoint and shows parsed protocol, transport, address, port, lifecycle state, and subscription provenance.
- Manual connection edits preserve profile IDs and user intent while migrating lifecycle refs, Dead Servers timestamps, Deep Bench selectors, quality history, favorites, statistics, and enabled routing targets. Active or pinned edits validate and apply transactionally with exact state/config/runtime rollback.
- Subscription-managed share links remain read-only while their display names can be changed.
- Added local atomic revalidation for `No group` profiles. The full batch is parsed before mutation; malformed links and newly introduced lifecycle collisions leave state unchanged, while pre-existing equivalent identities remain valid.

### Mihomo Parameters

- Replaced the full `MihomoFeatures` replacement API with a strict bounded `{parameters, runtime}` contract and stable-ID Web UI controls that load automatically and work in both languages.
- Kept router-relevant Expert controls for transport, keep-alive, TCP concurrency, sniffer lists, loopback tunnels, hosts, QUIC troubleshooting, and a limited advanced DNS surface.
- Removed relay, NTP, SMUX, arbitrary dialers, Mihomo listener authentication, user proxy/rule providers, parallel raw/typed/sub-rules, and ignored DNS ECS/disable fields from the Parameters path.
- Fixed GEO loader, fake-IP persistence, UDP, the canonical fallback group, and External Controller at `127.0.0.1:9090` as router invariants; controller credentials are never returned by the API.
- Added strict validation, atomic config activation/persistence, rollback on runtime or disk failure, and safe migration that removes obsolete secrets/URLs and forces legacy authenticated LAN listeners to loopback.

### Core lifecycle and memory

- Fixed a live split-brain where an orphaned old Mihomo owned all VPN listeners while a new child remained alive without a dataplane. Readiness now proves that every required TCP/UDP listener belongs to the tracked child before accepting its External Controller.
- Added Linux `PR_SET_PDEATHSIG`, parent-race protection, deterministic stop/reap semantics, hot-reload ownership checks, and shutdown ordering that terminates Mihomo before a potentially slow GeoBase join.
- Made active-profile and Parameters activation validate generated config, wait for owned runtime readiness, serialize through one apply lock, and restore exact previous config/state/core/firewall identity on failure.
- Bounded `/connections` reads to 16 MiB, removed duplicate full JSON parse/serialize/clone passes, pages before GeoIP enrichment, and caches `geoip.metadb` by file identity. This reduced observed HincyRay RSS from approximately 120 MiB to the 20–40 MiB range after orphan cleanup.

### Diagnostics and compatibility

- Added bounded parsing of Happ/Xray XHTTP `extra` JSON with typed support for padding obfuscation, headers, session/sequence/uplink placement, range values, reuse/XMUX settings, and structural redaction.
- Fixed `xPaddingObfsMode` boolean generation and added the Xray-compatible `uplink-chunk-size: 3000-4000` default for header/cookie packet uplinks, working around Mihomo v1.19.29's omitted-range failure. The previously failing `n-eu1 Yandex CDN WARP device-2` profile passed ICMP, TCP, proxy HTTPS, YouTube, Telegram, and AI Studio live checks with zero packet loss.
- Fixed benchmark concurrency persistence after page reload, made benchmark admission atomic, displayed all active workers, and clarified that a row lightning action tests one server while group/selected/Full scopes use up to the configured 1–6 workers. Live verification observed four active profile workers simultaneously.
- Preserved the serialized external YouTube and Telegram service boundaries while profile-level ping/runtime pipelines continue concurrently.

## v1.2.2 - 2026-08-16

- Restored the benchmark concurrency control as a native accessible selector with the supported 1–6 range instead of a custom menu clipped by its settings panel.
- Made Quick and Full Test run the same serialized YouTube playback probe whenever the temporary Mihomo runtime starts; unrelated ping failures no longer fabricate a skipped YouTube result.
- Added one bounded retry for transient DNS/connect/TLS/reset/timeout and HTTP `408`/`425`/`429`/`5xx` failures, explicit bounded HTTP-status validation for bootstrap/player responses, and a 2 MiB player-response limit.
- Made YouTube media verification try up to three distinct direct video formats, including a progressive fallback. This avoids false `403` results observed live for `itag 160` while other formats delivered the requested media range through the same profile.
- After a successful active-profile transaction, close existing Mihomo connections so manual and automatic server switches force applications to reconnect through the newly selected upstream instead of retaining the old exit IP.

## v1.2.1 - 2026-08-15

- Fixed the built-in Mihomo updater exhausting router memory while decompressing a core release. `gunzip` now streams directly into the staged binary instead of buffering the complete decompressed executable in the HincyRay process.
- Preserved updater verification, binary backup, core restart, and rollback behavior while cleaning partial staged output on decompression failures.
- Fixed subscription wrappers with an unescaped URL query value, such as `https://provider.example/happlink?link=https://provider.example/sub/<token>`, being split into two invalid subscription candidates.

## v1.2.0 - 2026-08-12

- Replaced the profile speed-test controls with explicit Quick and Full service diagnostics. Quick Test applies an any-of ICMP/direct-TCP/proxy-HTTPS ping gate and then checks YouTube, Telegram, and AI Studio in fail-fast order; Full Test records every stage independently.
- Added bounded server concurrency from 1 to 6, persisted ping/YT/TG/AI indicators, and result sorting by complete outcome, successful checks, then ping. Diagnostic service failures no longer alter health counters, cooldown, failover, or auto-selection history.
- Fixed widespread false-red YouTube results by serializing the anonymous YouTube boundary, extending its connect budget, and carrying the Innertube visitor cookies and matching client identity into the bounded direct-media request.
- Made benchmark Mihomo use the writable temporary config directory instead of resolving its home under `/.config/mihomo` on the router.
- Restored Happ-compatible subscription imports when a provider first returns a syntactically valid but unusable `0.0.0.0:1` sentinel profile.
- Added a tested operational guide for locking Foxconn T99W175 / Cinterion MV31-W LTE B3 as PCC while retaining B1+B7 carrier aggregation on Keenetic.

## v1.1.0 - 2026-07-28

- Added the disabled-by-default experimental «Паровозик»: domains absent from enabled applied GeoBases are tried DIRECT first, verified DIRECT failures are immediately tested through the current VPN plus up to five selected live server routes, and learned results are exposed as separate managed `Паровозик Direct` / `Паровозик VPN` rules below GeoBase precedence.
- Added a compact subscription-column consist selector that excludes Dead Servers, displays no endpoint secrets or technical connection fields, and preserves unsaved selections across periodic status refreshes.
- Replaced the AI Studio Quick Test request/redirect heuristic with the bounded `vernette/ipregion` method: read Google's exit-region code through the tested profile, resolve its country name, and match it against Google's published AI Studio/Gemini region list. The legacy direct AI Studio probe remains compiled but disabled for rollback; the authorized Telegram media probe remains active because ipregion has no Telegram check.
- Removed the superseded browser-extension experiment and its extension-only routing/CORS API surface.

## v1.0.0 - 2026-07-26

v1.0.0 is the first stable public HincyRay release. It packages the hardened Keenetic/Mihomo dataplane and control plane from the v0.21-v0.22 series with the completed production Web UI and a public installation/release path.

### Production Web UI

- Replaced the previous embedded panel with the completed Fluent/Acrylic redesign while preserving the production API, authentication, routing, diagnostics, lifecycle, and Mihomo controls.
- Restored the HincyRay brand mark and favicon instead of the placeholder white square.
- Made profile groups consume the available section width and arranged profile entries into adaptive multi-column desktop/tablet grids; mobile remains a focused single-column layout.
- Kept optional benchmark metrics configurable and labelled inside compact profile cards, with `YT`/`TG`/`AI` service results beside profile identity.
- Added moving activity feedback for Quick Test and other long-running test, download, apply, update, backup, GeoBase, and routing operations.
- Tightened preview/production separation so mock data is used only for local `file:` previews; fixture-backed and live daemon pages use real API data.
- Preserved responsive routing, device, connection, and active-connection views without page-level horizontal overflow.

### Stable router runtime

- Declared the transactional Mihomo activation path, TCP REDIRECT + UDP TPROXY firewall model, persistent ndm hook, watchdog fallback health, local DNS bootstrap, and rollback-safe desired state as the stable v1 runtime contract.
- Includes canonical `srv-v1` routing refs and separate `srv-v2` lifecycle refs, virtual Dead Servers, Deep Bench history, bounded automatic failover, managed GeoBase, safe mode, backups, OpenAPI contracts, and redacted diagnostics.
- Includes real sequential Quick Test checks for YouTube, Telegram, and AI Studio without Python, `yt-dlp`, a JavaScript runtime, or a TUN path.
- Includes Argon2id Web UI authentication, bounded cryptographic sessions, same-origin mutation checks, login throttling, structurally redacted configs/logs, and private Telegram session storage.

### Distribution and documentation

- Changed the project to a public GitHub repository and changed installer fallback to download the exact `v1.0.0` `hincyray` asset from public GitHub Releases; local `HINCYRAY_BIN_PATH` remains supported for offline installs.
- Synchronized package/lockfile, embedded UI, installer, installer contract, English/Russian README, release notes, and operational guidance on v1.0.0.
- Added a versioned release evidence document at `docs/releases/v1.0.0.md`.

### Verification

- Release gate and live deployment evidence is recorded in `docs/releases/v1.0.0.md`.

## v0.22.1 - 2026-07-25

- Fixed policy-client DHCP loss: transparent firewall chains now bypass limited broadcast, link-local, loopback, all RFC1918 ranges, and multicast before TCP REDIRECT/UDP TPROXY. The same generated bypass list is installed by the persistent ndm hook; live verification observed DHCP broadcasts hit RETURN instead of `proxy-active`.
- Fixed the proxy-hostname DNS bootstrap loop by using configured local DNS servers as the default Mihomo `proxy-server-nameserver`. Hostname-based active profiles now start without depending on DNS through the not-yet-established proxy.
- Made watchdog health require both the aggregate `proxy` group and the actual `proxy-active` outbound to report alive, closing a false-healthy state observed live as `proxy alive=true/now=proxy-active` with `proxy-active alive=false`.
- Kept `YT`/`TG`/`AI` Quick Test indicators visible beside profile names when optional metric columns are hidden.
- Expanded Dead Servers with single/all Quick Test, restore-all, and atomic clear; removed synthetic score/Smart Select behavior while retaining raw latency, jitter, loss, speed, success/failure, cooldown, and Deep Bench history.
- Added subscription title/announcement metadata and preserved full profile names containing spaces and emoji.
- Added bounded AI Studio regional validation using contract v5 service results and fail-closed Google sign-in handling.
- Kept routing-rule deletions as pending desired state when activation cannot run, and hardened subscription loading with bounded decode/content compatibility handling.
- Release gates: 493 Rust tests, 119 frontend routes, 17 Playwright tests, fmt/check/both clippy profiles/installer/diff, aarch64 release build, live transparent client verification, and router E2E passed.

## v0.22.0 - 2026-07-22

- Replaced Quick Test's server-port/CDN smoke checks with real per-profile service validation. YouTube now bootstraps a visitor-bound `ANDROID_VR` Innertube player response and serves a bounded 512 KiB direct video range through the tested profile using only Rust and `curl`; no Python, `yt-dlp`, JavaScript runtime, or TUN path is required.
- Added authorized Telegram media validation through `grammers`: a serialized per-profile probe resolves a configured public peer, loads one selected message, and downloads one bounded media chunk through the temporary profile SOCKS listener.
- Added Telegram provisioning/status/confirm/delete APIs and Web UI, including login-code and optional 2FA flows. API hash, phone, login code, and password are never returned or written to `state.json`; private config and SQLite session files use mode `0600`, and the delete action attempts Telegram sign-out before removing local session files.
- Versioned persisted service results as contract v4 so obsolete CDN, MTProto handshake, and failed intermediate extractor results cannot appear as current green/red `YT` or `TG` indicators. Quick Test runs profiles sequentially because one Telegram session must not be shared by concurrent clients.
- Added compact profile `YT`/`TG` indicators and a persisted metric-column gear menu without widening the default table. Browser coverage verifies provisioning payloads and confirms credentials are not persisted in browser storage.
- Removed the unused oversized RKN bypass subsystem and legacy router `geoip.dat` path; MetaCubeX `geosite.dat` + `geoip.metadb` remain the supported geo assets. The installer no longer stages or removes `geoip.dat`.
- Simplified managed GeoBase projection: with `MATCH,proxy`, automatically classified Active domains remain in the manifest but no redundant Active provider is loaded; static Active networks remain explicit. Renamed the GeoIP preset to “RU IP Direct (advanced)” and consolidated the UI around RU Direct, managed GeoBase, and bounded Always VPN overrides.
- Live validation on Keenetic Giga found and removed a PyInstaller `/tmp` memory spike from the rejected `yt-dlp` prototype. The final native probe completed a three-profile YT+TG batch with all checks green, no Python/QuickJS processes, and approximately 197 MiB minimum `MemAvailable`; router E2E passed.
- Release gates: 487 Rust tests, 118 frontend routes, 14 Playwright tests, fmt/check/both clippy profiles/installer/diff, aarch64 release build, and live router E2E passed.

## v0.21.7 - 2026-07-21

- Kept DIRECT and RU whitelist routes independent of VPN upstream health by using configured local DNS servers as Mihomo `direct-nameserver` defaults while preserving explicit advanced DNS overrides.
- Added a selected-server Quick Test mode: one one-second TCP reachability probe per profile, bounded to eight parallel workers, with no download/upload stages or temporary Mihomo process.
- Stopped background auto-VPN learning from restarting Mihomo after a learned-domain change. Learned exceptions persist and take effect on the next explicit routing apply or core restart, avoiding router-wide connection interruption.
- Synchronized both Web UI auto-switch controls and documented deferred auto-VPN exception application.
- Gates: 490 Rust tests, 114 frontend routes, 12 Playwright tests, fmt/check/both clippy profiles/installer/diff all passed. The aarch64 artifact was deployed with a complete rollback set and passed DIRECT/VPN probes, fallback/firewall checks, live parallel Quick Test, and router E2E.

## v0.21.6 - 2026-07-16

- Added the virtual Dead Servers lifecycle group without overwriting subscription/manual provenance, including atomic batch move/restore APIs, active-profile protection, startup reconciliation, and transactional Mihomo dataplane activation with field-scoped rollback.
- Split immutable identity by contract: routing targets remain `srv-v1`, while Dead Servers, Deep Bench, selectors, and quality history use canonical lifecycle `srv-v2` references. Legacy current-profile refs migrate at startup; orphan v1 Trash entries remain restorable.
- Canonical lifecycle identity now ignores display fragments, normalizes URL scheme and domain-host case, deterministically orders query keys without losing repeated values, and canonicalizes VMess JSON without its display name. Connection-setting changes still produce a different identity.
- Excluded Dead Servers from automatic/all/subscription benchmark and selection scopes while preserving explicit diagnostics, and kept enabled pinned routing intent on active fallback until restore.
- Added the Web UI virtual group, bulk selection/actions, provenance display, lifecycle-aware benchmark/history projections, and regression coverage across frontend/API, migration, routing, activation, and rollback contracts.
- Made desktop egui stroke widths explicitly `f32`, keeping the all-features build compatible with the stable compiler's `float_literal_f32_fallback` lint under `-D warnings`.
- Made the local subscription HTTP fixture consume bounded request headers before replying, preserving the strict empty-content assertion without Linux TCP-reset races.
- Corrected private-repository installation: automatic downloads now require `HINCYRAY_GITHUB_TOKEN`, resolve the exact release asset through GitHub's authenticated API, and keep credentials out of URLs and logs; local `HINCYRAY_BIN_PATH` remains credential-free.
- Gates: full Rust/frontend/installer gate passed locally; Rust tests report 488 passed. The aarch64 artifact was hash-verified, deployed to Keenetic Giga with complete binary/state/history/config rollback coverage, and passed independent lifecycle projections plus router E2E.

## v0.21.5 - 2026-07-16

- Replaced historical-score-only failover with protocol-verified failover: history now orders candidates, but a candidate must pass every fresh HTTPS sample through its own temporary Mihomo instance before the daemon switches to it.
- Moved failover identity from mutable numeric profile IDs to immutable raw profile descriptors, with a final under-lock re-resolution before transactional activation. Concurrent profile refreshes or user switches can no longer redirect failover to a different object.
- Failed active profiles and failed candidates receive persisted raw-keyed cooldowns; Trash Bin entries and profiles already in cooldown are excluded. Each failover cycle is bounded to the top eight eligible candidates.
- Added regression coverage for strict rejection of partial protocol availability, raw-keyed exclusions, Trash/cooldown filtering, and health-failure cooldown state.

## v0.21.4 - 2026-07-16

- Fixed temporary Mihomo process diagnostics across router benchmarks, speed tests, Deep Bench, and desktop tests: stdout and stderr are now preserved in one ordered process log instead of discarding stdout.
- Early Mihomo exits now include the actual bounded startup/configuration diagnostic rather than an opaque `exit status: 1`, making shared runner failures distinguishable from real proxy-profile failures.
- Added regression coverage proving diagnostics written to both process streams survive in the combined log.

## v0.21.3 - 2026-07-16

- Fixed destructive subscription refresh: a successful HTTP response that contains zero supported profiles is now a content error, including empty, HTML/challenge, maintenance, and unsupported JSON responses.
- Made subscription replacement transactional at the state boundary: an empty profile set is rejected before any existing group profile, ID, or active-profile state can change. Only the explicit subscription/group deletion APIs may erase a group.
- Added regression coverage for HTTP 200 empty-content responses and for preserving a populated subscription group when an empty replacement is rejected.

## v0.21.2 - 2026-07-16

- Hotfix: GeoBase Active rule providers now target the `proxy` fallback group instead of the raw `proxy-active` outbound. This preserves Mihomo's `[proxy-active, DIRECT]` safety path when the active upstream server flaps or times out, preventing policy-marked clients from losing internet on broad generated GeoBase rules.
- Added regression coverage forbidding broad GeoBase `RULE-SET,...,proxy-active` targets; Active routing intent now matches ordinary `active` route rules by resolving through the fallback group.

## v0.21.1 - 2026-07-15

- Completed the remaining v0.21 control-plane contracts instead of leaving them as release-note promises.
- Onboarding readiness now checks Mihomo, active profile, `geoip.metadb`, Keenetic policy mark, kernel modules/TPROXY capability, Mihomo core, EC reachability when enabled, DNS listener health, transparent firewall state, and the ndm firewall hook.
- Added generated OpenAPI/JSON schema output at `GET /api/openapi.json`; `GET /api/contracts` now points at the schema endpoint and lists typed endpoint contracts.
- Routing preview now returns typed diff entries for rule-count changes, MATCH target changes, GeoBase apply, core restart, and firewall reload instead of forcing the Web UI to parse human strings.
- Connections table now has an explicit “create/change rule” flow in addition to quick target select and “why this route” diagnostics.
- `/api/logs` now redacts suspicious log lines before returning Mihomo log tails to the Web UI.
- Browser E2E smoke coverage expanded from 6 to 12 tests: login, connection search/pagination/action/rule editor, device accounting, routing rule add/apply, DNS save/apply, profile import, mobile bottom navigation, and prompt-free rename.
- Decomposition continued: Mihomo External Controller transport moved to `hincyray_mihomo_api`; routing resource normalization moved to `hincyray_routing`.
- Gates: full Rust/frontend/installer/browser gate passed locally; Rust tests now report 467 passed and Playwright reports 12 passed.
- Router validation: v0.21.1 aarch64 binary SHA256 `a7f89cfac39b2f676deb7a8ead35925905cccab71a783a00d815faaaba6b1e94` was deployed to Keenetic Giga, copied back byte-for-byte, and router E2E passed.

## v0.21.0 - 2026-07-15

v0.21.0 is the hardening and operability release. It turns the router daemon from a feature-heavy single-file control plane into a contract-driven system with explicit security, bounded APIs, transactional runtime changes, browser smoke coverage, and safer installer lifecycle semantics.

### Security and authentication

- Web UI passwords are now stored as Argon2id PHC hashes with random salts. Legacy plaintext state is migrated on load and is not serialized again.
- Session tokens are generated from cryptographically secure 256-bit randomness instead of timestamp/PID material.
- Sessions have idle and absolute expiry, a hard cap, and are invalidated when username, password, auth-enabled state, or state restore changes the security boundary.
- Login attempts are throttled per source IP after repeated failures.
- State-changing HTTP requests enforce same-origin checks when `Origin` is present.
- Request bodies are bounded and malformed UTF-8/length handling is rejected before handler logic.
- The browser keeps the Bearer token in `sessionStorage`; stale `localStorage.hincyray_token` is removed during Web UI boot.
- Security headers are emitted for the embedded UI/API responses.
- Password hashing/verification work is capacity-limited per daemon instance, preventing CPU exhaustion without making parallel tests share a process-global limiter.

### Secret redaction and diagnostics safety

- `GET /api/mihomo-config` and `GET /api/mihomo-config/preview` now pass generated YAML through structural redaction before returning it to the browser.
- Known credential families are redacted, including proxy passwords, UUID-like user secrets where appropriate, private keys, preshared keys, bearer/API secrets, TLS client key material, and provider URLs carrying opaque tokens.
- The Web UI escapes rendered config output instead of injecting it as HTML.
- Redaction is fail-closed: malformed generated YAML is not returned raw.

### Typed, bounded API surface

- Added `src/hincyray_api.rs` for typed DTOs and bounded response contracts.
- Added `GET /api/contracts` so the Web UI and diagnostics can discover contract version, bounded endpoints, auth scheme, and same-origin mutation policy.
- Added `GET /api/onboarding/status` with readiness checks and remediation for Mihomo, active profile, GeoIP asset, core, transparent firewall/TPROXY state, and the ndm firewall hook.
- Added `GET /api/routing/summary` for a compact routing/safe-mode/runtime summary.
- Added `GET /api/routing/connection-context` to provide a bounded server projection for connection routing controls without raw share links or credentials.
- Added `GET /api/routing/preview` to compare desired vs applied config hashes, GeoBase generations, firewall/core effects, and conflicts without mutating runtime.
- Added `POST /api/routing/explain` for local route explanation by host/resource/source/port/network while marking Mihomo-owned GEOSITE/GEOIP/RULE-SET decisions as runtime-owned instead of guessing.
- Added `GET /api/memory-estimate` as a factual current-state report: rule-source bytes on disk, current Mihomo RSS, MemAvailable, rule/provider counts, safe-mode state, and observed risk. It no longer pretends to forecast future peak allocation.
- Added `GET/POST /api/safe-mode` for reversible suppression of heavy optional features such as RKN bypass, managed GeoBases, proxy/rule providers, sub-rules, raw/typed rules, tunnels, and smux.
- Added `POST /api/mihomo-api/connections/page` for server-side search, filtering, offset, and clamped limits over Mihomo connections.
- Added `POST /api/mihomo-api/connections/device-traffic` for bounded per-device accounting over observed source IPs.

### Runtime activation and rollback

- Routing apply now runs through a serialized activation path: clone authoritative state, generate desired config, validate, atomically write, restart/start Mihomo, observe readiness, apply firewall, and commit desired GeoBase generation only after success.
- Activation failure restores previous config bytes, core state, firewall state, and policy state instead of leaving mixed desired/applied runtime.
- Safe mode rollback is field-scoped: it suppresses generated heavy features without purging profiles, subscriptions, source artifacts, backups, or history.
- Desired vs applied GeoBase state is explicitly reported, so the UI can show when a config requires apply.

### Web UI reliability and responsiveness

- The Web UI boot contract was tightened so required loaders and DOM targets are statically verified.
- Connections views now use server-side pagination/search instead of dumping unbounded `/connections` payloads into the browser.
- Connection search indexes the exact rendered flag-plus-host label, fixing searches such as `🇷🇺 chatgpt.com`.
- Connections actions now use canonical server refs/context rather than requiring the browser to infer internal routing identity.
- Added route explanation, apply preview, onboarding/readiness, safe-mode, and factual memory cards.
- Profile rename now uses an in-page dialog with keyboard behavior instead of `window.prompt`.
- Responsive table-to-card rendering adds `data-label` from table headers for mobile/tablet layouts.
- Mobile/tablet navigation and sheets were added while keeping the UI a single embedded document with no CDN/build step.

### Module boundaries

- Added `src/hincyray_security.rs` for password hashing, password verification, session generation/expiry/caps, login throttling, and password-work limiting.
- Added `src/hincyray_api.rs` for versioned DTOs and bounded API contracts.
- Added `src/hincyray_webui.rs` as the embedded Web UI asset boundary.
- `src/hincyray.rs` remains the composition root for HTTP dispatch, persisted state, activation, core/firewall/watchdog orchestration, and route handlers.

### Installer and router lifecycle safety

- The installer now uses an Entware-aware transaction model with lifecycle locking and rollback guards.
- Generated init scripts detach the daemon with `nohup`, redirect stdin, own the authoritative PID file, and verify `/proc/<pid>/exe` before signaling.
- Stale PID files pointing at another process are rejected instead of killed.
- The installer starts core through the daemon API where appropriate and no longer relies on unsafe argv/process-name scans.
- Repository operational guidance now forbids `pgrep -f`, `pkill -f`, `killall`, and similar process-name lifecycle controls for HincyRay because they can match and terminate the invoking SSH shell.

### Tests and CI

- Added deterministic Playwright browser smoke tests with a fixture server.
- Browser smoke covers Web UI boot without JavaScript errors, exact flag+host search, native connection-route action payloads, and the profile rename dialog.
- Added `package.json`, `package-lock.json`, and `playwright.config.mjs` for reproducible browser tests.
- Added `scripts/installer-lifecycle-contract-test.py` for static installer/init lifecycle invariants.
- CI now runs Rust gates, frontend contract checks, installer lifecycle checks, and browser smoke tests.
- Final local gates passed: `cargo fmt --all --check`, `cargo check --all-targets --all-features`, both clippy profiles with `-D warnings`, `cargo test --all-targets --all-features` (464 passed), frontend contract, installer lifecycle contract, Playwright browser tests (6 passed), and `git diff --check`.

### Router validation

- Cross-built no-default-features aarch64 router binary for Keenetic/Entware.
- Final binary SHA256: `61721753bd49f171f3c7ae5b2299691c5d0ffc4275468caa5a68b3345b8c023d`.
- Deployed on Keenetic Giga through the authoritative init script with backup and rollback guard.
- Live `/opt/sbin/hincyray` was copied back from the router and its SHA matched the local release artifact.
- Live checks passed: `/api/health` reports `0.21.0`, `/api/status` reports core running, `/api/safe-mode` reports core/firewall running, `/api/onboarding/status` reports ready, and router E2E passed.

Full release notes are in `docs/releases/v0.21.0.md` and on the GitHub Release page.

## v0.19.4 - 2026-07-05

- Fluent Reveal spotlight effect fixed and extended to all interactive elements:
  - Root cause fix: `var()` inside `radial-gradient()` position was not resolving in some browsers, making the spotlight static at 50%/50% (looked like a flat fill).
  - Moved `var()` to `left`/`top` + `transform:translate(-50%,-50%)` for reliable cross-browser cursor tracking.
  - Extended Reveal from sidebar nav to buttons (`.btn`), chips (`.chip`), section headers (`.section-header`), custom select triggers/options, sub-tabs, and nav flyout items.
  - `btn-accent` gets a light spotlight (`var(--bg) 24%`) for visibility on blue background.
  - Switched `mousemove` to `pointermove` (touch + mouse). Handler moved to start of `init()` so async errors cannot prevent registration.
- `/api/profiles/add` now accepts subscription URLs, not just share links. When a user pastes `https://provider.example/sub/<token>`, the endpoint fetches and imports all profiles from the subscription (direct + proxy fallback), instead of returning "could not parse share link". The subscription source is also persisted for later refresh.
- Frontend contract test updated with new Reveal selectors and `pointermove` marker.
- Tests: 352 passed, 0 clippy warnings.

## v0.19.3 - 2026-07-04

- Emergency Web UI performance fix: removed the periodic heavyweight `refreshDashboard()` loop that fanned out across profiles, routing, subscriptions, backups, DNS, HWID, auth, update status, traffic, connection log, and Mihomo EC endpoints every 5 seconds.
- Kept only lightweight periodic loops: `/api/system` + `/api/memory-guard` every 3 seconds and `/api/status` every 5 seconds.
- Added a frontend contract guard forbidding `setInterval(refreshDashboard...)` / `hrDashboardRefreshInterval` so the request-storm regression cannot return.
- Live router latency after fix: `/` ~200 ms, `/api/health` ~150-200 ms, `/api/system` ~200 ms (previous bad v0.19.2 build caused multi-second delays/timeouts under the Web UI request storm).

## v0.19.2 - 2026-07-04

- Made the System hardware/resource block refresh independently every 3 seconds via a lightweight `/api/system` + `/api/memory-guard` heartbeat.
- Made the Memory card clickable and keyboard-accessible, opening a live breakdown with Linux memory summary, Mihomo/HincyRay RSS, top RSS processes, and Memory Guard warnings.
- Moved auto-refresh loop registration to the start of Web UI initialization and made it idempotent/exception-safe so later UI initialization errors cannot leave resource metrics stuck at the first snapshot.
- Strengthened `scripts/frontend-contract-test.py` to require the System refresh loop, memory breakdown entrypoint, and new memory DOM targets.
- Tests: 350 passed, 0 clippy warnings.

## v0.19.1 - 2026-07-04

- Fixed the System page hardware block: hardware/resource metrics are visible in the existing System section, and the dead sidebar "Hardware" item was removed.
- Made `POST /api/mihomo-config/validate` bounded: the daemon releases the state lock before validation, runs `mihomo -t` with an 8-second deadline, captures bounded stdout/stderr, kills hung validators, and returns `timeout: true` instead of blocking the API.
- Strengthened `scripts/frontend-contract-test.py` to reject sidebar navigation entries without section panels/NAV_MAP entries and to verify System renderer DOM targets.
- Tests: 350 passed, 0 clippy warnings.

## v0.19.0 - 2026-07-04

- Moved hardware metrics into the System page and kept `/api/system` as the single structured system source.
- Added Mihomo config validator: `POST /api/mihomo-config/validate`.
- Added diagnostics: `GET /api/diagnostics/dns`, `GET /api/diagnostics/udp-quic`, and `GET /api/memory-guard` with top RSS processes.
- Added Prometheus metrics endpoint: `GET /metrics`.
- Added subscription refresh reports: `GET /api/subscriptions/refresh-report`.
- Added backend undo stack: `GET /api/undo`, `POST /api/undo/restore`.
- Added bounded state compaction for metrics history, connection log, undo stack, and refresh reports.
- Added `hincyray` CLI commands: `status`, `doctor`, `validate-config`, `restart-core`, `apply-routing`, `backup`.
- Added global Web UI search in the sidebar.
- Added `scripts/frontend-contract-test.py`, `scripts/router-e2e.sh`, `scripts/hincyray-doctor.sh`, and CI with fast daemon clippy + full clippy.
- Tests: 348 passed.

## v0.18.0 - 2026-07-04

- Added profile group sharing API `POST /api/profile-groups/share` for sharing a whole subscription/group (all servers in the group), plus `POST /api/profile-groups/delete` for deleting a whole visible group/subscription.
- Kept single-server `POST /api/profiles/share`, but moved user-facing Web UI sharing/deletion to subscription/group headers in the profiles table.
- Fixed Web UI/backend contract mismatches: single profile add now sends `raw`, Sub-Store sends `sort_by`, auto-update settings save/load uses `/api/update/settings` and `/api/update/status`.
- Fixed EC raw buttons to display real API responses instead of mock data.
- Fixed `/api/system` Web UI binding to the actual nested system schema and replaced demo values with placeholders.
- Removed confusing per-server share/QUIC row actions from the subscription workflow; routing rules remain the user-facing QUIC control.
- Added 15-second undo for routing rule deletion and updated device view toward connected devices with traffic aggregation.
- Added Web UI controls audit document.
- Tests: 344 passed, 0 clippy warnings.

## v0.17.0 - 2026-07-04

### Added
- **RKN Bypass**: `SplitRoutingSettings.rkn_bypass_enabled` (default `true`), `rkn_bypass_url`, `rkn_bypass_interval` fields. When enabled, injects a `RULE-SET,ru-bypass,proxy` rule provider that downloads `itworksig/rublacklist` bypass.list (744K+ domains blocked in Russia) through the proxy, refreshed every 24h. Also injects `GEOIP,RU,DIRECT` and `GEOIP,CN,DIRECT` so Russian/Chinese IPs go direct. Rule order: user rules → QUIC block → raw rules → RKN bypass (RULE-SET → GEOIP,RU → GEOIP,CN) → RU Direct → port-mode → MATCH. `RouterExtra` gains `rkn_bypass_enabled`, `rkn_bypass_url`, `rkn_bypass_interval`. `RKN_BYPASS_DEFAULT_URL`/`RKN_BYPASS_DEFAULT_INTERVAL` constants in `mihomo_config.rs`.
- **Reset to factory defaults**: `POST /api/routing/reset` endpoint. Resets rkn_bypass (enabled, default URL, 24h interval), ru_direct_mode=geosite, match_target=proxy, port_mode=AllowList, proxy_ports=80/443, routing_rules=QUIC Block only, raw_rules=cleared. Infrastructure settings (enabled, auto_switch, vpn_subnet, redirect_port, policy_name, geo_asset_path) preserved. WebUI button "↺ Штатные настройки" calls reset then apply.
- **Configurable sniffer override-destination**: `MihomoFeatures.sniffer_override_destination` (default `true`). `/api/dns` GET/POST bridges the field. WebUI checkbox in DNS section. `saveDns()` now calls `/api/routing/apply` after saving.
- 12 new tests (339 total).

### Changed
- `build_mihomo_router_config()`: RKN bypass rules and rule provider injected when `extra.rkn_bypass_enabled`. Provider merged with user-configured rule providers (user's `ru-bypass` takes precedence).
- `handle_routing_settings()`: accepts `rkn_bypass_enabled`, `rkn_bypass_url`, `rkn_bypass_interval`.
- `build_sniffer_json()`: reads `features.sniffer_override_destination` instead of hardcoded `true`.
- `saveRoutingSettings()` in WebUI: sends `rkn_bypass_enabled`, `rkn_bypass_url`, `rkn_bypass_interval`.
- `updateRoutingForm()` in WebUI: reads RKN bypass fields from API response.

### Migration
- Old state files: `rkn_bypass_enabled` defaults to `true`, `rkn_bypass_url` defaults to `itworksig/rublacklist`, `rkn_bypass_interval` defaults to 86400. `sniffer_override_destination` defaults to `true`.

## v0.16.0 - 2026-07-04

### Added
- **MATCH toggle**: `SplitRoutingSettings.match_target` field (`"proxy"` or `"direct"`). Controls the final `MATCH,proxy` vs `MATCH,direct` rule. Visible as an immutable first row in the rules table with a dropdown. Locked to `proxy` when no routing rules exist. API rejects `match_target=direct` when rules are empty.
- **Per-rule port mode**: `RoutingRule.port_mode` field (`"include"` or `"exclude"`). "Include" emits standard `DST-PORT` rules. "Exclude" wraps domain/IP rules in `AND,((<rule>),(NOT,(DST-PORT,<port>))),target`.
- **AND rule composition**: `rule_to_strings()` in `mihomo_config.rs` now ANDs multiple condition types (domains/IPs + ports + network) into a single Mihomo rule instead of emitting separate OR-style rules. Refactored `domain_rule_body()` and `ip_rule_body()` to produce rule bodies without target for AND composition.
- **Geo provider API**: `GET /api/geo/providers` (MetaCubeX/Loyalsoldier/v2fly), `POST /api/geo/download` (downloads geosite.dat/geoip.metadb through SOCKS proxy with .bak backup), `GET /api/geo/status` (file exists/size).
- **Preset target override**: `POST /api/routing-presets/apply` accepts optional `target` field to override preset's hardcoded target.
- **Routing conflict detection**: `GET /api/routing` returns `conflicts` array with warnings when per-rule ports clash with global PortMode.
- **Inline cell editing in WebUI**: click any cell in the rules table to edit in place. Target and protocol use re-rendered `<select>` (same pattern as MATCH row). Name, domains, and ports use inline input/textarea.
- **Geo provider card in WebUI**: provider dropdown, file status, download button.
- **Preset target picker in WebUI**: clicking a preset chip shows a target selector dropdown.
- 10 new tests (323 total).

### Changed
- **QUIC block migrated to regular rule**: `load_state()` converts `block_quic_global`/`quic_mode=Block` into a `RoutingRule { name: "QUIC Block", network: "udp", ports: ["443"], target: "reject" }`. Removed "Block QUIC globally" checkbox and "QUIC mode" dropdown from WebUI settings. `build_mihomo_router_config()` only auto-generates QUIC block for system-level reasons (TPROXY unavailable, per-profile block_quic).
- **"Сеть" → "Протокол"**: renamed throughout WebUI.
- **`saveRoutingSettings()`**: sends `match_target`, removed `block_quic`/`quic_mode` fields.
- **`XrayRouteRule`**: added `port_mode` field.
- **`RouterExtra`**: added `match_target` field.

### Migration
- Old state files without `match_target`: migrated based on `port_mode` (AllowList→`direct`, others→`proxy`).
- Old state files with `block_quic_global=true` or `quic_mode=block`: "QUIC Block" rule inserted at index 0.

## v0.15.6 - 2026-07-03

### Added

- **RU Direct**: route Russian domains direct before `MATCH,proxy`. Two modes: `tld` (`DOMAIN-SUFFIX,ru,DIRECT` + `.рф`/`xn--p1ai`) and `geosite` (`GEOSITE,category-ru,DIRECT` from `geosite.dat` — includes `vk.com`, `yandex.com` and other Russian services on foreign TLDs). Exceptions list sends specified domains through VPN despite RU Direct. State: `SplitRoutingSettings.ru_direct_mode` + `ru_direct_exceptions`. API: `POST /api/routing/settings` accepts both fields. Web UI: RU Direct card in rules section with mode select + exceptions textarea.
- **Unified rules UI**: merged separate "Домены" and "IPs" textareas into a single field with auto-classification (`geoip:`/`ip-asn:`/bare IP → IP, rest → domain). Rich placeholder showing domain, zone, and IP examples.
- **Expanded service catalog**: 23 services (YouTube, Netflix, Twitch, Spotify, Telegram, Discord, OpenAI, Google, Apple, Microsoft, Steam, Reddit, Twitter/X, Facebook, Instagram, TikTok, Disney+, HBO Max, Amazon, GitHub, Cloudflare, VK, Yandex) + 3 domain zones (`.ru`, `.рф`, `RU все GEOSITE`). Chips rendered dynamically from `/api/routing` catalog, grouped "Сервисы" and "Доменные зоны". Click chip → appends entry to textarea.
- **Rule editing**: pencil (✎) button on each routing rule — populates form for inline edit with "Save" and "Cancel" buttons.
- **Chain-check `info` status**: GEOIP/GEOSITE runtime rules and "no active connection" nodes are now `info` (blue/accent), not `warn`. Summary counts `info` separately; overall status is `ok` when only `info` nodes exist.

### Fixed

- **Routing rules CRUD**: delete was DOM-only (rule reappeared on refresh); now calls API + reloads from server. Toggle (enable/disable) was visual-only; now persists via API. Preset apply now reloads rules after applying. Removed dead "Быстрая строка" button that never persisted anything.
- **`network=any` normalization**: `any`/`all`/`*`/`tcp,udp`/empty in routing rules no longer emits `NETWORK,any` (which crashes Mihomo with "unsupported network type"). Two-layer defense: `normalize_route_network()` at daemon level, `normalize_mihomo_network()` at config generator level.
- **Chain-check russified**: all node labels and details now in Russian. "External controller unavailable or core stopped" split into 3 specific causes: core stopped, EC disabled, EC unreachable.
- **Custom select sync**: `initCustomSelects()` now runs before `refreshDashboard()` so Acrylic dropdowns are enhanced before async API data arrives. Explicit `syncCustomSelect` after `updateRoutingForm` ensures RU Direct mode dropdown reflects server state.

### Verified

- Local gates: 313 tests, 0 clippy warnings.
- Router E2E on Keenetic Giga: core running, active profile id 80, `ru_direct_mode=geosite` with `2ip.ru` exception, config contains `DOMAIN-SUFFIX,2ip.ru,proxy` before `GEOSITE,category-ru,DIRECT`, catalog returns 26 entries, rules CRUD verified, chain-check `bad=0 info=2 status=ok`.

## v0.15.5 - 2026-07-03

### Added

- **Routing chain diagnostics**: `GET/POST /api/routing/chain-check` plus Web UI metro-line visualization for common and per-device transparent routing chains.
- **All VPN preset**: “Без пресетов / Всё VPN” clears split routing rules and uses final `MATCH,proxy` for intercepted traffic.
- **Local GeoIP enrichment**: `/api/mihomo-api/connections` adds `metadata.destinationCountry` from local `geoip.metadb`, supporting both MaxMind GeoIP2 Country records and Mihomo Meta-geoip0 scalar/array records.

### Fixed

- Subscription group refresh now sends the saved subscription URL to `/api/subscriptions/refresh-one`; group delete buttons are only shown for real subscription groups.
- Unlock checks now return a direct/proxy matrix for each service and accept both `service` and `services` request fields.
- Proxy/rule provider cancel buttons remove the whole provider card instead of a wrong parent element.
- Mihomo memory and connections handling now tolerate EC-disabled/fallback states without toast spam.
- UDP TPROXY detection now loads `xt_TPROXY` and `xt_socket` before probing iptables target/match support. Previously detection ran before module loading, so Keenetic stayed in TCP-only REDIRECT mode even though the required modules existed.

### Safety

- Router routing rules and preset apply reject known OOM-heavy `geosite:category-ads-all` before Mihomo config generation, preventing Keenetic out-of-memory crashes.

### Verified

- Local gates: 306 tests, 0 clippy warnings.
- Router E2E on Keenetic Giga: core running, active profile id 80, EC enabled, Cloudflare direct blocked/proxy OK, unsafe ad-block preset rejected with HTTP 400, routing chain has `bad=0`, connection metadata enriched with `destinationCountry`, UDP TPROXY modules/listener/mangle rules present and chain UDP node OK.

## v0.15.4 - 2026-07-03

### Fixed

- **Systematic Web UI button audit (~40 buttons)**: every action button now has a proper handler. Previously many buttons called `api()` without success toast, error handling, or reload — clicking them appeared to do nothing.
  - `apiAction(method, path, body, successMsg, reloadFn)` wrapper standardises all action calls: toast on success, reload section if provided.
  - `api(method, path, body, silent)` — `silent=true` suppresses error toasts. Used for background polling (EC endpoints `/proxies`, `/connections`, `/memory`, `/traffic` every 5s) — no more spam when External Controller is disabled.
  - Error toasts auto-hide after 5s (was infinite, requiring manual close).
  - Human-readable EC error: "External Controller is disabled. Enable it in Mihomo → Settings…" instead of raw 502 JSON.
- **Save/load functions**: `saveAutoSettings()` (15 fields: auto_select, auto_bench_interval, auto_switch, failover_fail_count, smart_select, maintenance, auto_refresh, etc.), `saveSubStore()` (enabled, include/exclude filter, sort, rename_rules, deduplicate), `saveRoutingSettings()` (12 split routing fields), `saveAuth()` — all with success toasts.
- **`saveFeatures()` GET→merge→POST→apply**: previously POST clobbered all features not represented in the UI form. Now does GET first, merges form fields into the existing object, POSTs the merged result, then calls `/api/routing/apply` automatically.
- **Result modals**: `showConfig()` (YAML config in wide modal), `checkUpdate()` (version info modal), `loadLogs()` (log viewer with toast), `doTrace()` (decision/name/reason/source/target/candidates in `#diagOutput`).
- **Speed test UI**: `speedTest()` modal shows Mbps, bytes, elapsed. Service selector (Cloudflare/OVH/Google/Custom URL) via `applySpeedService()`. Mode and timeout selectors. Upload/jitter/packet-loss honestly omitted — no compatible upload endpoint exists.
- **Delay test**: "running…" toast instead of silent hang.
- ID attributes added to ~50 form fields (Auto-Select, Maintenance, Sub-Store, Features, EC sections) — enables proper `document.getElementById()` access.
- ~40 new i18n entries (RU/EN).

### Added

- **Benchmark details**: collapsible `<details>` with per-server results table (ID, profile, status, latency, jitter, speed, packet loss, error). `renderBenchResults(results)` populates both `#benchResultsBody` (benchmark section) and `#testsBenchBody` (overview Tests section).
- **Overview "Tests" section** (`ov-tests`): new sidebar nav item with cards (`testsUp`, `testsDown`, `testsMem`), quick buttons (speed test, delay test, benchmark, proxy status, traffic), compact top-20 bench results table.
- **Mihomo memory procfs fallback**: `read_process_rss_kb(pid)` reads `VmRSS` from `/proc/<pid>/status` when EC is disabled or returns `inuse:0`. Response includes `"source":"procfs"` field. Verified: `{"inuse":35724,"oslimit":0,"source":"procfs"}`.
- **Device routing UI clarity**: split into two tables — "Detected LAN devices" (shows all scanned devices from `/api/devices`, including those without override) and "Individual override routes" (only explicit per-device rules from `/api/device-routes`). Warning text: override routes have priority above domain/GEO rules. Default target changed from `direct` to `active`. `loadDevices()` auto-loads on page init (silent, no toast spam).

### Verified

- Local gates: 301 tests, 0 clippy warnings.
- Router E2E on Keenetic Giga: all save/load buttons functional, EC endpoints silent when disabled, speed test returns Cloudflare download speed, benchmark details populated, device scan shows Pixel 6a (192.168.2.35) in LAN table without needing override, memory procfs fallback returns 35724 KB.

## v0.15.3 - 2026-07-03

### Fixed

- **DNS section buttons now functional**: "Тест утечки" (leak test), "Диагностика" (diagnostics), and "Сохранить" (save) buttons in the Web UI DNS section were calling the API but discarding the response — nothing was displayed to the user.
  - **Save**: now sends all 4 fields (`enabled`, `query_strategy`, `remote_servers`, `local_servers`) from the form, previously only sent `enabled` and `query_strategy`. Shows success toast.
  - **Leak test**: results now displayed in a wide modal with a structured table — status badge (OK/leak/warn), split routing state, iptables rule checks, DNS inbound listener, proxy exit IP + location, DNS via proxy vs direct, leak verdict.
  - **Diagnostics**: results now displayed in a wide modal — split routing state, DNS listener port, local DNS query (via Mihomo), direct DNS query (system resolver), Mihomo EC DNS query, proxy trace sample.
- **DNS diagnostics `local_dns` broken on BusyBox**: `run_nslookup` used `nslookup host server#port` syntax (Bind9), but Keenetic BusyBox nslookup doesn't support port at all. Replaced with `dns_query_tcp` — a pure-Rust DNS-over-TCP (RFC 7766) query implementation with no external tool dependencies. Constructs a minimal DNS A-record query (RFC 1035), sends over TCP, parses the response (answer IPs, rcode, answer count). Works on any platform.
  - `build_dns_a_query(name)` — constructs DNS query packet
  - `parse_dns_a_response(resp)` — parses DNS response, extracts A-record IPs
  - `dns_query_tcp(host, port, name)` — ties them together with TCP I/O (3s connect timeout, 5s read timeout)

### Added

- Result modal (`#resultModal`) with `.modal-wide` CSS variant (max-width 680px, scrollable).
- `.result-table`, `.result-badge` (ok/bad/warn), `.result-pre` CSS classes for structured result display.
- `showResultModal(title, html)` / `closeResultModal()` helpers.
- i18n translations for all DNS result labels (RU/EN).
- 6 new tests: `dns_a_query_builds_valid_packet`, `dns_a_query_single_label`, `dns_a_response_parse_ok`, `dns_a_response_parse_nxdomain`, `dns_a_response_parse_too_short`, `dns_query_tcp_connection_refused`.

### Verified

- Local gates: 301 tests, 0 clippy warnings.
- Router E2E on Keenetic Giga: DNS GET returns settings, DNS POST saves all 4 fields, leak test returns `status:"ok"` with proxy exit IP/location, diagnostics returns `local_dns: {ok:true, ips:["198.18.0.10"]}` (Mihomo fake-ip), `direct_dns` via nslookup works, `mihomo_dns_query` via EC API works, proxy trace shows Cloudflare trace.

## v0.15.2 - 2026-07-03

### Added

- **Profile sorting by column click**: 13 sortable columns (Имя, Протокол, Балл, Задержка, Скорость, EWMA, Джиттер, Потери, Ошибки, Cooldown, Транспорт, Адрес). First click — ascending (▲), second — descending (▼). Arrow indicator shown in active header. Null/zero values sorted to end on ascending. Dropdown sort selector delegates to same logic. `getSortValue()` handles `cooldown_until_unix=0` as "no cooldown" (sent to end on ascending).
- **Collapsed group persistence**: profile group collapse state saved to `localStorage` (`hr_collapsed_groups`) — survives page reload. `loadCollapsedGroups()` / `saveCollapsedGroups()` helpers. `collapsedGroups` Set loaded on startup.
- **Favorites table**: replaced text-only favorite list with full `tbl-compact` table matching main profiles table (16 columns: ★, ID, Имя, Протокол, Балл, Действия, Задержка, Скорость, EWMA, Джиттер, Потери, Ошибки, Cooldown, QUIC, Транспорт, Адрес). Select/✎/✕ buttons inline. Removed debug "GET /api/favorites" button.
- **`normalizeProfiles()` merge**: profiles endpoint (has `id`, `block_quic`, friendly group name) merged with stats overlay (latency, score, ewma, failures). Previously preferred stats only, causing `id` to show as `undefined` and group to show raw subscription URL instead of friendly name. `shortGroupName()` shows domain for URL-based groups.
- **Compact profile table CSS**: `.tbl-compact` class with `padding:4px 8px`, `font:12px` (was `padding:8px 12px`, `font:14px`).
- **Traffic/memory live updates**: `loadTrafficMemory()` fetches `/api/traffic` + `/api/mihomo-api/memory` on every 5s refresh, updates 7 DOM elements (`tUp`, `tDown`, `tUpTotal`, `tDownTotal`, `psUp`, `psDown`, `psMem`). Previously cards showed static "12 kbps", "34 kbps", "12 MB".
- **Delay test fix**: `handle_mihomo_api_delay` empty body → `{}` fallback (was "invalid JSON: EOF"). `delayTest()` in UI sends `{}` and shows toast with result.
- **WebDAV wiring**: WebDAV upload/download buttons now read from input fields (`webdavUrl`, `webdavUser`, `webdavPass`) and send JSON body. Previously sent empty POST → "invalid JSON body".
- **`fmtKbps()` helper**: formats kbps → "N kbps" or "N.N Mbps".
- 1 new test: `api_delay_empty_body_uses_defaults`.
- Removed `max-width:1200px` from `.main-content` — table uses full available width.

### Changed

- Profile table column order: ★, ID, Имя, Протокол, **Балл**, **Действия**, Задержка, Скорость, EWMA, Джиттер, Потери, Ошибки, Cooldown, QUIC, Транспорт, **Адрес** (last). Score and action buttons moved near the start so they're visible without horizontal scrolling.
- `.main` restored to `overflow-y:auto` (app-shell layout with internal scroll). `.app` stays `height:100vh;overflow:hidden`.
- Profile group headers show shortened domain name for URL-based groups.

### Verified

- Local gates: `cargo fmt --all`, `cargo check --all-targets --all-features`, `cargo clippy --all-targets --all-features`, `cargo test --all-targets --all-features` (295 tests, 0 clippy warnings).
- Router E2E on Keenetic Giga KN-1012: health, profiles (id/group correct), traffic (live kbps), memory, delay test (50-69ms), collapse persists across page reload, column sort ascending/descending, favorites table with inline select.

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
