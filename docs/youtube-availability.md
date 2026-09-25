# YouTube Availability

Current local v1.3.13, dated 2026-09-17, is deployed: final gates (685 Rust / 92 browser tests / 131 frontend routes), SHA/rollback, router E2E, actual four-candidate HTTP 503 preservation, and a single-active-88 YT-only preview pass are in [its record](releases/v1.3.13.md). [Shared service parameters](service-check-parameters.md) are the current ordinary-scope policy: `availability_full` with explicit ordered prefix/fail-fast, no search/preflight; only advanced global Find N has a target. Actual desktop/mobile DOM confirmed enabled controls, green/current YT and gray/skipped TG/AI; intercepted builder starts were not forwarded. Four successful concurrent router transfers, new All/TG/AI positives, and live fail-fast service sequences remain unverified. The retained method/history notes below and all v1.3.12 (674 Rust / 88 browser tests) and older evidence remain unchanged; native contract 7 and thumbnail contract 1 stay separate. GitHub publication/download availability remain pending and unauthorized.

## User Search

Every user-facing search action now uses the same YouTube availability check:

- Fetch `https://www.youtube.com/@MrBeast` through the candidate's isolated Mihomo/SOCKS core.
- Confirm the public channel identity from the page's structured data.
- Extract previews for three distinct videos, excluding avatars and channel images.
- Fetch and decode all three images successfully.

There is no YouTube login, saved cookie session, Innertube request, JavaScript execution, or video download in this check. No alternate YouTube method is offered. All/global, subscription, group, single, favorite, selected, and explicit Dead Servers Check Services actions use `availability_full`, omit `search`, and attempt YouTube/Telegram/AI without a generic preflight gate, regardless of stored global Find N target/prefix/fail-fast values. Advanced parameters are opt-in and global-only; Find N retains its prefix, preflight, and early-stop behavior. Scope boundaries remain separate.

Success means **the channel page and video previews are accessible**. It does not claim video playback or Google-account access.

## Bounds

- Channel HTML: 2 MiB, 20 seconds, 5-second connection timeout.
- Each preview: 128 KiB, 8 seconds, 5-second connection timeout.
- Preview URLs: HTTPS on `i.ytimg.com`, port 443, matching video ID/path, no credentials or redirects.
- Decoding: JPEG, PNG, or WebP; dimensions at most 1024 pixels, allocation limit 16 MiB.
- YouTube work remains serialized. Temporary cores and curl cancellation/reaping are unchanged. Startup memory admission estimates an 80 MiB router reserve and 48 MiB per worker; unknown/zero worker budgets reject with HTTP 503. This is not a continuous reserve guarantee or concurrent YouTube-probe promise.

Incomplete pages, consent/challenge pages, unsupported layouts, and invalid images never qualify as successful preview access. Diagnostics are categorical; raw HTML and URL payloads are not exposed.

## Evidence And Compatibility

Availability evidence uses `youtube_thumbnails`, contract **1**. New API methods are `availability_quick` and `availability_full`; adaptive results use `search_availability`. These are the only methods sent by the search UI.

Existing `quick`/`full` API behavior and native contract **7** are retained for the shipped API and persisted history, not called by the new user search. Native playback still requires real video transfer and is never inferred from thumbnails. Old native evidence cannot become a preview pass, and preview evidence cannot become a native pass.

Availability results persist diagnostic resources, not generic health metrics or an overall native Quick/Full pass. Native promotion, automatic Dead Servers movement, and AutoSelect do not run for availability searches, including completed scopes. Their saved compatibility settings remain separate; explicit manual selection/movement/restoration is unchanged.

Explicit Check Services actions use `availability_full` for continued complete checks. Opt-in advanced global search retains availability Quick/Full policy and `search_availability` discovery results; it does not change explicit-action semantics. Browser compatibility help/controls explain separate native API/history, not an alternate YouTube method. Saved native post-action settings remain intact but do not apply to availability. Do not update generic EWMA health from page/image evidence.

## Indicators And Diagnostics

Header/table/profile lightning actions consistently mean Check Services for the whole chosen scope, including favorites and explicit dead diagnostics. Explicit actions continue all three checks; Find N is a separate opt-in advanced global button with collapsed parameters. Current conclusive attempts render red/green, unknown remains amber, and gray means stale/no-attempt/skipped, not an implicit failure/pass. Native contract-7/contract-6 results are not silently converted into contract-1 previews. Fixed indicators and canonical-ref/exact-ID matching remain.

Technical explanations live in collapsed Profiles check details rather than the sidebar. Sidebar activity shows the operation name/count, Stop, and animation only; advanced parameter/checkbox labels describe their global-only scope.

Fresh results overlay after profile loading only when public canonical `srv-v2` lifecycle `server_ref` and exact profile ID both match. Service freshness uses independent public `last_service_test_unix`; generic health/traffic activity cannot make old service evidence fresh. Status exposes the canonical ref, never private raw identity. Unrequested/skipped or preflight-rejected services are not silently rendered as current failures.

Current service evidence uses a six-hour freshness window with 60-second future-time tolerance; a zero timestamp is not-tested, not newly healthy. Exact-ID/ref overlay and the scope request matrix passed fixture tests. Read-only Chromium loaded the real router UI and verified active-88 green and existing-431 red YT/TG/AI indicators, collapsed details, no sidebar technical nodes, no mobile overflow, and zero JavaScript errors. No live lightning button was clicked, so live DOM observation is separate from fixture request-transport evidence.

Private temporary-core warning logs contribute only fixed-category diagnostics from a bounded 64 KiB tail, without raw addresses or log output. The original HTTP/curl error is preserved and categorical upstream deadline evidence is appended: TLS EOF before a service check is transport evidence, not a tested YouTube failure. Protocol, SNI, certificate verification, and timeouts are not changed without proof.

Sampled 5-second deadlines on WebSocket/TLS, gRPC/Reality, and Hysteria2 candidates do not identify a credential/server/network cause; even an established owned TCP socket does not prove a completed proxy stream. Profile 93's fresh reparse produced byte-identical config, with no observed persisted-field loss. The original 335 preflight rejects mean services untested, not 335 proven false failures, dead servers, or a claim that only one server works.

## Verification

The historical isolated ten-endpoint experiment confirmed the channel and three decoded previews through one endpoint. The other nine timed out without proving they were dead. Its successful case transferred about 1.37 MiB of HTML/images; that is not a measurement of the release's production test, a byte-cost comparison, or a quantitative speedup.

All final-version v1.3.12 gates passed: 674 Rust tests, 88 browser tests, 131 frontend routes, formatting/check/both Clippy/installer/diff gates. Historical v1.3.11 and older results remain separate and unchanged. The minimal first-alias Trash-list lookup fix also preserves restorable legacy orphans; live `/api/trash` succeeded within five seconds with 519 entries.

Pre-update v1.3.11 direct `availability_full` diagnostics of profile 431 (Obhod 10, old aliases 93/100) omitted `search` and attempted each service once: YouTube `transport_error`, Telegram read 0 bytes, AI curl 28 timeout. All were conclusive failures. Positive endpoint TCP did not establish proxy HTTPS forwarding, which reached curl 35/HTTP 000/TLS EOF. The primary was not alive while its pinned group used active-88 fallback. The old single-click Find N target-5 path returned no results without testing YouTube; gray then meant no attempt, not success. Primary forwarding remains unrepaired, with no established builder-loss/protocol/provider/network cause or parameter guess.

The deployed v1.3.12 controlled active-88 `availability_full` request omitted `search`, requested one worker, and passed all three services: one attempt/success each, stable true and inconclusive false. YouTube confirmed MrBeast identity and three actually decoded previews (`youtube_thumbnails`, contract 1), Telegram passed authorized media (contract 7), and AI passed ipregion region checking (contract 7); all three ping checks also passed. Result timestamp `1789627115` and public lifecycle ref matched stats service epoch. No native YouTube video, dummy HTTP-200 substitute, or automatic native quality/Dead Servers/AutoSelect action was used. Desired routing/settings and durable active/ID/order/dead/promoted projections compared unchanged; expected resource/stats/cursor/traffic changes are not byte-identical state isolation.

During the historical verified v1.3.11 deployment, profile 93 was tested first: one rejected TLS preflight, no service test/result, terminal `exhausted`; curl 35/HTTP 0/EOF was preserved and fixed `[deadline_exceeded]` appended from the owned core warning tail without raw logs/addresses. Active profile 88 was tested last: one admitted preflight and availability completion, one good result, `target_reached`, summary passed 1. Contract-1 MrBeast identity plus three distinct decoded previews passed; native video was not checked and Telegram/AI attempts were zero. Public canonical `server_ref` matched current profile 88, and a separate stats GET had `last_service_test_unix` equal to the positive result's fresh timestamp (>0).

In that deployment, profile projections, provenance, order/dead membership, and pinned/device routing intent compared unchanged. Other profiles' service/resource timestamps stayed unchanged; accounting/search bookkeeping may change, so this is not full-state byte isolation. No native quality/Dead Servers/AutoSelect action was triggered. That deployment ended with the positive profile-88 result; this is historical page/preview evidence, not native playback or proof that other candidates fail YouTube.

The historical v1.3.10 production `availability_quick` on active profile 88 requested one worker, target 1, YouTube prefix. One candidate/preflight/availability-stage completion, zero preflight rejects, and one good result ended `target_reached` without cancellation; summary passed/failed/unknown was 1/0/0. The `search_availability` result contained `youtube_thumbnails` contract 1, one attempt/success, reachable/stable true, inconclusive false, and no error. The actual production parser confirmed MrBeast identity plus three distinct decoded previews; no native YouTube resource was emitted, Telegram/AI attempts were zero, and no raw connection identity was serialized.

In that v1.3.10 test, active identity, server ref, profile order, and Dead Servers projections compared unchanged. Resources/stats/search cursor and background traffic accounting may change as expected; this is not a full-state byte-isolation claim or generic EWMA/native-health evidence. Raw image buffers remain private/ephemeral; historical logs and limitations remain in its release record. Clock/NTP were unchanged by v1.3.11/v1.3.12, and historical v1.3.9 chronology remains intact. Reboot persistence, live cancellation under load, memory-pressure/unknown-budget HTTP 503, load behavior, and service coverage on other profiles remain unverified; Telegram/AI were live-tested on active 88 in v1.3.12. Preview success still does not prove playback.
