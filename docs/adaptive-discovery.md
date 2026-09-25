# Unified Search and Adaptive Discovery

Current local v1.3.13, dated 2026-09-17, is deployed, with final gates (685 Rust / 92 browser tests / 131 frontend routes), SHA/rollback, router E2E, live four-candidate HTTP 503 preservation, and single-active-88 YT-only success in [its record](releases/v1.3.13.md). [Shared service parameters](service-check-parameters.md) govern ordinary `availability_full` prefix/fail-fast checks without search/preflight. Find N target remains exclusive to the separate explicit advanced global action; retained discovery policy/history below is not the ordinary-action default. Actual desktop/mobile DOM confirmed enabled ordinary/advanced All/fail-fast, advanced target 5/max 20, and YT current/TG-AI skipped; intercepted builders did not start router jobs. Four positive concurrent router transfers, new All/TG/AI positives, and live fail-fast service sequences remain unverified. All v1.3.12 (674 Rust / 88 browser tests) and older evidence is unchanged; native contract-7 API/history stays separate. GitHub publication/download availability remain pending and unauthorized.

## Usage

Global, selected, subscription, group, and single-profile actions use one shared parameter set and start flow. Stop mode, target, service prefix, failure policy, and requested concurrency are stored in the browser, not as per-scope daemon settings.

**Complete scope** (`complete_scope`) visits the eligible scope using YouTube channel/previews plus Telegram/AI Studio. Choose short-circuit after YouTube/Telegram failure (`availability_quick`) or continue subsequent service checks (`availability_full`). Complete scope does not enable a find-N target or a prefix-only service selection. This shared action disables download/upload speed stages; it does not introduce arbitrary service subsets or an alternate YouTube verification method.

**Find N** (`find_n`) stops after a target from 1 to 20 has passed the required service prefix:

- YouTube (default).
- YouTube + Telegram.
- YouTube + Telegram + AI Studio.

Telegram requires the existing authorized probe session. Find N uses bounded availability Quick discovery, including the YouTube+Telegram+AI Studio prefix. Prefix-only complete-scope checking and an independent continue-after-failure discovery policy are not offered. Availability searches, including completed scopes, never select an active server automatically or run native promotion, automatic Dead Servers, or AutoSelect. Legacy native `quick`/`full` API post-action settings remain separate for shipped compatibility, not an old mode in the user search UI.

Automatic/global/subscription scopes exclude Dead Servers; find N excludes them even in explicit selections. Explicit single/bulk Dead Servers diagnostics always use complete scope, overriding a browser find-N preference, and may include dead profiles. Selecting complete scope does not by itself classify failures as dead or change provenance.

## Execution

The following preflight, ordering, and target rules apply to find-N discovery, not to complete-scope availability checks:

Each candidate first runs a bounded HTTPS request through its real proxy protocol in an isolated temporary Mihomo. Any completed request with HTTP status 200-599 demonstrates transport reachability, even if the endpoint rejects the client; it is neither a channel/preview pass nor YouTube playback. An unsuccessful preflight retries once on an alternate domain through the same isolated core. Rejected preflights skip requested service checks and produce no persisted health/Dead Servers penalty. Admitted candidates reuse that core for requested availability checks. Direct ICMP/TCP probes remain explicitly unrequested, avoiding a TCP-only gate for UDP transports.

Search stops admitting candidates after finding the requested number of unique lifecycle identities. In-flight work is bounded by both the remaining target and existing router memory/concurrency limits. Workers wait when remaining target slots are temporarily occupied; they do not permanently retire and can resume as failed/rejected candidates release slots. Target completion is not cancellation. Exhaustion with fewer usable servers is a valid outcome.

Current-contract service history younger than six hours changes candidate priority only; every counted server must pass a new measurement. General TCP timestamps do not refresh service evidence. Canonical aliases are deduplicated; endpoint/provenance buckets are interleaved. Persisted rotating exploration makes later searches gradually inspect unknown candidates, including candidates previously rejected at preflight. There is no unattended background testing loop.

The serving Mihomo, routing, DNS and firewall are unchanged. Cancellation continues to kill/reap benchmark-owned children. The private temporary core home, configuration, and log remain available until the child is reaped; temporary cores are not kept permanently in RAM. Status retains at most the last 20 preflight diagnostics with structurally redacted errors bounded to 2 KiB, not raw credentials or private core files.

## YouTube Outcomes

User search uses `youtube_thumbnails` contract 1: MrBeast channel identity plus three distinct decoded previews, not Innertube/video/cookie/JavaScript/authentication. The production target-1 search on active profile 88 reached its target with one contract-1 pass and no cancellation; active identity/order/dead projections stayed unchanged. Resource/search bookkeeping and background traffic accounting may change. This proves only page/preview access on one profile, not native playback or generic EWMA/Mihomo health; see [bounds and separation](youtube-availability.md).

### Native Compatibility

The separate legacy native API/history uses resource contract 7 and direct VISIONOS Innertube without mandatory web watch/bootstrap or a JavaScript runtime. Only successful media transfer with video MIME and at least 16 KiB of actual bytes can pass. Player metadata, HTTP reachability, previews, and zero-byte media responses cannot prove playback. This is not the current user search method.

Bot/login refusal such as `LOGIN_REQUIRED`, HTTP 429, and HTTP client-compatibility refusals are inconclusive: neither a server failure nor a pass. The UI renders unknown in amber; summaries preserve unknown rather than counting it as false failure or a stale legacy success. Unknown evidence cannot cause promotion, Dead Servers movement, or AutoSelect, and unknown history stays unknown. The serde-defaulted `inconclusive` field permits older saved structures; contract-6 resource evidence is stale and cannot become a current success.

The old ANDROID_VR 1.65.10 client is obsolete; upstream reports described format HTTP 403 from 2026-08-17. Direct VISIONOS and VR research through the serving SOCKS route both returned `LOGIN_REQUIRED` and zero actual media bytes. A configured primary pin does not prove which upstream an earlier HTTP request used: later loaded observations showed pinned aliases 93/100 not alive and fallback selecting `proxy-active` on active profile 88. No successful anonymous direct media method has been demonstrated. The v1.3.9 native patch improved gating and outcome honesty, not proven playback availability; v1.3.10 adds separate preview evidence, not a native pass. No authentication cookies/sessions, request workarounds, captcha, JavaScript, or yt-dlp runtime are added.

## Concurrency and Memory

Requested server workers remain bounded to 1-6. Temporary-core startup admission uses an 80 MiB router reserve and a 48 MiB per-worker estimate from available memory. A known budget permitting zero workers or an unknown available-memory budget rejects the start with HTTP 503 rather than forcing one worker.

This guard is a startup estimate, not continuous memory monitoring or a guarantee that 80 MiB stays free throughout the run. Other processes and actual core/probe allocations can change memory use after admission. YouTube availability remains serialized, the separate native probe retains its serialized boundary, and Telegram serializes its one private session: four requested server workers are not four simultaneous YouTube or Telegram checks.

Status separates the requested count, effective worker capacity, active work, and current admission limit. `memory_cap` explains startup capacity reduction, `candidate_count` explains a smaller eligible scope, and `target_slots` explains remaining discovery slots. An active count below the request is not by itself worker loss or a claim of native-probe parallelism.

## API

The shared UI modes translate to availability API methods; `stop_mode` and the browser failure-policy control are not request fields. Complete scope sends `method: "availability_quick"` for short-circuit or `method: "availability_full"` for continue, omits `search`, and disables download/upload. Find N sends:

```json
{
  "method": "availability_quick",
  "search": {"target_good": 5, "required_services": "youtube"},
  "concurrency": 3,
  "test_download": false,
  "test_upload": false
}
```

Send to `POST /api/bench/start`. Optionally add `subscription_url` or `profile_ids`, never both. Search excludes Dead Servers even in explicit selections. Nested search options reject unknown fields. `search: null` is ordinary exhaustive testing, not discovery.

Start responses include `requested_concurrency` and effective `concurrency`. `GET /api/bench/status` includes `concurrency_status` with `requested`, `effective`, `active`, `admission_limit`, and `limit_reasons` (`memory_cap`, `candidate_count`, `target_slots`). Complete-scope status has no discovery target.

`GET /api/bench/status` includes nullable `search` progress: `found_good`, `target_good`, `required_services`, `preflight_completed`, `preflight_rejected`, `quick_completed`, and terminal `finish_reason` (`target_reached`, `exhausted`, `cancelled`). `total` is the number of deduplicated eligible candidates; `completed` includes preflight rejects and may remain below `total` on early success.

Availability discovery results have `method: "search_availability"`; `success` describes the requested availability prefix, not an exhaustive native Quick pass or playback. An inconclusive required service does not count toward `found_good`; unrequested services have zero attempts. Resource diagnostics persist without generic EWMA health or overall native Quick/Full success, and cannot consume stale/unknown native evidence as a preview pass. Untested/preflight-rejected profiles are not marked failed or dead. Status omits raw connection credentials, redacts diagnostic strings, and excludes results whose identity no longer resolves to the displayed profile ID.

## Other Hardening

- Persistent Linux Mihomo spawning uses a bounded owner thread so creator HTTP-thread exit does not deliver `PDEATHSIG`; actual child ownership and daemon-death cleanup remain intact. Caller-exit and rollback regressions passed 10 iterations each. The owner adds one baseline daemon thread, not an optional application runtime.
- Login-throttling overflow retains existing blocks instead of clearing the source table.
- Unavailable/malformed local controller state is inconclusive upstream evidence. It resets the consecutive-failure streak without penalizing the active profile or initiating failover. Valid Mihomo fallback observations remain the health authority; no duplicate periodic upstream probes were added.
- Delayed navigation focus does not steal focus from a discovery input on the next animation frame.

## Limits

Historical v1.3.8 controlled YouTube searches used three canonical candidates and four requested workers. Target 3 admitted three effective workers, reached peak active work of three, and exhausted the scope with one reported good server. Target 1 retained three effective workers but intentionally bounded peak active work to one, reached the target, and left one candidate untested. Active identity, profile order, and Dead Servers membership stayed unchanged. These are contract-6-era observations, not v1.3.9 playback evidence; counters, limit reasons, and logs remain in [the unchanged v1.3.8 record](releases/v1.3.8.md).

Those traces demonstrate historical admission and early stopping, not failed-reservation worker retention or parallel YouTube probes. The later search snapshot of 337 eligible / 336 completed / 335 preflight rejected / one native test cannot establish the health of all rejected candidates. Browser routing is not interchangeable with isolated-profile diagnostics, and a static pin does not establish an earlier request's actual chain.

Live v1.3.9 searches of profiles 88/93 requested two workers and target 2 YouTube: two candidates completed, two preflights completed, one rejected, one native test completed, zero good servers, and terminal `exhausted` without cancellation. Profile 88 was reachable but YouTube returned bot `LOGIN_REQUIRED`, contract-7 unknown with zero successes; summary passed/failed/inconclusive was 0/0/1. Profile 93 failed both-domain TLS preflight (curl 35, HTTP 000, EOF), so no native result was assigned. Its actual transport is VLESS WebSocket/TLS, not gRPC; the EOF cause is unproven. Telegram/AI attempts were zero, no raw connection identity was exposed, and active/order/dead projections stayed unchanged.

The user-authorized manual clock correction aligned router/local UTC; initial 17:23 UTC checks remained unsynchronized with manual user time. A repeated search had the same counters and unknown summary; profile 88 first timed out (curl 28/HTTP 0), then returned bot refusal, while profile 93 retained both-domain EOF. Router E2E passed again. Independent 17:34 UTC checks subsequently confirmed automatic NTP synchronization twice: `accurate=yes`, `synchronized=yes`, `usertime=no`, server `pool.ntp.org`, router 17:34:19 UTC versus host 17:34:20 UTC. Both added servers remain present in current native configuration. No causal explanation for initial failure/later synchronization or playback outcome is established, and no additional media request was made by that audit. No system-wide configuration save was performed; reboot persistence remains unverified. Full chronology and evidence are in the release record.

Live cancellation under load, low-memory/unknown-budget HTTP 503, and Telegram/AI combinations were not exercised. No quantitative wall-clock speedup, causal explanation for all original rejects, or successful anonymous media playback is claimed.

This reduces unnecessary work; it does not make an exhaustive all-service test free. YouTube and Telegram retain their serialized native probe boundaries. A failed measurement endpoint can reject otherwise useful proxies, so preflight rejection never becomes durable Dead Servers evidence. Shared persistent test-core reuse, continuous QoE switching and wholesale Hydrat architecture replacement are intentionally excluded.
