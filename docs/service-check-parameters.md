# Service Check Parameters

Local v1.3.13 policy update, dated 2026-09-17, is deployed. All final-version gates passed (685 Rust / 92 browser tests / 131 routes), separately from earlier development evidence; artifact hash agreement, retained complete rollback, router E2E, live four-candidate HTTP 503 preservation, and single-active-profile YT-only success are in [the v1.3.13 record](releases/v1.3.13.md). Separate real desktop/mobile DOM confirmed enabled All/fail-fast controls and YT green/current with TG/AI gray/skipped; intercepted single/global builders never forwarded starts. Four concurrent successful router transfers remain unverified. v1.3.12 and all historical evidence are unchanged. This documentation finalization performs no commands, router operations, credential handling, or clock/power action; GitHub commit/push/publication remain pending and unauthorized.

## Shared Parameters

Every Check Services action retains its scope and sends the chosen service prefix and failure policy explicitly:

- YT: channel identity and three decoded previews only; Telegram/AI are unrequested.
- YT+TG: YouTube availability followed by Telegram media.
- YT+TG+AI or All: all three services, with the existing ping evidence.
- Stop after YT/TG failure: skip later selected services after a failed prerequisite. Unchecked services are not reported as failures.
- **Full Ping check**: browser-persisted, default off. Ordinary availability
  checks now use one HTTPS HEAD request through the candidate's isolated Mihomo
  by default. ICMP and direct TCP are skipped with zero attempts, without DNS
  resolution or connection timeouts for those probes. Enable the switch to
  restore ICMP, TCP and proxy HTTPS diagnostics. The same temporary core is reused
  for selected services. Native Quick/Full compatibility checks retain their
  existing three-probe behavior; advanced Find N retains its existing minimal
  HTTPS preflight regardless of this switch.
- **Reject servers without Ping**: optional, browser-persisted, default off.
  When enabled, the selected Ping mode runs first. If none of its probes
  responds, all selected service checks are skipped with zero
  attempts and the candidate fails on Ping. Any successful Ping permits the
  selected service prefix; ICMP failure alone does not reject it. This applies
  to every ordinary scope and prefix independently of the YT/TG failure toggle.
  Find N already requires its isolated HTTPS preflight before service checks;
  it retains this stricter existing gate with either switch position.
  No automatic Dead Servers movement or native playback evidence is added.

All and the failure toggle are selectable in both ordinary and advanced modes. Existing browser choices are retained. A fresh browser defaults to All with continued checking.

Ordinary actions process their whole selected scope, without an adaptive preflight gate. The separate advanced global Find N action alone applies the candidate target and early stop. Neither path changes routing, active selection, promotion, or Dead Servers automatically.

## Workers

An ordinary explicit-policy request requires the selected worker count, bounded by candidate count. Four workers for four or more candidates either starts with four effective workers or returns HTTP 503 explaining the smaller memory budget. It does not silently start with fewer workers. Checking one server uses one worker, not four duplicate tests.

Availability workers now use an 80 MiB reserve plus an estimated **16 MiB
incremental memory per worker** for up to three workers: three require 128 MiB
available. Requests above three retain the conservative 48 MiB/worker estimate.
Executable/shared library pages are shared with the main Mihomo and must not be
counted as private RSS for every worker. Private cores use `GOMEMLIMIT=16MiB` and
`GOGC=20`; this is a soft Go runtime budget, not a hard RSS ceiling. Native and
speed diagnostics retain the older 48 MiB/worker admission estimate. Unknown or
zero budgets reject. Availability jobs sample MemAvailable every 100 ms and
cancel/reap their owned children if it falls below the 80 MiB reserve (or cannot
be read). Status exposes `memory_pressure`, and UI identifies this stop reason.
This monitoring reacts to pressure; it cannot promise a hard instantaneous
reserve in the presence of unrelated traffic or sudden allocations.

Channel/preview checks run independently across admitted workers, with private
cores, captures and unchanged decoder limits for each candidate. HTML is dropped
before preview decoding. Completed/cancelled candidates reap their temporary
cores before deleting private files and call glibc `malloc_trim` outside state
locks to return freed daemon heap pages promptly; the end of the job trims again
after workers join. Live result/history objects remain intentionally retained.
File cache remains reclaimable by Linux rather than being globally purged.
Legacy native Innertube probes and the shared Telegram session remain serialized.

Advanced Find N retains memory-bounded workers and limits admitted candidates by the remaining target. Requesting four with a target of one still admits one candidate at a time.

## API

```json
{
  "method": "availability_full",
  "profile_ids": [0, 1, 2, 3],
  "concurrency": 4,
  "test_download": false,
  "test_upload": false,
  "service_checks": {
    "required_services": "youtube",
    "fail_fast": false
  }
}
```

`service_checks` is optional, accepts either availability method, and is mutually exclusive with `search`. `required_services` and `fail_fast` are required when provided; optional booleans `reject_no_ping` and `full_ping` default to false. Unknown fields and invalid values reject. Missing/null preserves the method's service selection defaults and uses minimal Ping for availability. Native Quick/Full API behavior and native resource contract 7 remain separate from thumbnail contract 1.

Include `"full_ping": true` in `service_checks` to restore the complete Ping
diagnostics. Omitted/false means one proxy HTTPS sample, with the existing
six-second request timeout and private-core readiness/cancellation guards.
Successful ICMP/TCP cannot authorize a candidate in minimal mode because neither
probe runs. With rejection enabled, failed proxy HTTPS skips the requested
services; with rejection disabled, service checks still run as requested.
Removing the two direct probes saves their waiting time; it does not shorten
YT/TG/AI work or lift the router's worker/memory bounds.

To enable early Ping rejection, include `"reject_no_ping": true` in
`service_checks`. The service indicators remain skipped/not tested rather than
displaying a fabricated YT/TG/AI failure. Saved historical policy objects without
this property keep continued service checking.

Advanced availability search accepts `required_services: "all"` and an explicit boolean `fail_fast`. Omitting search failure policy retains the previous fail-fast default. Unrequested/skipped resources retain zero attempts; thumbnail results never become native playback or generic health evidence.

## Local Verification

All pre-version development gates passed: formatting, all-target/all-feature check, both Clippy configurations with warnings denied, 685 Rust tests, 92 browser tests, frontend contract (131 routes), installer contract, and diff check. Logs: `/tmp/opencode/service-final-*.log`. Separately, all final v1.3.13 gates passed with 685 Rust / 92 browser tests / 131 routes, installer, formatting, check, both Clippy configurations with `-D warnings`, and diff check. Final logs: `/tmp/opencode/v1313-{fmt,check,clippy-router,clippy-all,tests,frontend,installer,browser,diff-check,build}.log`.

Browser fixtures cover exact four-worker admission, insufficient/unknown memory rejection before replacing a job, shared policy persistence, scopes, and skipped-service colors. The four-thread local SOCKS-failure regression verifies native playback mutex independence, not successful concurrent router transfers. Development verification previously stopped at unavailable SSH authentication; restored access superseded that blocker before the separately completed deployment. No commands or router/native/power operations occur in this documentation finalization.

The live four-candidate ordinary YT/no-fail-fast request with concurrency four returned HTTP 503 before reservation (`memory_gate: false`, `memory_permits: 3`, `requested: 4`); five prior job metadata fields and idle status were preserved. The final single `[88]` request used the same policy/concurrency, admitted exactly one for one candidate, completed one with search null/no preflight, and passed real channel/three-preview checking. This is candidate-count bounding, not silently reducing four-candidate work to a memory budget. TG/AI were unrequested with zero attempts/successes; native YouTube was absent. Live All/TG/AI positives, dynamic fail-fast sequences, backend acceptance across all scopes, four admitted positive workers, peak/continuous memory, cancellation under load, and reboot persistence remain unverified. v1.3.12's all-service pass is historical, not reused v1.3.13 evidence.

Separate deployed-page audit (`/tmp/opencode/v1313-live-ui.mjs`, `/tmp/opencode/v1313-live-ui.log`) confirmed ordinary/advanced All and fail-fast enabled, target 5/max 20 in advanced Find N, label toggling only browser/localStorage state, current YT green with skipped TG/AI gray, closed details, and no sidebar technical nodes/mobile overflow/JS errors. Single YT/false and ordinary global All/true builders captured concurrency four, `availability_full`, explicit `service_checks`, and no search. Both received intercepted mock 503; zero mutations reached the router, presentation stayed unchanged, and an invalid scoped/advanced combination did not post. These are frontend-builder checks on a real page, not newly accepted backend tests or a live All/fail-fast service sequence.

## Ping rejection deployment, 2026-10-02

User-authorized local patched v1.3.35 build installed through `S99hincyray`.
Local/staged/installed ARM64 SHA256:
`2b261f7bf7bd6eedb806460d155a1628bede4a8636fef79e259dda720b3be04d`.
Complete six-file post-stop rollback (including the preceding memory-cleanup
build): `/opt/etc/hincyray/rollback-ping-gate-20261002-224657-19528`.

Final gates passed: fmt/check, both Clippy configurations, 728 Rust tests,
126 browser tests, 140 frontend routes, installer lifecycle and diff check.
Logs: `/tmp/opencode/ping-gate-*.log`.

Live health/core/firewall, DNS DNAT 1053, TCP REDIRECT 10810, UDP TPROXY 10811,
table 111, canonical fail-closed selector, REJECT-first pool and router E2E
passed. Active 88, 390 profiles, 47 rules and enabled 16-member pool remained;
checked durable state projection and exact quality history/private bot/automation
settings matched the rollback snapshot. State/config modes were 0600, stage
absent and memory warnings empty (RSS 87704 KiB, available 165384 KiB).

The live OpenAPI exposes boolean `reject_no_ping`. Empty-scope requests for all
four prefixes passed policy parsing and returned the expected scope HTTP 400
without starting jobs. A fresh isolated browser verified the deployed checkbox,
browser persistence, four request builders with Ping rejection on and service
fail-fast off, no mobile overflow and zero JS errors. All four starts were
intercepted; zero network benchmarks were forwarded. Actual dead-server early
skipping is regression-tested locally, not claimed as a new live measurement.
Live UI proof: `/tmp/opencode/ping-gate-live-ui.log`; deployment proof:
`/tmp/opencode/ping-gate-deploy-final.log`.

The preliminary verification expected the wrong empty-scope error text and
triggered a complete SHA256-verified rollback before successful retry. No
release publication or Git operation was performed.

## Minimal Ping local update, 2026-10-02

Ordinary availability checks default to proxy HTTPS only. The new Full Ping
slider restores the three-probe diagnostics and persists independently of Ping
rejection and service fail-fast. All ordinary scope builders share this policy;
advanced Find N keeps its separate minimal preflight contract.

Final local gates passed: fmt/check, both Clippy configurations, 731 Rust tests,
127 browser tests, 140 frontend routes, installer lifecycle and diff check.
Logs: `/tmp/opencode/minimal-ping-*.log`. Regressions verify that minimal mode
never invokes ICMP/TCP, skipped probes contribute no attempted samples, complete
mode invokes both probes, cancellation prevents the next probe, omitted API
policy uses minimal availability Ping, and the switch persists across reloads.
Both modes are exercised by shared request builders across ordinary scopes.

This update is locally verified; it has not been deployed to the router or
measured against a live 150-server subscription. The preceding deployed build
and rollback evidence above remain historical facts.

## Three-worker deployment, 2026-10-02

User-authorized patched v1.3.35 now includes minimal Ping and economical
availability workers. ARM64 SHA256 agrees locally/staged/installed:
`eb22a659c292a22b6cc79705ba3d3260325815531934437868e2251e1dbc230f`.
Complete six-file post-stop rollback:
`/opt/etc/hincyray/rollback-three-workers-20261002-233052-29410`.

Final gates: fmt/check, both Clippy configurations, 733 Rust tests, 127 browser
tests, 140 frontend routes, installer lifecycle and diff check. Logs:
`/tmp/opencode/three-worker-*.log`. The spawned-core regression checks Go budget
environment and survival after a short caller thread exits; another regression
forces reserve cancellation and verifies worker join without completion actions.

Live `[88,134,136]` YT-only request admitted exactly three workers. Samples saw
four actual Mihomo processes (main plus three private cores); all three passed
proxy HTTPS and real MrBeast channel/three decoded previews, with zero-attempt
ICMP/TCP/TG/AI. Minimum sampled MemAvailable: 139172 KiB. Before/after available
memory: 171876/182820 KiB; HincyRay RSS: 32884/20724 KiB. Immediately after job
completion only the main core remained. These HTTPS times are not game RTT.

A separate All-services request was cancelled while three private cores were
alive. All three exact PIDs disappeared, their exact private home directories
were removed, and status became stopped with zero completed candidates. Available
memory was 174792 KiB before, 148172 during and 174732 immediately after the stop;
HincyRay RSS was 21140/20896 KiB before/after. No global cache purge or restart of
the main core was used for either test.

Health/core/firewall, fail-closed selector/pool, DNS/REDIRECT/TPROXY/table 111 and
router E2E passed. Active 88, 390 profiles, 47 rules and enabled pool preserved;
durable projection/private settings matched, with intentional diagnostic history
updates. Memory warnings were empty and stage absent. Read-only live browser
audit verified minimal default, full-mode persistence, concurrency-three builders,
no mobile overflow/JS errors; both starts intercepted (none forwarded).

Proof: `/tmp/opencode/three-worker-deploy-final.log`,
`/tmp/opencode/three-worker-cancel.log`, `/tmp/opencode/three-worker-live-ui.log`;
router bounded samples: `/tmp/hincyray-three-workers-proof` and
`/tmp/hincyray-three-workers-cancel`. A preliminary BusyBox fractional-sleep
verification error triggered a complete verified rollback before successful retry.
Full 150-server sustained scanning, three simultaneous All-service successes,
and intentional live reserve exhaustion were not reproduced. The earlier
local-only minimal-Ping status is superseded by this deployment.
