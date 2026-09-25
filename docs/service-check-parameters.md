# Service Check Parameters

Local v1.3.13 policy update, dated 2026-09-17, is deployed. All final-version gates passed (685 Rust / 92 browser tests / 131 routes), separately from earlier development evidence; artifact hash agreement, retained complete rollback, router E2E, live four-candidate HTTP 503 preservation, and single-active-profile YT-only success are in [the v1.3.13 record](releases/v1.3.13.md). Separate real desktop/mobile DOM confirmed enabled All/fail-fast controls and YT green/current with TG/AI gray/skipped; intercepted single/global builders never forwarded starts. Four concurrent successful router transfers remain unverified. v1.3.12 and all historical evidence are unchanged. This documentation finalization performs no commands, router operations, credential handling, or clock/power action; GitHub commit/push/publication remain pending and unauthorized.

## Shared Parameters

Every Check Services action retains its scope and sends the chosen service prefix and failure policy explicitly:

- YT: channel identity and three decoded previews only; Telegram/AI are unrequested.
- YT+TG: YouTube availability followed by Telegram media.
- YT+TG+AI or All: all three services, with the existing ping evidence.
- Stop after YT/TG failure: skip later selected services after a failed prerequisite. Unchecked services are not reported as failures.

All and the failure toggle are selectable in both ordinary and advanced modes. Existing browser choices are retained. A fresh browser defaults to All with continued checking.

Ordinary actions process their whole selected scope, without an adaptive preflight gate. The separate advanced global Find N action alone applies the candidate target and early stop. Neither path changes routing, active selection, promotion, or Dead Servers automatically.

## Workers

An ordinary explicit-policy request requires the selected worker count, bounded by candidate count. Four workers for four or more candidates either starts with four effective workers or returns HTTP 503 explaining the smaller memory budget. It does not silently start with fewer workers. Checking one server uses one worker, not four duplicate tests.

The 80 MiB reserve and 48 MiB per temporary core remain unchanged. Four workers require an estimated 272 MiB available at admission. Unknown or zero budgets reject. This is a startup estimate, not a continuous reserve guarantee.

Channel/preview checks run independently across admitted workers, with private cores, captures and decoder limits for each candidate. They no longer wait for the native YouTube playback mutex. Legacy native Innertube probes and the shared Telegram session remain serialized. Four concurrent successful thumbnail transfers and peak memory consumption still need live router validation.

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

`service_checks` is optional, accepts either availability method, and is mutually exclusive with `search`. Its two fields are required when provided; unknown fields and invalid values reject. Missing/null preserves the shipped method defaults. Native Quick/Full API behavior and native resource contract 7 remain separate from thumbnail contract 1.

Advanced availability search accepts `required_services: "all"` and an explicit boolean `fail_fast`. Omitting search failure policy retains the previous fail-fast default. Unrequested/skipped resources retain zero attempts; thumbnail results never become native playback or generic health evidence.

## Local Verification

All pre-version development gates passed: formatting, all-target/all-feature check, both Clippy configurations with warnings denied, 685 Rust tests, 92 browser tests, frontend contract (131 routes), installer contract, and diff check. Logs: `/tmp/opencode/service-final-*.log`. Separately, all final v1.3.13 gates passed with 685 Rust / 92 browser tests / 131 routes, installer, formatting, check, both Clippy configurations with `-D warnings`, and diff check. Final logs: `/tmp/opencode/v1313-{fmt,check,clippy-router,clippy-all,tests,frontend,installer,browser,diff-check,build}.log`.

Browser fixtures cover exact four-worker admission, insufficient/unknown memory rejection before replacing a job, shared policy persistence, scopes, and skipped-service colors. The four-thread local SOCKS-failure regression verifies native playback mutex independence, not successful concurrent router transfers. Development verification previously stopped at unavailable SSH authentication; restored access superseded that blocker before the separately completed deployment. No commands or router/native/power operations occur in this documentation finalization.

The live four-candidate ordinary YT/no-fail-fast request with concurrency four returned HTTP 503 before reservation (`memory_gate: false`, `memory_permits: 3`, `requested: 4`); five prior job metadata fields and idle status were preserved. The final single `[88]` request used the same policy/concurrency, admitted exactly one for one candidate, completed one with search null/no preflight, and passed real channel/three-preview checking. This is candidate-count bounding, not silently reducing four-candidate work to a memory budget. TG/AI were unrequested with zero attempts/successes; native YouTube was absent. Live All/TG/AI positives, dynamic fail-fast sequences, backend acceptance across all scopes, four admitted positive workers, peak/continuous memory, cancellation under load, and reboot persistence remain unverified. v1.3.12's all-service pass is historical, not reused v1.3.13 evidence.

Separate deployed-page audit (`/tmp/opencode/v1313-live-ui.mjs`, `/tmp/opencode/v1313-live-ui.log`) confirmed ordinary/advanced All and fail-fast enabled, target 5/max 20 in advanced Find N, label toggling only browser/localStorage state, current YT green with skipped TG/AI gray, closed details, and no sidebar technical nodes/mobile overflow/JS errors. Single YT/false and ordinary global All/true builders captured concurrency four, `availability_full`, explicit `service_checks`, and no search. Both received intercepted mock 503; zero mutations reached the router, presentation stayed unchanged, and an invalid scoped/advanced combination did not post. These are frontend-builder checks on a real page, not newly accepted backend tests or a live All/fail-fast service sequence.
