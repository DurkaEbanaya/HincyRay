# Mihomo process restart and memory cleanup

The Overview **Restart** button (`POST /api/core/restart`) now stops and reaps
the tracked Mihomo child, then launches a new child through the daemon's
persistent spawn-owner thread. It no longer chooses a configuration hot reload.

**Clear memory** (`POST /api/core/cleanup`) uses the same full process reset to
release all old process allocations, including retained buffers and sessions.
The UI explicitly states that all Mihomo connections are interrupted. The API
and UI report the previous/new PID and optional RSS samples in KiB before and
after readiness. RSS is not guaranteed to decrease: the replacement process
loads rules and GeoBase and immediately handles new traffic.

Both operations validate the generated applied-GeoBase configuration before
stopping the existing child, preserve canonical active/REJECT selector intent,
reset best-of-best to REJECT until re-admission, enforce listener ownership and
readiness, and retain transactional config/runtime rollback. Concurrent apply
or reset operations return HTTP 409; cleanup of a stopped core returns HTTP 400.
Ordinary configuration apply retains its hot-reload behavior.

This operation resets Mihomo process memory. It does not drop Linux page caches,
delete saved profiles/history, clear system-wide conntrack, or kill unrelated
processes. Mihomo's optional debug GC endpoint is not enabled or exposed.

## Router deployment, 2026-10-02

Installed as a local patched v1.3.35 build with user authorization. SHA256
matched the local, staged and installed ARM64 binary:
`ddb547173fd2a8e1bec938ab50f8fc1f493212147dd6b151cd3f7e5f0e3537af`.

Final local gates passed: fmt, all-target/all-feature check, router/all-feature
Clippy, 724 Rust tests, 125 browser tests, 140 frontend routes, installer
lifecycle contract and diff check. Logs: `/tmp/opencode/mihomo-cleanup-*.log`.

The init-script update retained a complete six-file rollback set at
`/opt/etc/hincyray/rollback-mihomo-cleanup-20261002-222028-13565`.
Live restart changed PID 13729 → 13822; cleanup changed 13822 → 13908. Both old
children were absent from `/proc`. Immediate RSS increased during initialization
(cleanup 128388 → 147268 KiB), subsequently measured 88576 KiB with 164996 KiB
available and no memory-guard warnings. This verifies process replacement, not
a guaranteed immediate RSS decrease or a proven memory-leak fix.

Health/core/firewall, main active selector, REJECT-first pool, DNS 1053,
REDIRECT 10810, TPROXY 10811/table 111 and router E2E passed. Active profile 88,
390 profiles, 47 rules and enabled 16-member pool were preserved. The checked
durable state projection and exact history/private notification/automation
settings matched the post-stop snapshot; state/config modes remained 0600 and
the staged binary was removed.

Two preliminary attempts restored the old SHA256-verified binary and complete
settings set: first due to an expected concurrent-apply HTTP 409, second due to
the verification script expecting DNS REDIRECT instead of the actual DNAT
contract. The final script waits boundedly on 409 and checks the correct DNAT
rule. Final private proof: `/tmp/opencode/mihomo-cleanup-deploy-final.log`.
No release publication or Git operation was performed.
