# HincyRay v0.22 Architecture Addendum

Status: implemented and live-validated, 2026-07-22. This addendum extends the stable v0.21 control-plane contracts documented in [`architecture-v0.21.md`](architecture-v0.21.md).

## Quick Test service contract

Quick Test validates service use through each selected profile, not server TCP reachability or a public CDN logo. Profiles run sequentially because the Telegram session storage must not be opened by concurrent clients.

Each profile gets its own temporary Mihomo SOCKS listener:

```text
profile
  -> temporary Mihomo SOCKS
     -> YouTube visitor bootstrap + Innertube player + 512 KiB media range
     -> Telegram authorized message lookup + one media chunk
     -> AI Studio page request + regional redirect check
```

Results are persisted in `ProfileStats.resource_tests` with contract version 5. The Web UI renders only the current contract, preventing obsolete probes from appearing as current `YT`/`TG`/`AI` status.

### YouTube

The daemon implements only the narrow requirement needed by Quick Test:

1. Fetch the fixed test video's watch page through the profile and capture visitor cookie/data.
2. Call the `ANDROID_VR` Innertube player endpoint with the visitor context.
3. Select direct video format `itag 160`, falling back to another direct video URL.
4. Download bytes `0..524287` through the same profile.

This path uses Rust, Mihomo, and `curl`. It deliberately does not embed Python, `yt-dlp`, a JavaScript runtime, or a general YouTube downloader. If YouTube stops returning a direct format for this supported input, the probe reports a bounded extraction error instead of attempting an unbounded compatibility framework.

### Telegram

`src/telegram_probe.rs` owns Telegram authorization and media download through `grammers-client`/`grammers-session`:

- `POST /api/telegram-probe/request-code` stores validated configuration privately and requests a login code.
- `POST /api/telegram-probe/confirm` completes code and optional 2FA authentication.
- `GET /api/telegram-probe/status` returns only non-secret state, peer, and message ID.
- `POST /api/telegram-probe/delete` attempts sign-out and removes local session/config files.

The configured public peer and message ID identify one operator-selected media message. Quick Test resolves that peer, loads exactly that message, and downloads one 256 KiB chunk.

### AI Studio

The daemon opens `aistudio.google.com` through the same temporary profile SOCKS listener with bounded time and response size. Request failures and redirects to Google AI's `available-regions` page are reported as a failed `AI` result.

## Secret and session boundary

Telegram data is not part of `HincyrayState`:

| File | Purpose | Mode |
|---|---|---|
| `telegram-probe.json` | API ID/hash, phone, peer, message ID, authorization flag | `0600` |
| `telegram.session` | Telegram authorization keys and peer cache | `0600` |

SQLite `-wal`/`-shm` sidecars are corrected to `0600` whenever present. API responses never contain API hash, phone, login code, or 2FA password. The Web UI clears transient credential fields after submission and does not place them in `localStorage`.

## Routing simplification

The legacy oversized RKN bypass provider and router `geoip.dat` path are removed. Router geo inputs are:

- MetaCubeX `geosite.dat`;
- MetaCubeX `geoip.metadb` with `geo-auto-update: false`;
- managed GeoBase artifacts;
- bounded Always VPN exceptions.

Under `MATCH,proxy`, automatically classified Active domains do not need a redundant Active rule provider because the final match already proxies them. Static Active networks remain explicit because they represent operator-authored routing intent.

Routing-rule deletions persist as desired state even when low memory or an unavailable upstream prevents immediate Mihomo activation. The API reports `applied:false`, `requires_apply:true`, and a bounded `activation_error`; additions and edits retain transactional rollback on failed activation.

## Subscription compatibility pipeline

Subscription compatibility is split into independent stages: network path (`direct`, SOCKS5h, SOCKS5, HTTP), client identity (sing-box then Happ when the server rejects or returns unusable content), bounded HTTP decoding, nested gzip/base64 payload decoding, and profile-format detection. A timeout, DNS, TLS, or connection failure advances to the next network path without retrying the same broken path under another User-Agent. Successful HTTP content still must contain at least one supported profile, so refresh cannot erase a working group with a challenge or maintenance response.

This covers ordinary standards-based and Happ-compatible subscription endpoints. Provider-side encryption, CAPTCHA/browser attestation, account-bound request signatures, and unsupported proxy schemas remain explicit compatibility boundaries rather than being guessed from response text.

## Live resource evidence

The rejected standalone `yt-dlp` prototype unpacked a PyInstaller runtime into RAM-backed `/tmp`, reducing `MemAvailable` to roughly 18 MiB and triggering the router OOM killer during a batch. It was removed.

The final native implementation completed three sequential profiles with both services green:

- no `yt-dlp`, Python, or QuickJS process;
- approximately 197 MiB minimum `MemAvailable` during the batch;
- approximately 204 MiB available after validation;
- core, fallback, firewall/TPROXY, and router E2E healthy.
