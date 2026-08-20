# HincyRay for Android: implementation options

## Recommended direction

Android-only HincyRay can reach a working VPN dataplane fastest by using [ClashMetaForAndroid](https://github.com/MetaCubeX/ClashMetaForAndroid) as the Android platform shell while keeping HincyRay domain rules separate from Android lifecycle code.

CMFA already owns the expensive mobile boundaries: `VpnService`, TUN, foreground-service lifecycle, Binder IPC, embedded Mihomo through its Go/JNI bridge, Room-backed configuration storage, proxy groups, traffic, connections, DNS/geodata, network changes, automation and quick-settings integration.

The recommended boundary is:

```text
Android / CMFA fork
  Kotlin UI, Room/DataStore, Keystore, WorkManager, VpnService
                           │
                           ▼
shared HincyRay domain crate
  profile/subscription parsing, XHTTP transforms, srv-v2 identity,
  Dead Servers reducers, quality models/history, redaction, presets
                           │
                           ▼
CMFA core bridge / embedded Mihomo
  TUN, DNS, proxy groups, connections, logs, actual packet transport
```

Do not port the Keenetic daemon composition root or run a second daemon inside Android. Router-only code includes iptables REDIRECT/TPROXY, the ndm hook, `/opt` paths, init/PID ownership, LAN source-IP policy routing and child-process Mihomo lifecycle.

## Licensing

CMFA is licensed under GNU GPLv3. A distributed fork/APK that combines HincyRay changes with CMFA must be distributed under GPLv3 with corresponding source, build scripts, notices and marked modifications. Package name, branding, icons and URI schemes should be replaced. HincyRay's MIT code can be included, but the resulting application is GPLv3 rather than MIT-only.

Mihomo itself is MIT-licensed. A fresh Android application built directly around Mihomo could retain an MIT application license, but would need to implement the Android service, TUN and core bridge boundaries itself.

## Model mismatch to solve first

CMFA primarily treats a profile as a complete Clash YAML document containing proxies and groups. HincyRay treats each server as an individually managed lifecycle entity with a share link, canonical `srv-v2` identity, quality history and Dead Servers state.

Before adding many features, define one owner for:

- subscription refresh and server identity;
- lifecycle metadata after provider updates;
- manual versus subscription provenance;
- Dead Servers membership;
- routing targets and quality history;
- persistence transactions between Room and Mihomo configuration.

Avoid a second JSON state store beside CMFA Room without an explicit transactional owner.

## Portable HincyRay capabilities

Good shared-domain candidates:

- bounded share-link and subscription parsing;
- Happ compatibility/fallback policy;
- XHTTP `extra` parsing and lossless updates;
- lifecycle canonicalization and `srv-v2` references;
- Dead Servers transition validation;
- quality history and result aggregation;
- routing presets and structural redaction.

Capabilities that require an Android implementation:

- Quick/Full probe transport through a selected embedded-Mihomo outbound;
- cancellation with Kotlin coroutines/Go core rather than external `curl`, `ping` and temporary Mihomo processes;
- Android Profile Logger based on Mihomo connections/logs plus Wi-Fi/LTE, battery and foreground state;
- Keystore, Room migrations, WorkManager and foreground notifications;
- VPN handover, metered-network and battery policy.

## Suggested phases

### v0.1: dataplane proof

- Fork a pinned CMFA commit and pin its Mihomo submodule/toolchains.
- Replace package ID, signing and branding.
- Keep the existing CMFA UI stack initially.
- Import HincyRay-supported share links.
- Add one-server-centric selection and a minimal XHTTP editor.
- Verify Reality/XHTTP, VMess, Trojan, Shadowsocks and Hysteria2 across Wi-Fi/LTE handover.

### v0.2: HincyRay identity

- Extract the shared domain crate and expose it through UniFFI/JNI.
- Add `srv-v2`, manual/subscription provenance, favorites and quality history.
- Add Dead Servers semantics and a native Quick Test.

### v0.3: diagnostics

- Add native YouTube, Telegram and AI checks without external executables.
- Add Android Profile Logger and bounded AI-ready reports.
- Apply battery/metered-network limits and prompt cancellation.

### v1.0

- Auto-Select and routing presets.
- Robust Room migrations and reproducible signed releases.
- Crash-report redaction, accessibility and Android VPN lifecycle tests.

## Principal risks

1. Continuous merge cost from CMFA Android, Gradle, Go/JNI and Mihomo updates.
2. GPLv3 obligations for the complete distributed application.
3. Divergent CMFA YAML-profile and HincyRay server-identity models.
4. Limited upstream test coverage, requiring service, migration, VPN and handover tests early.
5. Scope explosion if HincyRay features and a Compose rewrite are attempted simultaneously.

The fork is a strong route to an Android MVP if GPLv3 is acceptable. For long-term maintainability, use CMFA as the platform/dataplane shell and keep HincyRay behavior in a shared domain layer rather than embedding router-daemon logic in Kotlin.
