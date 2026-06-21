# HincyRay v0.5

# English | [Русский](#русский)

---

# English

HincyRay is a lightweight VPN/proxy client for Keenetic Homebrew routers. v0.5 ships a router daemon (`hincyray`) that reuses the parser, Xray config generator, and quality scoring originally developed for the `XrayVpnTest` desktop tool, and exposes an embedded web panel on the router LAN. v0.5 adds HWID fingerprint hardcoding for Happ subscriptions, VMess/Trojan/Shadowsocks protocol support, port-based routing (allow-lists/deny-lists), DNS anti-leak protection, and GeoIP/GeoSite asset path configuration. v0.4 replaced TPROXY with tun2socks (TUN device + iproute2 policy routing). v0.3 added WiFi-only traffic split, per-server QUIC toggle, and a live service catalog.

The desktop app `xray-vpn-test` is still built from this crate behind the `desktop` feature, but its role is diagnostics and benchmarking only. See [`docs/hincyray-v0.1-status.md`](docs/hincyray-v0.1-status.md) for the version status and [`docs/keenetic-client-roadmap.md`](docs/keenetic-client-roadmap.md) for the longer plan.

## Features

- Router daemon `hincyray` runs on Keenetic Giga KN-1012 (Entware aarch64) and exposes a JSON HTTP API plus an embedded web panel.
- Web panel at `http://<router-ip>:8088/` for status, subscription import, profile selection, Xray core start/stop/restart, ping/benchmark, stats/rating, favorites, subscription refresh, WiFi traffic split rules, per-server QUIC toggle, HWID fingerprint, DNS anti-leak, and port routing — no external CDN or build step required.
- **v0.5 protocol support**: VLESS (Reality/TLS/XHTTP), VMess (base64-JSON, WS/gRPC/TCP), Trojan (TLS), Shadowsocks (new + legacy base64 format). WireGuard and Hysteria2 are rejected with a clear error message (use sing-box or mihomo for those).
- **v0.5 HWID fingerprint hardcoding**: configurable device identity for Happ subscription fetches. Replaces the real device ID with a fixed, consistent fingerprint (HWID + OS version + device model + app version) so the server's cross-check passes. API: `GET/POST /api/hwid`.
- **v0.5 DNS anti-leak**: when enabled, Xray uses configured remote DNS servers (DoH/plain) for proxied domains and local DNS for direct domains, preventing DNS leaks through the system resolver. The `freedom` outbound switches to `UseIP` strategy. API: `GET/POST /api/dns`.
- **v0.5 port routing**: three modes — `all` (proxy everything, default), `allow_list` (only proxy specified ports), `deny_list` (proxy all except specified ports). Per-rule port and network (TCP/UDP) matching. API: `POST /api/routing/settings` with `port_mode`, `proxy_ports`, `bypass_ports`.
- **v0.5 GeoIP/GeoSite asset path**: configurable path to `.dat` files. Sets `XRAY_LOCATION_ASSET` env var when starting the Xray core, enabling `geosite:*` and `geoip:*` rule matching.
- Accepts direct `vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://`/`hy2://` share links, HTTPS subscription URLs, and Xray-style JSON configs with `outbounds` (VLESS/VMess/Trojan/Shadowsocks).
- Loads Happ/TutNet-style subscriptions that require Android-like request headers, with automatic retry using the Happ `User-Agent` and `X-*` headers (now with configurable HWID).
- Generates Xray client configs for all supported protocols via the shared `xray_config` module.
- Persists state, profiles, active profile, generated Xray config, saved subscription sources, favorites, per-profile stats, split-routing rules, per-server QUIC flags, DNS settings, and HWID config under `/opt/etc/hincyray/` on Entware.
- **v0.4 TUN-based WiFi VPN routing via tun2socks**: `tun2socks` creates a TUN device (`tun0`) and forwards WiFi VPN traffic (192.168.2.0/24) to Xray's second SOCKS inbound (127.0.0.1:10810) via iproute2 policy routing. iptables mangle MARK + fwmark rule for source-based routing. FORWARD ACCEPT rules allow br1↔tun0 forwarding. 10-second watchdog reinstalls any iptables rules wiped by ndm.
- **v0.3 WiFi traffic split**: routing rules scoped to the tun2socks SOCKS inbound. Rules can match `geosite:*` categories, custom domains, IP/CIDR, `geoip:*`, ports, and network type (TCP/UDP). Targets: `direct`, active server, best server, or a fixed profile.
- **v0.3 service catalog**: choose a rule source project and pull live category lists from GitHub.
- **v0.3 per-server QUIC toggle**: each profile row has a QUIC button. When enabled, HincyRay blocks UDP 443 for that server, forcing services to fall back to TCP.
- **v0.2 background benchmark**: TCP/HEAD/GET methods. TCP probes directly; HEAD/GET spin up a temporary Xray SOCKS per profile. Stats survive restarts.
- **v0.2 stats, favorites, subscription refresh**: per-profile metrics, favorites by raw link, re-fetch saved subscriptions.

## Current limitations

- **No automatic routing installed by the daemon by default.** The v0.4 WiFi VPN segment uses tun2socks for `192.168.2.0/24` only; automatic failover and auto-select are still post-MVP.
- **Hysteria2 and WireGuard are not supported by the Xray backend.** Selecting them returns a clear 400 error. Use sing-box or mihomo for those protocols.
- **Router internet may require manual artifact copy.** See [`docs/hincyray-entware-install.md`](docs/hincyray-entware-install.md).
- **Benchmark HEAD/GET requires `curl` in PATH.**
- **Auto-select is a flag, not an active loop.** The daemon does not yet continuously benchmark or switch the active profile on failure.

## Build

Requirements: Rust 2024 toolchain.

### Router daemon (HincyRay v0.5)

```bash
cargo build --release --no-default-features --bin hincyray
```

Binary at: `target/release/hincyray`

For cross-compilation to Keenetic Entware (aarch64):

```bash
cargo zigbuild --release --no-default-features --bin hincyray --target aarch64-unknown-linux-gnu.2.27
patchelf --set-interpreter /opt/lib/ld-linux-aarch64.so.1 --set-rpath /opt/lib \
  target/aarch64-unknown-linux-gnu/release/hincyray
```

### Desktop diagnostics (XrayVpnTest)

```bash
cargo build --release --bin xray-vpn-test   # default features include "desktop"
```

Runtime benchmarking on macOS needs `sing-box` and `xray` in `PATH`:

```bash
brew install sing-box xray
```

### Quality gates

```bash
cargo fmt
cargo test
cargo clippy --all-targets --all-features
```

## Web panel

```text
http://<router-ip>:8088/
```

The page is served inline from `index_html()` and talks to the JSON API over `fetch`. No external CDN or build step.

Environment overrides:

- `HINCYRAY_LISTEN` — bind address, default `0.0.0.0:8088`.
- `HINCYRAY_STATE` — state file path. Auto-detected: `/opt/etc/hincyray/state.json` (Entware), `/etc/hincyray/state.json` (OpenWrt), `$HOME/.config/hincyray/state.json`, or `./hincyray-state.json`.
- `HINCYRAY_XRAY_CONFIG` — generated Xray config path. Defaults to `xray-client.json` next to the state file.

## HTTP API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Embedded web panel. |
| `GET` | `/api/health` | `{ "ok": true, "service": "hincyray", "version": ... }`. |
| `GET` | `/api/status` | Active profile, profile count, listen info, xray paths, core status, DNS enabled, HWID. |
| `GET` | `/api/profiles` | Imported profiles with id/name/protocol/transport/address/port/active/group/block_quic. |
| `POST` | `/api/profiles/import` | Share links, Xray JSON config, or subscription URL. |
| `POST` | `/api/profiles/block-quic` | Toggle per-server QUIC/UDP 443 block. |
| `POST` | `/api/active-profile` | Set active profile, generate Xray config. |
| `GET` | `/api/xray/config` | Generated Xray client config. |
| `POST` | `/api/core/start` | Start Xray core with `XRAY_LOCATION_ASSET` env. |
| `POST` | `/api/core/stop` | Stop Xray core. |
| `POST` | `/api/core/restart` | Restart Xray core. |
| `GET` | `/api/bench/status` | Live benchmark job status. |
| `POST` | `/api/bench/start` | Start background benchmark (tcp/head/get). |
| `POST` | `/api/bench/stop` | Cancel running benchmark. |
| `GET` | `/api/stats` | Per-profile metrics + aggregates, sorted by score. |
| `POST` | `/api/favorites/toggle` | Toggle favorite by profile ID. |
| `GET` | `/api/favorites` | List favorite profiles. |
| `GET` | `/api/subscriptions` | List saved subscription sources. |
| `POST` | `/api/subscriptions/refresh` | Re-fetch all saved subscriptions. |
| `POST` | `/api/subscriptions/refresh-one` | Re-fetch a single subscription by URL. |
| `GET` | `/api/routing` | Split-routing settings, rules, service catalog, sources. |
| `POST` | `/api/routing/settings` | Save split-routing settings (including port_mode, proxy_ports, bypass_ports, geo_asset_path). |
| `POST` | `/api/routing/rules` | Save WiFi-only routing rules (domains/IPs/services/ports/network/target). |
| `POST` | `/api/routing/catalog/refresh` | Pull live service categories from GitHub. |
| `POST` | `/api/routing/apply` | Regenerate Xray config and restart core. |
| `GET` | `/api/routing/tun-status` | TUN/tun2socks/iptables/core health check. |
| `POST` | `/api/routing/tun-start` | Start tun2socks and install routing rules. |
| `POST` | `/api/routing/tun-stop` | Stop tun2socks and remove routing rules. |
| `GET` | `/api/dns` | DNS anti-leak settings. |
| `POST` | `/api/dns` | Save DNS anti-leak settings (enabled, remote_servers, local_servers, query_strategy). |
| `GET` | `/api/hwid` | HWID fingerprint config. |
| `POST` | `/api/hwid` | Save HWID fingerprint (hwid, os_version, device_model, device_os, app_version). |

## WiFi VPN segment (v0.4, tun2socks)

- `scripts/wifi-segment-setup.sh` — creates the `HincyRay-VPN` SSID on `192.168.2.0/24` via Keenetic `ndmc`.
- The daemon handles all routing internally via `TunManager`:
  1. `tun2socks` creates a TUN device (`tun0`) and forwards traffic to Xray's second SOCKS inbound (`127.0.0.1:10810`).
  2. iptables mangle MARK chain marks packets from `192.168.2.0/24` with fwmark `0x111`.
  3. iproute2 fwmark rule routes marked packets through the TUN.
  4. FORWARD ACCEPT rules allow br1↔tun0 forwarding.
  5. 10-second watchdog reinstalls any iptables rules wiped by ndm.

Only `192.168.2.0/24` is steered through Xray; `192.168.1.0/24` keeps the main uplink. TUN interface and iproute2 rules survive ndm reloads.

## Documentation

- [`docs/hincyray-v0.1-status.md`](docs/hincyray-v0.1-status.md) — version status.
- [`docs/hincyray-entware-install.md`](docs/hincyray-entware-install.md) — Entware install runbook.
- [`docs/keenetic-client-roadmap.md`](docs/keenetic-client-roadmap.md) — product roadmap.

## Notes

- VLESS XHTTP is not supported by `sing-box`; the router daemon uses `xray` exclusively.
- v0.5 adds VMess, Trojan, and Shadowsocks support for both Xray (router) and sing-box (benchmark).
- HWID fingerprint values follow the pattern from HWID-HARDCODING.md: a 16-hex HWID, consistent OS/model pair, and matching User-Agent.
- DNS anti-leak: remote DNS queries go through the proxy; local DNS handles direct domains (e.g. `geosite:cn`).
- Port routing: allow-list mode proxies only listed ports; deny-list mode proxies all except listed ports. Per-rule port matching uses Xray's `"port"` field.
- GeoIP/GeoSite: set `geo_asset_path` to the directory containing `geoip.dat` and `geosite.dat`; the daemon sets `XRAY_LOCATION_ASSET` when starting Xray.
- Do not put real subscription URLs or tokens into bug reports or docs; use the placeholder `https://provider.example/sub/<token>`.

---

# Русский

HincyRay — лёгкий VPN/proxy-клиент для роутеров Keenetic с Entware. v0.5 поставляет роутер-демон (`hincyray`), который переиспользует парсер, генератор Xray-конфигов и формулу оценки качества из десктопного инструмента `XrayVpnTest`, и предоставляет встроенную веб-панель в локальной сети роутера. v0.5 добавляет хардкод HWID-фингерпринта для подписок Happ, поддержку протоколов VMess/Trojan/Shadowsocks, портовый роутинг (allow-list/deny-list), защиту от утечек DNS и настройку путей к GeoIP/GeoSite-файлам. v0.4 заменила TPROXY на tun2socks (TUN-устройство + iproute2 policy routing). v0.3 добавила WiFi-сплит роутинга, поключальный QUIC-тоггл и живой каталог сервисов.

Десктопное приложение `xray-vpn-test` собирается из того же крейта с фичей `desktop`, но его роль — диагностика и бенчмаркинг. См. [`docs/hincyray-v0.1-status.md`](docs/hincyray-v0.1-status.md) и [`docs/keenetic-client-roadmap.md`](docs/keenetic-client-roadmap.md).

## Возможности

- Роутер-демон `hincyray` работает на Keenetic Giga KN-1012 (Entware aarch64) и предоставляет JSON HTTP API + встроенную веб-панель.
- Веб-панель на `http://<ip-роутера>:8088/`: статус, импорт подписок, выбор профиля, запуск/стоп/рестарт Xray, пинг/бенчмарк, статы/рейтинг, избранное, обновление подписок, правила сплит-роутинга WiFi, поключальный QUIC-тоггл, HWID-фингерпринт, защита от утечек DNS, портовый роутинг — без внешних CDN или сборки фронтенда.
- **v0.5 поддержка протоколов**: VLESS (Reality/TLS/XHTTP), VMess (base64-JSON, WS/gRPC/TCP), Trojan (TLS), Shadowsocks (новый + legacy base64 формат). WireGuard и Hysteria2 отклоняются с понятной ошибкой (используйте sing-box или mihomo).
- **v0.5 хардкод HWID-фингерпринта**: настраиваемая идентификация устройства для запросов подписок Happ. Заменяет реальный device ID на фиксированный, согласованный фингерпринт (HWID + версия OC + модель + версия приложения), чтобы серверная cross-check проверка прошла. API: `GET/POST /api/hwid`.
- **v0.5 защита от утечек DNS**: при включении Xray использует настроенные удалённые DNS-серверы (DoH/обычные) для проксируемых доменов и локальные DNS для прямых доменов, предотвращая утечки через системный резолвер. Outbound `freedom` переключается на стратегию `UseIP`. API: `GET/POST /api/dns`.
- **v0.5 портовый роутинг**: три режима — `all` (проксировать всё, по умолчанию), `allow_list` (проксировать только указанные порты), `deny_list` (проксировать всё кроме указанных). Поправильный матчинг портов и сети (TCP/UDP). API: `POST /api/routing/settings` с `port_mode`, `proxy_ports`, `bypass_ports`.
- **v0.5 GeoIP/GeoSite**: настраиваемый путь к `.dat`-файлам. Устанавливает переменную окружения `XRAY_LOCATION_ASSET` при запуске ядра Xray, включая матчинг правил `geosite:*` и `geoip:*`.
- Принимает прямые share-ссылки `vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://`/`hy2://`, HTTPS-URL подписок и Xray JSON-конфиги с `outbounds` (VLESS/VMess/Trojan/Shadowsocks).
- Загружает подписки Happ/TutNet, требующие Android-подобных заголовков, с автоматическим повтором через Happ `User-Agent` и `X-*` заголовки (теперь с настраиваемым HWID).
- Генерирует Xray-конфиги для всех поддерживаемых протоколов через общий модуль `xray_config`.
- Сохраняет состояние, профили, активный профиль, сгенерированный Xray-конфиг, источники подписок, избранное, статы, правила роутинга, QUIC-флаги, DNS-настройки и HWID-конфиг в `/opt/etc/hincyray/` на Entware.
- **v0.4 WiFi VPN через tun2socks**: `tun2socks` создаёт TUN-устройство (`tun0`) и направляет WiFi VPN-трафик (192.168.2.0/24) на второй SOCKS-inbound Xray (127.0.0.1:10810) через iproute2 policy routing. mangle MARK + fwmark для source-based routing. FORWARD ACCEPT для br1↔tun0. Watchdog 10 секунд переустанавливает iptables-правила, снесённые ndm.
- **v0.3 сплит-роутинг WiFi**: правила роутинга для tun2socks SOCKS-inbound. Матчат `geosite:*`, домены, IP/CIDR, `geoip:*`, порты и тип сети (TCP/UDP). Цели: `direct`, активный сервер, лучший сервер или фиксированный профиль.
- **v0.3 каталог сервисов**: выбор источника правил и загрузка живых списков категорий с GitHub.
- **v0.3 поключальный QUIC-тоггл**: кнопка QUIC у каждого профиля. Блокирует UDP 443 для выбранного сервера.
- **v0.2 бенчмарк/статы/избранное/обновление подписок**: фоновые бенчмарки (TCP/HEAD/GET), метрики по профилям, избранное по raw-ссылке, рефетч подписок.

## Ограничения

- **Демон не устанавливает автоматический роутинг по умолчанию.** WiFi VPN-сегмент v0.4 работает только для `192.168.2.0/24`; автоматический failover и auto-select — post-MVP.
- **Hysteria2 и WireGuard не поддерживаются ядром Xray.** Возвращается понятная ошибка 400. Используйте sing-box или mihomo.
- **Интернет на роутере может требовать ручного копирования артефактов.** См. [`docs/hincyray-entware-install.md`](docs/hincyray-entware-install.md).
- **Бенчмарк HEAD/GET требует `curl` в PATH.**
- **Auto-select — это флаг, а не активный цикл.** Демон пока не бенчмаркает непрерывно и не переключает профиль при сбое.

## Сборка

Требуется: Rust 2024 toolchain.

### Роутер-демон (HincyRay v0.5)

```bash
cargo build --release --no-default-features --bin hincyray
```

Бинарник: `target/release/hincyray`

Кросс-компиляция для Keenetic Entware (aarch64):

```bash
cargo zigbuild --release --no-default-features --bin hincyray --target aarch64-unknown-linux-gnu.2.27
patchelf --set-interpreter /opt/lib/ld-linux-aarch64.so.1 --set-rpath /opt/lib \
  target/aarch64-unknown-linux-gnu/release/hincyray
```

### Десктоп-диагностика (XrayVpnTest)

```bash
cargo build --release --bin xray-vpn-test   # default features include "desktop"
```

Для бенчмаркинга на macOS нужны `sing-box` и `xray` в `PATH`:

```bash
brew install sing-box xray
```

### Проверка качества

```bash
cargo fmt
cargo test
cargo clippy --all-targets --all-features
```

## Веб-панель

```text
http://<ip-роутера>:8088/
```

Страница встроена в `index_html()` и общается с JSON API через `fetch`. Без внешних CDN и сборки.

Переменные окружения:

- `HINCYRAY_LISTEN` — адрес привязки, по умолчанию `0.0.0.0:8088`.
- `HINCYRAY_STATE` — путь к файлу состояния. Авто-определение: `/opt/etc/hincyray/state.json` (Entware), `/etc/hincyray/state.json` (OpenWrt), `$HOME/.config/hincyray/state.json` или `./hincyray-state.json`.
- `HINCYRAY_XRAY_CONFIG` — путь к генерируемому Xray-конфигу. По умолчанию `xray-client.json` рядом с файлом состояния.

## HTTP API

| Метод | Путь | Назначение |
| --- | --- | --- |
| `GET` | `/` | Встроенная веб-панель. |
| `GET` | `/api/health` | `{ "ok": true, "service": "hincyray", "version": ... }`. |
| `GET` | `/api/status` | Активный профиль, количество, пути, статус ядра, DNS, HWID. |
| `GET` | `/api/profiles` | Импортированные профили. |
| `POST` | `/api/profiles/import` | Импорт share-ссылок, JSON-конфига или URL подписки. |
| `POST` | `/api/profiles/block-quic` | Тоггл блокировки QUIC/UDP 443 для профиля. |
| `POST` | `/api/active-profile` | Установка активного профиля. |
| `GET` | `/api/xray/config` | Сгенерированный Xray-конфиг. |
| `POST` | `/api/core/start` | Запуск ядра Xray (с `XRAY_LOCATION_ASSET`). |
| `POST` | `/api/core/stop` | Остановка ядра. |
| `POST` | `/api/core/restart` | Перезапуск ядра. |
| `GET` | `/api/bench/status` | Статус бенчмарка. |
| `POST` | `/api/bench/start` | Запуск фонового бенчмарка (tcp/head/get). |
| `POST` | `/api/bench/stop` | Отмена бенчмарка. |
| `GET` | `/api/stats` | Метрики по профилям, отсортировано по score. |
| `POST` | `/api/favorites/toggle` | Тоггл избранного. |
| `GET` | `/api/favorites` | Список избранного. |
| `GET` | `/api/subscriptions` | Сохранённые подписки. |
| `POST` | `/api/subscriptions/refresh` | Обновить все подписки. |
| `POST` | `/api/subscriptions/refresh-one` | Обновить одну подписку по URL. |
| `GET` | `/api/routing` | Настройки и правила сплит-роутинга, каталог сервисов. |
| `POST` | `/api/routing/settings` | Сохранить настройки (вкл. port_mode, proxy_ports, bypass_ports, geo_asset_path). |
| `POST` | `/api/routing/rules` | Сохранить правила (домены/IP/сервисы/порты/сеть/цель). |
| `POST` | `/api/routing/catalog/refresh` | Загрузить каталог сервисов с GitHub. |
| `POST` | `/api/routing/apply` | Перегенерировать конфиг и перезапустить ядро. |
| `GET` | `/api/routing/tun-status` | Статус TUN/tun2socks/iptables/ядра. |
| `POST` | `/api/routing/tun-start` | Запустить tun2socks. |
| `POST` | `/api/routing/tun-stop` | Остановить tun2socks. |
| `GET` | `/api/dns` | Настройки защиты от утечек DNS. |
| `POST` | `/api/dns` | Сохранить DNS-настройки. |
| `GET` | `/api/hwid` | Конфиг HWID-фингерпринта. |
| `POST` | `/api/hwid` | Сохранить HWID-фингерпринт. |

## WiFi VPN-сегмент (v0.4, tun2socks)

- `scripts/wifi-segment-setup.sh` — создаёт SSID `HincyRay-VPN` на `192.168.2.0/24` через Keenetic `ndmc`.
- Демон управляет всем роутингом через `TunManager`:
  1. `tun2socks` создаёт TUN (`tun0`) и направляет трафик на SOCKS Xray (`127.0.0.1:10810`).
  2. iptables mangle MARK маркирует пакеты из `192.168.2.0/24` меткой `0x111`.
  3. iproute2 fwmark-правило направляет меченые пакеты через TUN.
  4. FORWARD ACCEPT разрешает br1↔tun0.
  5. Watchdog 10 секунд переустанавливает iptables-правила после ndm.

Только `192.168.2.0/24` идёт через Xray; `192.168.1.0/24` использует основной аплинк. TUN и iproute2 переживают ndm-перезагрузки.

## Документация

- [`docs/hincyray-v0.1-status.md`](docs/hincyray-v0.1-status.md) — статус версий.
- [`docs/hincyray-entware-install.md`](docs/hincyray-entware-install.md) — runbook установки на Entware.
- [`docs/keenetic-client-roadmap.md`](docs/keenetic-client-roadmap.md) — roadmap продукта.

## Заметки

- VLESS XHTTP не поддерживается `sing-box`; роутер-демон использует только `xray`.
- v0.5 добавляет VMess, Trojan и Shadowsocks для Xray (роутер) и sing-box (бенчмарк).
- Значения HWID следуют паттерну из HWID-HARDCODING.md: 16-символьный hex HWID, согласованная пара OC/модели и соответствующий User-Agent.
- Защита от утечек DNS: удалённые DNS-запросы идут через прокси; локальные DNS обрабатывают прямые домены (напр. `geosite:cn`).
- Порт-роутинг: allow-list проксирует только указанные порты; deny-list проксирует всё кроме указанных. Поправильный матчинг портов использует поле `"port"` в Xray.
- GeoIP/GeoSite: укажите `geo_asset_path` к директории с `geoip.dat` и `geosite.dat`; демон устанавливает `XRAY_LOCATION_ASSET` при запуске Xray.
- Не помещайте реальные URL подписок или токены в баг-репорты и документацию; используйте плейсхолдер `https://provider.example/sub/<token>`.
