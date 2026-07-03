# HincyRay v0.15.2

[English](README.md) | [Русский](README.ru.md)

---

HincyRay — лёгкий VPN/proxy-клиент для роутеров Keenetic. Поставляет роутер-демон (`hincyray`), который переиспользует парсер и формулу оценки качества из десктопного инструмента `XrayVpnTest`, и предоставляет встроенную веб-панель в локальной сети роутера.

Демон использует **Mihomo (Clash.Meta)** как единое прокси-ядро, поддерживая VLESS (Reality/xhttp), VMess, Trojan, Shadowsocks, ShadowsocksR, Snell, HTTP, SOCKS, AnyTLS, Hysteria v1/v2 (port hopping), WireGuard, TUIC, SSH, MASQUE, OpenVPN и Tailscale. Transparent proxying через iptables NAT REDIRECT (TCP) + TPROXY (UDP) — без tun2socks, без TUN-устройства.

## Как это работает

```
Устройство на Keenetic-политике "HincyRay"
         |
         v
  iptables nat PREROUTING
  (матч по policy connmark)
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
  Активный outbound (VLESS/VMess/Trojan/SS/Hy2/WG/TUIC)
         |
         v
  Интернет
```

Устройства, не назначенные на политику, используют обычный маршрут — основная сеть не затрагивается.

### Выживание при ndm firewall reload

Демон `ndm` в Keenetic пересоздаёт все iptables chains при изменениях конфигурации, событиях WAN и обновлении DHCP. HincyRay устанавливает hook-скрипт в `/opt/etc/ndm/netfilter.d/hincyray.sh`, который **ndm вызывает сам** после каждой перезагрузки firewall, переустанавливая все правила атомарно. Watchdog каждые 10 секунд — запасная страховка.

## Возможности

### v0.15.2

- **Сортировка профилей по клику на заголовок**: клик по сортируемой колонке (Балл, Задержка, Скорость, EWMA и др.) — сортировка по возрастанию ▲, повторный клик — по убыванию ▼. Состояние сохраняется при 5-секундном обновлении.
- **Сохранение свёрнутых групп**: состояние сворачивания групп профилей сохраняется в `localStorage` — переживает перезагрузку страницы.
- **Таблица избранных**: полноценная компактная таблица со всеми метриками и кнопками Выбрать/Переименовать/Удалить, заменяет старый текстовый список.
- **Фикс ID/групп профилей**: `normalizeProfiles` мержит profiles + stats — ID отображаются корректно (0, 1, 2…), группы показывают дружелюбные имена вместо URL подписки.
- **Компактная таблица профилей**: уменьшены padding и шрифт; порядок колонок изменён (Балл и кнопки ближе к началу, Адрес в конце).
- **Живые обновления трафика/памяти**: карточки статуса прокси теперь загружают реальные данные из `/api/traffic` и `/api/mihomo-api/memory` каждые 5 секунд.
- **Фикс теста задержки**: пустое тело POST больше не вызывает "invalid JSON" — демон использует значения по умолчанию.
- **Подключение WebDAV**: кнопки загрузки/скачивания теперь читают поля ввода и отправляют JSON-тело.

### v0.15.1

- **Fluent/Acrylic веб-панель**: новая встроенная веб-панель (`src/webui/index.html`), встраивается через `include_str!`. 7 групп навигации, 24 пункта сайдбара, 16 подсекций Mihomo Features, кастомные Acrylic-дропдауны, RU/EN i18n (~180 пар), светлая/тёмная тема со слайдером яркости, тултипы, login-оверлей, confirm-модалка, toast-уведомления, адаптивная нижняя навигация для мобильных, real `fetch()` API-хелпер с Bearer-авторизацией, production data-лоадеры для всех 87 эндпоинтов демона, data-URI лого (без внешних ассетов).
- **Фикс EC-стриминга**: `first_stream_json()` парсит первый JSON-снапшот из бесконечных стрим-эндпоинтов Mihomo (`/traffic`, `/memory`), успешен даже когда `curl --max-time` завершается с кодом 28 (таймаут на бесконечном стриме).
- **Опциональные EC-эндпоинты**: `/api/mihomo-api/configs/geo` и `/api/mihomo-api/rules/disable` теперь возвращают `{"supported":false}` (200) при ответе 405 от Mihomo EC, вместо 502 транспортной ошибки.
- **Фикс мерцания UI**: `updateStatusUI` разделён на `updateStatusCards` (карточки ядра/профиля/версии) и `updateRoutingForm` (поля формы роутинга) — предотвращает перезапись карточек частичными данными при `loadRouting()`.

### v0.15.0

- **10 новых outbound-протоколов**: ShadowsocksR, Snell, HTTP proxy, SOCKS, AnyTLS, Hysteria v1, SSH, MASQUE, OpenVPN, Tailscale. Парсинг share-ссылок в `profiles.rs` + Mihomo YAML-билдеры в `mihomo_config.rs`.
- **Relay proxy groups**: `ProxyGroupType::Relay` для цепочечных proxy-групп.
- **DNS parity-поля**: `fake-ip-filter-mode`, `fake-ip-ttl`, `use-hosts`, `use-system-hosts`, `default-nameserver`, `proxy-server-nameserver-policy`, `direct-nameserver-follow-policy`, `ecs`, `ecs-override`, `disable-ipv4/6`, `disable-qtype-N`.
- **Типизированные правила**: `MihomoRuleConfig` для `IN-NAME`, `IN-USER`, `PROCESS-*`, `UID`, `DSCP`, `RULE-SET` и других типов правил Mihomo — добавляются перед raw-правилами.
- **EC API parity-эндпоинты**: `GET /api/mihomo-api/version`, `/configs`, `/configs/geo`, `/rules`, `/providers/proxies`, `/providers/rules`; `POST /api/mihomo-api/cache/fakeip/flush`, `/cache/dns/flush`, `/rules/disable`.
- **Маппинг Hysteria v1**: `hysteria://` / `hy://` теперь маппится на `Protocol::Hysteria` (v1); `hysteria2://` / `hy2://` остаётся `Protocol::Hysteria2`.

### v0.14.0

- **Rule Trace**: `POST /api/routing/trace` объясняет локальное решение роутинга для host/IP/port/protocol/source IP. Runtime-матчи `geosite:*`, `geoip:*` и `rule-set:*` помечаются как кандидаты для оценки Mihomo, а не угадываются локально.
- **Sub-Store Lite**: лёгкая чистка уже распарсенных профилей — include/exclude-фильтры, правила переименования, дедуп по protocol/address/port, сортировка по name/group/protocol/address/score/latency и backup-before-apply. `GET/POST /api/substore-lite`, `POST /api/substore-lite/apply`.
- **Smart Auto-Select 2.0**: EWMA score/latency/download, минимальное число успешных проверок, штраф за ошибки и cooldown для падающих профилей. Настраивается через `/api/auto-settings`.
- **Бэкапы и WebDAV**: локальные state-бэкапы create/list/restore/delete плюс WebDAV upload/download. Restore валидирует JSON состояния, создаёт pre-restore backup и безопасно регенерирует runtime-конфиг.
- **Diagnostics & Recovery**: секция веб-панели для rule trace, DNS diagnostics, unlock checks, Sub-Store Lite, бэкапов, WebDAV и закрытия соединений.
- **Unlock checker + DNS diagnostics**: `POST /api/unlock-check` проверяет популярные сервисы; `GET /api/dns/diagnostics` проверяет локальный resolver и доступность Mihomo DNS/API.
- **Scheduled maintenance**: watchdog может периодически создавать backup, обновлять подписки, перезапускать Mihomo и закрывать соединения.
- **Connection control**: `POST /api/mihomo-api/connections/close` закрывает все соединения или фильтрует по id, host, source IP.
- **Фикс wildcard External Controller**: демон ходит на loopback при wildcard bind (`0.0.0.0`, `[::]`, `:port`). RU Direct presets теперь используют только `geoip:RU`, чтобы не зависеть от отсутствующего `geosite:ru`.

### v0.13.0

- **REJECT target**: блокировка совпавших доменов, IP, портов или per-device routes через Mihomo `REJECT`.
- **Routing presets**: RU Direct, Ad Block, Only Web VPN, Block Social, RU Direct + Ad Block. `GET /api/routing-presets`, `POST /api/routing-presets/apply`.
- **Web UI authentication**: настройки логина/пароля, in-memory session tokens и Bearer auth.
- **Mihomo backend для desktop benchmark**: десктопная диагностика использует Mihomo для всех поддержанных протоколов, включая WireGuard и TUIC.

### v0.12.0

- **Hysteria2 port hopping**: query-параметры `mport`/`ports` и `hopInterval`/`hop_interval` парсятся из share-ссылок, попадают в Mihomo как поля `ports` + `hop-interval`.
- **Profile CRUD API**: `POST /api/profiles/add` (парсинг share-ссылки), `POST /api/profiles/delete` (удаление по ID, реиндексация), `POST /api/profiles/update` (переименование, тоггл block_quic). Только бэкенд, UI ожидает редизайн.
- **Автообновление подписок**: watchdog Phase 7 обновляет все подписки с настраиваемым интервалом. По умолчанию отключено. Если активный профиль удалён при обновлении, авто-выбирается лучший доступный.
- **Статистика трафика**: накопительные счётчики байт upload/download, сохраняемые в state. Скорость в реальном времени через Mihomo `/traffic` API. `GET /api/traffic`, `GET /api/mihomo-api/traffic`, `GET /api/mihomo-api/memory`.
- **Лог соединений**: сохраняемый лог соединений, прошедших через прокси (хост, исходный IP, chain, правило, upload/download). Лимит 500 записей. `GET /api/connection-log`.
- **API speed test**: `POST /api/mihomo-api/speed-test` скачивает файл 10 МБ через SOCKS-прокси и возвращает Mbps, затраченное время и количество байт. URL по умолчанию: Cloudflare.
- **Per-device routing**: маршрутизация конкретных устройств (по IP) на другую цель (DIRECT, активный прокси, конкретный профиль). Реализовано как правила `SRC-IP-CIDR`, добавляемые перед общими правилами роутинга. ARP-скан для обнаружения устройств. `GET /api/device-routes`, `POST /api/device-routes`, `POST /api/device-routes/delete`, `GET /api/devices`, `POST /api/device-routes/apply`.

### v0.11.0

- **Mihomo parity pack**: правила DOMAIN-KEYWORD, правила IP-SUFFIX/SRC-IP-CIDR/SRC-IP-SUFFIX, правила SRC-PORT/IN-PORT, ws-opts early-data, grpc-opts advanced, mTLS certificate/private-key, ECH query-server-name, nameserver-policy, include-all/include-all-proxies для proxy groups, raw-правила логики AND/OR/NOT.

### v0.10.0

- **Поддержка протоколов WireGuard + TUIC**: парсинг share-ссылок `wireguard://`/`wg://` и `tuic://`. Mihomo outbounds с private key, public key, allowed-ips, reserved, MTU (WG) и uuid, password, congestion controller, udp-relay-mode (TUIC).
- **ECH (Encrypted Client Hello)**: query-параметр `ech` парсится из VLESS/Trojan-ссылок и VMess JSON. Добавляет `ech-opts` с enable + опциональным base64 config + query-server-name.
- **xhttp advanced**: no-grpc-header, x-padding-*, uplink-http-method, session-*, seq-*, uplink-data-*, sc-max-each-post-bytes, sc-min-posts-interval-ms, XMUX reuse settings.
- **Sub-rules**: именованные группы правил через `SubRuleConfig`. `GET/POST /api/mihomo-features` включает конфигурацию sub-rules.
- **Правила GEOIP/IP-ASN**: префиксы `geoip:`, `geoip-asn:`/`ip-asn:`, `src-geoip:`, `src-ip-asn:` в правилах роутинга. `reality-opts.support-x25519mlkem768`.

### v0.9.1

- **Интеграция External Controller API**: клиентские функции `mihomo_api_get()`, `mihomo_api_get_json()`, `mihomo_api_delay()`. Прокси-эндпоинты `GET /api/mihomo-api/proxies`, `GET /api/mihomo-api/connections`, `POST /api/mihomo-api/delay`.
- **Фильтрация proxy groups**: `filter`, `exclude_filter`, `exclude_type`, `include_all_providers` для выбора узлов в больших наборах профилей. `tcp_concurrent` (подключение ко всем IP, побеждает первый).
- **Watchdog 3-режимный failover**: (1) proxy_group включён — делегирование Mihomo native; (2) external controller — API delay test; (3) fallback — SOCKS curl health check.
- **Веб-панель "Proxy Status"**: живое состояние групп, соединения, delay test.

### v0.9.0

- **Расширенные возможности Mihomo**: мастер-структура `MihomoFeatures`. Proxy groups (url-test/fallback/load-balance/select), external controller (REST API), NTP, proxy/rule providers, smux, улучшения DNS (cache-algorithm=arc, prefer-h3, respect-rules), улучшения sniffer, experimental, per-proxy defaults, tunnels, hosts, authentication. `GET/POST /api/mihomo-features`. `domain_rule()` поддерживает префиксы `regex:` и `wildcard:`.

### v0.8.0

- **Миграция на Mihomo**: заменяет Xray + sing-box как единое прокси-ядро. Все протоколы обрабатываются одним бинарником. Сниффер включён, DNS в режиме fake-ip. Конфиг генерируется как YAML.
- **Автообновление Mihomo**: проверка GitHub releases через SOCKS-прокси, автоматическая загрузка и установка новых бинарников. Резервная копия `.bak`, откат при ошибке.
- **Исправления transparent proxy**: DNS всегда включён, TPROXY порт 10811, `geo-auto-update: false`, требуется `geoip.metadb`, stdout в log-файл.

### v0.7.0

- **NAT REDIRECT + TPROXY**: iptables transparent proxy через Keenetic traffic policy connmarks. Без tun2socks, без TUN-устройства. В 9-35× быстрее tun2socks.
- **Интеграция с Keenetic RCI**: запрашивает connmark политики, авто-создаёт политику, если не найдена.
- **ndm hook-скрипт**: авто-генерируется, вызывается ndm после каждой перезагрузки firewall.
- **Переключатель QUIC**: Block (по умолчанию) или Proxy (через TPROXY).
- **Авто-загрузка kernel modules**: `xt_TPROXY`, `xt_socket`, `xt_comment`.

### v0.6.0–v0.6.1

- **Always-on watchdog**: перезапуск ядра с exponential backoff, мониторинг firewall-правил.
- **Health-check failover**: 3 последовательных сбоя → переключение на следующий лучший профиль.
- **Auto-benchmark + auto-select**: запланированный бенчмарк, переключение на профиль с наивысшим score.
- **Graceful shutdown**: SIGTERM/SIGINT останавливает ядро, удаляет iptables, сохраняет state.
- **Восстановление после повреждения state**: повреждённый `state.json` → бэкап, свежее состояние.
- **Системный мониторинг**: CPU/RAM/temp/load/uptime через `/proc` + `/sys`.
- **Интерактивный атомарный установщик**: `scripts/hincyray-install.sh`.

### v0.1–v0.5

- **Поддержка протоколов**: VLESS (Reality/TLS/xhttp), VMess (base64-JSON, WS/gRPC/TCP), Trojan, Shadowsocks, Hysteria2, WireGuard, TUIC.
- **HWID-фингерпринт**: настраиваемая идентификация устройства для запросов подписок Happ.
- **Защита от утечек DNS**: удалённые DNS через прокси, локальные DNS для прямых доменов.
- **Портовый роутинг**: режимы all / allow_list / deny_list.
- **GeoIP/GeoSite**: настраиваемый путь к geo-ассетам.
- **WiFi traffic split**: правила матчат geosite, домены, IP/CIDR, geoip, порты, тип сети.
- **Бенчмарк/статы/избранное/подписки**: методы TCP/HEAD/GET, метрики по профилям, обновление подписок.

## Требования

### Роутер (Keenetic Giga KN-1012 или аналогичный ARM64)

- Entware с `curl`, `jq`, `mihomo`
- Файл `geoip.metadb` в geo-директории (необходим Mihomo; не может скачать с заблокированного GitHub)
- Kernel modules: `xt_TPROXY.ko`, `xt_socket.ko`, `xt_comment.ko`
- Keenetic traffic policy (авто-создаётся HincyRay или вручную в Keenetic Web UI)
- `iptables` с поддержкой `connmark`, `REDIRECT`, `TPROXY`, `socket`, `comment`

### Десктоп (macOS)

- `mihomo` в `PATH` для desktop benchmark.

## Сборка

### Роутер-демон

```bash
cargo zigbuild --release --no-default-features --bin hincyray --target aarch64-unknown-linux-gnu.2.27
patchelf --set-interpreter /opt/lib/ld-linux-aarch64.so.1 --set-rpath /opt/lib \
  target/aarch64-unknown-linux-gnu/release/hincyray
```

### Десктоп-диагностика

```bash
cargo build --release --bin xray-vpn-test
```

### Проверка качества

```bash
cargo fmt --all
cargo check --all-targets --all-features
cargo test --all-targets --all-features   # 295 тестов
cargo clippy --all-targets --all-features   # 0 предупреждений
```

## Установка

Используйте интерактивный атомарный установщик:

```bash
sh scripts/hincyray-install.sh
```

Установщик проверяет kernel modules, создаёт директорию ndm hook, устанавливает бинарник, init-скрипт и состояние по умолчанию. Staging → backup → atomic `mv` → verify → commit/rollback.

См. [`docs/hincyray-entware-install.md`](docs/hincyray-entware-install.md) для ручной установки.

## Веб-панель

```
http://<ip-роутера>:8088/
```

Fluent/Acrylic-дизайн с 7 группами навигации, 24 пунктами сайдбара, RU/EN i18n, светлой/тёмной темой. Статус, профили, бенчмарк, импорт, подписки, правила роутинга, per-device routing, управление firewall, DNS, диагностика, бэкапы, HWID, системный монитор, обновление Mihomo, возможности Mihomo, статус прокси, трафик и соединения, логи — всё на одной странице. Автообновление каждые 5 секунд. Без внешних CDN и сборки.

### Переменные окружения

| Переменная | По умолчанию |
|---|---|
| `HINCYRAY_LISTEN` | `0.0.0.0:8088` |
| `HINCYRAY_STATE` | `/opt/etc/hincyray/state.json` (Entware) |
| `HINCYRAY_MIHOMO_CONFIG` | `mihomo-config.yaml` рядом с файлом состояния |

## HTTP API

| Метод | Путь | Назначение |
|---|---|---|
| `GET` | `/` | Встроенная веб-панель |
| `GET` | `/api/health` | Здоровье сервиса + версия |
| `GET` | `/api/status` | Активный профиль, статус ядра, сплит-роутинг, DNS, HWID, mihomo_version, update_available_version, proxy_group_enabled, ec_enabled |
| `GET` | `/api/profiles` | Импортированные профили |
| `POST` | `/api/profiles/import` | Импорт share-ссылок / URL подписки / Xray JSON |
| `POST` | `/api/profiles/add` | Добавить одиночный профиль из raw share-ссылки |
| `POST` | `/api/profiles/delete` | Удалить профиль по ID |
| `POST` | `/api/profiles/update` | Обновить имя профиля и/или block_quic |
| `POST` | `/api/profiles/block-quic` | Тоггл флага block_quic на профиле |
| `POST` | `/api/active-profile` | Установка активного профиля, регенерация конфига, перезапуск ядра |
| `GET` | `/api/mihomo-config` | Сгенерированный Mihomo-конфиг |
| `POST` | `/api/core/start` | Запуск ядра Mihomo |
| `POST` | `/api/core/stop` | Остановка ядра Mihomo |
| `POST` | `/api/core/restart` | Перезапуск ядра Mihomo |
| `GET` | `/api/bench/status` | Статус бенчмарка |
| `POST` | `/api/bench/start` | Запуск бенчмарка (tcp/head/get) |
| `POST` | `/api/bench/stop` | Отмена бенчмарка |
| `GET` | `/api/stats` | Метрики по профилям |
| `POST` | `/api/favorites/toggle` | Тоггл избранного |
| `GET` | `/api/favorites` | Список избранного |
| `GET` | `/api/subscriptions` | Сохранённые подписки |
| `POST` | `/api/subscriptions/refresh` | Обновить все подписки |
| `POST` | `/api/subscriptions/refresh-one` | Обновить отдельную подписку по URL |
| `POST` | `/api/subscriptions/delete` | Удалить подписку и её профили |
| `GET` | `/api/routing` | Настройки роутинга + правила + каталог |
| `POST` | `/api/routing/settings` | Сохранить настройки роутинга |
| `POST` | `/api/routing/rules` | Сохранить правила роутинга |
| `POST` | `/api/routing/apply` | Перегенерировать конфиг + перезапуск ядра + перезапуск firewall |
| `GET` | `/api/routing-presets` | Встроенные routing presets |
| `POST` | `/api/routing-presets/apply` | Применить routing preset |
| `POST` | `/api/routing/trace` | Объяснить локальное решение роутинга для host/IP/port/source запроса |
| `GET` | `/api/routing/firewall-status` | Проверка здоровья firewall/iptables/ndm-hook |
| `POST` | `/api/routing/firewall-start` | Запустить firewall |
| `POST` | `/api/routing/firewall-stop` | Остановить firewall |
| `GET` | `/api/device-routes` | Список правил per-device routing |
| `POST` | `/api/device-routes` | Добавить/обновить маршрут устройства (upsert по IP) |
| `POST` | `/api/device-routes/delete` | Удалить маршрут устройства по IP |
| `GET` | `/api/devices` | Сканировать устройства LAN через `/proc/net/arp` |
| `POST` | `/api/device-routes/apply` | Перегенерировать конфиг + перезапуск ядра |
| `GET` | `/api/dns` | Настройки DNS anti-leak |
| `POST` | `/api/dns` | Сохранить DNS-настройки |
| `GET` | `/api/dns/leak-test` | Тест на утечку DNS |
| `GET` | `/api/dns/diagnostics` | Диагностика resolver + Mihomo DNS |
| `GET` | `/api/logs` | Хвост логов Mihomo (последние 200 строк) |
| `GET` | `/api/system` | CPU/RAM/temp/load/uptime |
| `GET` | `/api/auto-settings` | Auto-select, auto-switch, auto-benchmark, auto-refresh настройки |
| `POST` | `/api/auto-settings` | Сохранить авто-настройки |
| `GET` | `/api/hwid` | Конфиг HWID-фингерпринта |
| `POST` | `/api/hwid` | Сохранить HWID-фингерпринт |
| `GET` | `/api/update/status` | Версия Mihomo, доступное обновление, настройки автообновления |
| `POST` | `/api/update/check` | Проверка GitHub releases на наличие новой версии Mihomo |
| `POST` | `/api/update/apply` | Скачать и установить доступное обновление Mihomo |
| `POST` | `/api/update/settings` | Сохранить auto-update enabled / интервал |
| `GET` | `/api/mihomo-features` | Конфиг MihomoFeatures (proxy groups, EC, NTP, providers и т.д.) |
| `POST` | `/api/mihomo-features` | Сохранить конфиг MihomoFeatures |
| `GET` | `/api/mihomo-api/proxies` | Проксирование `GET /proxies` на Mihomo REST API |
| `GET` | `/api/mihomo-api/connections` | Проксирование `GET /connections` на Mihomo REST API |
| `POST` | `/api/mihomo-api/connections/close` | Закрыть все/отфильтрованные соединения Mihomo |
| `POST` | `/api/mihomo-api/delay` | Тест delay прокси через Mihomo API |
| `GET` | `/api/mihomo-api/traffic` | Проксирование `GET /traffic` на Mihomo REST API |
| `GET` | `/api/mihomo-api/memory` | Проксирование `GET /memory` на Mihomo REST API |
| `GET` | `/api/mihomo-api/version` | Проксирование `GET /version` на Mihomo REST API |
| `GET` | `/api/mihomo-api/configs` | Проксирование `GET /configs` на Mihomo REST API |
| `GET` | `/api/mihomo-api/configs/geo` | Проксирование `GET /configs/geo` на Mihomo REST API |
| `GET` | `/api/mihomo-api/rules` | Проксирование `GET /rules` на Mihomo REST API |
| `GET` | `/api/mihomo-api/providers/proxies` | Проксирование `GET /providers/proxies` на Mihomo REST API |
| `GET` | `/api/mihomo-api/providers/rules` | Проксирование `GET /providers/rules` на Mihomo REST API |
| `POST` | `/api/mihomo-api/cache/fakeip/flush` | Очистка fake-ip кэша Mihomo |
| `POST` | `/api/mihomo-api/cache/dns/flush` | Очистка DNS кэша Mihomo |
| `POST` | `/api/mihomo-api/rules/disable` | Отключение правила Mihomo по индексу |
| `POST` | `/api/mihomo-api/speed-test` | Скачать 10 МБ через SOCKS-прокси, вернуть Mbps |
| `POST` | `/api/unlock-check` | Проверить доступность популярных сервисов через proxy path |
| `GET` | `/api/substore-lite` | Настройки Sub-Store Lite |
| `POST` | `/api/substore-lite` | Сохранить настройки Sub-Store Lite |
| `POST` | `/api/substore-lite/apply` | Применить Sub-Store Lite cleanup с backup |
| `GET` | `/api/backups` | Список state-бэкапов |
| `POST` | `/api/backups/create` | Создать state backup |
| `POST` | `/api/backups/restore` | Восстановить state backup |
| `POST` | `/api/backups/delete` | Удалить state backup |
| `POST` | `/api/backups/webdav-upload` | Загрузить backup в WebDAV |
| `POST` | `/api/backups/webdav-download` | Скачать и восстановить backup из WebDAV |
| `POST` | `/api/auth/login` | Создать session token веб-панели |
| `POST` | `/api/auth/logout` | Удалить session token веб-панели |
| `GET` | `/api/auth-settings` | Настройки Web UI authentication |
| `POST` | `/api/auth-settings` | Сохранить настройки Web UI authentication |
| `GET` | `/api/traffic` | Накопительная + realtime статистика трафика |
| `GET` | `/api/connection-log` | Сохраняемый лог соединений (лимит 500 записей) |

## WiFi VPN-сегмент (опционально)

- `scripts/wifi-segment-setup.sh` — создаёт SSID `HincyRay-VPN` на `192.168.2.0/24` через Keenetic `ndmc`.
- Назначьте каждое устройство, которое должно идти через VPN, на Keenetic traffic policy "HincyRay". **Одного SSID/подсети недостаточно**: HincyRay матчит пакеты по policy connmark.
- Демон управляет всем transparent proxying через `FirewallManager`:
  1. Запрашивает connmark политики через Keenetic RCI API.
  2. Устанавливает iptables nat HINCYRAY chain (TCP REDIRECT на порт 10810) по connmark.
  3. Устанавливает iptables mangle HINCYRAY_UDP chain (UDP TPROXY на порт 10811) если TPROXY доступен.
  4. Устанавливает DNS DNAT-правила (порт 53 → 127.0.0.1:1053).
  5. Генерирует ndm hook-скрипт для выживания при firewall reload.
  6. Watchdog переустанавливает правила при отсутствии.

### Per-device routing

Устройства, назначенные на политику HincyRay, могут индивидуально маршрутизироваться на другую цель (DIRECT, активный прокси или конкретный профиль). Правила добавляются как `SRC-IP-CIDR,<ip>/32,<target>` перед общими правилами роутинга, обеспечивая приоритет правил для конкретных устройств.

Используйте секцию "Per-Device Routing" в веб-панели:
1. Нажмите "Scan devices (ARP)" для обнаружения устройств LAN.
2. Добавьте маршрут: выберите IP устройства, имя и цель.
3. Нажмите "Apply Mihomo config" для активации.

## Документация

- [`docs/benchmark-tun2socks-vs-redirect.md`](docs/benchmark-tun2socks-vs-redirect.md) — бенчмарк tun2socks vs NAT REDIRECT (ускорение 9-35×).
- [`docs/hincyray-entware-install.md`](docs/hincyray-entware-install.md) — runbook установки на Entware.
- [`docs/hincyray-v0.1-status.md`](docs/hincyray-v0.1-status.md) — статус версий.
- [`docs/keenetic-client-roadmap.md`](docs/keenetic-client-roadmap.md) — roadmap продукта.

## Миграция состояния

Существующий `state.json` из любой предыдущей версии автоматически мигрируется:
- v0.7→v0.8: `xray_path`→`mihomo_path`, `singbox_path` удалено, добавлены поля auto-update.
- v0.8→v0.9: добавлен `mihomo_features` со значениями по умолчанию.
- v0.9→v0.10: изменений state нет (только поддержка новых протоколов).
- v0.10→v0.11: `dns_nameserver_policy`, `raw_rules` добавлены в MihomoFeatures.
- v0.11→v0.12: `auto_refresh_enabled`, `auto_refresh_interval_hours`, `last_auto_refresh_unix`, `traffic_total_up_bytes`, `traffic_total_down_bytes`, `connection_log`, `device_routes` добавлены со значениями по умолчанию.
- v0.12→v0.13: добавлен `web_ui_auth` с disabled default; routing targets принимают `reject`.
- v0.13→v0.14: добавлены `sub_store_lite`, `smart_select`, `maintenance` и EWMA/cooldown profile stats со значениями по умолчанию.
- v0.14→v0.15: новые варианты `Protocol` (ShadowsocksR, Snell, Http, Socks, AnyTls, Hysteria, Ssh, Masque, OpenVpn, Tailscale), `ProxyGroupType::Relay`, DNS parity-поля (`dns_fake_ip_filter_mode`, `dns_fake_ip_ttl`, `dns_use_hosts`, `dns_use_system_hosts`, `dns_default_nameserver`, `dns_proxy_server_nameserver_policy`, `dns_direct_nameserver_follow_policy`, `dns_ecs`, `dns_ecs_override`, `dns_disable_ipv4`, `dns_disable_ipv6`, `dns_disable_qtypes`), `typed_rules` (Vec<MihomoRuleConfig>) добавлены в MihomoFeatures со значениями по умолчанию.

Ручное вмешательство не требуется.

## Лицензия

MIT
