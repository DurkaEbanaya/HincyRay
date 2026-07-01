# HincyRay v0.8.0

[English](README.md) | [Русский](README.ru.md)

---

HincyRay — лёгкий VPN/proxy-клиент для роутеров Keenetic. Поставляет роутер-демон (`hincyray`), который переиспользует парсер, формулу оценки качества и модули конфигурации из десктопного инструмента `XrayVpnTest`, и предоставляет встроенную веб-панель в локальной сети роутера.

**v0.7 заменил tun2socks на iptables NAT REDIRECT + TPROXY** — ускорение throughput в 9-35× (бенчмарк: [`docs/benchmark-tun2socks-vs-redirect.md`](docs/benchmark-tun2socks-vs-redirect.md)). Без TUN-устройства, без userspace TCP-стека, без бинарника `tun2socks`.

**v0.8 заменяет связку Xray + sing-box на Mihomo (Meta) как единое прокси-ядро.** Один бинарник обрабатывает все протоколы (VLESS/VMess/Trojan/Shadowsocks/Hysteria2), включает сниффер доменов (HTTP/TLS/QUIC) и DNS в режиме fake-ip. Больше не нужен ни Xray, ни sing-box на роутере. Добавлено автообновление Mihomo через GitHub releases (через локальный SOCKS-прокси, так как GitHub заблокирован с роутера) и исправлены пять багов transparent proxy, выявленных через E2E-тестирование с Pixel 6a.

## Как это работает

```
Устройство на Keenetic-политике "HincyRay"
         │
         ▼
  iptables nat PREROUTING
  (матч по policy connmark)
         │
    ┌────┴────┐
    ▼         ▼
  TCP       UDP
    │         │
  REDIRECT  TPROXY
  →10810    →10811
    │         │
    ▼         ▼
  Mihomo redir/tproxy inbounds
  (redir-in TCP, tproxy-in UDP)
         │
         ▼
  Активный VLESS/VMess/Trojan/SS/Hysteria2 outbound
         │
         ▼
  Интернет
```

Устройства, не назначенные на политику, используют обычный маршрут — основная сеть не затрагивается.

TCP-трафик перенаправляется через `nat REDIRECT` на порт 10810 (redir-listener), UDP — через `mangle TPROXY` на порт 10811 (tproxy-listener). Разные порты исключают конфликт TCP-бинда между redir и tproxy listener'ами Mihomo.

### Выживание при ndm firewall reload

Демон ndm в Keenetic пересоздаёт все iptables chains при изменениях конфигурации, событиях WAN и обновлении DHCP. HincyRay устанавливает hook-скрипт в `/opt/etc/ndm/netfilter.d/hincyray.sh`, который **ndm вызывает сам** после каждой перезагрузки firewall, переустанавливая все правила атомарно. Watchdog каждые 10 секунд — запасная страховка.

## Возможности

- **v0.8 единое ядро Mihomo**: роутер-демон использует Mihomo (Meta) как единственное прокси-ядро. `src/mihomo_config.rs` генерирует YAML-конфиг со всеми протоколами (VLESS/VMess/Trojan/SS/Hysteria2), сниффером доменов (HTTP/TLS/QUIC) и DNS в режиме fake-ip. Xray и sing-box больше не нужны на роутере. `src/xray_config.rs` оставлен только для десктоп-тестера.
- **v0.8 автообновление Mihomo**: проверка GitHub releases через локальный SOCKS-прокси (GitHub заблокирован с роутера). Watchdog Phase 6: автопроверка по расписанию + автоустановка. Замена бинарника через unlink+copy (избегает ETXTBSY), резервная копия `.bak`, откат при ошибке. Веб-панель: секция "Mihomo Update" с карточками версий, кнопками check/apply и тумблером автообновления.
- **v0.8 исправления transparent proxy**: пять багов, выявленных через E2E-тестирование с Pixel 6a: (1) DNS всегда включён в router-конфиге — firewall безусловно DNATит DNS на порт 1053; (2) TPROXY listener перенесён на порт 10811 (раньше конфликтовал с redir TCP bind на 10810); (3) `geo_dir_from_state` возвращает саму директорию (раньше возвращал parent); (4) `geo-auto-update: false` + требуется файл `geoip.metadb` (Mihomo виснет, пытаясь скачать с заблокированного GitHub); (5) stdout Mihomo направлен в log-файл (раньше `/dev/null`, логи были пустые).
- **v0.7.0 Fixed применение active profile**: `POST /api/active-profile` применяет выбранный профиль к state, сгенерированному конфигу, запущенному ядру и сохранённому state как одну операцию. Ядро не делает hot-reload конфиг-файлов, поэтому выбор профиля перезапускает ядро.
- **v0.7.0 Fixed failover selection**: auto-switch запоминает профили, уже провалившие health-check в текущем outage, и может использовать профиль с `success_count > 0` / `score = 0` как низкоприоритетный fallback вместо цикла по stale winner'ам.
- **v0.7 NAT REDIRECT + TPROXY**: iptables transparent proxy через Keenetic traffic policy connmark. TCP через `nat REDIRECT`, UDP через `mangle TPROXY`. Без tun2socks, без TUN.
- **v0.7 интеграция с Keenetic RCI**: запрашивает `localhost:79/rci/show/ip/policy` для получения connmark политики. Авто-создаёт политику, если не найдена.
- **v0.7 ndm hook-скрипт**: авто-генерируется в `/opt/etc/ndm/netfilter.d/hincyray.sh`, вызывается ndm после каждой перезагрузки firewall. Правила переживают ndm-перезапуски.
- **v0.7 переключатель QUIC**: `Block` (по умолчанию — форсирует TCP fallback) или `Proxy` (через TPROXY). Настраивается глобально и по правилам в веб-панели.
- **v0.7 авто-загрузка kernel modules**: `xt_TPROXY`, `xt_socket`, `xt_comment` загружаются при старте. TPROXY недоступен → TCP-only REDIRECT + QUIC блокируется.
- **v0.6 always-on watchdog**: отслеживает ядро Mihomo и перезапускает с exponential backoff (10с → 300с max). Также мониторит firewall-правила и переустанавливает при отсутствии.
- **v0.6 health-check failover**: проверяет SOCKS-туннель каждые 10 секунд. После 3 сбоев переключается на следующий лучший профиль по score.
- **v0.6 auto-benchmark**: планирует TCP benchmark для всех профилей каждые N часов.
- **v0.6 auto-select**: после benchmark переключается на профиль с наивысшим score.
- **v0.6 graceful shutdown**: SIGTERM/SIGINT останавливает Mihomo, удаляет iptables-правила, очищает ndm hook, сохраняет состояние.
- **v0.6 восстановление после повреждения state**: повреждённый `state.json` → бэкап в `.corrupt`, создаётся свежее состояние.
- **v0.5 поддержка протоколов**: VLESS (Reality/TLS/XHTTP), VMess (base64-JSON, WS/gRPC/TCP), Trojan (TLS), Shadowsocks, Hysteria2. WireGuard отклоняется с понятной ошибкой.
- **v0.5 HWID-фингерпринт**: настраиваемая идентификация устройства для запросов подписок Happ.
- **v0.5 защита от утечек DNS**: удалённые DNS через прокси, локальные для прямых доменов. `GET /api/dns/leak-test` для проверки.
- **v0.5 портовый роутинг**: режимы `all` / `allow_list` / `deny_list` с поправильным матчингом портов и сети (TCP/UDP).
- **v0.5 GeoIP/GeoSite**: настраиваемый путь к geo-директории, переменная `XRAY_LOCATION_ASSET`.
- **v0.3 сплит-роутинг WiFi**: правила матчат `geosite:*`, домены, IP/CIDR, `geoip:*`, порты, тип сети. Цели: `direct`, активный, лучший или фиксированный профиль.
- **v0.2 бенчмарк/статы/избранное/подписки**: TCP/HEAD/GET методы, метрики по профилям, избранное по raw-ссылке, обновление подписок.

## Требования

### Роутер (Keenetic Giga KN-1012 или аналогичный ARM64)

- Entware с `curl`, `jq`, `mihomo`
- Kernel modules: `xt_TPROXY.ko`, `xt_socket.ko`, `xt_comment.ko` (обычно в `/lib/modules/$(uname -r)/`)
- Файл `geoip.metadb` в geo-директории (необходим Mihomo для fake-ip DNS; `geo-auto-update: false`, так как GitHub заблокирован)
- Keenetic traffic policy (авто-создаётся HincyRay или вручную в Keenetic Web UI)
- `iptables` с поддержкой `connmark`, `REDIRECT`, `TPROXY`, `socket`, `comment`

### Десктоп (macOS)

- `sing-box` и `xray` в `PATH` (`brew install sing-box xray`) — только для десктоп-тестера, не для роутера

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
cargo fmt
cargo test
cargo clippy --all-targets --all-features
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

Статус, профили, бенчмарк, импорт, подписки, правила роутинга, управление firewall, DNS, HWID, системный монитор, логи, обновление Mihomo — всё на одной странице. Автообновление каждые 5 секунд. Без внешних CDN и сборки.

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
| `GET` | `/api/status` | Активный профиль, статус ядра, сплит-роутинг, DNS, HWID, версия Mihomo, доступное обновление |
| `GET` | `/api/profiles` | Импортированные профили |
| `POST` | `/api/profiles/import` | Импорт share-ссылок / URL подписки / Xray JSON |
| `POST` | `/api/active-profile` | Установка активного профиля, регенерация конфига, перезапуск ядра, сохранение state |
| `GET` | `/api/mihomo-config` | Сгенерированный Mihomo-конфиг |
| `POST` | `/api/core/start` | Запуск ядра Mihomo |
| `POST` | `/api/core/stop` | Остановка ядра |
| `POST` | `/api/core/restart` | Перезапуск ядра |
| `GET` | `/api/bench/status` | Статус бенчмарка |
| `POST` | `/api/bench/start` | Запуск бенчмарка (tcp/head/get) |
| `POST` | `/api/bench/stop` | Отмена бенчмарка |
| `GET` | `/api/stats` | Метрики по профилям |
| `POST` | `/api/favorites/toggle` | Тоггл избранного |
| `GET` | `/api/favorites` | Список избранного |
| `GET` | `/api/subscriptions` | Сохранённые подписки |
| `POST` | `/api/subscriptions/refresh` | Обновить все подписки |
| `GET` | `/api/routing` | Настройки и правила роутинга, каталог |
| `POST` | `/api/routing/settings` | Сохранить настройки (quic_mode, port_mode и т.д.) |
| `POST` | `/api/routing/rules` | Сохранить правила роутинга |
| `POST` | `/api/routing/apply` | Перегенерировать конфиг + перезапуск ядра + firewall |
| `GET` | `/api/routing/firewall-status` | Статус firewall/iptables/ndm-hook |
| `POST` | `/api/routing/firewall-start` | Запустить firewall (установка iptables + ndm hook) |
| `POST` | `/api/routing/firewall-stop` | Остановить firewall (удаление правил + очистка ndm hook) |
| `GET` | `/api/dns` | Настройки DNS |
| `POST` | `/api/dns` | Сохранить DNS-настройки |
| `GET` | `/api/dns/leak-test` | Тест на утечку DNS |
| `GET` | `/api/hwid` | Конфиг HWID |
| `POST` | `/api/hwid` | Сохранить HWID |
| `GET` | `/api/auto-settings` | Auto-select, auto-switch, интервал auto-benchmark |
| `POST` | `/api/auto-settings` | Сохранить авто-настройки |
| `GET` | `/api/logs` | Хвост логов Mihomo (последние 200 строк) |
| `GET` | `/api/system` | CPU/RAM/temp/load/uptime |
| `GET` | `/api/update/status` | Текущая и доступная версии Mihomo, статус автообновления |
| `POST` | `/api/update/check` | Проверка GitHub releases через SOCKS-прокси |
| `POST` | `/api/update/apply` | Скачать и установить новую версию Mihomo (backup + rollback) |
| `POST` | `/api/update/settings` | Сохранить настройки автообновления (enabled, интервал) |

## WiFi VPN-сегмент (опционально)

- `scripts/wifi-segment-setup.sh` — создаёт SSID `HincyRay-VPN` на `192.168.2.0/24` через Keenetic `ndmc`.
- Назначьте каждое устройство, которое должно идти через VPN, на Keenetic-политику "HincyRay" / "XKeen". **Одного SSID/подсети недостаточно**: HincyRay матчится по policy connmark, который Keenetic ставит только `ip hotspot` host'ам, назначенным на эту политику.
- Демон управляет всем transparent proxying через `FirewallManager`:
  1. Запрашивает connmark политики через Keenetic RCI API.
  2. Устанавливает iptables nat HINCYRAY chain (TCP REDIRECT на порт 10810) по connmark.
  3. Устанавливает iptables mangle HINCYRAY_UDP chain (UDP TPROXY на порт 10811) если TPROXY доступен.
  4. Устанавливает DNS DNAT-правила (порт 53 → 127.0.0.1:1053).
  5. Генерирует ndm hook-скрипт для выживания при firewall reload.
  6. Watchdog переустанавливает правила при отсутствии.

### Обязательное назначение клиента в Keenetic policy

Transparent WiFi routing работает только для host'ов, которым Keenetic ставит connmark traffic policy. Клиент, подключённый к `HincyRay-VPN`, но оставленный в `conform` / default policy, полностью обойдёт HincyRay; counters в `HINCYRAY` останутся нулевыми.

Назначьте клиента в Web UI Keenetic или через `ndmc`:

```bash
# Замените на реальный MAC клиента.
ndmc -c 'ip hotspot host <client-mac> policy Policy0'
ndmc -c 'system configuration save'
```

`Policy0` — внутреннее имя Keenetic для политики, описание которой в тестовой установке было `XKeen`. Проверьте фактическое имя/mark политики на своём роутере:

```bash
curl -s localhost:79/rci/show/ip/policy
```

Проверьте, что host маркируется правильно:

```bash
ndmc -c 'show running-config' | grep -i '<client-mac>'
iptables -t mangle -L _NDM_HOTSPOT_PREROUTING_MANGL -n -v | grep -i '<client-mac>'
iptables -t nat -L HINCYRAY -n -v
```

Ожидаемый результат для VPN-routed host:

```text
host <client-mac> policy Policy0
MARK set 0xffffaaa
CONNMARK save
HINCYRAY ... REDIRECT ... counters растут, когда клиент открывает сайт
```

Если у host'а видно `conform` вместо `policy Policy0`, Keenetic создаст обычный `RETURN` rule для этого MAC, и HincyRay не увидит трафик.

## Документация

- [`docs/benchmark-tun2socks-vs-redirect.md`](docs/benchmark-tun2socks-vs-redirect.md) — бенчмарк tun2socks vs NAT REDIRECT (ускорение 9-35×).
- [`docs/hincyray-entware-install.md`](docs/hincyray-entware-install.md) — runbook установки на Entware.
- [`docs/hincyray-v0.1-status.md`](docs/hincyray-v0.1-status.md) — статус версий.
- [`docs/keenetic-client-roadmap.md`](docs/keenetic-client-roadmap.md) — roadmap продукта.

## Миграция состояния (v0.7 → v0.8)

Существующий `state.json` автоматически мигрируется при загрузке:

- `xray_path` → `mihomo_path` (старое поле удаляется, новое получает значение по умолчанию `mihomo`)
- `xray_config_path` → `mihomo_config_path` (управляется через `HINCYRAY_MIHOMO_CONFIG`)
- `singbox_path` → удалено
- Добавлены со значениями по умолчанию: `auto_update_enabled` (`false`), `auto_update_interval_hours` (`24`), `last_update_check_unix` (`0`), `update_available_version` (`null`), `mihomo_version` (`null`)
- `dns_settings.enabled` принудительно устанавливается в `true`, если `split_routing.enabled` равно `true` (DNS необходим для сплит-роутинга)

Ручное вмешательство не требуется.

## Лицензия

MIT
