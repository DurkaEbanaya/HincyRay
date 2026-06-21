# HincyRay v0.7.0

[English](README.md) | [Русский](README.ru.md)

---

HincyRay — лёгкий VPN/proxy-клиент для роутеров Keenetic. Поставляет роутер-демон (`hincyray`), который переиспользует парсер, генератор Xray-конфигов и формулу оценки качества из десктопного инструмента `XrayVpnTest`, и предоставляет встроенную веб-панель в локальной сети роутера.

**v0.7 заменяет tun2socks на iptables NAT REDIRECT + TPROXY** — ускорение throughput в 9-35× (бенчмарк: [`docs/benchmark-tun2socks-vs-redirect.md`](docs/benchmark-tun2socks-vs-redirect.md)). Без TUN-устройства, без userspace TCP-стека, без бинарника `tun2socks`.

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
  →10810    →10810
    │         │
    ▼         ▼
  Xray dokodemo-door inbounds
  (redir-in TCP, tproxy-in UDP)
         │
         ▼
  Активный VLESS/VMess/Trojan/SS outbound
         │
         ▼
  Интернет
```

Устройства не назначенные на политику используют обычный маршрут — основная сеть не затрагивается.

### Выживание при ndm firewall reload

Демон ndm в Keenetic пересоздаёт все iptables chains при изменениях конфигурации, событиях WAN и обновлении DHCP. HincyRay устанавливает hook-скрипт в `/opt/etc/ndm/netfilter.d/hincyray.sh`, который **ndm вызывает сам** после каждой перезагрузки firewall, переустанавливая все правила атомарно. Watchdog каждые 10 секунд — запасная страховка.

## Возможности

- **v0.7 NAT REDIRECT + TPROXY**: iptables transparent proxy через Keenetic traffic policy connmark. TCP через `nat REDIRECT`, UDP через `mangle TPROXY`. Без tun2socks, без TUN.
- **v0.7 интеграция с Keenetic RCI**: запрашивает `localhost:79/rci/show/ip/policy` для получения connmark политики. Авто-создаёт политику если не найдена.
- **v0.7 ndm hook-скрипт**: авто-генерируется в `/opt/etc/ndm/netfilter.d/hincyray.sh`, вызывается ndm после каждой перезагрузки firewall. Правила переживают ndm-перезапуски.
- **v0.7 переключатель QUIC**: `Block` (по умолчанию — форсирует TCP fallback) или `Proxy` (через TPROXY). Настраивается глобально и по правилам в веб-панели.
- **v0.7 авто-загрузка kernel modules**: `xt_TPROXY`, `xt_socket`, `xt_comment` загружаются при старте. TPROXY недоступен → TCP-only REDIRECT + QUIC блокируется.
- **v0.6 always-on watchdog**: отслеживает ядро Xray и перезапускает с exponential backoff (10с → 300с max). Также мониторит firewall-правила и переустанавливает при отсутствии.
- **v0.6 health-check failover**: проверяет SOCKS-туннель каждые 10 секунд. После 3 сбоев переключается на следующий лучший профиль по score.
- **v0.6 auto-benchmark**: планирует TCP benchmark для всех профилей каждые N часов.
- **v0.6 auto-select**: после benchmark переключается на профиль с наивысшим score.
- **v0.6 graceful shutdown**: SIGTERM/SIGINT останавливает Xray, удаляет iptables-правила, очищает ndm hook, сохраняет состояние.
- **v0.6 восстановление после повреждения state**: повреждённый `state.json` → бэкап в `.corrupt`, создаётся свежее состояние.
- **v0.5 поддержка протоколов**: VLESS (Reality/TLS/XHTTP), VMess (base64-JSON, WS/gRPC/TCP), Trojan (TLS), Shadowsocks. Hysteria2/WireGuard отклоняются с понятной ошибкой.
- **v0.5 HWID-фингерпринт**: настраиваемая идентификация устройства для запросов подписок Happ.
- **v0.5 защита от утечек DNS**: удалённые DNS через прокси, локальные для прямых доменов. `GET /api/dns/leak-test` для проверки.
- **v0.5 портовый роутинг**: режимы `all` / `allow_list` / `deny_list` с поправильным матчингом портов и сети (TCP/UDP).
- **v0.5 GeoIP/GeoSite**: настраиваемый путь к `.dat`-файлам, переменная `XRAY_LOCATION_ASSET`.
- **v0.3 сплит-роутинг WiFi**: правила матчат `geosite:*`, домены, IP/CIDR, `geoip:*`, порты, тип сети. Цели: `direct`, активный, лучший или фиксированный профиль.
- **v0.2 бенчмарк/статы/избранное/подписки**: TCP/HEAD/GET методы, метрики по профилям, избранное по raw-ссылке, обновление подписок.

## Требования

### Роутер (Keenetic Giga KN-1012 или аналогичный ARM64)

- Entware с `curl`, `jq`, `xray`
- Kernel modules: `xt_TPROXY.ko`, `xt_socket.ko`, `xt_comment.ko` (обычно в `/lib/modules/$(uname -r)/`)
- Keenetic traffic policy (авто-создаётся HincyRay или вручную в Keenetic Web UI)
- `iptables` с поддержкой `connmark`, `REDIRECT`, `TPROXY`, `socket`, `comment`

### Десктоп (macOS)

- `sing-box` и `xray` в `PATH` (`brew install sing-box xray`)

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

Статус, профили, бенчмарк, импорт, подписки, правила роутинга, управление firewall, DNS, HWID, системный монитор, логи — всё на одной странице. Автообновление каждые 5 секунд. Без внешних CDN и сборки.

### Переменные окружения

| Переменная | По умолчанию |
|---|---|
| `HINCYRAY_LISTEN` | `0.0.0.0:8088` |
| `HINCYRAY_STATE` | `/opt/etc/hincyray/state.json` (Entware) |
| `HINCYRAY_XRAY_CONFIG` | `xray-client.json` рядом с файлом состояния |

## HTTP API

| Метод | Путь | Назначение |
|---|---|---|
| `GET` | `/` | Встроенная веб-панель |
| `GET` | `/api/health` | Здоровье сервиса + версия |
| `GET` | `/api/status` | Активный профиль, статус ядра, сплит-роутинг, DNS, HWID |
| `GET` | `/api/profiles` | Импортированные профили |
| `POST` | `/api/profiles/import` | Импорт share-ссылок / URL подписки / Xray JSON |
| `POST` | `/api/active-profile` | Установка активного профиля |
| `GET` | `/api/xray/config` | Сгенерированный Xray-конфиг |
| `POST` | `/api/core/start` | Запуск ядра Xray |
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
| `GET` | `/api/logs` | Хвост логов Xray (последние 200 строк) |
| `GET` | `/api/system` | CPU/RAM/temp/load/uptime |

## WiFi VPN-сегмент (опционально)

- `scripts/wifi-segment-setup.sh` — создаёт SSID `HincyRay-VPN` на `192.168.2.0/24` через Keenetic `ndmc`.
- Назначьте устройства на Keenetic-политику "HincyRay" (или "XKeen") в Web UI Keenetic.
- Демон управляет всем transparent proxying через `FirewallManager`:
  1. Запрашивает connmark политики через Keenetic RCI API.
  2. Устанавливает iptables nat HINCYRAY chain (TCP REDIRECT на порт 10810) по connmark.
  3. Устанавливает iptables mangle HINCYRAY_UDP chain (UDP TPROXY на порт 10810) если TPROXY доступен.
  4. Устанавливает DNS DNAT-правила (порт 53 → 127.0.0.1:1053).
  5. Генерирует ndm hook-скрипт для выживания при firewall reload.
  6. Watchdog переустанавливает правила при отсутствии.

## Документация

- [`docs/benchmark-tun2socks-vs-redirect.md`](docs/benchmark-tun2socks-vs-redirect.md) — бенчмарк tun2socks vs NAT REDIRECT (ускорение 9-35×).
- [`docs/hincyray-entware-install.md`](docs/hincyray-entware-install.md) — runbook установки на Entware.
- [`docs/hincyray-v0.1-status.md`](docs/hincyray-v0.1-status.md) — статус версий.
- [`docs/keenetic-client-roadmap.md`](docs/keenetic-client-roadmap.md) — roadmap продукта.

## Миграция состояния (v0.6 → v0.7)

Существующий `state.json` с полями tun2socks автоматически мигрируется:
- `tun_socks_port` → `redirect_port`
- `tun_device`, `tun_address`, `tun2socks_path`, `tun_mtu` → удалены
- `policy_name`, `policy_mark`, `quic_mode`, `tproxy_available` → добавлены со значениями по умолчанию

Ручное вмешательство не требуется.

## Лицензия

MIT
