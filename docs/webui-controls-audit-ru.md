# HincyRay Web UI: понятное описание кнопок, переключателей и найденных аномалий

Дата аудита: 2026-07-04  
Версия проекта: v0.18.0  
Фокус: Web UI роутерного демона `hincyray`, файл `src/webui/index.html`, backend `src/hincyray.rs`.

## 1. Важная модель: не WiFi сам по себе, а политика Keenetic

HincyRay не делает магию по названию WiFi-сети. Правильная цепочка такая:

```text
SSID / сегмент / устройство
→ Keenetic traffic policy, например Xkeen/HincyRay
→ connmark этой политики
→ iptables-правила HincyRay
→ Mihomo
```

Отдельная SSID полезна как удобный способ назначить одну политику сразу всему сегменту. Если SSID `HincyRay-VPN` создана, но сегменту не назначена политика Xkeen/HincyRay, это обычная WiFi-сеть.

## 2. Как проверялось

Проверено безопасно:

- UI-контролы из `src/webui/index.html`.
- JS-функции, которые вызываются кнопками/переключателями.
- API endpoint'ы, которые вызывает UI.
- Backend handlers в `src/hincyray.rs`.
- Существующие тесты проекта.

На момент первичного аудита было запущено:

```text
cargo check --all-targets --all-features — OK
cargo test --all-targets --all-features — OK, 339 tests passed
```

После аудита начат fix-pass в коде. Исправления, уже внесённые в рабочее дерево, отмечены ниже как **Статус: исправлено в коде**; для них ещё требуется полный финальный gate и, при необходимости, live E2E на роутере.

Не выполнялись без отдельного подтверждения разрушительные live-действия на роутере: остановка ядра, остановка firewall, restore backup, WebDAV restore, обновление Mihomo, reset маршрутизации, закрытие всех соединений. В документе они отмечены отдельно.

## 3. Обзор → Система

### Карточки статуса

- **Ядро** — показывает, запущен ли процесс Mihomo.
- **Профиль** — текущий активный профиль.
- **Профилей** — количество импортированных профилей.
- **SOCKS / HTTP** — локальные входы Mihomo.
- **Mihomo** — версия бинарника Mihomo.

### Кнопки

- **▶ Запустить** — `POST /api/core/start`. Генерирует конфиг и запускает Mihomo.
- **■ Остановить** — `POST /api/core/stop`. Останавливает Mihomo. Есть подтверждение.
- **↻ Перезапустить** — `POST /api/core/restart`. Перегенерирует конфиг и перезапускает ядро.
- **⬆ Применить маршруты** — `POST /api/routing/apply`. Перезапускает firewall-правила и, если ядро уже работало, перезапускает Mihomo с новым конфигом.

**Аномалии/риски:** нет явных несостыковок. Действия реально меняют runtime.

## 4. Профили

### Добавить один профиль

- Поле **Share link** — ссылка `vless://`, `vmess://`, `trojan://`, `ss://` и т.п.
- Поле **Группа** — пользовательское имя группы.
- Кнопка **+ Добавить профиль** — должна добавить один профиль.

**Статус: исправлено в коде.** UI теперь отправляет `{raw: ...}`, как требует backend `POST /api/profiles/add`. Массовый импорт ниже использует другой endpoint и остаётся согласованным.

### Таблица профилей

- **★** — добавить/убрать профиль из избранного: `POST /api/favorites/toggle`.
- **Выбрать** — сделать профиль активным: `POST /api/active-profile`.
- **✎** — переименовать профиль через prompt: `POST /api/profiles/update`.
- **✕** — удалить профиль: `POST /api/profiles/delete`, есть подтверждение. Если удалить активный профиль, backend останавливает core.
- **⤴ Поделиться / QR** в заголовке группы — `POST /api/profile-groups/share`; backend по `group` возвращает всю подписку/группу серверов. Для URL-подписки QR кодирует URL, для именованной группы возвращается bundle raw links; QR может отсутствовать, если bundle физически не помещается в QR.
- **✕** в заголовке группы — `POST /api/profile-groups/delete`; удаляет всю видимую подписку/группу серверов, а не один server profile.
- Заголовки колонок — сортировка на клиенте.
- Поиск — фильтр на клиенте по имени/протоколу.
- Группы профилей — можно сворачивать/разворачивать; состояние хранится в `localStorage`.

**Статус: исправлено в коде.** Профильный QUIC toggle и ошибочные per-server share actions убраны из пользовательского сценария подписок; действия шаринга/удаления находятся на заголовке подписки/группы.

## 5. Импорт и подписки

### Массовый импорт

- Поле **Вставьте ссылки / URL подписки / Xray JSON** — принимает direct share links, URL подписок, Xray JSON.
- Поле **Группа** — применится к прямым профилям без собственной группы.
- **Импортировать** — `POST /api/profiles/import` с `{text, group}`.

Это согласовано с backend: handler принимает JSON с `text` и `group`.

### Добавить один профиль в разделе импорта

**Статус: исправлено в коде.** Дублирующий блок одиночного добавления из раздела импорта убран, чтобы не было двух разных UI-путей к одному backend-контракту.

### Подписки

- **↻ Обновить все** — `POST /api/subscriptions/refresh`.
- **↻ у строки** — `POST /api/subscriptions/refresh-one`.
- **✕ у строки** — `POST /api/subscriptions/delete`, есть подтверждение.

**Риск:** обновление подписок делает сетевые запросы и может менять набор профилей/ID.

## 6. Бенчмарк

- **Метод**:
  - `tcp` — быстрый TCP-ping.
  - `head` — HTTP HEAD.
  - `get` — HTTP GET/download.
- **Probe URL** — URL проверки доступности.
- **Download URL** — URL файла для теста скорости.
- **▶ Запустить** — `POST /api/bench/start`.
- **■ Остановить** — `POST /api/bench/stop`.
- Прогресс и результаты опрашиваются через `GET /api/bench/status`.

Backend проверяет метод и отказывает, если профилей нет или benchmark уже запущен.

**Аномалии/риски:** runtime зависит от доступности Mihomo и сети. Без live-запуска на роутере подтверждён только контракт и unit-тесты.

## 7. Маршрутизация / Split Routing

### Главный переключатель

- **Split Routing / Прозрачный прокси** — сохраняется в `split_routing.enabled` через **Сохранить настройки**.
- При включении backend принудительно включает DNS anti-leak, потому что firewall DNAT'ит DNS на `:1053`.

### Основные поля

- **Auto-switch при сбое** — включает failover на следующий профиль при health-check проблемах.
- **Источник правил** — источник каталога сервисов для chips.
- **VPN Subnet** — подсеть сегмента, исторически `192.168.2.0/24`. Важно: это не единственный критерий маршрутизации; решает policy/connmark.
- **Redirect Port** — TCP REDIRECT listener Mihomo, обычно `10810`.
- **Policy Name** — имя политики Keenetic, по которой HincyRay узнаёт connmark.
- **Geo asset path** — каталог geo-файлов Mihomo.
- **Port Mode**:
  - `All` — проксировать всё.
  - `Allow List` — проксировать только указанные порты.
  - `Deny List` — проксировать всё кроме указанных портов.
- **Proxy ports / Bypass ports** — списки портов для выбранного режима.
- **Сохранить настройки** — `POST /api/routing/settings`.
- **↺ Штатные настройки** — `POST /api/routing/reset`, затем UI вызывает `POST /api/routing/apply`.

**Статус: исправлено в коде.** Формулировка заменена на “Маршрутизация Xkeen политики”; пояснение теперь явно говорит, что техническая основа — Keenetic traffic policy/connmark, а SSID/сегмент только удобный способ назначить policy группе клиентов.

### RKN Bypass

- **Включить обход блокировок РКН** — включает rule provider `ru-bypass`.
- **URL списка** — источник списка, по умолчанию `itworksig/rublacklist`.
- **Интервал обновления** — как часто Mihomo обновляет rule provider.

Ожидаемая логика конфига: заблокированные домены идут через proxy; `GEOIP,RU,DIRECT` и `GEOIP,CN,DIRECT` идут напрямую после rule-set.

### Геобаза

- **Поставщик** — выбранный источник geo assets.
- **↻ Загрузить/обновить** — `POST /api/geo/download`.
- Статус — `GET /api/geo/status`.

**Риск:** скачивание требует сети и места на роутере.

### Быстрые шаблоны

- **Без пресетов / Всё VPN** — очищает пользовательские правила/настраивает всё через VPN.
- **RU Direct** — русские ресурсы напрямую.
- **Ad Block** — блокировка рекламных категорий.
- **Web VPN Only** — только web-порты через VPN.
- **Block Social** — блокировка соцсетей.
- **RU + AdBlock** — RU Direct + ad-block.
- При некоторых preset'ах UI показывает временный dropdown цели: `active`, `direct`, `reject`.

Backend: `POST /api/routing-presets/apply`.

### RU Direct

- **Режим**:
  - `off` — выключено.
  - `tld` — `.ru`, `.рф`/`xn--p1ai` напрямую.
  - `geosite` — `GEOSITE,category-ru,DIRECT`.
- **Исключения** — домены, которые пойдут через VPN несмотря на RU Direct.
- **Сохранить** — тот же `saveRoutingSettings()`.

### Правила маршрутизации

- **Имя** — понятное название правила.
- **Цель**:
  - `active` — через активный профиль/группу proxy.
  - `direct` — напрямую.
  - `best` — через лучший профиль.
  - `reject` — заблокировать.
  - `profile:0` — выбранный профиль по ID.
- **Протокол** — `any`, `tcp`, `udp`.
- **Порты** — `80,443` или диапазоны.
- **Режим портов** — только эти / кроме этих.
- **Домены, зоны и IP** — `geosite:youtube`, `googlevideo.com`, `geoip:us`, `ip-asn:15169`, `ru`, `xn--p1ai`.
- Chips сервисов добавляют entries в textarea.
- **+ Добавить правило** — сохраняет весь массив правил через `POST /api/routing/rules`.
- Таблица правил поддерживает inline-редактирование ячеек.
- **MATCH row** — финальное правило `MATCH,proxy` или `MATCH,direct`. `direct` запрещён backend'ом, если пользовательских правил нет.
- **⬆ Применить** — `POST /api/routing/apply`.

**Статус: частично исправлено в коде.** Удаление правила теперь показывает временный undo-блок на 15 секунд вместо confirm-dialog. Inline-редактирование по-прежнему сохраняет на blur — это осознанная UX-модель, но требует аккуратности.

### Файрвол

- **Запустить файрвол** — `POST /api/routing/firewall-start`.
- **Остановить** — `POST /api/routing/firewall-stop`, есть подтверждение.

**Статус: уточнено в коде.** Текст UI поясняет: остановка firewall отключает transparent interception, но не останавливает Mihomo и его SOCKS/HTTP входы.

## 8. DNS

- **Anti-leak DNS** — настройка `dns_settings.enabled`; в router split mode фактически DNS нужен всегда.
- **Стратегия запросов** — `UseIPv4`, `UseIPv6`, `UseIP`.
- **Удалённые DNS** — DNS через proxy.
- **Локальные DNS** — DNS напрямую.
- **Override destination (sniffed domain)** — включает `sniffer.override-destination`, чтобы доменные правила работали при DoH/DoT/SNI.
- **Сохранить** — `POST /api/dns`, затем `POST /api/routing/apply`.
- **Тест утечки** — `GET /api/dns/leak-test`.
- **Диагностика** — `GET /api/dns/diagnostics`.

**Аномалии/риски:** переключатель Anti-leak DNS может выглядеть как “можно выключить DNS”, но при split routing firewall всё равно рассчитан на DNS listener `:1053`. Правильнее воспринимать это как legacy/UI-настройку, а не как безопасный способ выключить DNS в router mode.

## 9. Mihomo → Параметры

### Реально подключены к save/load

Через `GET/POST /api/mihomo-features` реально сохраняются:

- Глобальные: GEO loader, Unified delay, Store fake-ip, Store selected, TCP concurrent, keep-alive interval/idle, Disable keep-alive.
- Proxy Groups: enabled, type, health-check URL, interval, timeout, tolerance, lazy, max failed, strategy, expected status, filter, exclude filter, exclude type, include all providers/all/proxies.
- External Controller: enabled, address, secret, allow origins, allow private network.

После сохранения UI вызывает `POST /api/routing/apply`.

### Частично или не подключены

Визуально есть карточки NTP, Per-proxy defaults, DNS расширенные, Sniffer, Sub-rules, Typed rules, Raw rules, Proxy providers, Rule providers, Tunnels, Authentication, Experimental, Hosts. Но большинство полей в этих карточках не имеют `id` и не читаются в `saveFeatures()`/`loadFeatures()`.

**Аномалия:** эти элементы выглядят как рабочие настройки, но в текущем UI они в основном декоративные/неподключенные. Backend поддерживает многие из этих структур, но экран сохраняет только ограниченный набор.

## 10. Статус прокси

- Карточки скорости/памяти — через `GET /api/traffic` и `GET /api/mihomo-api/memory`.
- **Тест задержки** — `POST /api/mihomo-api/delay`.
- **Сброс Fake-IP** — `POST /api/mihomo-api/cache/fakeip/flush`.
- **Сброс DNS** — `POST /api/mihomo-api/cache/dns/flush`.
- **Закрыть все соединения** — `POST /api/mihomo-api/connections/close` с `{scope:'all'}`.
- Таблица групп прокси — `GET /api/mihomo-api/proxies`.
- Активные соединения — `GET /api/mihomo-api/connections`.
- EC API raw buttons — должны показывать raw JSON из Mihomo EC.
- **Disable rules** — `POST /api/mihomo-api/rules/disable`, есть подтверждение.

**Аномалии:**

- **Статус: исправлено в коде.** `showEcRaw()` теперь показывает реальный ответ `/api/mihomo-api/...` либо текст ошибки, без mock/sample JSON.
- **Закрыть все соединения** выполняется без подтверждения, хотя действие разрушительное для текущих подключений.

## 11. Трафик и подключения

- Карточки скорости/итога — traffic stats.
- **Сервис** — быстрый выбор URL speed-test.
- **Что тестируем** — download, ping, both.
- **Timeout** — timeout speed-test.
- **Download URL** — URL тестового файла.
- **Тест скорости** — ping через EC delay и/или `POST /api/mihomo-api/speed-test`.
- Лог подключений — `GET /api/connection-log`.

**Риск:** speed-test создаёт реальный трафик через proxy.

## 12. Тесты

Это обзорный shortcut-раздел:

- **Тест скорости** — тот же `speedTest()`.
- **Тест задержки** — тот же `delayTest()`.
- **Бенчмарк серверов** — переход в раздел бенчмарка.
- **Статус прокси** — переход.
- **Трафик и подключения** — переход.

## 13. Подключённые устройства

- **Сканировать LAN** — `GET /api/devices`, читает `/proc/net/arp`.
- Таблица обнаруженных устройств — показывает ARP-устройства и, если доступны активные соединения Mihomo, агрегирует upload/download по source IP.

**Статус: исправлено в коде.** Нерабочий UI создания persistent device override убран из пользовательского экрана. Backend endpoint'ы device routes оставлены для совместимости/API, но экран теперь не обещает то, что не сохраняет.

## 14. Диагностика

### Цепь маршрутизации

- **Source IP устройства** — IP клиента.
- **Проверить цепь** — `POST /api/routing/chain-check` с `source_ip`.
- **Только общая цепь** — тот же endpoint без source IP.

Проверяет последовательность: политика Keenetic → firewall → Mihomo → правила.

### Трассировка

- **Host / Source IP / Port** — параметры проверки.
- **Трассировать** — `POST /api/routing/trace`.

Для GEOIP/GEOSITE/RULE-SET trace может честно сказать, что финальное решение принимает Mihomo runtime.

### Разблокировка

- Chips YouTube/Netflix/OpenAI/Spotify/Cloudflare — `POST /api/unlock-check`.
- Показывает direct vs proxy reachable/status/latency.

## 15. Sub-Store Lite

- **Pipeline активен** — сохраняет `enabled`.
- **Include filter** — оставить только профили, где есть ключевые слова.
- **Exclude filter** — исключить профили по ключевым словам.
- **Сортировка** — визуально `name/group/protocol/address/score/latency`.
- **Rename rules** — строки вида `старое → новое`.
- **Deduplicate** — удалить дубли по protocol/address/port.
- **Сохранить** — `POST /api/substore-lite`.
- **Применить** — `POST /api/substore-lite/apply`; перед применением backend создаёт backup.

**Статус: исправлено в коде.** UI отправляет поле `sort_by`, как ждёт backend struct.

## 16. Автоматизация → Auto-Select

- **Auto-Select включён** — watchdog может выбирать лучший профиль.
- **Интервал бенчмарка** — период авто-бенчмарка в часах.
- **Auto-refresh subscriptions** — автообновление подписок.
- **Auto-refresh interval** — интервал обновления подписок.
- **Failover Auto-switch** — переключение при сбое.
- **Текущие подряд ошибки** — runtime-счётчик watchdog; отображается read-only.
- **Smart Auto-Select 2.0** — min success, cooldown, failure penalty.
- **Сохранить/Загрузить** — `POST/GET /api/auto-settings`.

**Статус: исправлено в коде.** UI больше не отправляет `failover_fail_count` в `POST /api/auto-settings`; поле стало read-only отображением runtime-состояния.

## 17. Автоматизация → Обслуживание

- **Включено** — включить scheduled maintenance.
- **Час/Минута UTC** — время запуска.
- **Интервал дней** — периодичность.
- **Бэкап** — создать backup перед задачами.
- **Обновлять подписки** — refresh subscriptions.
- **Перезапускать Mihomo** — restart core.
- **Закрывать соединения** — close connections.
- **Сохранить/Загрузить** — тот же `/api/auto-settings`.

## 18. Железо

Показывает CPU/RAM/temp/load/uptime/host/per-core из `GET /api/system`.

**Статус: исправлено в коде.** Demo-значения заменены на `—`; `updateSystemUI()` читает фактическую nested-схему `/api/system`: `cpu`, `memory`, `load`, `uptime_secs`, `hostname`, `model`.

## 19. Обновление Mihomo

- **Проверить обновления** — `POST /api/update/check`. Требует запущенный core, потому что GitHub проверяется через SOCKS proxy.
- **Обновить** — `POST /api/update/apply`, есть подтверждение. Скачивает, заменяет binary, рестартует core, при failure пытается rollback.
- **Авто-обновление** toggle и interval — `GET /api/update/status`, `POST /api/update/settings`.

**Статус: исправлено в коде.** UI загружает статус обновлений и сохраняет `auto_update_enabled`/`auto_update_interval_hours` через backend endpoint.

## 20. HWID Fingerprint

- Поля HWID/OS Version/Device Model/Device OS/App Version/Bundle ID/API Version.
- **Сохранить** — `POST /api/hwid`.
- **Загрузить** — `GET /api/hwid`.

Назначение: согласованный fingerprint для подписок/серверов, которые проверяют устройство и User-Agent.

## 21. Авторизация панели

- **Защита паролем** — включает auth middleware.
- **Имя пользователя** — login.
- **Новый пароль** — новый пароль; placeholder “Не менять”.
- **Сохранить** — `POST /api/auth-settings`.
- **Выйти** — `POST /api/auth/logout`, удаляет token из localStorage.

**Риск:** если поле пароля пустое, нужно live-проверить, сохраняет ли backend старый пароль или устанавливает пустой. По коду UI всегда отправляет `password` как текущее значение поля.

## 22. Acrylic, тема, язык, меню, подсказки

Локальные UI-настройки, backend не трогают:

- Переключение темы.
- Язык RU/EN.
- Яркость.
- Сворачивание sidebar.
- Acrylic sliders: прозрачность, blur, saturation, noise, gloss.
- Tooltips toggle — сохраняется в `localStorage`.

## 23. Логи

- **↻ Обновить логи** — `GET /api/logs`.
- **Копировать** — копирует текст из блока логов в clipboard.
- **Сохранить .md** — скачивает локальный markdown-файл логов.

## 24. Конфигурация

- **Показать конфигурацию** — `GET /api/mihomo-config`, показывает YAML/JSON в modal.

## 25. Бэкапы и WebDAV

- **Создать бэкап** — `POST /api/backups/create`.
- **Восстановить** — `POST /api/backups/restore`, есть подтверждение; может перезапустить core.
- **✕ удалить backup** — `POST /api/backups/delete`, есть подтверждение.
- **WebDAV URL/User/Password**.
- **↑ Загрузить** — `POST /api/backups/webdav-upload`.
- **↓ Скачать** — `POST /api/backups/webdav-download`; скачанный state применяется, создаётся pre-restore backup, core перезапускается если работал.

**Риск:** restore/WebDAV download — разрушительные операции для текущего state.

## 26. Главные найденные аномалии

1. **Исправлено:** одиночное добавление профиля теперь отправляет `raw`.
2. **Исправлено:** Sub-Store sort теперь отправляет `sort_by`.
3. **Исправлено:** нерабочий UI создания device override убран из пользовательского экрана; экран стал списком подключённых устройств.
4. **Остаётся:** Mihomo Features частично декоративны — много полей не имеют `id` и не участвуют в `saveFeatures()`.
5. **Исправлено:** EC raw показывает реальный ответ API.
6. **Исправлено:** Auto-update UI подключён к `/api/update/status` и `/api/update/settings`.
7. **Исправлено:** `failover_fail_count` стал read-only runtime-счётчиком и не отправляется в SET.
8. **Исправлено:** QUIC toggle профиля убран из таблицы; пользовательский QUIC control остаётся в routing rules.
9. **Остаётся:** “Закрыть все соединения” без подтверждения.
10. **Исправлено:** терминология WiFi заменена на policy/connmark wording.
11. **Исправлено:** статичные demo-значения Hardware заменены на placeholders и реальные `/api/system` bindings.
12. **Добавлено:** `POST /api/profiles/share` для share-link + QR SVG по `profile_id` без раскрытия raw-ссылок в обычном списке профилей.

## 27. Что нужно для настоящего live E2E всех функций

Чтобы проверить именно поведение на роутере, а не только кодовый контракт, нужен отдельный проход с разрешением на опасные действия:

- Можно ли останавливать/запускать Mihomo?
- Можно ли останавливать firewall HincyRay?
- Можно ли делать reset routing defaults?
- Можно ли закрывать все соединения?
- Можно ли делать restore backup/WebDAV download на реальном state?
- Можно ли запускать update Mihomo?
- Можно ли создавать/удалять тестовые профили, правила, device routes и backups?

Без этого корректно проверять только read-only endpoint'ы и безопасные save/load сценарии.
