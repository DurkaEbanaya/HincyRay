# T99W175 / MV31-W: B3 как постоянная главная LTE-несущая

Этот документ фиксирует рабочую настройку модема Foxconn T99W175 / Cinterion MV31-W (Qualcomm SDX55) в Keenetic Giga KN-1012:

- разрешены LTE B1, B3 и B7;
- B3 всегда используется как PCC/PCell;
- B1 и B7 остаются доступными как SCC/SCell;
- проверенная агрегация после настройки: B3 + B1 + B7.

## Почему одной маски диапазонов недостаточно

Маска B1+B3+B7 только разрешает диапазоны. Она не задаёт роль несущей, поэтому сеть может выбрать B1 как PCC и B3 как SCC. Для гарантии B3 в роли PCC нужен LTE cell lock на конкретную B3-соту по паре `PCI + DL EARFCN`.

Cell lock привязан к конкретной соте. Если B3 с указанными PCI/EARFCN исчезнет, модем может остаться без LTE до восстановления соты или снятия lock.

## Доступ к AT-каналу

На этом роутере рабочий AT-порт модема:

```text
/dev/ttyUSB0
```

Перед обменом:

```sh
stty -F /dev/ttyUSB0 115200 raw -echo
```

На Keenetic команды также можно отправлять штатным `ndmc`, например:

```text
interface UsbQmi0 tty send AT^LTE_LOCK?
```

## Безопасная диагностика

Следующие команды только читают состояние:

```text
AT^DEBUG?
AT^CA_INFO?
AT+VZWRSRP?
AT+VZWRSRQ?
AT^BAND_PREF_EXT?
AT^LTE_LOCK?
```

Назначение:

- `AT^DEBUG?` — PCC/SCC, band, EARFCN, PCI и показатели сигнала;
- `AT^CA_INFO?` — роли PCC и SCC в агрегации;
- `AT+VZWRSRP?`, `AT+VZWRSRQ?` — соседние LTE-соты с PCI и EARFCN;
- `AT^BAND_PREF_EXT?` — разрешённые и запрещённые диапазоны;
- `AT^LTE_LOCK?` — текущий cell lock.

Перед настройкой было обнаружено:

```text
PCC: B1, EARFCN 350, PCI 137
SCC: B3, EARFCN 1725, PCI 150
```

## Зафиксированные команды

### 1. Оставить только B1, B3 и B7

У `AT^BAND_PREF_EXT` значение `1` означает disable, `2` — enable. Сначала отключаются остальные поддерживаемые LTE-диапазоны, затем явно включаются B1/B3/B7:

```text
AT^BAND_PREF_EXT=LTE,1,2:4:5:8:12:13:14:17:18:19:20:25:26:28:29:30:32:34:38:39:40:41:42:46:48:66:71
AT^BAND_PREF_EXT=LTE,2,1:3:7
```

Проверка должна показать:

```text
LTE,Enable Bands :1,3,7,
```

Важно: `AT^BAND_PREF_EXT=LTE,2,1:3:7` сам по себе только включает эти три диапазона, но не отключает остальные. Поэтому нужны обе команды.

### 2. Зафиксировать обнаруженную B3 как PCC

Для текущей B3-соты:

```text
AT^LTE_LOCK=150,1725
AT^LTE_LOCK?
```

Ожидаемый ответ:

```text
^LTE_LOCK:(150,1725),
```

Синтаксис из официального MV31-W AT Command Reference Guide:

```text
AT^LTE_LOCK=<PCI>,<DL_EARFCN>[,<PCI>,<DL_EARFCN>...]
```

Поддерживается до восьми пар. Для требования «B3 всегда PCC» используется одна конкретная B3-пара.

### 3. Применить cell lock

Cell lock вступает в силу после перезагрузки модема:

```text
AT+RESET
```

LTE/WAN при этом кратковременно отключается.

## Проверка результата

После восстановления модема выполнить:

```text
AT^DEBUG?
AT^CA_INFO?
AT^BAND_PREF_EXT?
AT^LTE_LOCK?
```

Фактически полученный результат:

```text
pcell: lte_band:3
channel:1725 pci:150

scell: lte_band:1
channel:350 pci:137

scell: lte_band:7
channel:3200 pci:332
```

И краткая CA-проекция:

```text
PCC info: Band is LTE_B3, Band_width is 10.0 MHz
SCC1 info: Band is LTE_B1, Band_width is 10.0 MHz
SCC2 info: Band is LTE_B7, Band_width is 10.0 MHz
```

Также проверить доступность локального сервиса:

```sh
curl --max-time 8 http://127.0.0.1:8088/api/health
```

## Особенность Keenetic

В выполненной настройке после `AT+RESET` Keenetic один раз восстановил полную LTE band mask, хотя cell lock сохранился. Поэтому после перезагрузки потребовалось повторно выполнить две команды `AT^BAND_PREF_EXT` без ещё одной перезагрузки. Повторная проверка подтвердила:

```text
LTE,Enable Bands :1,3,7,
^LTE_LOCK:(150,1725),
PCC: B3
SCC: B1 + B7
```

После любого будущего reset, переподключения или обновления модема нужно проверять и lock, и band mask отдельно.

## Откат

Снять только cell lock и вернуть обычный выбор PCC сетью:

```text
AT^LTE_LOCK
AT+RESET
```

После восстановления проверить:

```text
AT^LTE_LOCK?
```

Ожидаемый ответ:

```text
^LTE_LOCK:Have not set cell lock before
```

Вернуть заводскую конфигурацию диапазонов:

```text
AT^BAND_PREF_EXT
```

Это отдельная операция: снятие cell lock не восстанавливает band mask, а восстановление band mask не снимает cell lock.

## Источник

Официальное руководство: `TC_MV31-W_AT_Command_Reference_Guide_r2.pdf`, раздел `15.41 AT^LTE_LOCK - Lock EARFCN and PCI in LTE network`.
