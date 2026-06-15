# JammVPN — WFP split-tunnel driver

Kernel-mode WFP callout-драйвер, реализующий per-app connect-redirect для
раздельного туннелирования (ТЗ, раздел 3, `SPL-*`).

> **Статус: собирается в `.sys`.** `src/driver.{c,h}` реализуют разбор конфига
> (формат `ipc.rs`), лестницу решений (зеркало `jammvpn_core::split::decide`),
> connect-redirect и регистрацию каллаутов. **Компилируется и линкуется WDK
> (cl/link) в `JammVpnSplit.sys`** — все вызовы WFP-API провалидированы реальными
> заголовками 10.0.26100. **Не загружался** — kernel-драйвер требует
> админ-прав/test-signing/перезагрузки; запуск — на целевой машине (ниже).

## Зачем драйвер

Чистый user-mode WFP умеет только Permit/Block. Перенаправление соединения
(connect-redirect) выполняется callout'ом в режиме ядра. Драйвер принимает
решение в момент `connect` на слое `ALE_CONNECT_REDIRECT_V4/V6` и перенаправляет
сокеты **только выбранных процессов** в локальный прокси, не трогая остальной
трафик и локальную сеть.

## Контракт с user-mode

Коды IOCTL, путь к устройству и бинарный формат правил — единый источник истины
в Rust: [`crates/platform-windows/src/wfp/ipc.rs`](../crates/platform-windows/src/wfp/ipc.rs).
Значения в [`src/driver.h`](src/driver.h) обязаны совпадать с ним.

| IOCTL | Назначение |
|-------|------------|
| `JAMM_IOCTL_SET_CONFIG` | загрузить/обновить набор правил (`encode_config`) |
| `JAMM_IOCTL_CLEAR` | снять все правила (`SPL-40`) |
| `JAMM_IOCTL_GET_STATS` | статистика (`SPL-54`) |

## Сборка (требуется WDK)

1. Установить **Visual Studio** + **Windows Driver Kit (WDK)** соответствующей
   версии (или **EWDK**). WDK ставится поверх Windows SDK той же версии и
   добавляет kernel-заголовки (`Include\<ver>\km`), km-библиотеки и тулсет
   `WindowsKernelModeDriver10.0` для VS.
2. **Способ A — командная строка (проверено, не требует VS-расширения WDK):**
   запусти `powershell -ExecutionPolicy Bypass -File build.ps1`. Скрипт зовёт
   `cl /kernel` + `link /DRIVER` напрямую и кладёт `build\JammVpnSplit.sys`.
   Ключевые моменты (если правишь сам): `km\crt` в `/I` идёт **первым** (иначе
   `<crtdefs.h>` берётся из MSVC и ломается на `_CRTIMP_ALT`); нужны дефайны
   `/DNDIS_WDM=1 /DNDIS630=1` (для `NET_BUFFER_LIST` в `fwpsk.h`); `driver.h`
   подключает `<initguid.h>` до WFP-заголовков (иначе GUID'ы — неразрешённые
   внешние). Версии путей в `build.ps1` поправь под свою установку.
3. **Способ B — Visual Studio:** открыть `JammVpnSplit.vcxproj` (нужно
   **VS-расширение WDK**, тулсет `WindowsKernelModeDriver10.0`; его ставит
   установщик WDK отдельным шагом) → собрать `x64`. Если расширения нет —
   используй способ A.
3. Сверить помеченные `СВЕРИТЬ:` места с актуальным WDK (имена полей
   `FWPS_CONNECT_REQUEST0`, владение redirect-context, доступность
   `RtlUTF8ToUnicodeN`) — компилятор/анализатор драйвера их проверит.

### Что уже реализовано в `driver.c`

- Разбор `IOCTL_SET_CONFIG` в `JAMM_CONFIG` (порядок полей/типы строго по
  `encode_config` из `ipc.rs`), атомарная замена под `FAST_MUTEX`, `CLEAR`.
- Лестница `JammDecide`: hairpin (endpoints) → bypass(LAN) → force_direct →
  force_tunnel → решение по приложению (inclusive/exclusive). Совпадение
  приложения — по имени (хвост `\name`) или по exe-пути (хвост без буквы диска;
  `ALE_APP_ID` — NT-путь).
- Сопоставление CIDR/IP (зеркало `IpCidr::contains`), порядок байт V4 host→network.
- `connect-redirect` на `127.0.0.1:redirect_port` + сохранение original-dst в
  redirect-context (19 байт, формат `encode_redirect_context`); защита от
  повторного перенаправления своего сокета (`FwpsQueryConnectionRedirectState0`).
- Регистрация provider/sublayer/callouts(V4/V6)/filters в одной транзакции
  (`FWPM_SESSION_FLAG_DYNAMIC` — авто-очистка от «сирот»), снятие в `Unload`.

### Что осталось/проверить на машине с WDK

- Отдельные WFP-фильтры hairpin/LAN большого веса и kill-switch block-фильтры
  (сейчас исключения покрыты лестницей `JammDecide` → PERMIT).
- `IOCTL_GET_STATS` (счётчики).
- Реальный прогон: загрузить драйвер, поднять локальный редирект-прокси на
  `redirect_port` (читает original-dst через
  `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT`), проверить per-app редирект.

## Тест-подпись и загрузка (для разработки)

PoC можно гонять без покупки сертификата — в режиме test-signing:

```powershell
# 1. Включить тестовый режим (требует перезагрузки):
bcdedit /set testsigning on

# 2. Сделать тестовый сертификат и подписать .sys (один раз):
#    makecert/signtool из WDK; pvk2pfx; signtool sign /fd sha256 ...

# 3. Зарегистрировать и запустить службу драйвера:
sc create JammVpnSplit type= kernel binPath= C:\path\JammVpnSplit.sys
sc start  JammVpnSplit

# 4. Остановить/удалить:
sc stop JammVpnSplit ; sc delete JammVpnSplit
```

> ⚠️ Тестовый режим снижает безопасность системы — только на dev-машине/в ВМ.
> Для релиза нужна полноценная подпись драйвера (EV/attestation/WHQL).

## Структура

```
wfp-driver/
  README.md          # этот файл
  src/
    driver.h         # устройство, IOCTL (должны совпадать с ipc.rs), типы
    driver.c         # DriverEntry/Unload, IOCTL-диспетчер, регистрация каллаутов, classify
```

Детальный план реализации (последовательность вызовов FWPM/FWPS, поток
redirect, получение original-dst в user-mode, веса/sublayer, жизненный цикл) —
во внутреннем документе `planning/WFP-DRIVER-DESIGN.md`.
