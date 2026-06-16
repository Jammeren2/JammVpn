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

> Примечание: на новом WDK компилятор сам проверит имена полей
> `FWPS_CONNECT_REQUEST0`, доступность `RtlUTF8ToUnicodeN` и т.п. — драйвер уже
> собирается на SDK/WDK 10.0.26100.

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

## Загрузка на своей машине (test-signing) — пошагово

Для локального использования без боевой подписи. Скрипты `load.ps1`/`unload.ps1`
делают всю рутину (самоподпись + доверие + подпись `.sys` + служба).

**Шаг 0 (один раз, нужна перезагрузка):** включить тестовый режим.
Открой **PowerShell от администратора**:
```powershell
bcdedit /set testsigning on
```
…и **перезагрузись**. После загрузки в правом нижнем углу появится надпись
«Test Mode» — это норма. *Если включён Secure Boot, его придётся выключить в
BIOS/UEFI — иначе testsigning не активируется.*

**Шаг 1 — собрать драйвер** (если ещё не собран):
```powershell
cd C:\Users\my\Desktop\py\vpn\wfp-driver
powershell -ExecutionPolicy Bypass -File build.ps1
```

**Шаг 2 — подписать и загрузить** (PowerShell **от администратора**):
```powershell
cd C:\Users\my\Desktop\py\vpn\wfp-driver
powershell -ExecutionPolicy Bypass -File load.ps1
```
Скрипт создаст тестовый сертификат `CN=JammVPN Test Driver`, добавит его в
доверенные (Root + TrustedPublisher), подпишет `build\JammVpnSplit.sys` и
запустит службу `JammVpnSplit`.

**Шаг 3 — пользоваться:** в JammVPN запусти локальный прокси (вкладка
«Главная»), добавь правило с **процессом** (напр. `name:chrome.exe`) и
действием **«проксировать»** (вкладка «Маршруты»), затем нажми **«Применить»**
в блоке «Раздельное туннелирование» (вкладка «Дополнительно»). Трафик этого
приложения пойдёт в туннель, остальные процессы не затрагиваются.

**Снять драйвер:**
```powershell
powershell -ExecutionPolicy Bypass -File unload.ps1
```

После каждой пересборки (`build.ps1`) перезапусти `load.ps1` (он переподпишет
и перезагрузит службу). Выключить тестовый режим: `bcdedit /set testsigning off`
+ перезагрузка.

> ⚠️ Тестовый режим снижает безопасность системы — только на своей dev-машине.
> Для раздачи другим нужна боевая подпись (EV-сертификат + attestation Microsoft).
> Известное ограничение текущей сборки: redirect-context не освобождается
> по завершении соединения (контролируемая утечка ~19 байт/соединение) — для
> локального использования некритично, дорабатывается отдельно.

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
