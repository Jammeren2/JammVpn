# JammVPN — WFP split-tunnel driver

Kernel-mode WFP callout-драйвер, реализующий per-app connect-redirect для
раздельного туннелирования (ТЗ, раздел 3, `SPL-*`).

> **Статус: скелет.** Каркас (`src/driver.{c,h}`) задаёт структуру и точки
> расширения, но **ещё не реализован полностью и не компилировался** — требует
> WDK. Бизнес-логика классификации зеркалит `jammvpn_core::split::decide`.

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
   версии (или **EWDK**).
2. Создать проект «Kernel Mode Driver, Empty (KMDF/WDM)», добавить `src/*.c`,
   слинковать с `fwpkclnt.lib`, `ntoskrnl.lib`, `uuid.lib`.
   (Сборка из VS/MSBuild; CMake для kernel-драйверов не используется.)

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
