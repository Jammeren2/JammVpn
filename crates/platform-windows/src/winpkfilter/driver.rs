//! Авто-установка NDIS-драйвера WinpkFilter (`ndisrd`), вшитого в бинарник.
//!
//! Файлы драйвера (WHQL-подпись Microsoft) встроены в exe через `include_bytes!`,
//! поэтому на чужом ПК ничего качать/ставить вручную не нужно: при первом запуске
//! раздельного туннелирования драйвер распаковывается во временную папку и ставится
//! системной утилитой `netcfg` (как NDIS LightWeight Filter, без перезагрузки).
//! Требует прав администратора.

use ndisapi::Ndisapi;
use std::path::{Path, PathBuf};

// Пакет драйвера для x64 (amd64). Подписан Microsoft → ставится без test-signing.
const INF: &[u8] = include_bytes!("../../drivers/ndisrd/amd64/ndisrd_lwf.inf");
const SYS: &[u8] = include_bytes!("../../drivers/ndisrd/amd64/ndisrd.sys");
const CAT: &[u8] = include_bytes!("../../drivers/ndisrd/amd64/ndisrd.cat");

/// ComponentId из INF (`%ndisrd_Desc%=Install, nt_ndisrd`) — его ждёт `netcfg -i`.
const COMPONENT_ID: &str = "nt_ndisrd";

/// `true`, если драйвер `NDISRD` уже доступен (устройство открывается).
pub fn is_installed() -> bool {
    Ndisapi::new("NDISRD").is_ok()
}

/// Гарантирует наличие драйвера: если не установлен — распаковывает вшитый пакет
/// и ставит его через `netcfg`. Возвращает `Ok(true)`, если драйвер был установлен
/// в этом вызове, `Ok(false)` — если уже был. `Err` — при ошибке установки.
pub fn ensure_installed(log: &dyn Fn(String)) -> Result<bool, String> {
    if is_installed() {
        return Ok(false);
    }
    if !super::is_elevated() {
        return Err("установка драйвера требует запуска JammVPN от администратора".into());
    }
    log("драйвер ndisrd не найден — устанавливаю вшитый пакет".into());
    let dir = extract()?;
    install_via_netcfg(&dir.join("ndisrd_lwf.inf"), log)?;
    // LWF-драйвер поднимается асинхронно (привязка к адаптерам) — ждём устройство.
    for _ in 0..50 {
        if is_installed() {
            log("драйвер ndisrd установлен и доступен".into());
            return Ok(true);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err("драйвер установлен, но устройство NDISRD ещё недоступно — возможно, нужна перезагрузка".into())
}

/// Удаляет драйвер из системы (`netcfg -u`). Требует прав администратора.
pub fn uninstall(log: &dyn Fn(String)) -> Result<(), String> {
    if !super::is_elevated() {
        return Err("удаление драйвера требует прав администратора".into());
    }
    let out = netcfg(&["-u", COMPONENT_ID])?;
    log(format!(
        "netcfg uninstall: code={:?} {}",
        out.status.code(),
        oem(&out.stdout)
    ));
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("netcfg -u вернул код {:?}", out.status.code()))
    }
}

/// Распаковывает вшитые файлы драйвера в `%TEMP%\jammvpn-ndisrd` (рядом, чтобы
/// `.cat`/`.sys`/`.inf` лежали вместе — это нужно проверке подписи при установке).
fn extract() -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join("jammvpn-ndisrd");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("ndisrd_lwf.inf"), INF).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("ndisrd.sys"), SYS).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("ndisrd.cat"), CAT).map_err(|e| e.to_string())?;
    Ok(dir)
}

/// `netcfg -l <inf> -c s -i nt_ndisrd` — установка NDIS LWF-компонента.
fn install_via_netcfg(inf: &Path, log: &dyn Fn(String)) -> Result<(), String> {
    let inf = inf.to_string_lossy().to_string();
    let out = netcfg(&["-l", &inf, "-c", "s", "-i", COMPONENT_ID])?;
    log(format!(
        "netcfg install: code={:?} {}",
        out.status.code(),
        oem(&out.stdout)
    ));
    if out.status.success() || is_installed() {
        Ok(())
    } else {
        Err(format!(
            "netcfg вернул код {:?}: {}",
            out.status.code(),
            oem(&out.stdout)
        ))
    }
}

/// Запускает `netcfg.exe` с аргументами без всплывающего окна консоли.
fn netcfg(args: &[&str]) -> Result<std::process::Output, String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    std::process::Command::new("netcfg")
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("не удалось запустить netcfg: {e}"))
}

/// Грубое декодирование вывода `netcfg` (OEM-кодировка консоли) для лога.
fn oem(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().replace('\n', " ").replace('\r', "")
}
