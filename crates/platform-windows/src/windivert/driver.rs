//! Драйвер WinDivert: подписанный `WinDivert64.sys` вшит в exe и распаковывается
//! рядом с исполняемым файлом. Статически слинкованный user-mode WinDivert ищет
//! `.sys` в каталоге модуля (т.е. рядом с exe) и сам ставит/запускает службу при
//! `WinDivertOpen` (нужны права администратора). Перезагрузка не требуется.

/// Официальный подписанный драйвер WinDivert 2.2.2 (basil00), x64.
const SYS: &[u8] = include_bytes!("../../drivers/windivert/WinDivert64.sys");

/// Распаковывает `WinDivert64.sys` рядом с exe, если его там ещё нет (или размер
/// отличается). Сам `WinDivertOpen` затем создаёт и запускает службу драйвера.
pub fn ensure_installed(log: &dyn Fn(String)) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = exe.parent().ok_or("нет родительской папки exe")?;
    let target = dir.join("WinDivert64.sys");
    let need = match std::fs::metadata(&target) {
        Ok(m) => m.len() != SYS.len() as u64,
        Err(_) => true,
    };
    if need {
        std::fs::write(&target, SYS)
            .map_err(|e| format!("не удалось распаковать WinDivert64.sys рядом с exe: {e}"))?;
        log(format!("WinDivert64.sys распакован: {}", target.display()));
    }
    Ok(())
}
