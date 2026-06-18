//! Драйвер WinDivert: подписанный `WinDivert64.sys` вшит в exe и распаковывается
//! рядом с исполняемым файлом. Статически слинкованный user-mode WinDivert ищет
//! `.sys` в каталоге модуля (т.е. рядом с exe) и сам ставит/запускает службу при
//! `WinDivertOpen` (нужны права администратора). Перезагрузка не требуется.

/// Официальный подписанный драйвер WinDivert 2.2.2 (basil00), x64.
const SYS: &[u8] = include_bytes!("../../drivers/windivert/WinDivert64.sys");
/// User-mode WinDivert.dll (delay-load: грузится при первом вызове WinDivert).
const DLL: &[u8] = include_bytes!("../../drivers/windivert/WinDivert.dll");

/// Распаковывает `WinDivert.dll` и `WinDivert64.sys` рядом с exe (если их там нет
/// или размер отличается). DLL должен лежать рядом ДО первого вызова WinDivert
/// (delay-load его подхватит); `WinDivertOpen` затем создаёт службу из `.sys`.
pub fn ensure_installed(log: &dyn Fn(String)) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = exe.parent().ok_or("нет родительской папки exe")?;
    for (name, bytes) in [("WinDivert.dll", DLL), ("WinDivert64.sys", SYS)] {
        let target = dir.join(name);
        let need = match std::fs::metadata(&target) {
            Ok(m) => m.len() != bytes.len() as u64,
            Err(_) => true,
        };
        if need {
            std::fs::write(&target, bytes)
                .map_err(|e| format!("не удалось распаковать {name} рядом с exe: {e}"))?;
            log(format!("{name} распакован: {}", target.display()));
        }
    }
    Ok(())
}
