//! Контракт подсистемы раздельного туннелирования (ТЗ, раздел 3, `SPL-*`).
//!
//! Здесь определена платформо-независимая *поверхность управления* split:
//! конфигурация, режимы, неизменяемый список обхода локальной сети и трейт
//! [`SplitController`]. Реальная реализация для Windows — WFP user-mode
//! connect-redirect — появится позже; пока есть [`NoopSplitController`],
//! позволяющий собрать и протестировать приложение целиком.

use std::fmt;

/// Режим раздельного туннелирования (`SPL-19`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitMode {
    /// В тоннель идут ТОЛЬКО соединения выбранных приложений.
    Inclusive,
    /// В тоннель идёт ВСЁ, КРОМЕ соединений выбранных приложений.
    Exclusive,
}

/// Способ сопоставления приложения (`SPL-08`, `SPL-09`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppMatcher {
    /// Полный путь к `.exe` — первичный, строгий ключ.
    ExePath(String),
    /// Имя процесса — фолбэк, менее строгий (риск коллизий имён).
    ProcessName(String),
}

/// Конфигурация подсистемы split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitConfig {
    /// Режим (см. [`SplitMode`]).
    pub mode: SplitMode,
    /// Список приложений, к которым применяется решение режима.
    pub apps: Vec<AppMatcher>,
    /// Наследовать правило дочерними процессами (`SPL-14`).
    pub inherit_children: bool,
    /// Kill-switch: не выпускать перенаправляемый трафик напрямую при
    /// разрыве тоннеля (`SPL-30`..`SPL-34`).
    pub kill_switch: bool,
    /// Пользовательские «всегда напрямую» (CIDR) — `SPL-25`.
    pub force_direct_cidrs: Vec<String>,
    /// Пользовательские «всегда в тоннель» (CIDR) — `SPL-25`.
    pub force_tunnel_cidrs: Vec<String>,
    /// Адреса активного VPN-сервера для hairpin-исключения (`SPL-27`..`SPL-29`).
    pub server_endpoints: Vec<String>,
}

impl Default for SplitConfig {
    fn default() -> Self {
        Self {
            mode: SplitMode::Inclusive,
            apps: Vec::new(),
            inherit_children: true,
            kill_switch: false,
            force_direct_cidrs: Vec::new(),
            force_tunnel_cidrs: Vec::new(),
            server_endpoints: Vec::new(),
        }
    }
}

/// Диапазоны/назначения, которые ВСЕГДА идут напрямую в обоих режимах
/// (`SPL-23`): локальная сеть, loopback, link-local, ULA, multicast/broadcast.
pub const ALWAYS_BYPASS_CIDRS: &[&str] = &[
    // IPv4
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
    // IPv6
    "::1/128",
    "fe80::/10",
    "fc00::/7",
    "ff00::/8",
];

/// Ошибка подсистемы split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SplitError {
    /// Бэкенд ещё не реализован (текущая фаза).
    NotImplemented,
    /// Нет прав администратора/UAC (`SPL-56`, `SPL-57`).
    AccessDenied,
    /// Ошибка нижележащего бэкенда (WFP и т. п.).
    Backend(String),
}

impl fmt::Display for SplitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SplitError::NotImplemented => write!(f, "бэкенд split ещё не реализован"),
            SplitError::AccessDenied => write!(f, "нет прав (требуется администратор/UAC)"),
            SplitError::Backend(s) => write!(f, "ошибка бэкенда split: {s}"),
        }
    }
}

impl std::error::Error for SplitError {}

/// Контракт управления раздельным туннелированием.
///
/// Реализация для Windows применяет/снимает набор WFP-фильтров атомарно
/// (`SPL-35`..`SPL-38`).
pub trait SplitController {
    /// Атомарно применить конфигурацию.
    fn apply(&mut self, config: &SplitConfig) -> Result<(), SplitError>;
    /// Снять все правила, вернуть систему в исходное состояние (`SPL-40`).
    fn clear(&mut self) -> Result<(), SplitError>;
    /// Активен ли сейчас набор правил.
    fn is_active(&self) -> bool;
}

/// Заглушка: не перенаправляет трафик, но реализует контракт. Позволяет
/// собирать и тестировать приложение до готовности WFP-слоя.
#[derive(Debug, Default)]
pub struct NoopSplitController {
    active: Option<SplitConfig>,
}

impl SplitController for NoopSplitController {
    fn apply(&mut self, config: &SplitConfig) -> Result<(), SplitError> {
        self.active = Some(config.clone());
        Ok(())
    }

    fn clear(&mut self) -> Result<(), SplitError> {
        self.active = None;
        Ok(())
    }

    fn is_active(&self) -> bool {
        self.active.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_inclusive_no_killswitch() {
        let c = SplitConfig::default();
        assert_eq!(c.mode, SplitMode::Inclusive);
        assert!(c.inherit_children);
        assert!(!c.kill_switch);
        assert!(c.apps.is_empty());
    }

    #[test]
    fn bypass_list_covers_lan() {
        assert!(ALWAYS_BYPASS_CIDRS.contains(&"192.168.0.0/16"));
        assert!(ALWAYS_BYPASS_CIDRS.contains(&"10.0.0.0/8"));
        assert!(ALWAYS_BYPASS_CIDRS.contains(&"127.0.0.0/8"));
        assert!(ALWAYS_BYPASS_CIDRS.contains(&"::1/128"));
    }

    #[test]
    fn noop_controller_toggles_active() {
        let mut c = NoopSplitController::default();
        assert!(!c.is_active());
        c.apply(&SplitConfig::default()).unwrap();
        assert!(c.is_active());
        c.clear().unwrap();
        assert!(!c.is_active());
    }
}
