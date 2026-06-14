//! Исполнительный слой раздельного туннелирования для Windows (ТЗ, раздел 3).
//!
//! Модель и движок решений (что направить в тоннель) живут в
//! [`jammvpn_core::split`]. Здесь — *исполнение* этих решений: контракт
//! [`SplitController`], применяющий/снимающий набор WFP-фильтров.
//!
//! Реальная WFP-реализация (под `cfg(windows)`, через `windows-rs`) появится
//! позже; пока есть [`NoopSplitController`], позволяющий собрать и
//! протестировать приложение целиком.

use std::fmt;

// Реэкспорт модели из ядра — чтобы потребители платформенного слоя не зависели
// напрямую от `jammvpn_core` для базовых типов.
pub use jammvpn_core::split::{
    decide, Action, AppMatcher, ConnApp, ConnRequest, IpCidr, SplitConfig, SplitMode,
    ALWAYS_BYPASS_CIDRS,
};

/// Ошибка исполнительного слоя split.
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

/// Контракт исполнения раздельного туннелирования.
///
/// Реализация для Windows применяет/снимает набор WFP-фильтров атомарно
/// (`SPL-35`..`SPL-38`), транслируя решения движка [`decide`] в действия WFP.
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
    fn reexported_model_is_usable() {
        let c = SplitConfig::default();
        assert_eq!(c.mode, SplitMode::Inclusive);
        assert!(ALWAYS_BYPASS_CIDRS.contains(&"192.168.0.0/16"));
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

    #[test]
    fn decide_reachable_through_platform_reexport() {
        let app = ConnApp {
            exe_path: Some("C:\\app.exe".into()),
            process_name: None,
        };
        let cfg = SplitConfig {
            apps: vec![AppMatcher::ExePath("C:\\app.exe".into())],
            ..Default::default()
        };
        let req = ConnRequest {
            app: &app,
            dst_ip: "203.0.113.9".parse().unwrap(),
            dst_port: 443,
        };
        assert_eq!(decide(&req, &cfg, true), Action::Tunnel);
    }
}
