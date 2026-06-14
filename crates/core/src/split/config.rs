//! Модель конфигурации split и сопоставление приложений.

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

/// Описание процесса-инициатора соединения (для классификации).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnApp {
    /// Полный путь к образу процесса, если известен.
    pub exe_path: Option<String>,
    /// Имя процесса (`app.exe`), если известно.
    pub process_name: Option<String>,
}

impl AppMatcher {
    /// Совпадает ли матчер с указанным приложением.
    pub fn matches(&self, app: &ConnApp) -> bool {
        match self {
            AppMatcher::ExePath(p) => app
                .exe_path
                .as_deref()
                .is_some_and(|e| e.eq_ignore_ascii_case(p)),
            AppMatcher::ProcessName(n) => effective_name(app)
                .as_deref()
                .is_some_and(|x| x.eq_ignore_ascii_case(n)),
        }
    }
}

fn effective_name(app: &ConnApp) -> Option<String> {
    if let Some(n) = &app.process_name {
        return Some(n.clone());
    }
    app.exe_path.as_deref().map(file_name)
}

fn file_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

/// Конфигурация подсистемы split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitConfig {
    /// Режим (см. [`SplitMode`]).
    pub mode: SplitMode,
    /// Приложения, к которым применяется решение режима.
    pub apps: Vec<AppMatcher>,
    /// Наследовать правило дочерними процессами (`SPL-14`).
    pub inherit_children: bool,
    /// Kill-switch: не выпускать перенаправляемый трафик напрямую при
    /// неготовности тоннеля (`SPL-30`..`SPL-34`).
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

impl SplitConfig {
    /// Выбрано ли приложение (входит ли в список `apps`).
    pub fn app_selected(&self, app: &ConnApp) -> bool {
        self.apps.iter().any(|m| m.matches(app))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_by_exe_path_case_insensitive() {
        let m = AppMatcher::ExePath("C:\\Apps\\Chrome.exe".into());
        let app = ConnApp {
            exe_path: Some("c:\\apps\\chrome.exe".into()),
            process_name: None,
        };
        assert!(m.matches(&app));
    }

    #[test]
    fn matches_by_process_name_from_path() {
        let m = AppMatcher::ProcessName("chrome.exe".into());
        let app = ConnApp {
            exe_path: Some("C:\\Apps\\chrome.exe".into()),
            process_name: None,
        };
        assert!(m.matches(&app));
    }

    #[test]
    fn selection_respects_list() {
        let cfg = SplitConfig {
            apps: vec![AppMatcher::ProcessName("a.exe".into())],
            ..Default::default()
        };
        assert!(cfg.app_selected(&ConnApp {
            exe_path: Some("X\\a.exe".into()),
            process_name: None
        }));
        assert!(!cfg.app_selected(&ConnApp {
            exe_path: Some("X\\b.exe".into()),
            process_name: None
        }));
    }
}
