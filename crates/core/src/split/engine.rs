//! Движок решений split: по `{приложение, назначение}` → действие.
//!
//! Реализует приоритетную лестницу `SPL-21`:
//! 1. hairpin (трафик к VPN-серверу) → напрямую (`SPL-27`);
//! 2. локальная сеть и системные исключения → напрямую (`SPL-23`);
//! 3. пользовательские «всегда напрямую» → напрямую (`SPL-25`);
//! 4. пользовательские «всегда в тоннель» → в тоннель (`SPL-25`);
//! 5. решение по приложению согласно режиму (`SPL-19`);
//! 6. kill-switch: если нужно в тоннель, а тоннель не готов — блок/прямой
//!    выход в зависимости от настройки (`SPL-32`, `SPL-34`).

use super::cidr::IpCidr;
use super::config::{ConnApp, SplitConfig, SplitMode, ALWAYS_BYPASS_CIDRS};
use std::net::IpAddr;

/// Итоговое действие для соединения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Выпустить напрямую, минуя тоннель.
    Direct,
    /// Направить в тоннель.
    Tunnel,
    /// Заблокировать (kill-switch при неготовом тоннеле).
    Block,
}

/// Запрос на соединение, подлежащий классификации.
#[derive(Debug, Clone, Copy)]
pub struct ConnRequest<'a> {
    /// Инициатор соединения.
    pub app: &'a ConnApp,
    /// Адрес назначения.
    pub dst_ip: IpAddr,
    /// Порт назначения.
    pub dst_port: u16,
}

#[derive(Clone, Copy)]
enum Route {
    Direct,
    Tunnel,
}

/// Принимает решение по приоритетной лестнице `SPL-21`.
///
/// `tunnel_up` — готов ли сейчас тоннель (влияет на kill-switch).
pub fn decide(req: &ConnRequest, cfg: &SplitConfig, tunnel_up: bool) -> Action {
    // 1. Hairpin: трафик к самому VPN-серверу — всегда напрямую.
    if cfg
        .server_endpoints
        .iter()
        .any(|e| endpoint_ip(e) == Some(req.dst_ip))
    {
        return Action::Direct;
    }
    // 2. Локальная сеть и системные исключения.
    if cidrs_contain(ALWAYS_BYPASS_CIDRS.iter().copied(), req.dst_ip) {
        return Action::Direct;
    }
    // 3. Пользовательские «всегда напрямую».
    if cidrs_contain(
        cfg.force_direct_cidrs.iter().map(String::as_str),
        req.dst_ip,
    ) {
        return Action::Direct;
    }
    // 4–5. «Всегда в тоннель» либо решение по приложению.
    let intended = if cidrs_contain(
        cfg.force_tunnel_cidrs.iter().map(String::as_str),
        req.dst_ip,
    ) {
        Route::Tunnel
    } else {
        let selected = cfg.app_selected(req.app);
        match cfg.mode {
            SplitMode::Inclusive if selected => Route::Tunnel,
            SplitMode::Inclusive => Route::Direct,
            SplitMode::Exclusive if selected => Route::Direct,
            SplitMode::Exclusive => Route::Tunnel,
        }
    };
    // 6. Применяем готовность тоннеля и kill-switch.
    match intended {
        Route::Direct => Action::Direct,
        Route::Tunnel if tunnel_up => Action::Tunnel,
        Route::Tunnel if cfg.kill_switch => Action::Block,
        Route::Tunnel => Action::Direct,
    }
}

fn cidrs_contain<'a>(list: impl Iterator<Item = &'a str>, ip: IpAddr) -> bool {
    list.filter_map(|c| IpCidr::parse(c).ok())
        .any(|c| c.contains(ip))
}

/// Извлекает IP из строки endpoint вида `"ip"` или `"ip:port"`.
fn endpoint_ip(e: &str) -> Option<IpAddr> {
    if let Ok(ip) = e.parse::<IpAddr>() {
        return Some(ip);
    }
    e.rsplit_once(':')
        .and_then(|(host, _)| host.parse::<IpAddr>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::split::AppMatcher;

    fn app(path: &str) -> ConnApp {
        ConnApp {
            exe_path: Some(path.to_string()),
            process_name: None,
        }
    }

    fn dst(ip: &str) -> IpAddr {
        ip.parse().unwrap()
    }

    fn cfg_incl(apps: Vec<AppMatcher>) -> SplitConfig {
        SplitConfig {
            mode: SplitMode::Inclusive,
            apps,
            ..Default::default()
        }
    }

    fn selected_cfg() -> SplitConfig {
        cfg_incl(vec![AppMatcher::ExePath("C:\\app.exe".into())])
    }

    #[test]
    fn lan_always_direct_even_if_selected() {
        let a = app("C:\\app.exe");
        let r = ConnRequest {
            app: &a,
            dst_ip: dst("192.168.1.10"),
            dst_port: 443,
        };
        assert_eq!(decide(&r, &selected_cfg(), true), Action::Direct);
    }

    #[test]
    fn inclusive_selected_tunnels() {
        let a = app("C:\\app.exe");
        let r = ConnRequest {
            app: &a,
            dst_ip: dst("203.0.113.9"),
            dst_port: 443,
        };
        assert_eq!(decide(&r, &selected_cfg(), true), Action::Tunnel);
    }

    #[test]
    fn inclusive_unselected_direct() {
        let a = app("C:\\other.exe");
        let r = ConnRequest {
            app: &a,
            dst_ip: dst("203.0.113.9"),
            dst_port: 443,
        };
        assert_eq!(decide(&r, &selected_cfg(), true), Action::Direct);
    }

    #[test]
    fn exclusive_inverts() {
        let mut cfg = selected_cfg();
        cfg.mode = SplitMode::Exclusive;
        let sel = app("C:\\app.exe");
        let r_sel = ConnRequest {
            app: &sel,
            dst_ip: dst("203.0.113.9"),
            dst_port: 443,
        };
        assert_eq!(decide(&r_sel, &cfg, true), Action::Direct);

        let other = app("C:\\other.exe");
        let r_other = ConnRequest {
            app: &other,
            dst_ip: dst("203.0.113.9"),
            dst_port: 443,
        };
        assert_eq!(decide(&r_other, &cfg, true), Action::Tunnel);
    }

    #[test]
    fn hairpin_to_server_is_direct() {
        let mut cfg = selected_cfg();
        cfg.server_endpoints = vec!["203.0.113.9:443".into()];
        let a = app("C:\\app.exe");
        let r = ConnRequest {
            app: &a,
            dst_ip: dst("203.0.113.9"),
            dst_port: 443,
        };
        assert_eq!(decide(&r, &cfg, true), Action::Direct);
    }

    #[test]
    fn killswitch_blocks_when_tunnel_down() {
        let mut cfg = selected_cfg();
        cfg.kill_switch = true;
        let a = app("C:\\app.exe");
        let r = ConnRequest {
            app: &a,
            dst_ip: dst("203.0.113.9"),
            dst_port: 443,
        };
        assert_eq!(decide(&r, &cfg, false), Action::Block);
        cfg.kill_switch = false;
        assert_eq!(decide(&r, &cfg, false), Action::Direct);
    }

    #[test]
    fn force_tunnel_pulls_unselected_in() {
        let mut cfg = selected_cfg();
        cfg.force_tunnel_cidrs = vec!["203.0.113.0/24".into()];
        let a = app("C:\\other.exe");
        let r = ConnRequest {
            app: &a,
            dst_ip: dst("203.0.113.9"),
            dst_port: 443,
        };
        assert_eq!(decide(&r, &cfg, true), Action::Tunnel);
    }

    #[test]
    fn force_direct_wins_over_selection() {
        let mut cfg = selected_cfg();
        cfg.force_direct_cidrs = vec!["203.0.113.0/24".into()];
        let a = app("C:\\app.exe");
        let r = ConnRequest {
            app: &a,
            dst_ip: dst("203.0.113.9"),
            dst_port: 443,
        };
        assert_eq!(decide(&r, &cfg, true), Action::Direct);
    }
}
