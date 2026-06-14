//! Модель правила маршрутизации и его сопоставление.

use super::domain::DomainRule;
use crate::split::{AppMatcher, ConnApp, IpCidr};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Действие правила.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteAction {
    /// Выпустить напрямую.
    #[default]
    Direct,
    /// Направить в прокси: `None` — дефолтный outbound, `Some(tag)` — конкретный.
    Proxy(Option<String>),
    /// Заблокировать.
    Block,
}

/// Правило маршрутизации.
///
/// Семантика: правило срабатывает, если для **каждой непустой** категории
/// критериев совпало хотя бы одно значение (AND между категориями, OR внутри).
/// Правило без единого критерия — catch-all (срабатывает всегда), пригодно как
/// финальное.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Доменные критерии.
    pub domains: Vec<DomainRule>,
    /// IP-диапазоны.
    pub ip_cidrs: Vec<IpCidr>,
    /// Процессы.
    pub processes: Vec<AppMatcher>,
    /// Порты назначения.
    pub ports: Vec<u16>,
    /// Действие при срабатывании.
    pub action: RouteAction,
}

/// Соединение, подлежащее маршрутизации.
#[derive(Debug, Clone, Copy)]
pub struct RouteRequest<'a> {
    /// Имя хоста назначения, если известно.
    pub domain: Option<&'a str>,
    /// IP назначения, если известен.
    pub ip: Option<IpAddr>,
    /// Порт назначения.
    pub port: u16,
    /// Инициатор соединения.
    pub app: &'a ConnApp,
}

impl Rule {
    /// Совпадает ли правило с запросом.
    pub fn matches(&self, req: &RouteRequest) -> bool {
        if !self.domains.is_empty() {
            match req.domain {
                Some(h) if self.domains.iter().any(|d| d.matches(h)) => {}
                _ => return false,
            }
        }
        if !self.ip_cidrs.is_empty() {
            match req.ip {
                Some(ip) if self.ip_cidrs.iter().any(|c| c.contains(ip)) => {}
                _ => return false,
            }
        }
        if !self.processes.is_empty() && !self.processes.iter().any(|m| m.matches(req.app)) {
            return false;
        }
        if !self.ports.is_empty() && !self.ports.contains(&req.port) {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> ConnApp {
        ConnApp {
            exe_path: Some("C:\\app.exe".into()),
            process_name: None,
        }
    }

    fn req<'a>(
        domain: Option<&'a str>,
        ip: Option<&str>,
        port: u16,
        app: &'a ConnApp,
    ) -> RouteRequest<'a> {
        RouteRequest {
            domain,
            ip: ip.map(|s| s.parse().unwrap()),
            port,
            app,
        }
    }

    #[test]
    fn domain_rule_matches() {
        let a = app();
        let rule = Rule {
            domains: vec![DomainRule::Suffix("example.com".into())],
            action: RouteAction::Proxy(None),
            ..Default::default()
        };
        assert!(rule.matches(&req(Some("a.example.com"), None, 443, &a)));
        assert!(!rule.matches(&req(Some("other.net"), None, 443, &a)));
        // нет домена в запросе — доменное правило не срабатывает.
        assert!(!rule.matches(&req(None, Some("1.2.3.4"), 443, &a)));
    }

    #[test]
    fn and_across_categories() {
        let a = app();
        let rule = Rule {
            domains: vec![DomainRule::Keyword("video".into())],
            ports: vec![443],
            action: RouteAction::Direct,
            ..Default::default()
        };
        assert!(rule.matches(&req(Some("video.cdn"), None, 443, &a)));
        // домен ок, но порт не тот -> не срабатывает.
        assert!(!rule.matches(&req(Some("video.cdn"), None, 80, &a)));
    }

    #[test]
    fn empty_rule_is_catch_all() {
        let a = app();
        let rule = Rule {
            action: RouteAction::Block,
            ..Default::default()
        };
        assert!(rule.matches(&req(None, None, 1, &a)));
    }

    #[test]
    fn ip_and_process() {
        let a = app();
        let rule = Rule {
            ip_cidrs: vec![IpCidr::parse("10.0.0.0/8").unwrap()],
            processes: vec![AppMatcher::ProcessName("app.exe".into())],
            action: RouteAction::Direct,
            ..Default::default()
        };
        assert!(rule.matches(&req(None, Some("10.1.2.3"), 22, &a)));
        // IP вне диапазона.
        assert!(!rule.matches(&req(None, Some("11.0.0.1"), 22, &a)));
    }
}
