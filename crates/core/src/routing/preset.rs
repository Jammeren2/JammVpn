//! Готовые наборы правил из явных списков.
//!
//! Пресеты на основе geosite/geoip-баз (обход РФ-блокировок, «только-зарубеж» и
//! т.п.) появятся после интеграции загрузки баз; здесь — базовые конструкторы.

use super::domain::DomainRule;
use super::rule::{RouteAction, Rule};

/// Единственное catch-all правило: весь трафик в прокси.
pub fn all_proxy() -> Vec<Rule> {
    vec![Rule {
        action: RouteAction::Proxy(None),
        ..Default::default()
    }]
}

/// Единственное catch-all правило: весь трафик напрямую.
pub fn all_direct() -> Vec<Rule> {
    vec![Rule {
        action: RouteAction::Direct,
        ..Default::default()
    }]
}

/// По правилу на каждый доменный суффикс с действием «напрямую».
pub fn direct_domains(suffixes: &[&str]) -> Vec<Rule> {
    suffixes
        .iter()
        .map(|s| Rule {
            domains: vec![DomainRule::Suffix((*s).to_string())],
            action: RouteAction::Direct,
            ..Default::default()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::{evaluate, RouteRequest};
    use crate::split::ConnApp;

    #[test]
    fn direct_domains_then_default_proxy() {
        let app = ConnApp::default();
        let mut rules = direct_domains(&["sberbank.ru", "gosuslugi.ru"]);
        rules.extend(all_proxy());

        let ru = RouteRequest {
            domain: Some("online.sberbank.ru"),
            ip: None,
            port: 443,
            app: &app,
        };
        let foreign = RouteRequest {
            domain: Some("youtube.com"),
            ip: None,
            port: 443,
            app: &app,
        };
        assert_eq!(
            evaluate(&rules, &ru, &RouteAction::Direct),
            RouteAction::Direct
        );
        assert_eq!(
            evaluate(&rules, &foreign, &RouteAction::Direct),
            RouteAction::Proxy(None)
        );
    }
}
