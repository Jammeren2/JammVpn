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

/// Правило: домены-суффиксы → действие.
fn suffix_rule(suffixes: &[&str], action: RouteAction) -> Rule {
    Rule {
        domains: suffixes
            .iter()
            .map(|s| DomainRule::Suffix((*s).to_string()))
            .collect(),
        action,
        ..Default::default()
    }
}

/// Обход РФ: российские домены (.ru/.рф + крупные сервисы) — напрямую, остальное
/// — в прокси. Доменная эвристика (не требует geo-баз). Для точности по IP можно
/// добавить правило `geoip:ru` вручную при загруженных базах.
pub fn bypass_ru() -> Vec<Rule> {
    vec![
        suffix_rule(
            &["ru", "su", "xn--p1ai", "vk.com", "vk.cc", "userapi.com", "mycdn.me"],
            RouteAction::Direct,
        ),
        Rule {
            action: RouteAction::Proxy(None),
            ..Default::default()
        },
    ]
}

/// Только Discord — через прокси, остальной трафик — напрямую.
pub fn discord_only() -> Vec<Rule> {
    vec![
        suffix_rule(
            &[
                "discord.com",
                "discord.gg",
                "discordapp.com",
                "discordapp.net",
                "discord.media",
                "discordcdn.com",
            ],
            RouteAction::Proxy(None),
        ),
        Rule {
            action: RouteAction::Direct,
            ..Default::default()
        },
    ]
}

/// Реестр готовых пресетов: `(id, имя, описание, правила)`.
pub fn presets() -> Vec<(&'static str, &'static str, &'static str, Vec<Rule>)> {
    vec![
        (
            "all-proxy",
            "Всё через прокси",
            "Весь трафик идёт через выбранный узел.",
            all_proxy(),
        ),
        (
            "all-direct",
            "Всё напрямую",
            "Весь трафик идёт напрямую (прокси отключён правилами).",
            all_direct(),
        ),
        (
            "bypass-ru",
            "Обход РФ",
            "Российские домены (.ru/.рф, VK и др.) — напрямую, остальное — в прокси.",
            bypass_ru(),
        ),
        (
            "discord",
            "Только Discord",
            "Discord — через прокси, остальной трафик — напрямую.",
            discord_only(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::{evaluate, RouteRequest};
    use crate::split::ConnApp;

    #[test]
    fn presets_registry_nonempty_and_unique_ids() {
        let p = presets();
        assert!(p.len() >= 4);
        let mut ids: Vec<&str> = p.iter().map(|(id, ..)| *id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), p.len(), "id пресетов должны быть уникальны");
        // Каждый пресет — непустой набор правил.
        assert!(p.iter().all(|(_, _, _, rules)| !rules.is_empty()));
    }

    #[test]
    fn bypass_ru_routes_ru_direct_foreign_proxy() {
        let app = ConnApp::default();
        let rules = bypass_ru();
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
        assert_eq!(evaluate(&rules, &ru, &RouteAction::Direct), RouteAction::Direct);
        assert_eq!(
            evaluate(&rules, &foreign, &RouteAction::Direct),
            RouteAction::Proxy(None)
        );
    }

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
