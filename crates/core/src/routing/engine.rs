//! Вычисление маршрута: first-match по списку правил.

use super::rule::{RouteAction, RouteRequest, Rule};

/// Возвращает действие первого сработавшего правила, иначе — `default`.
pub fn evaluate(rules: &[Rule], req: &RouteRequest, default: &RouteAction) -> RouteAction {
    for rule in rules {
        if rule.matches(req) {
            return rule.action.clone();
        }
    }
    default.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::DomainRule;
    use crate::split::ConnApp;

    fn sample_rules() -> Vec<Rule> {
        vec![
            Rule {
                domains: vec![DomainRule::Suffix("ads.net".into())],
                action: RouteAction::Block,
                ..Default::default()
            },
            Rule {
                domains: vec![DomainRule::Suffix("example.com".into())],
                action: RouteAction::Proxy(None),
                ..Default::default()
            },
        ]
    }

    #[test]
    fn first_match_wins_else_default() {
        let app = ConnApp::default();
        let rules = sample_rules();
        // Замыкание возвращает владеющее RouteAction (без утечки заимствования).
        let route = |host: &str| -> RouteAction {
            let req = RouteRequest {
                domain: Some(host),
                ip: None,
                port: 443,
                app: &app,
            };
            evaluate(&rules, &req, &RouteAction::Direct)
        };
        assert_eq!(route("x.ads.net"), RouteAction::Block);
        assert_eq!(route("a.example.com"), RouteAction::Proxy(None));
        assert_eq!(route("unknown.org"), RouteAction::Direct);
    }
}
