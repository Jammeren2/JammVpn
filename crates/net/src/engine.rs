//! Движок туннеля: маршрутизация → выбор исходящего (ТЗ, разделы 4–5).
//!
//! Связывает движок правил [`jammvpn_core::routing`] с набором именованных
//! [`Outbound`]. На каждое соединение определяет действие (Direct / прокси по
//! тегу / Block) и проксирует через выбранный исходящий.

use crate::inbound::{relay_through, reply, socks_handshake};
use crate::outbound::Outbound;
use crate::target::Target;
use jammvpn_core::routing::{evaluate, RouteAction, RouteRequest, Rule};
use jammvpn_core::split::ConnApp;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

/// Решение для соединения.
#[derive(Debug, Clone)]
pub enum Decision {
    /// Проксировать через выбранный исходящий.
    Connect(Outbound),
    /// Заблокировать.
    Block,
}

/// Движок: правила маршрутизации + именованные исходящие.
pub struct Engine {
    outbounds: HashMap<String, Outbound>,
    default_proxy: Option<String>,
    rules: Vec<Rule>,
    default_action: RouteAction,
}

impl Engine {
    /// Создаёт движок.
    ///
    /// - `outbounds` — именованные прокси (тег → исходящий);
    /// - `default_proxy` — тег для правил `Proxy(None)`;
    /// - `rules` — правила (first-match);
    /// - `default_action` — действие, если ни одно правило не сработало.
    pub fn new(
        outbounds: HashMap<String, Outbound>,
        default_proxy: Option<String>,
        rules: Vec<Rule>,
        default_action: RouteAction,
    ) -> Self {
        Self {
            outbounds,
            default_proxy,
            rules,
            default_action,
        }
    }

    /// Определяет решение для цели соединения.
    ///
    /// Процесс-инициатор на уровне SOCKS5 неизвестен, поэтому правила по
    /// приложению здесь не срабатывают (их применяет драйвер до редиректа).
    pub fn resolve_target(&self, target: &Target) -> Decision {
        let app = ConnApp::default();
        let (domain, ip) = match target {
            Target::Domain(host, _) => (Some(host.as_str()), None),
            Target::Socket(addr) => (None, Some(addr.ip())),
        };
        let req = RouteRequest {
            domain,
            ip,
            port: target.port(),
            app: &app,
        };
        match evaluate(&self.rules, &req, &self.default_action) {
            RouteAction::Direct => Decision::Connect(Outbound::Direct),
            RouteAction::Block => Decision::Block,
            RouteAction::Proxy(tag) => {
                let key = tag.or_else(|| self.default_proxy.clone());
                match key.and_then(|k| self.outbounds.get(&k).cloned()) {
                    Some(ob) => Decision::Connect(ob),
                    None => Decision::Block,
                }
            }
        }
    }
}

/// SOCKS5-сервер с маршрутизацией: на каждое соединение применяет правила
/// движка и проксирует через выбранный исходящий (либо блокирует).
pub async fn serve_socks_routed(listener: TcpListener, engine: Arc<Engine>) -> io::Result<()> {
    loop {
        let (mut client, _) = listener.accept().await?;
        let eng = Arc::clone(&engine);
        tokio::spawn(async move {
            let target = match socks_handshake(&mut client).await {
                Ok(t) => t,
                Err(_) => return,
            };
            match eng.resolve_target(&target) {
                Decision::Connect(ob) => {
                    let _ = relay_through(client, &ob, &target).await;
                }
                Decision::Block => {
                    let _ = client.write_all(&reply(0x02)).await; // not allowed by ruleset
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::Socks5Config;
    use jammvpn_core::routing::DomainRule;

    fn engine_with(rules: Vec<Rule>, default_proxy: Option<String>) -> Engine {
        let mut obs = HashMap::new();
        obs.insert(
            "ss".to_string(),
            Outbound::Socks5(Socks5Config {
                server: "127.0.0.1:9".to_string(),
                username: None,
                password: None,
            }),
        );
        Engine::new(obs, default_proxy, rules, RouteAction::Direct)
    }

    fn domain(host: &str) -> Target {
        Target::Domain(host.to_string(), 443)
    }

    #[test]
    fn direct_by_default() {
        let e = engine_with(vec![], None);
        assert!(matches!(
            e.resolve_target(&domain("x.com")),
            Decision::Connect(Outbound::Direct)
        ));
    }

    #[test]
    fn proxy_by_rule_tag() {
        let rules = vec![Rule {
            domains: vec![DomainRule::Suffix("proxy.test".into())],
            action: RouteAction::Proxy(Some("ss".into())),
            ..Default::default()
        }];
        let e = engine_with(rules, None);
        assert!(matches!(
            e.resolve_target(&domain("a.proxy.test")),
            Decision::Connect(Outbound::Socks5(_))
        ));
        assert!(matches!(
            e.resolve_target(&domain("a.other")),
            Decision::Connect(Outbound::Direct)
        ));
    }

    #[test]
    fn block_rule() {
        let rules = vec![Rule {
            domains: vec![DomainRule::Keyword("ads".into())],
            action: RouteAction::Block,
            ..Default::default()
        }];
        let e = engine_with(rules, None);
        assert!(matches!(
            e.resolve_target(&domain("ads.net")),
            Decision::Block
        ));
    }

    #[test]
    fn proxy_none_uses_default_proxy_else_block() {
        let rule = Rule {
            action: RouteAction::Proxy(None),
            ..Default::default()
        };
        let with_default = engine_with(vec![rule.clone()], Some("ss".into()));
        assert!(matches!(
            with_default.resolve_target(&domain("any")),
            Decision::Connect(Outbound::Socks5(_))
        ));
        let without_default = engine_with(vec![rule], None);
        assert!(matches!(
            without_default.resolve_target(&domain("any")),
            Decision::Block
        ));
    }
}
