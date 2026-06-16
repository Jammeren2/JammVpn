//! Движок туннеля: маршрутизация → выбор исходящего (ТЗ, разделы 4–5).
//!
//! Связывает движок правил [`jammvpn_core::routing`] с набором именованных
//! [`Outbound`]. На каждое соединение определяет действие (Direct / прокси по
//! тегу / Block) и проксирует через выбранный исходящий.

use crate::dns::{DnsResolver, DnsServer};
use crate::fakeip::FakeIp;
use crate::from_profile::outbound_from_profile;
use crate::inbound::{reply, socks_handshake, SocksRequest};
use crate::outbound::Outbound;
use crate::target::Target;
use jammvpn_core::config::{AppConfig, DnsServerConfig};
use jammvpn_core::geo::{GeoIpDb, GeoSiteDb};
use jammvpn_core::routing::{RouteAction, Rule};
use jammvpn_core::split::ConnApp;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Решение для соединения.
#[derive(Debug, Clone)]
pub enum Decision {
    /// Проксировать через выбранный исходящий.
    Connect(Outbound),
    /// Заблокировать.
    Block,
}

/// Результат маршрутизации: решение + эффективная цель.
///
/// `target` может отличаться от исходной: при FakeIP-реверсе поддельный IP
/// заменяется восстановленным доменом, чтобы исходящий подключался по домену
/// (реальный резолв — на стороне прокси/Direct, без утечки DNS).
#[derive(Debug, Clone)]
pub struct Routed {
    /// Что делать с соединением.
    pub decision: Decision,
    /// Цель для подключения исходящим.
    pub target: Target,
}

/// Движок: правила маршрутизации + именованные исходящие.
///
/// Опционально содержит DNS-резолвер (чтобы IP-CIDR/geoip правила срабатывали и
/// для доменных целей) и FakeIP (восстановление домена по поддельному IP).
pub struct Engine {
    outbounds: HashMap<String, Outbound>,
    default_proxy: Option<String>,
    rules: Vec<Rule>,
    default_action: RouteAction,
    resolver: Option<DnsResolver>,
    fakeip: Option<Arc<FakeIp>>,
    geosite: Option<Arc<GeoSiteDb>>,
    geoip: Option<Arc<GeoIpDb>>,
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
            resolver: None,
            fakeip: None,
            geosite: None,
            geoip: None,
        }
    }

    /// Добавляет DNS-резолвер: домены резолвятся для проверки IP-CIDR правил
    /// (лениво, только когда правило различается лишь по IP).
    pub fn with_resolver(mut self, resolver: DnsResolver) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Добавляет FakeIP: восстановление домена по поддельному IP при маршрутизации.
    pub fn with_fakeip(mut self, fakeip: Arc<FakeIp>) -> Self {
        self.fakeip = Some(fakeip);
        self
    }

    /// Добавляет базу geosite (правила `geosite:категория` по доменам).
    pub fn with_geosite(mut self, db: Arc<GeoSiteDb>) -> Self {
        self.geosite = Some(db);
        self
    }

    /// Добавляет базу geoip (правила `geoip:страна` по IP).
    pub fn with_geoip(mut self, db: Arc<GeoIpDb>) -> Self {
        self.geoip = Some(db);
        self
    }

    /// FakeIP-аллокатор движка (для DNS-сервера, отвечающего поддельными IP).
    pub fn fakeip(&self) -> Option<&Arc<FakeIp>> {
        self.fakeip.as_ref()
    }

    /// Именованные исходящие (тег → исходящий) — для тестирования задержек
    /// ([`crate::urltest::test_outbounds`]) и выбора узла.
    pub fn outbounds(&self) -> &HashMap<String, Outbound> {
        &self.outbounds
    }

    /// Описания правил, ссылающихся на geo-категории, базы для которых НЕ
    /// загружены (`geosite`/`geoip` == None). Непустой результат означает, что
    /// набор правил не может быть выполнен: geo-критерий тогда никогда не
    /// совпадает, и `Block`-правило молча выродилось бы в пропуск (fail-open).
    /// Фронтенд должен отказаться от запуска, а не выпускать трафик мимо правил.
    pub fn missing_geo_refs(&self) -> Vec<String> {
        let mut missing = Vec::new();
        for (i, rule) in self.rules.iter().enumerate() {
            if !rule.geosite.is_empty() && self.geosite.is_none() {
                missing.push(format!(
                    "правило #{}: geosite {:?} — база geosite не загружена",
                    i + 1,
                    rule.geosite
                ));
            }
            if !rule.geoip.is_empty() && self.geoip.is_none() {
                missing.push(format!(
                    "правило #{}: geoip {:?} — база geoip не загружена",
                    i + 1,
                    rule.geoip
                ));
            }
        }
        missing
    }

    /// Движок, тунелирующий ВЕСЬ трафик через единственный исходящий.
    pub fn single_proxy(outbound: Outbound) -> Self {
        let mut outbounds = HashMap::new();
        outbounds.insert("proxy".to_string(), outbound);
        Engine::new(
            outbounds,
            Some("proxy".to_string()),
            Vec::new(),
            RouteAction::Proxy(None),
        )
    }

    /// Строит движок из загруженного конфига [`AppConfig`].
    ///
    /// Серверы становятся именованными исходящими (тег = имя профиля);
    /// нераспознанные/неподдержанные серверы пропускаются.
    pub fn from_config(cfg: &AppConfig) -> Self {
        let mut outbounds = HashMap::new();
        for server in &cfg.servers {
            if let Ok(ob) = outbound_from_profile(server) {
                outbounds.insert(server.name.clone(), ob);
            }
        }
        let default_action = if cfg.settings.default_to_proxy {
            RouteAction::Proxy(None)
        } else {
            RouteAction::Direct
        };
        let mut engine = Engine::new(
            outbounds,
            cfg.settings.default_proxy.clone(),
            cfg.rules.clone(),
            default_action,
        );
        // DNS-резолвер: первый корректно разобранный сервер из конфига.
        if let Some(server) = cfg.dns.servers.iter().find_map(dns_server_from_config) {
            engine.resolver = Some(DnsResolver::new(server));
        }
        // FakeIP: при включении. Некорректный диапазон в конфиге не отключает
        // фичу — откатываемся на дефолтный 198.18.0.0/15.
        if cfg.dns.fakeip.enabled {
            const DEFAULT_RANGE: &str = "198.18.0.0/15";
            let fi = FakeIp::new(&cfg.dns.fakeip.range).or_else(|e| {
                eprintln!(
                    "предупреждение: некорректный FakeIP-диапазон «{}» ({e}); беру {DEFAULT_RANGE}",
                    cfg.dns.fakeip.range
                );
                FakeIp::new(DEFAULT_RANGE)
            });
            match fi {
                Ok(fi) => engine.fakeip = Some(Arc::new(fi)),
                Err(e) => eprintln!("предупреждение: FakeIP отключён ({e})"),
            }
        }
        // Базы geosite/geoip: загружаем при заданных путях (сбой → предупреждение).
        if let Some(p) = &cfg.geo.geosite_path {
            match GeoSiteDb::load(Path::new(p)) {
                Ok(db) => engine.geosite = Some(Arc::new(db)),
                Err(e) => eprintln!("предупреждение: geosite не загружен ({e})"),
            }
        }
        if let Some(p) = &cfg.geo.geoip_path {
            match GeoIpDb::load(Path::new(p)) {
                Ok(db) => engine.geoip = Some(Arc::new(db)),
                Err(e) => eprintln!("предупреждение: geoip не загружен ({e})"),
            }
        }
        engine
    }

    /// Определяет решение для цели соединения **без DNS-резолва** (синхронно).
    ///
    /// # ⚠️ Внимание: НЕ использовать для доменных целей при IP/geoip-правилах
    ///
    /// Для доменной цели ([`Target::Domain`] с нелитеральным хостом, т.е. без
    /// собственного IP) IP-критерии (`ip_cidrs`/`geoip`) **молча пропускаются**:
    /// домен здесь не резолвится, IP неизвестен — правило не срабатывает, и
    /// маршрутизация уходит в `default_action` (обычно `Direct`). Это значит, что
    /// `geoip:ru -> Block` или `ip_cidrs -> Block` на этом пути **fail-open**:
    /// блокировка молча обходится. Наличие резолвера ([`with_resolver`]) тут НЕ
    /// помогает — метод синхронный и не резолвит вовсе.
    ///
    /// Корректную fail-closed семантику (резолв домена + сбой DNS → `Block`) даёт
    /// только асинхронный [`Engine::route`] — используйте **его** для любого
    /// реального трафика. `resolve_target` допустим лишь там, где гарантировано
    /// нет IP/geoip-правил, либо цель — всегда литеральный IP / [`Target::Socket`].
    /// Расхождение закреплено тестом
    /// `resolve_target_fails_open_vs_route_on_domain_ip_rule`.
    ///
    /// [`with_resolver`]: Engine::with_resolver
    ///
    /// ---
    ///
    /// Процесс-инициатор на уровне SOCKS5 неизвестен, поэтому правила по
    /// приложению здесь не срабатывают (их применяет драйвер до редиректа).
    /// IP-критерии (`ip_cidrs`/`geoip`) для доменной цели срабатывают только если
    /// домен сам — литеральный IP; полный резолв — через [`Engine::route`].
    /// Доменные критерии (`domains`/`geosite`) работают всегда.
    pub fn resolve_target(&self, target: &Target) -> Decision {
        let app = ConnApp::default();
        let port = target.port();
        let (domain, ip) = match target {
            // Литеральный IP, закодированный как домен (легальный SOCKS5 ATYP=3),
            // тоже подаём IP-правилам — иначе IP-CIDR Block/Proxy тривиально обходятся.
            Target::Domain(host, _) => (Some(host.as_str()), literal_ip(host)),
            Target::Socket(addr) => (None, Some(addr.ip())),
        };
        let mut action = self.default_action.clone();
        for rule in &self.rules {
            if !self.non_ip_ok(rule, domain, port, &app) {
                continue;
            }
            if !has_ip_crit(rule) {
                action = rule.action.clone();
                break;
            }
            // Есть IP-критерий: без резолва сверяем только известный IP.
            if let Some(i) = ip {
                if self.ip_in_rule(rule, i) {
                    action = rule.action.clone();
                    break;
                }
            }
        }
        self.act(&action)
    }

    /// Маршрутизирует цель с учётом DNS (FakeIP-реверс + ленивый резолв доменов
    /// для IP-CIDR правил). Возвращает решение и эффективную цель подключения.
    ///
    /// Семантика first-match сохранена: доменные правила выше по списку решают
    /// раньше, чем дойдёт до резолва.
    ///
    /// **Сбой DNS — fail-closed для блокировки.** Если IP-CIDR `Block`-правило не
    /// удалось подтвердить (DNS недоступен/таймаут/пустой ответ), движок НЕ
    /// понижает решение до default (обычно `Direct`) — иначе подавление DNS
    /// открывало бы обход блокировки. Вместо этого, если ни одно правило не
    /// сработало явно, применяется `Block`. Явный матч любого правила (включая
    /// доменный `Direct`/`Proxy`) имеет приоритет над этим fail-closed.
    ///
    /// **Приватность.** Для IP-CIDR правил по доменной цели резолв выполняется
    /// локальным резолвером движка (в т.ч. для `Proxy`-правил). Используйте DoT/DoH
    /// (шифрованный транспорт) и предпочитайте доменные/geosite-правила; в
    /// TUN-режиме FakeIP убирает локальный резолв полностью.
    pub async fn route(&self, target: &Target) -> Routed {
        let app = ConnApp::default();
        let port = target.port();
        let (mut domain, mut ip) = match target {
            Target::Domain(host, _) => (Some(host.clone()), literal_ip(host)),
            Target::Socket(addr) => (None, Some(addr.ip())),
        };

        // FakeIP-реверс: цель — поддельный IP → восстанавливаем домен и дальше
        // маршрутизируем и подключаемся по домену (резолв на стороне исходящего).
        let mut effective = target.clone();
        if let Some(fi) = &self.fakeip {
            if let Some(i) = ip {
                if let Some(d) = fi.domain_of(i) {
                    effective = Target::Domain(d.clone(), port);
                    domain = Some(d);
                    ip = None;
                }
            }
        }

        // Проход по правилам (first-match) с ленивым резолвом для IP-критериев.
        // `resolved`: None — ещё не резолвили; Some(Ok) — адреса; Some(Err) — сбой
        // (различаем явно, чтобы сбой DNS не маскировался под «нет совпадения»).
        let mut resolved: Option<Result<Vec<IpAddr>, ()>> = None;
        let mut action = self.default_action.clone();
        let mut matched = false;
        let mut pending_block = false;
        for rule in &self.rules {
            // Не-IP критерии: домен (domains+geosite), порт, процесс.
            if !self.non_ip_ok(rule, domain.as_deref(), port, &app) {
                continue;
            }
            // Нет IP-критерия → правило сработало.
            if !has_ip_crit(rule) {
                action = rule.action.clone();
                matched = true;
                break;
            }
            // IP известен — сверяем напрямую (ip_cidrs + geoip).
            if let Some(i) = ip {
                if self.ip_in_rule(rule, i) {
                    action = rule.action.clone();
                    matched = true;
                    break;
                }
                continue;
            }
            // Домен без IP: резолвим (единожды) и сверяем адреса с ip_cidrs+geoip.
            if let Some(r) = &self.resolver {
                if resolved.is_none() {
                    let name = domain.as_deref().unwrap_or_default();
                    resolved = Some(r.resolve(name).await.map_err(|_| ()));
                }
                match resolved.as_ref() {
                    Some(Ok(ips)) => {
                        if ips.iter().any(|rip| self.ip_in_rule(rule, *rip)) {
                            action = rule.action.clone();
                            matched = true;
                            break;
                        }
                    }
                    // Сбой резолва + Block-правило: IP не подтвердить, но молча
                    // пропускать нельзя — помечаем для fail-closed (см. ниже).
                    Some(Err(())) if matches!(rule.action, RouteAction::Block) => {
                        pending_block = true;
                    }
                    _ => {}
                }
            }
        }

        // Неподтверждённый из-за сбоя DNS Block не должен утекать в default.
        if !matched && pending_block {
            action = RouteAction::Block;
        }

        Routed {
            decision: self.act(&action),
            target: effective,
        }
    }

    /// Совпали ли НЕ-IP критерии правила: домен (`domains`/`geosite`), порт, процесс.
    fn non_ip_ok(&self, rule: &Rule, domain: Option<&str>, port: u16, app: &ConnApp) -> bool {
        if !rule.domains.is_empty() || !rule.geosite.is_empty() {
            match domain {
                Some(h) if self.domain_in_rule(rule, h) => {}
                _ => return false,
            }
        }
        if !rule.ports.is_empty() && !rule.ports.contains(&port) {
            return false;
        }
        if !rule.processes.is_empty() && !rule.processes.iter().any(|m| m.matches(app)) {
            return false;
        }
        true
    }

    /// Совпадает ли домен с правилом: явные `domains` ИЛИ категории `geosite`.
    fn domain_in_rule(&self, rule: &Rule, host: &str) -> bool {
        rule.domains.iter().any(|d| d.matches(host))
            || rule.geosite.iter().any(|cat| {
                self.geosite
                    .as_ref()
                    .is_some_and(|db| db.matches(cat, host))
            })
    }

    /// Входит ли IP в правило: явные `ip_cidrs` ИЛИ страны `geoip`.
    fn ip_in_rule(&self, rule: &Rule, ip: IpAddr) -> bool {
        rule.ip_cidrs.iter().any(|c| c.contains(ip))
            || rule
                .geoip
                .iter()
                .any(|cc| self.geoip.as_ref().is_some_and(|db| db.matches(cc, ip)))
    }

    /// Превращает действие правила в решение (резолвит тег прокси).
    fn act(&self, action: &RouteAction) -> Decision {
        match action {
            RouteAction::Direct => Decision::Connect(Outbound::Direct),
            RouteAction::Block => Decision::Block,
            RouteAction::Proxy(tag) => {
                let key = tag.clone().or_else(|| self.default_proxy.clone());
                match key.and_then(|k| self.outbounds.get(&k).cloned()) {
                    Some(ob) => Decision::Connect(ob),
                    None => Decision::Block,
                }
            }
        }
    }
}

/// Есть ли у правила IP-критерий (`ip_cidrs` или `geoip`).
fn has_ip_crit(rule: &Rule) -> bool {
    !rule.ip_cidrs.is_empty() || !rule.geoip.is_empty()
}

/// Парсит `host` как литеральный IP, нормализуя завершающую точку и обрамляющие
/// скобки. Без этого `"1.1.1.9."` или `"[::1]"` дали бы `ip=None` и обошли
/// IP-CIDR/geoip-правила (трафик ушёл бы в default вместо Block/Proxy).
fn literal_ip(host: &str) -> Option<IpAddr> {
    let h = host.strip_suffix('.').unwrap_or(host);
    let h = h
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(h);
    h.parse::<IpAddr>().ok()
}

/// Преобразует описание DNS-сервера из конфига в транспорт `net` (None — если
/// адрес не разобрался).
fn dns_server_from_config(c: &DnsServerConfig) -> Option<DnsServer> {
    match c {
        DnsServerConfig::Udp { server } => server.parse().ok().map(DnsServer::Udp),
        DnsServerConfig::Dot { server, sni } => server.parse().ok().map(|s| DnsServer::Dot {
            server: s,
            sni: sni.clone(),
        }),
        DnsServerConfig::Doh { url } => Some(DnsServer::Doh(url.clone())),
    }
}

/// Предел одновременных клиентских соединений (анти-DoS).
const MAX_CONNECTIONS: usize = 1024;
/// Таймаут на SOCKS5-рукопожатие: висящий клиент не должен держать ресурсы.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// SOCKS5-сервер с маршрутизацией: на каждое соединение применяет правила
/// движка и проксирует через выбранный исходящий (либо блокирует). Число
/// одновременных соединений ограничено ([`MAX_CONNECTIONS`]), рукопожатие — под
/// таймаутом ([`HANDSHAKE_TIMEOUT`]).
pub async fn serve_socks_routed(listener: TcpListener, engine: Arc<Engine>) -> io::Result<()> {
    serve_routed(listener, engine, MAX_CONNECTIONS).await
}

async fn serve_routed(
    listener: TcpListener,
    engine: Arc<Engine>,
    max_conns: usize,
) -> io::Result<()> {
    let sem = Arc::new(tokio::sync::Semaphore::new(max_conns));
    loop {
        let (mut client, _) = listener.accept().await?;
        // Лимит исчерпан → отклоняем (закрываем) новое соединение, а не копим задачи.
        let permit = match Arc::clone(&sem).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let eng = Arc::clone(&engine);
        tokio::spawn(async move {
            let _permit = permit; // держим до конца обработки соединения
            // Сниффим первый байт без потребления: 0x05 → SOCKS5, иначе → HTTP-прокси.
            // Так один локальный порт принимает и SOCKS5, и HTTP CONNECT (для
            // системного прокси Windows, который говорит по HTTP).
            let mut peeked = [0u8; 1];
            let first = match tokio::time::timeout(HANDSHAKE_TIMEOUT, client.peek(&mut peeked)).await
            {
                Ok(Ok(1)) => peeked[0],
                _ => return,
            };
            if first != 0x05 {
                let _ = tokio::time::timeout(HANDSHAKE_TIMEOUT, handle_http(client, &eng)).await;
                return;
            }
            let req =
                match tokio::time::timeout(HANDSHAKE_TIMEOUT, socks_handshake(&mut client)).await {
                    Ok(Ok(r)) => r,
                    _ => return, // таймаут рукопожатия или ошибка
                };
            match req {
                SocksRequest::Connect(target) => {
                    let routed = eng.route(&target).await;
                    match routed.decision {
                        Decision::Connect(ob) => match ob.connect_tcp(&routed.target).await {
                            Ok(up) => {
                                let _ = client.write_all(&reply(0x00)).await;
                                let g = crate::conn::register(
                                    target_label(&routed.target),
                                    via_label(&ob),
                                );
                                let _ = crate::conn::copy_counted(client, up, &g).await;
                            }
                            Err(_) => {
                                let _ = client.write_all(&reply(0x05)).await; // connection refused
                            }
                        },
                        Decision::Block => {
                            let _ = client.write_all(&reply(0x02)).await; // not allowed by ruleset
                        }
                    }
                }
                SocksRequest::UdpAssociate => {
                    let _ = crate::udp::udp_associate(client, eng).await;
                }
            }
        });
    }
}

/// Метка маршрута для монитора соединений.
fn via_label(ob: &Outbound) -> &'static str {
    match ob {
        Outbound::Direct => "direct",
        _ => "proxy",
    }
}

/// Текстовое представление цели для монитора (`host:port` / `ip:port`).
fn target_label(t: &Target) -> String {
    match t {
        Target::Domain(h, p) => format!("{h}:{p}"),
        Target::Socket(a) => a.to_string(),
    }
}

/// Обрабатывает HTTP-прокси соединение: `CONNECT host:port` (туннель, для HTTPS)
/// и absolute-form запросы (`GET http://host/path` — обычный HTTP). Маршрутизация
/// — тем же движком. Нужно для системного прокси Windows (WinINET говорит по HTTP).
async fn handle_http(mut client: TcpStream, engine: &Engine) -> io::Result<()> {
    let head = read_http_head(&mut client).await?;
    let text = String::from_utf8_lossy(&head);
    let req_line = text.split("\r\n").next().unwrap_or("");
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target_str = parts.next().unwrap_or("").to_string();

    if method.eq_ignore_ascii_case("CONNECT") {
        // authority-form: host:port (порт обязателен).
        let (host, port) = split_host_port(&target_str, 443);
        let routed = engine.route(&Target::Domain(host, port)).await;
        match routed.decision {
            Decision::Connect(ob) => match ob.connect_tcp(&routed.target).await {
                Ok(up) => {
                    client
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await?;
                    let g = crate::conn::register(target_label(&routed.target), via_label(&ob));
                    crate::conn::copy_counted(client, up, &g).await
                }
                Err(e) => {
                    let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    Err(e)
                }
            },
            Decision::Block => {
                client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
                Ok(())
            }
        }
    } else {
        // absolute-form: METHOD http://host[:port]/path HTTP/1.1 → форвард в origin-form.
        let Some((host, port, path)) = parse_absolute_uri(&target_str) else {
            client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await?;
            return Ok(());
        };
        let routed = engine.route(&Target::Domain(host, port)).await;
        match routed.decision {
            Decision::Connect(ob) => match ob.connect_tcp(&routed.target).await {
                Ok(mut up) => {
                    // Переписываем строку запроса в origin-form, сохраняя заголовки.
                    let headers_block = head
                        .windows(2)
                        .position(|w| w == b"\r\n")
                        .map(|i| &head[i + 2..])
                        .unwrap_or(b"");
                    let mut out = format!("{method} {path} HTTP/1.1\r\n").into_bytes();
                    out.extend_from_slice(headers_block);
                    up.write_all(&out).await?;
                    let g = crate::conn::register(target_label(&routed.target), via_label(&ob));
                    crate::conn::copy_counted(client, up, &g).await
                }
                Err(e) => {
                    let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    Err(e)
                }
            },
            Decision::Block => {
                client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
                Ok(())
            }
        }
    }
}

/// Читает HTTP-заголовок до `\r\n\r\n` (с ограничением размера).
async fn read_http_head(client: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        if client.read(&mut byte).await? == 0 {
            return Err(io::Error::other("http: соединение закрыто до конца заголовка"));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > 16384 {
            return Err(io::Error::other("http: заголовок слишком велик"));
        }
    }
}

/// `host:port` → (host, port); без порта — `default`. Поддерживает `[v6]:port`.
fn split_host_port(s: &str, default: u16) -> (String, u16) {
    if let Some(rest) = s.strip_prefix('[') {
        // [v6]:port
        if let Some((h, p)) = rest.split_once("]:") {
            return (h.to_string(), p.parse().unwrap_or(default));
        }
        if let Some(h) = rest.strip_suffix(']') {
            return (h.to_string(), default);
        }
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => (h.to_string(), p.parse().unwrap_or(default)),
        _ => (s.to_string(), default),
    }
}

/// `http://host[:port]/path` → (host, port, "/path"). `None` — не absolute-form.
fn parse_absolute_uri(uri: &str) -> Option<(String, u16, String)> {
    let rest = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("https://"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = split_host_port(authority, 80);
    if host.is_empty() {
        return None;
    }
    Some((host, port, path.to_string()))
}

/// Транспарентный сервер для split-редиректа.
///
/// Драйвер WFP перенаправляет соединения выбранных приложений на этот локальный
/// порт. `original_dst` восстанавливает истинный адрес назначения (из
/// redirect-context драйвера — на Windows через `SIO_QUERY_WFP_CONNECTION_
/// REDIRECT_CONTEXT`), далее соединение маршрутизируется движком как обычно.
/// Лимит соединений — [`MAX_CONNECTIONS`]; `Block` → закрытие.
pub async fn serve_transparent_redirect<F>(
    listener: TcpListener,
    engine: Arc<Engine>,
    original_dst: F,
) -> io::Result<()>
where
    F: Fn(&TcpStream) -> io::Result<SocketAddr> + Send + Sync + 'static,
{
    let original_dst = Arc::new(original_dst);
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (client, _) = listener.accept().await?;
        // Лимит исчерпан → закрываем новое соединение, не копим задачи.
        let permit = match Arc::clone(&sem).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let eng = Arc::clone(&engine);
        let odf = Arc::clone(&original_dst);
        tokio::spawn(async move {
            let _permit = permit; // держим до конца обработки
            let dst = match odf(&client) {
                Ok(d) => d,
                Err(_) => return, // нет redirect-context (не наше соединение) → закрыть
            };
            let routed = eng.route(&Target::Socket(dst)).await;
            // Транспарентный redirect: клиентского протокола нет (в отличие от
            // SOCKS), поэтому подключаем исходящий и копируем напрямую, без
            // относящегося к SOCKS ответа.
            if let Decision::Connect(ob) = routed.decision {
                if let Ok(upstream) = ob.connect_tcp(&routed.target).await {
                    let g = crate::conn::register(target_label(&routed.target), via_label(&ob));
                    let _ = crate::conn::copy_counted(client, upstream, &g).await;
                }
            }
            // Decision::Block → просто закрываем соединение.
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::Socks5Config;
    use jammvpn_core::routing::DomainRule;

    #[tokio::test]
    async fn http_connect_tunnels_to_target() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Эхо-сервер как цель CONNECT.
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = echo.accept().await {
                let mut buf = [0u8; 5];
                if s.read_exact(&mut buf).await.is_ok() {
                    let _ = s.write_all(&buf).await;
                }
            }
        });

        // Смешанный inbound с Direct-маршрутизацией.
        let engine = Arc::new(Engine::from_config(&AppConfig::default()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = serve_socks_routed(listener, engine).await;
        });

        // Клиент шлёт HTTP CONNECT (первый байт 'C' ≠ 0x05 → HTTP-ветка).
        let mut c = TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: x\r\n\r\n",
            echo_addr.ip(),
            echo_addr.port()
        );
        c.write_all(req.as_bytes()).await.unwrap();

        // Ответ 200 (до \r\n\r\n).
        let mut resp = Vec::new();
        let mut b = [0u8; 1];
        loop {
            c.read_exact(&mut b).await.unwrap();
            resp.push(b[0]);
            if resp.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 200"));

        // Туннель работает: эхо.
        c.write_all(b"hello").await.unwrap();
        let mut out = [0u8; 5];
        c.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"hello");
    }

    #[tokio::test]
    async fn transparent_redirect_relays_to_original_dst() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Эхо-сервер играет роль «оригинального» пункта назначения.
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = echo.accept().await {
                let mut buf = [0u8; 5];
                if s.read_exact(&mut buf).await.is_ok() {
                    let _ = s.write_all(&buf).await;
                }
            }
        });

        // Движок с Direct-маршрутизацией (пустой конфиг).
        let engine = Arc::new(Engine::from_config(&AppConfig::default()));

        // Транспарентный сервер: original_dst всегда возвращает адрес эхо-сервера
        // (в бою его отдаёт redirect-context драйвера).
        let redir = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redir_addr = redir.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = serve_transparent_redirect(redir, engine, move |_| Ok(echo_addr)).await;
        });

        // Клиент подключается к редирект-серверу; ожидаем эхо через relay.
        let mut c = TcpStream::connect(redir_addr).await.unwrap();
        c.write_all(b"hello").await.unwrap();
        let mut out = [0u8; 5];
        c.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"hello");
    }

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

    use crate::dns::{DnsResolver, DnsServer};
    use crate::fakeip::FakeIp;
    use jammvpn_core::split::IpCidr;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tokio::net::UdpSocket;

    /// Mock-UDP-DNS: на любой запрос отвечает фиксированной A-записью (эхо ID,
    /// копия вопроса). Циклично — `resolve` шлёт A и AAAA.
    async fn mock_dns(answer: Ipv4Addr) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                let mut resp = Vec::new();
                resp.extend_from_slice(&[buf[0], buf[1]]); // ID
                resp.extend_from_slice(&0x8180u16.to_be_bytes()); // QR+RD+RA
                resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
                resp.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
                resp.extend_from_slice(&[0, 0, 0, 0]);
                resp.extend_from_slice(&buf[12..n]); // копия вопроса
                resp.extend_from_slice(&[0xC0, 0x0C]); // указатель на вопрос
                resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE_A
                resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
                resp.extend_from_slice(&60u32.to_be_bytes()); // TTL
                resp.extend_from_slice(&4u16.to_be_bytes()); // RDLEN
                resp.extend_from_slice(&answer.octets());
                let _ = sock.send_to(&resp, peer).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn connection_limit_rejects_excess() {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpStream;
        let engine = Arc::new(Engine::new(
            HashMap::new(),
            None,
            Vec::new(),
            RouteAction::Direct,
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_routed(listener, engine, 2)); // лимит = 2

        // Два «висящих» соединения (не шлём рукопожатие → держат permit в handshake).
        let c1 = TcpStream::connect(addr).await.unwrap();
        let c2 = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 3-е: сервер примет, permit нет → закроет; read вернёт EOF (0).
        let mut c3 = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 1];
        let r = tokio::time::timeout(Duration::from_secs(2), c3.read(&mut buf)).await;
        assert!(
            matches!(r, Ok(Ok(0))),
            "сверхлимитное соединение должно быть закрыто (EOF)"
        );
        drop((c1, c2));
    }

    #[tokio::test]
    async fn route_resolves_domain_for_ip_cidr_rule() {
        let dns_ip = Ipv4Addr::new(203, 0, 113, 7);
        let dns = mock_dns(dns_ip).await;
        let rule = Rule {
            ip_cidrs: vec![IpCidr::parse("203.0.113.0/24").unwrap()],
            action: RouteAction::Block,
            ..Default::default()
        };
        // Без резолвера: домен не резолвится → IP-CIDR не срабатывает → Direct.
        let plain = engine_with(vec![rule.clone()], None);
        let r = plain.route(&domain("blocked.example")).await;
        assert!(matches!(r.decision, Decision::Connect(Outbound::Direct)));
        // С резолвером: blocked.example → 203.0.113.7 ∈ CIDR → Block.
        let with_dns =
            engine_with(vec![rule], None).with_resolver(DnsResolver::new(DnsServer::Udp(dns)));
        let r = with_dns.route(&domain("blocked.example")).await;
        assert!(matches!(r.decision, Decision::Block));
    }

    #[tokio::test]
    async fn route_domain_rule_decides_before_resolve() {
        // rule1 (домен) выше rule2 (IP-CIDR на всё) → решает rule1, резолва нет.
        let rules = vec![
            Rule {
                domains: vec![DomainRule::Suffix("proxy.test".into())],
                action: RouteAction::Proxy(Some("ss".into())),
                ..Default::default()
            },
            Rule {
                ip_cidrs: vec![IpCidr::parse("0.0.0.0/0").unwrap()],
                action: RouteAction::Block,
                ..Default::default()
            },
        ];
        // Резолвер на «мёртвый» порт: дойди до резолва — был бы Block (или таймаут).
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let e = engine_with(rules, None).with_resolver(
            DnsResolver::new(DnsServer::Udp(dead))
                .with_timeout(std::time::Duration::from_millis(200)),
        );
        let r = e.route(&domain("a.proxy.test")).await;
        assert!(
            matches!(r.decision, Decision::Connect(Outbound::Socks5(_))),
            "доменное правило решает раньше IP-CIDR/резолва"
        );
    }

    // Мини-энкодер protobuf для синтетических geo-баз (core::geo::tests_support под
    // cfg(test) недоступен из net).
    fn pb_varint(out: &mut Vec<u8>, mut v: u64) {
        loop {
            let mut b = (v & 0x7F) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                break;
            }
        }
    }
    fn pb_len(out: &mut Vec<u8>, field: u32, data: &[u8]) {
        pb_varint(out, (u64::from(field) << 3) | 2);
        pb_varint(out, data.len() as u64);
        out.extend_from_slice(data);
    }
    fn pb_vint(out: &mut Vec<u8>, field: u32, v: u64) {
        pb_varint(out, u64::from(field) << 3);
        pb_varint(out, v);
    }

    /// Синтетические geo-базы: категория google (суффикс google.com), страна ru
    /// (1.1.1.0/24).
    fn geo_dbs() -> (Arc<jammvpn_core::GeoSiteDb>, Arc<jammvpn_core::GeoIpDb>) {
        // geosite: GeoSiteList{ GeoSite{ code="google", Domain{type=2,value="google.com"} } }
        let mut domain = Vec::new();
        pb_vint(&mut domain, 1, 2); // type=Domain(suffix)
        pb_len(&mut domain, 2, b"google.com");
        let mut gsite = Vec::new();
        pb_len(&mut gsite, 1, b"google");
        pb_len(&mut gsite, 2, &domain);
        let mut site = Vec::new();
        pb_len(&mut site, 1, &gsite);

        // geoip: GeoIPList{ GeoIP{ code="ru", CIDR{ ip=[1,1,1,0], prefix=24 } } }
        let mut cidr = Vec::new();
        pb_len(&mut cidr, 1, &[1, 1, 1, 0]);
        pb_vint(&mut cidr, 2, 24);
        let mut gip = Vec::new();
        pb_len(&mut gip, 1, b"ru");
        pb_len(&mut gip, 2, &cidr);
        let mut ip = Vec::new();
        pb_len(&mut ip, 1, &gip);

        (
            Arc::new(jammvpn_core::GeoSiteDb::parse(&site).unwrap()),
            Arc::new(jammvpn_core::GeoIpDb::parse(&ip).unwrap()),
        )
    }

    #[tokio::test]
    async fn route_geosite_matches_domain() {
        let (site, _) = geo_dbs();
        let rule = Rule {
            geosite: vec!["google".into()],
            action: RouteAction::Proxy(Some("ss".into())),
            ..Default::default()
        };
        let e = engine_with(vec![rule], None).with_geosite(site);
        // домен в категории → Proxy
        let r = e.route(&domain("www.google.com")).await;
        assert!(matches!(r.decision, Decision::Connect(Outbound::Socks5(_))));
        // вне категории → Direct
        let r = e.route(&domain("example.org")).await;
        assert!(matches!(r.decision, Decision::Connect(Outbound::Direct)));
    }

    #[tokio::test]
    async fn route_geoip_matches_after_resolve() {
        let (_, ip) = geo_dbs();
        let dns = mock_dns(Ipv4Addr::new(1, 1, 1, 7)).await; // 1.1.1.7 ∈ ru
        let rule = Rule {
            geoip: vec!["ru".into()],
            action: RouteAction::Block,
            ..Default::default()
        };
        // С резолвером: домен → 1.1.1.7 ∈ geoip:ru → Block.
        let e = engine_with(vec![rule.clone()], None)
            .with_geoip(ip.clone())
            .with_resolver(DnsResolver::new(DnsServer::Udp(dns)));
        let r = e.route(&domain("ru.example")).await;
        assert!(matches!(r.decision, Decision::Block));
        // Литеральный IP вне ru → Direct (geoip не совпал).
        let e2 = engine_with(vec![rule], None).with_geoip(ip);
        let r = e2
            .route(&Target::Socket(SocketAddr::from(([8, 8, 8, 8], 443))))
            .await;
        assert!(matches!(r.decision, Decision::Connect(Outbound::Direct)));
    }

    #[tokio::test]
    async fn route_literal_ip_with_trailing_dot_and_brackets() {
        // "10.1.2.3." и "[10.1.2.3]" должны распознаваться как литеральный IP и
        // подпадать под IP-CIDR правило (иначе обход через ATYP=domain).
        let rule = Rule {
            ip_cidrs: vec![IpCidr::parse("10.0.0.0/8").unwrap()],
            action: RouteAction::Block,
            ..Default::default()
        };
        let e = engine_with(vec![rule], None);
        for host in ["10.1.2.3", "10.1.2.3.", "[10.1.2.3]"] {
            let r = e.route(&domain(host)).await;
            assert!(
                matches!(r.decision, Decision::Block),
                "{host} должен блокироваться"
            );
        }
        // не-IP домен не затрагивается.
        let r = e.route(&domain("example.com")).await;
        assert!(matches!(r.decision, Decision::Connect(Outbound::Direct)));
    }

    #[test]
    fn missing_geo_refs_flags_unloaded_db() {
        let rules = vec![
            Rule {
                geosite: vec!["ads".into()],
                action: RouteAction::Block,
                ..Default::default()
            },
            Rule {
                geoip: vec!["ru".into()],
                action: RouteAction::Block,
                ..Default::default()
            },
        ];
        // Без баз: оба правила помечены.
        let e = engine_with(rules.clone(), None);
        assert_eq!(e.missing_geo_refs().len(), 2);
        // С базами: пусто.
        let (site, ip) = geo_dbs();
        let e2 = engine_with(rules, None).with_geosite(site).with_geoip(ip);
        assert!(e2.missing_geo_refs().is_empty());
        // Правила без geo: пусто даже без баз.
        let plain = engine_with(
            vec![Rule {
                domains: vec![DomainRule::Suffix("x.com".into())],
                action: RouteAction::Block,
                ..Default::default()
            }],
            None,
        );
        assert!(plain.missing_geo_refs().is_empty());
    }

    #[test]
    fn resolve_target_geoip_on_literal_ip() {
        // Синхронный путь: geoip по известному IP (без резолва).
        let (_, ip) = geo_dbs();
        let rule = Rule {
            geoip: vec!["ru".into()],
            action: RouteAction::Block,
            ..Default::default()
        };
        let e = engine_with(vec![rule], None).with_geoip(ip);
        assert!(matches!(
            e.resolve_target(&Target::Socket(SocketAddr::from(([1, 1, 1, 9], 443)))),
            Decision::Block
        ));
        assert!(matches!(
            e.resolve_target(&Target::Socket(SocketAddr::from(([8, 8, 8, 8], 443)))),
            Decision::Connect(Outbound::Direct)
        ));
    }

    #[tokio::test]
    async fn resolve_target_fails_open_vs_route_on_domain_ip_rule() {
        // Регрессия: закрепляет расхождение sync `resolve_target` и async `route`
        // на ОДНОЙ И ТОЙ ЖЕ конфигурации (geoip:ru -> Block + резолвер) для
        // доменной цели. Доменное имя `ru.example` резолвится в 1.1.1.7 ∈ geoip:ru:
        //   - resolve_target (sync) НЕ резолвит домен → IP-критерий молча
        //     пропускается → fail-open в default (Direct), даже когда резолвер
        //     задан (метод синхронный, резолвер он не использует вовсе);
        //   - route (async) резолвит → правило срабатывает → Block (fail-closed).
        //
        // Тест намеренно фиксирует ограничение из доки resolve_target: будущий
        // вызов resolve_target для доменных целей при IP/geoip-`Block` молча
        // открыл бы обход блокировки. Если sync-путь когда-то начнёт резолвить
        // (или иначе закроет дыру) — этот тест упадёт и заставит обновить доку.
        let (_, ip) = geo_dbs();
        let dns = mock_dns(Ipv4Addr::new(1, 1, 1, 7)).await; // 1.1.1.7 ∈ ru
        let rule = Rule {
            geoip: vec!["ru".into()],
            action: RouteAction::Block,
            ..Default::default()
        };
        let e = engine_with(vec![rule], None)
            .with_geoip(ip)
            .with_resolver(DnsResolver::new(DnsServer::Udp(dns)));

        // Sync: домен не резолвится → geoip:ru пропущен → fail-open (Direct).
        assert!(
            matches!(
                e.resolve_target(&domain("ru.example")),
                Decision::Connect(Outbound::Direct)
            ),
            "resolve_target молча пропускает geoip:ru для доменной цели (fail-open)"
        );
        // Async: тот же движок → домен → 1.1.1.7 ∈ geoip:ru → Block (fail-closed).
        let r = e.route(&domain("ru.example")).await;
        assert!(
            matches!(r.decision, Decision::Block),
            "route резолвит домен и применяет geoip:ru → Block"
        );
    }

    #[tokio::test]
    async fn route_block_by_ip_fails_closed_on_dns_failure() {
        // Block-по-IP-CIDR + цель-домен + неработающий DNS → fail-closed (Block),
        // а НЕ утечка в default(Direct).
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let rule = Rule {
            ip_cidrs: vec![IpCidr::parse("203.0.113.0/24").unwrap()],
            action: RouteAction::Block,
            ..Default::default()
        };
        let e = engine_with(vec![rule.clone()], None).with_resolver(
            DnsResolver::new(DnsServer::Udp(dead))
                .with_timeout(std::time::Duration::from_millis(200)),
        );
        let r = e.route(&domain("blocked.example")).await;
        assert!(
            matches!(r.decision, Decision::Block),
            "сбой DNS на Block → fail-closed"
        );

        // Контроль: без резолвера (DNS не настроен) поведение прежнее — Direct
        // (IP-CIDR по домену не вычисляется, fail-closed не активируется).
        let plain = engine_with(vec![rule], None);
        let r = plain.route(&domain("blocked.example")).await;
        assert!(matches!(r.decision, Decision::Connect(Outbound::Direct)));
    }

    #[tokio::test]
    async fn route_explicit_match_wins_over_pending_block() {
        // Block-по-IP (не подтверждается из-за сбоя DNS) ВЫШЕ явного доменного
        // Direct-правила. Явный матч должен победить fail-closed.
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let rules = vec![
            Rule {
                ip_cidrs: vec![IpCidr::parse("203.0.113.0/24").unwrap()],
                action: RouteAction::Block,
                ..Default::default()
            },
            Rule {
                domains: vec![DomainRule::Suffix("trusted.example".into())],
                action: RouteAction::Direct,
                ..Default::default()
            },
        ];
        let e = engine_with(rules, None).with_resolver(
            DnsResolver::new(DnsServer::Udp(dead))
                .with_timeout(std::time::Duration::from_millis(200)),
        );
        let r = e.route(&domain("a.trusted.example")).await;
        assert!(
            matches!(r.decision, Decision::Connect(Outbound::Direct)),
            "явное доменное Direct-правило приоритетнее неподтверждённого Block"
        );
    }

    #[tokio::test]
    async fn route_fakeip_reverse_recovers_domain() {
        let fi = Arc::new(FakeIp::new("198.18.0.0/15").unwrap());
        let fake = fi.allocate("blocked.ads");
        let mk_rule = || Rule {
            domains: vec![DomainRule::Keyword("ads".into())],
            action: RouteAction::Block,
            ..Default::default()
        };
        let target = Target::Socket(SocketAddr::from((fake, 443)));

        // С FakeIP: поддельный IP → восстановлен домен blocked.ads → Block,
        // эффективная цель переписана в домен (резолв на стороне исходящего).
        let e = engine_with(vec![mk_rule()], None).with_fakeip(fi.clone());
        let r = e.route(&target).await;
        assert!(matches!(r.decision, Decision::Block));
        assert!(matches!(r.target, Target::Domain(ref d, 443) if d == "blocked.ads"));

        // Без FakeIP: тот же IP — просто адрес, домен не восстановить → Direct.
        let e2 = engine_with(vec![mk_rule()], None);
        let r2 = e2.route(&target).await;
        assert!(matches!(r2.decision, Decision::Connect(Outbound::Direct)));
    }

    #[tokio::test]
    async fn route_matches_existing_sync_path_without_dns() {
        // route без резолвера/fakeip совпадает с resolve_target (нет регрессий).
        let rules = vec![Rule {
            domains: vec![DomainRule::Suffix("proxy.test".into())],
            action: RouteAction::Proxy(Some("ss".into())),
            ..Default::default()
        }];
        let e = engine_with(rules, None);
        let r = e.route(&domain("a.proxy.test")).await;
        assert!(matches!(r.decision, Decision::Connect(Outbound::Socks5(_))));
        let r = e.route(&domain("a.other")).await;
        assert!(matches!(r.decision, Decision::Connect(Outbound::Direct)));
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

    #[test]
    fn literal_ip_as_domain_matches_ip_rule() {
        use jammvpn_core::split::IpCidr;
        // Правило по IP-CIDR должно срабатывать даже если IP пришёл как ATYP=domain.
        let rule = Rule {
            ip_cidrs: vec![IpCidr::parse("10.0.0.0/8").unwrap()],
            action: RouteAction::Proxy(Some("ss".into())),
            ..Default::default()
        };
        let e = engine_with(vec![rule], None);
        assert!(matches!(
            e.resolve_target(&Target::Domain("10.1.2.3".to_string(), 443)),
            Decision::Connect(Outbound::Socks5(_))
        ));
    }

    #[test]
    fn engine_from_config() {
        use jammvpn_core::config::AppConfig;
        use jammvpn_core::parse_link;
        use jammvpn_core::routing::DomainRule;

        let mut cfg = AppConfig::default();
        cfg.servers
            .push(parse_link("ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#myproxy").unwrap());
        cfg.rules.push(Rule {
            domains: vec![DomainRule::Suffix("proxy.test".into())],
            action: RouteAction::Proxy(Some("myproxy".into())),
            ..Default::default()
        });
        let e = Engine::from_config(&cfg);
        assert!(matches!(
            e.resolve_target(&Target::Domain("a.proxy.test".to_string(), 443)),
            Decision::Connect(Outbound::Shadowsocks(_))
        ));
        assert!(matches!(
            e.resolve_target(&Target::Domain("other".to_string(), 443)),
            Decision::Connect(Outbound::Direct)
        ));
    }
}
