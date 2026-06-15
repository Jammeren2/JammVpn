//! Контроллер JammVPN: переиспользуемая логика управления узлами и локальным
//! прокси. Общая для CLI (`bin jammvpn`) и Tauri-UI.
//!
//! Связывает `core` (конфиг/парсеры), `net` (движок/прокси/url-test/подписки) и
//! `platform-windows` (DPAPI). Конфиг — `%APPDATA%/jammvpn/config.json`, секреты
//! в нём шифруются (DPAPI на Windows). Операции возвращают ДАННЫЕ (не печатают),
//! ошибки — человекочитаемой строкой; UI/CLI форматируют сами.

use jammvpn_core::routing::DomainRule;
use jammvpn_core::split::{AppMatcher, IpCidr};
use jammvpn_core::{parse_link, AppConfig, RouteAction, Rule, SecretStore, Subscription};
use jammvpn_net::{outbound_from_profile, serve_socks_routed, subscription, urltest, Engine};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;

/// Узел в списке (для UI/CLI).
#[derive(Debug, Clone, Serialize)]
pub struct NodeInfo {
    pub name: String,
    pub protocol: String,
    pub address: String,
    pub port: u16,
}

/// Результат теста задержки одного узла.
#[derive(Debug, Clone, Serialize)]
pub struct LatencyResult {
    pub name: String,
    /// Задержка в мс при успехе.
    pub latency_ms: Option<u64>,
    /// Текст ошибки при неуспехе.
    pub error: Option<String>,
}

/// Итог обновления одной подписки.
#[derive(Debug, Clone, Serialize)]
pub struct SubUpdate {
    pub url: String,
    /// Число узлов при успехе.
    pub count: Option<usize>,
    pub error: Option<String>,
}

/// Настройки маршрутизации (для UI).
#[derive(Debug, Clone, Serialize)]
pub struct SettingsInfo {
    /// Трафик без совпавшего правила: `true` — в прокси, иначе — напрямую.
    pub default_to_proxy: bool,
    /// Узел по умолчанию (для `Proxy(None)` и default-прокси).
    pub default_proxy: Option<String>,
}

/// Подписка в списке (для UI).
#[derive(Debug, Clone, Serialize)]
pub struct SubscriptionInfo {
    pub url: String,
    pub tag: Option<String>,
    pub update_interval_hours: u32,
}

/// Состояние geo-баз: пути и наличие файлов на диске (индикатор в UI).
#[derive(Debug, Clone, Serialize)]
pub struct GeoStatus {
    pub geosite_path: Option<String>,
    pub geosite_exists: bool,
    pub geoip_path: Option<String>,
    pub geoip_exists: bool,
}

/// Правило маршрутизации в плоском UI-представлении. Доменные и процессные
/// критерии кодируются строкой `тип:значение`; контроллер конвертирует в
/// [`Rule`]. Порядок в списке = порядок применения (first-match).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleInfo {
    /// Домены: `full:host` / `suffix:example.com` / `keyword:str` (без префикса → suffix).
    pub domains: Vec<String>,
    /// IP-CIDR: `10.0.0.0/8`, `1.2.3.4`, `::1/128`.
    pub ip_cidrs: Vec<String>,
    /// Процессы: `exe:C:\\app.exe` / `name:app.exe` (без префикса → name).
    pub processes: Vec<String>,
    /// Порты назначения.
    pub ports: Vec<u16>,
    /// geosite-категории (`google`, `cn`).
    pub geosite: Vec<String>,
    /// geoip-коды стран (`ru`, `us`).
    pub geoip: Vec<String>,
    /// Действие: `direct` | `proxy` | `block`.
    pub action: String,
    /// Тег прокси для `action == "proxy"` (пусто → дефолтный outbound).
    pub proxy_tag: Option<String>,
}

/// Путь к конфигу: `%APPDATA%/jammvpn/config.json` (или `$HOME/.config/...`).
pub fn config_path() -> PathBuf {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("jammvpn").join("config.json")
}

/// Хранилище секретов: DPAPI на Windows, иначе — без шифрования.
#[cfg(windows)]
pub fn secret_store() -> Box<dyn SecretStore> {
    Box::new(jammvpn_platform_windows::DpapiStore)
}
#[cfg(not(windows))]
pub fn secret_store() -> Box<dyn SecretStore> {
    Box::new(jammvpn_core::NoopStore)
}

/// Загружает конфиг (расшифровывая секреты); при ошибке возвращает пустой.
pub fn load_config(path: &Path, store: &dyn SecretStore) -> AppConfig {
    if path.exists() {
        AppConfig::load_protected(path, store).unwrap_or_else(|e| {
            eprintln!("предупреждение: не удалось загрузить конфиг ({e}); беру пустой");
            AppConfig::default()
        })
    } else {
        AppConfig::default()
    }
}

/// Сохраняет конфиг (шифруя секреты), создавая каталог при необходимости.
pub fn save_config(path: &Path, cfg: &AppConfig, store: &dyn SecretStore) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    cfg.save_protected(path, store).map_err(|e| e.to_string())
}

/// Загружает текущий конфиг штатным хранилищем.
pub fn load() -> AppConfig {
    load_config(&config_path(), secret_store().as_ref())
}

/// Список узлов из конфига.
pub fn list_nodes() -> Vec<NodeInfo> {
    load()
        .servers
        .iter()
        .map(|s| NodeInfo {
            name: s.name.clone(),
            protocol: s.protocol.to_string(),
            address: s.address.clone(),
            port: s.port,
        })
        .collect()
}

/// Импортирует узел (share-ссылка) или подписку (URL). Возвращает сообщение.
pub async fn import(arg: &str) -> Result<String, String> {
    let path = config_path();
    let store = secret_store();
    let mut cfg = load_config(&path, store.as_ref());

    let msg = if arg.starts_with("http://") || arg.starts_with("https://") {
        let sub = Subscription {
            url: arg.to_string(),
            tag: Some("subscription".to_string()),
            update_interval_hours: 12,
        };
        let servers = subscription::update_subscription(&sub, subscription::DEFAULT_TIMEOUT)
            .await
            .map_err(|e| e.to_string())?;
        let n = servers.len();
        subscription::merge_subscription(&mut cfg, &sub, servers);
        if !cfg.subscriptions.iter().any(|s| s.url == sub.url) {
            cfg.subscriptions.push(sub);
        }
        format!("импортировано узлов из подписки: {n}")
    } else {
        let profile = parse_link(arg).map_err(|e| e.to_string())?;
        let m = format!("импортирован узел: {} [{}]", profile.name, profile.protocol);
        cfg.servers.push(profile);
        m
    };
    save_config(&path, &cfg, store.as_ref())?;
    Ok(msg)
}

/// Тест задержек всех узлов (по умолчанию generate_204), отсортировано по
/// возрастанию задержки (ошибки — в конце).
pub async fn test_latencies(url: Option<&str>) -> Vec<LatencyResult> {
    let url = url.unwrap_or(urltest::DEFAULT_TEST_URL);
    let cfg = load();
    let engine = Engine::from_config(&cfg);
    let mut results =
        urltest::test_outbounds(engine.outbounds(), url, urltest::DEFAULT_TIMEOUT).await;
    results.sort_by(|a, b| match (&a.1, &b.1) {
        (Ok(x), Ok(y)) => x.cmp(y),
        (Ok(_), Err(_)) => std::cmp::Ordering::Less,
        (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
        (Err(_), Err(_)) => std::cmp::Ordering::Equal,
    });
    results
        .into_iter()
        .map(|(name, res)| LatencyResult {
            name,
            latency_ms: res.as_ref().ok().map(|d| d.as_millis() as u64),
            error: res.err().map(|e| e.to_string()),
        })
        .collect()
}

/// Обновляет все подписки, возвращает итоги по каждой.
pub async fn update_subscriptions() -> Result<Vec<SubUpdate>, String> {
    let path = config_path();
    let store = secret_store();
    let mut cfg = load_config(&path, store.as_ref());
    let subs = cfg.subscriptions.clone();
    let mut out = Vec::with_capacity(subs.len());
    for sub in &subs {
        match subscription::update_subscription(sub, subscription::DEFAULT_TIMEOUT).await {
            Ok(servers) => {
                let n = servers.len();
                subscription::merge_subscription(&mut cfg, sub, servers);
                out.push(SubUpdate {
                    url: sub.url.clone(),
                    count: Some(n),
                    error: None,
                });
            }
            Err(e) => out.push(SubUpdate {
                url: sub.url.clone(),
                count: None,
                error: Some(e.to_string()),
            }),
        }
    }
    save_config(&path, &cfg, store.as_ref())?;
    Ok(out)
}

/// Удаляет узел по имени из конфига (чистая логика, для тестов): возвращает,
/// был ли он. Если удалили узел, назначенный default-прокси, — сбрасывает его.
fn apply_remove(cfg: &mut AppConfig, name: &str) -> bool {
    let before = cfg.servers.len();
    cfg.servers.retain(|s| s.name != name);
    let removed = cfg.servers.len() != before;
    if removed && cfg.settings.default_proxy.as_deref() == Some(name) {
        cfg.settings.default_proxy = None;
    }
    removed
}

/// Удаляет узел по имени (с сохранением конфига). `Ok(false)` — узла не было.
pub fn remove_node(name: &str) -> Result<bool, String> {
    let path = config_path();
    let store = secret_store();
    let mut cfg = load_config(&path, store.as_ref());
    let removed = apply_remove(&mut cfg, name);
    if removed {
        save_config(&path, &cfg, store.as_ref())?;
    }
    Ok(removed)
}

/// Текущие настройки маршрутизации.
pub fn get_settings() -> SettingsInfo {
    let cfg = load();
    SettingsInfo {
        default_to_proxy: cfg.settings.default_to_proxy,
        default_proxy: cfg.settings.default_proxy.clone(),
    }
}

/// Сохраняет настройки маршрутизации.
pub fn set_settings(default_to_proxy: bool, default_proxy: Option<String>) -> Result<(), String> {
    let path = config_path();
    let store = secret_store();
    let mut cfg = load_config(&path, store.as_ref());
    cfg.settings.default_to_proxy = default_to_proxy;
    cfg.settings.default_proxy = default_proxy.filter(|s| !s.is_empty());
    save_config(&path, &cfg, store.as_ref())
}

/// Список подписок из конфига.
pub fn list_subscriptions() -> Vec<SubscriptionInfo> {
    load()
        .subscriptions
        .into_iter()
        .map(|s| SubscriptionInfo {
            url: s.url,
            tag: s.tag,
            update_interval_hours: s.update_interval_hours,
        })
        .collect()
}

/// Добавляет подписку (чистая логика): дубль по URL → `false` (не добавляет).
fn apply_add_subscription(cfg: &mut AppConfig, sub: Subscription) -> bool {
    if cfg.subscriptions.iter().any(|s| s.url == sub.url) {
        return false;
    }
    cfg.subscriptions.push(sub);
    true
}

/// Добавляет подписку в конфиг (без скачивания — после вызовите
/// [`update_subscriptions`]). URL обязан быть http(s). `Ok(false)` — уже есть.
pub fn add_subscription(
    url: &str,
    tag: Option<String>,
    interval_hours: u32,
) -> Result<bool, String> {
    let url = url.trim();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err("URL подписки должен начинаться с http:// или https://".into());
    }
    let sub = Subscription {
        url: url.to_string(),
        tag: tag.map(|t| t.trim().to_string()).filter(|t| !t.is_empty()),
        update_interval_hours: if interval_hours == 0 { 12 } else { interval_hours },
    };
    let path = config_path();
    let store = secret_store();
    let mut cfg = load_config(&path, store.as_ref());
    let added = apply_add_subscription(&mut cfg, sub);
    if added {
        save_config(&path, &cfg, store.as_ref())?;
    }
    Ok(added)
}

/// Удаляет подписку по URL (чистая логика): была ли удалена.
fn apply_remove_subscription(cfg: &mut AppConfig, url: &str) -> bool {
    let before = cfg.subscriptions.len();
    cfg.subscriptions.retain(|s| s.url != url);
    cfg.subscriptions.len() != before
}

/// Удаляет подписку по URL (узлы, уже импортированные из неё, остаются —
/// удалить можно вручную). `Ok(false)` — подписки не было.
pub fn remove_subscription(url: &str) -> Result<bool, String> {
    let path = config_path();
    let store = secret_store();
    let mut cfg = load_config(&path, store.as_ref());
    let removed = apply_remove_subscription(&mut cfg, url);
    if removed {
        save_config(&path, &cfg, store.as_ref())?;
    }
    Ok(removed)
}

/// Статус geo-баз по конфигу (наличие файлов на диске; чистая логика).
fn geo_status_of(cfg: &AppConfig) -> GeoStatus {
    let exists = |p: &Option<String>| {
        p.as_deref()
            .map(|s| Path::new(s).is_file())
            .unwrap_or(false)
    };
    GeoStatus {
        geosite_exists: exists(&cfg.geo.geosite_path),
        geoip_exists: exists(&cfg.geo.geoip_path),
        geosite_path: cfg.geo.geosite_path.clone(),
        geoip_path: cfg.geo.geoip_path.clone(),
    }
}

/// Текущий статус geo-баз (пути из конфига + проверка файлов).
pub fn geo_status() -> GeoStatus {
    geo_status_of(&load())
}

/// Задаёт пути к geo-базам (пустые → сброс в `None`). Существование файлов здесь
/// не проверяется — индикатор покажет [`geo_status`].
pub fn set_geo_paths(geosite: Option<String>, geoip: Option<String>) -> Result<(), String> {
    let norm = |o: Option<String>| o.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let path = config_path();
    let store = secret_store();
    let mut cfg = load_config(&path, store.as_ref());
    cfg.geo.geosite_path = norm(geosite);
    cfg.geo.geoip_path = norm(geoip);
    save_config(&path, &cfg, store.as_ref())
}

// --- Правила маршрутизации (CRUD + конвертеры core::Rule ↔ RuleInfo) ---

fn domain_to_string(d: &DomainRule) -> String {
    match d {
        DomainRule::Full(s) => format!("full:{s}"),
        DomainRule::Suffix(s) => format!("suffix:{s}"),
        DomainRule::Keyword(s) => format!("keyword:{s}"),
    }
}

/// `тип:значение` → `DomainRule` (без/с неизвестным префиксом → `Suffix`).
fn parse_domain(s: &str) -> DomainRule {
    let s = s.trim();
    match s.split_once(':') {
        Some(("full", v)) => DomainRule::Full(v.trim().to_string()),
        Some(("suffix", v)) => DomainRule::Suffix(v.trim().to_string()),
        Some(("keyword", v)) => DomainRule::Keyword(v.trim().to_string()),
        _ => DomainRule::Suffix(s.to_string()),
    }
}

fn process_to_string(m: &AppMatcher) -> String {
    match m {
        AppMatcher::ExePath(p) => format!("exe:{p}"),
        AppMatcher::ProcessName(n) => format!("name:{n}"),
    }
}

/// `тип:значение` → `AppMatcher` (без/с неизвестным префиксом → `ProcessName`).
fn parse_process(s: &str) -> AppMatcher {
    let s = s.trim();
    match s.split_once(':') {
        Some(("exe", v)) => AppMatcher::ExePath(v.trim().to_string()),
        Some(("name", v)) => AppMatcher::ProcessName(v.trim().to_string()),
        _ => AppMatcher::ProcessName(s.to_string()),
    }
}

/// Чистит список строк: trim + отбрасывает пустые.
fn clean_list(v: &[String]) -> Vec<String> {
    v.iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// [`Rule`] → плоский [`RuleInfo`] (для UI).
fn rule_to_info(r: &Rule) -> RuleInfo {
    let (action, proxy_tag) = match &r.action {
        RouteAction::Direct => ("direct".to_string(), None),
        RouteAction::Block => ("block".to_string(), None),
        RouteAction::Proxy(tag) => ("proxy".to_string(), tag.clone()),
    };
    RuleInfo {
        domains: r.domains.iter().map(domain_to_string).collect(),
        ip_cidrs: r.ip_cidrs.iter().map(|c| c.to_string()).collect(),
        processes: r.processes.iter().map(process_to_string).collect(),
        ports: r.ports.clone(),
        geosite: r.geosite.clone(),
        geoip: r.geoip.clone(),
        action,
        proxy_tag,
    }
}

/// Плоский [`RuleInfo`] → [`Rule`] (валидирует CIDR и действие).
fn info_to_rule(info: &RuleInfo) -> Result<Rule, String> {
    let mut ip_cidrs = Vec::new();
    for s in clean_list(&info.ip_cidrs) {
        ip_cidrs.push(IpCidr::parse(&s).map_err(|e| format!("неверный CIDR «{s}»: {e}"))?);
    }
    let action = match info.action.trim() {
        "direct" => RouteAction::Direct,
        "block" => RouteAction::Block,
        "proxy" => RouteAction::Proxy(
            info.proxy_tag
                .as_ref()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        ),
        other => return Err(format!("неизвестное действие: «{other}»")),
    };
    Ok(Rule {
        domains: clean_list(&info.domains).iter().map(|s| parse_domain(s)).collect(),
        ip_cidrs,
        processes: clean_list(&info.processes).iter().map(|s| parse_process(s)).collect(),
        ports: info.ports.clone(),
        geosite: clean_list(&info.geosite),
        geoip: clean_list(&info.geoip),
        action,
    })
}

/// Список правил (в порядке применения).
pub fn list_rules() -> Vec<RuleInfo> {
    load().rules.iter().map(rule_to_info).collect()
}

/// Добавляет правило в конец списка.
pub fn add_rule(info: RuleInfo) -> Result<(), String> {
    let rule = info_to_rule(&info)?;
    let path = config_path();
    let store = secret_store();
    let mut cfg = load_config(&path, store.as_ref());
    cfg.rules.push(rule);
    save_config(&path, &cfg, store.as_ref())
}

/// Заменяет правило по индексу (сохраняя позицию). Err — индекс вне диапазона.
pub fn update_rule(index: usize, info: RuleInfo) -> Result<(), String> {
    let rule = info_to_rule(&info)?;
    let path = config_path();
    let store = secret_store();
    let mut cfg = load_config(&path, store.as_ref());
    if index >= cfg.rules.len() {
        return Err(format!("индекс правила вне диапазона: {index}"));
    }
    cfg.rules[index] = rule;
    save_config(&path, &cfg, store.as_ref())
}

/// Удаляет правило по индексу (чистая логика): было ли удалено.
fn apply_remove_rule(cfg: &mut AppConfig, index: usize) -> bool {
    if index < cfg.rules.len() {
        cfg.rules.remove(index);
        true
    } else {
        false
    }
}

/// Удаляет правило по индексу. `Ok(false)` — индекс вне диапазона.
pub fn remove_rule(index: usize) -> Result<bool, String> {
    let path = config_path();
    let store = secret_store();
    let mut cfg = load_config(&path, store.as_ref());
    let removed = apply_remove_rule(&mut cfg, index);
    if removed {
        save_config(&path, &cfg, store.as_ref())?;
    }
    Ok(removed)
}

/// Перемещает правило вверх/вниз (меняет порядок применения; чистая логика).
fn apply_move_rule(cfg: &mut AppConfig, index: usize, up: bool) -> bool {
    let n = cfg.rules.len();
    if index >= n {
        return false;
    }
    let target = if up {
        if index == 0 {
            return false;
        }
        index - 1
    } else {
        if index + 1 >= n {
            return false;
        }
        index + 1
    };
    cfg.rules.swap(index, target);
    true
}

/// Перемещает правило вверх (`up=true`) или вниз. `Ok(false)` — двигать некуда.
pub fn move_rule(index: usize, up: bool) -> Result<bool, String> {
    let path = config_path();
    let store = secret_store();
    let mut cfg = load_config(&path, store.as_ref());
    let moved = apply_move_rule(&mut cfg, index, up);
    if moved {
        save_config(&path, &cfg, store.as_ref())?;
    }
    Ok(moved)
}

// --- Автозапуск при входе в систему (Windows: реестр Run) ---

/// Включён ли автозапуск приложения при входе (на не-Windows — всегда `false`).
#[cfg(windows)]
pub fn autostart_status() -> Result<bool, String> {
    jammvpn_platform_windows::autostart::is_enabled()
}
#[cfg(not(windows))]
pub fn autostart_status() -> Result<bool, String> {
    Ok(false)
}

/// Включает/выключает автозапуск (пишет путь к текущему exe в `HKCU\…\Run`).
#[cfg(windows)]
pub fn set_autostart(enabled: bool) -> Result<(), String> {
    if enabled {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        jammvpn_platform_windows::autostart::enable(&exe.to_string_lossy())
    } else {
        jammvpn_platform_windows::autostart::disable()
    }
}
#[cfg(not(windows))]
pub fn set_autostart(_enabled: bool) -> Result<(), String> {
    Err("автозапуск поддерживается только на Windows".into())
}

/// Строит движок для запуска прокси: `server` — весь трафик через узел, иначе —
/// маршрутизация по правилам конфига (с fail-closed-проверкой geo-баз).
pub fn build_engine(cfg: &AppConfig, server: Option<&str>) -> Result<Engine, String> {
    if let Some(name) = server {
        let profile = cfg
            .servers
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| format!("узел не найден: {name}"))?;
        let outbound = outbound_from_profile(profile).map_err(|e| e.to_string())?;
        Ok(Engine::single_proxy(outbound))
    } else {
        let engine = Engine::from_config(cfg);
        let missing = engine.missing_geo_refs();
        if !missing.is_empty() {
            return Err(format!(
                "geo-базы не загружены для части правил:\n  {}\n\
                 проверьте geo.geosite_path / geo.geoip_path в конфиге",
                missing.join("\n  ")
            ));
        }
        Ok(engine)
    }
}

/// Управляемый локальный SOCKS5-прокси (для UI: запуск/остановка).
pub struct ProxyController {
    addr: SocketAddr,
    server: Option<String>,
    handle: tokio::task::JoinHandle<()>,
}

impl ProxyController {
    /// Запускает прокси: биндит `listen`, строит движок (через `server` или по
    /// правилам), спавнит обслуживание. Возвращается после успешного бинда.
    pub async fn start(listen: &str, server: Option<String>) -> Result<Self, String> {
        let cfg = load();
        let engine = build_engine(&cfg, server.as_deref())?;
        let listener = TcpListener::bind(listen).await.map_err(|e| e.to_string())?;
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        let engine = Arc::new(engine);
        let handle = tokio::spawn(async move {
            let _ = serve_socks_routed(listener, engine).await;
        });
        Ok(Self {
            addr,
            server,
            handle,
        })
    }

    /// Адрес, на котором слушает прокси.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Узел, через который пущен весь трафик (`None` — маршрутизация по правилам).
    pub fn server(&self) -> Option<&str> {
        self.server.as_deref()
    }

    /// Останавливает прокси (закрывает слушатель; активные соединения завершатся).
    pub fn stop(self) {
        self.handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jammvpn_core::NoopStore;

    #[test]
    fn config_path_ends_correctly() {
        let p = config_path();
        assert!(p.ends_with("jammvpn/config.json") || p.ends_with("jammvpn\\config.json"));
    }

    #[test]
    fn save_load_roundtrip_with_secrets() {
        // Импорт ссылки → сохранение (шифрование секретов) → загрузка → совпадает.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("jammvpn-ctl-test-{}.json", std::process::id()));
        let store = NoopStore;

        let mut cfg = AppConfig::default();
        let profile =
            parse_link("vless://11111111-2222-3333-4444-555555555555@h:443?flow=x#node").unwrap();
        cfg.servers.push(profile);

        save_config(&path, &cfg, &store).unwrap();
        let loaded = load_config(&path, &store);
        assert_eq!(loaded.servers.len(), 1);
        assert_eq!(loaded.servers[0].name, "node");
        assert_eq!(
            loaded.servers[0].param("uuid"),
            Some("11111111-2222-3333-4444-555555555555")
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn apply_remove_node() {
        let mut cfg = AppConfig::default();
        cfg.servers
            .push(parse_link("ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#A").unwrap());
        cfg.servers
            .push(parse_link("ss://YWVzLTI1Ni1nY206cGFzcw==@5.6.7.8:8388#B").unwrap());
        cfg.settings.default_proxy = Some("B".to_string());

        // удаление несуществующего — false, ничего не меняет.
        assert!(!apply_remove(&mut cfg, "нет"));
        assert_eq!(cfg.servers.len(), 2);

        // удаление узла-default — сбрасывает default_proxy.
        assert!(apply_remove(&mut cfg, "B"));
        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(cfg.servers[0].name, "A");
        assert_eq!(cfg.settings.default_proxy, None);
    }

    #[test]
    fn apply_subscription_ops() {
        let mut cfg = AppConfig::default();
        let sub = Subscription {
            url: "https://x/sub".into(),
            tag: Some("g".into()),
            update_interval_hours: 6,
        };
        // добавление нового — true; дубль по URL — false (без дублей).
        assert!(apply_add_subscription(&mut cfg, sub.clone()));
        assert_eq!(cfg.subscriptions.len(), 1);
        assert!(!apply_add_subscription(&mut cfg, sub.clone()));
        assert_eq!(cfg.subscriptions.len(), 1);
        // удаление существующей — true; повторное — false.
        assert!(apply_remove_subscription(&mut cfg, "https://x/sub"));
        assert!(cfg.subscriptions.is_empty());
        assert!(!apply_remove_subscription(&mut cfg, "https://x/sub"));
    }

    #[test]
    fn geo_status_reflects_files() {
        let dir = std::env::temp_dir();
        let present = dir.join(format!("jammvpn-geo-test-{}.dat", std::process::id()));
        std::fs::write(&present, b"x").unwrap();

        let mut cfg = AppConfig::default();
        cfg.geo.geosite_path = Some(present.to_string_lossy().into_owned());
        cfg.geo.geoip_path =
            Some(dir.join("jammvpn-geo-absent.dat").to_string_lossy().into_owned());

        let st = geo_status_of(&cfg);
        assert!(st.geosite_exists);
        assert!(!st.geoip_exists);
        assert!(st.geosite_path.is_some());
        // путь без файла отдаётся, но exists=false.
        assert!(st.geoip_path.is_some());

        let _ = std::fs::remove_file(&present);
    }

    #[test]
    fn rule_info_roundtrip() {
        let rule = Rule {
            domains: vec![
                DomainRule::Suffix("example.com".into()),
                DomainRule::Keyword("ads".into()),
                DomainRule::Full("exact.host".into()),
            ],
            ip_cidrs: vec![IpCidr::parse("10.0.0.0/8").unwrap()],
            processes: vec![
                AppMatcher::ProcessName("app.exe".into()),
                AppMatcher::ExePath("C:\\app.exe".into()),
            ],
            ports: vec![443, 80],
            geosite: vec!["google".into()],
            geoip: vec!["ru".into()],
            action: RouteAction::Proxy(Some("node".into())),
        };
        let info = rule_to_info(&rule);
        assert_eq!(info.action, "proxy");
        assert_eq!(info.proxy_tag.as_deref(), Some("node"));
        assert_eq!(info.domains[0], "suffix:example.com");
        assert_eq!(info.processes[1], "exe:C:\\app.exe");
        // обратно совпадает побайтово.
        assert_eq!(info_to_rule(&info).unwrap(), rule);
    }

    #[test]
    fn info_to_rule_validates_and_defaults() {
        // плохой CIDR → ошибка.
        let bad = RuleInfo {
            ip_cidrs: vec!["not-a-cidr".into()],
            action: "direct".into(),
            ..Default::default()
        };
        assert!(info_to_rule(&bad).is_err());
        // неизвестное действие → ошибка.
        let bada = RuleInfo {
            action: "nope".into(),
            ..Default::default()
        };
        assert!(info_to_rule(&bada).is_err());
        // bare домен → Suffix, bare процесс → ProcessName, пустые отброшены.
        let info = RuleInfo {
            domains: vec!["example.com".into(), "  ".into()],
            processes: vec!["app.exe".into()],
            action: "block".into(),
            ..Default::default()
        };
        let rule = info_to_rule(&info).unwrap();
        assert_eq!(rule.domains, vec![DomainRule::Suffix("example.com".into())]);
        assert_eq!(rule.processes, vec![AppMatcher::ProcessName("app.exe".into())]);
        assert_eq!(rule.action, RouteAction::Block);
        // proxy без тега → Proxy(None).
        let p = RuleInfo {
            action: "proxy".into(),
            proxy_tag: Some("  ".into()),
            ..Default::default()
        };
        assert_eq!(info_to_rule(&p).unwrap().action, RouteAction::Proxy(None));
    }

    #[test]
    fn apply_rule_reorder_and_remove() {
        let mut cfg = AppConfig::default();
        let mk = |t: &str| Rule {
            domains: vec![DomainRule::Suffix(format!("{t}.com"))],
            action: RouteAction::Direct,
            ..Default::default()
        };
        cfg.rules = vec![mk("a"), mk("b"), mk("c")];
        // move b (index 1) вверх → [b, a, c].
        assert!(apply_move_rule(&mut cfg, 1, true));
        assert_eq!(cfg.rules[0].domains, vec![DomainRule::Suffix("b.com".into())]);
        // первый вверх — некуда (false); последний вниз — некуда (false).
        assert!(!apply_move_rule(&mut cfg, 0, true));
        assert!(!apply_move_rule(&mut cfg, 2, false));
        assert!(!apply_move_rule(&mut cfg, 9, true));
        // remove index 1 (a) → [b, c]; вне диапазона → false.
        assert!(apply_remove_rule(&mut cfg, 1));
        assert_eq!(cfg.rules.len(), 2);
        assert!(!apply_remove_rule(&mut cfg, 9));
    }

    #[test]
    fn build_engine_rejects_unknown_node() {
        let cfg = AppConfig::default();
        assert!(build_engine(&cfg, Some("нет-такого")).is_err());
        // По правилам (без geo) — ок.
        assert!(build_engine(&cfg, None).is_ok());
    }

    #[tokio::test]
    async fn proxy_controller_start_stop() {
        // Пустой конфиг → Direct-маршрутизация; запуск/остановка на эфемерном порту.
        let proxy = ProxyController::start("127.0.0.1:0", None).await.unwrap();
        assert!(proxy.addr().port() != 0);
        assert!(proxy.server().is_none());
        proxy.stop();
    }
}
