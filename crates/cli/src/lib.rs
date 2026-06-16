//! Контроллер JammVPN: переиспользуемая логика управления узлами и локальным
//! прокси. Общая для CLI (`bin jammvpn`) и Tauri-UI.
//!
//! Связывает `core` (конфиг/парсеры), `net` (движок/прокси/url-test/подписки) и
//! `platform-windows` (DPAPI). Конфиг — `%APPDATA%/jammvpn/config.json`, секреты
//! в нём шифруются (DPAPI на Windows). Операции возвращают ДАННЫЕ (не печатают),
//! ошибки — человекочитаемой строкой; UI/CLI форматируют сами.

use jammvpn_core::error::ParseError;
use jammvpn_core::model::ServerProfile;
use jammvpn_core::routing::DomainRule;
use jammvpn_core::split::{AppMatcher, IpCidr};
use jammvpn_core::{
    parse_awg_conf, parse_clash, parse_link, parse_singbox_config, parse_xray_config, AppConfig,
    RouteAction, Rule, SecretStore, SplitConfig, Subscription,
};
use jammvpn_core::LocalWgConfig;
use jammvpn_net::{
    gen_preshared_key, gen_private_key, outbound_from_profile, serve_socks_routed, subscription,
    urltest, wg_public_key, Engine, WgServer, WgServerParams,
};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
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
    /// Локальный адрес прокси (SOCKS5/HTTP).
    pub listen: Option<String>,
    /// Выбранный на «Главной» узел (весь трафик через него; `None` — по правилам).
    pub proxy_node: Option<String>,
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

/// Дозаписывает строку в файл лога (`%APPDATA%/jammvpn/jammvpn.log`). Для
/// диагностики там, где stdout/stderr не видны (GUI без консоли).
pub fn log_line(msg: &str) {
    use std::io::Write;
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let path = config_path()
        .parent()
        .map(|p| p.join("jammvpn.log"))
        .unwrap_or_else(|| PathBuf::from("jammvpn.log"));
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "[{secs}] {msg}");
    }
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

/// Активное соединение для монитора (срез реестра движка).
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionInfo {
    pub id: u64,
    pub target: String,
    pub via: String,
    pub up: u64,
    pub down: u64,
}

/// Список активных проксируемых соединений (живой срез).
pub fn list_connections() -> Vec<ConnectionInfo> {
    jammvpn_net::connection_snapshot()
        .into_iter()
        .map(|c| ConnectionInfo {
            id: c.id,
            target: c.target,
            via: c.via.to_string(),
            up: c.up,
            down: c.down,
        })
        .collect()
}

/// Принудительно закрывает соединение по `id`.
pub fn drop_connection(id: u64) -> bool {
    jammvpn_net::connection_drop(id)
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

/// Определяет формат текста конфига и парсит его в список профилей.
/// Возвращает (имя формата, результаты парсинга по элементам).
fn parse_any_config(text: &str) -> (&'static str, Vec<Result<ServerProfile, ParseError>>) {
    let t = text.trim_start();
    // JSON: сначала пробуем sing-box (поле `type`), затем Xray (`protocol`).
    // `[` — массив конфигов (подписка Happ/v2rayN).
    if t.starts_with('{') || t.starts_with('[') {
        let sb = parse_singbox_config(text);
        if sb.iter().any(|r| r.is_ok()) {
            return ("sing-box JSON", sb);
        }
        let xr = parse_xray_config(text);
        if xr.iter().any(|r| r.is_ok()) {
            return ("Xray JSON", xr);
        }
        return ("JSON", sb); // вернём ошибки sing-box для диагностики
    }
    // AmneziaWG / WireGuard .conf.
    if text.contains("[Interface]") {
        return ("AmneziaWG .conf", vec![parse_awg_conf(text)]);
    }
    // Clash / Clash.Meta YAML (секция proxies:).
    if text.contains("proxies:") {
        return ("Clash YAML", parse_clash(text));
    }
    // Иначе — ссылки построчно (поддерживает вставку нескольких ссылок).
    let links = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(parse_link)
        .collect();
    ("ссылки", links)
}

/// Импорт из вставленного текста конфига: ссылка(и) / Xray JSON / sing-box JSON
/// / AmneziaWG `.conf`. Добавляет найденные узлы в конфиг. Возвращает сообщение.
pub fn import_config(text: &str) -> Result<String, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("пустой ввод".into());
    }
    let (fmt, results) = parse_any_config(text);
    let mut profiles = Vec::new();
    let mut errors = 0usize;
    for r in results {
        match r {
            Ok(p) => profiles.push(p),
            Err(_) => errors += 1,
        }
    }
    if profiles.is_empty() {
        return Err(format!(
            "не удалось распознать конфиг (формат: {fmt}); узлов не найдено"
        ));
    }
    let n = profiles.len();
    let path = config_path();
    let store = secret_store();
    let mut cfg = load_config(&path, store.as_ref());
    cfg.servers.append(&mut profiles);
    save_config(&path, &cfg, store.as_ref())?;
    let mut msg = format!("импортировано узлов: {n} (формат: {fmt})");
    if errors > 0 {
        msg.push_str(&format!("; пропущено с ошибкой: {errors}"));
    }
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
        listen: cfg.settings.listen.clone(),
        proxy_node: cfg.settings.proxy_node.clone(),
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

/// Сохраняет настройки подключения (адрес прокси и выбранный узел). Пустые
/// строки трактуются как «не задано».
pub fn set_connection(listen: Option<String>, proxy_node: Option<String>) -> Result<(), String> {
    let path = config_path();
    let store = secret_store();
    let mut cfg = load_config(&path, store.as_ref());
    let norm = |s: Option<String>| s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    cfg.settings.listen = norm(listen);
    cfg.settings.proxy_node = norm(proxy_node);
    save_config(&path, &cfg, store.as_ref())
}

/// Сериализует WireGuard/AmneziaWG-узел в `.conf` и пишет файл рядом с конфигом.
/// Возвращает абсолютный путь к созданному файлу.
pub fn export_node_conf(name: &str) -> Result<String, String> {
    let cfg = load();
    let node = cfg
        .servers
        .iter()
        .find(|s| s.name == name)
        .ok_or_else(|| format!("узел не найден: {name}"))?;
    if !matches!(
        node.protocol,
        jammvpn_core::ProtocolKind::Wireguard | jammvpn_core::ProtocolKind::AmneziaWg
    ) {
        return Err("экспорт .conf доступен только для WireGuard/AmneziaWG".into());
    }
    let conf = node_to_wg_conf(node);

    // Безопасное имя файла из имени узла.
    let safe: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let dir = config_path()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let file = dir.join(format!("{safe}.conf"));
    std::fs::write(&file, conf).map_err(|e| e.to_string())?;
    Ok(file.to_string_lossy().to_string())
}

/// Собирает текст `.conf` (WireGuard/AmneziaWG) из параметров узла.
fn node_to_wg_conf(p: &ServerProfile) -> String {
    let mut s = String::from("[Interface]\n");
    if let Some(v) = p.param("private_key") {
        s.push_str(&format!("PrivateKey = {v}\n"));
    }
    if let Some(v) = p.param("address") {
        s.push_str(&format!("Address = {v}\n"));
    }
    if let Some(v) = p.param("dns") {
        s.push_str(&format!("DNS = {v}\n"));
    }
    // Обфускация AmneziaWG (если есть).
    for (label, key) in [
        ("Jc", "jc"),
        ("Jmin", "jmin"),
        ("Jmax", "jmax"),
        ("S1", "s1"),
        ("S2", "s2"),
        ("H1", "h1"),
        ("H2", "h2"),
        ("H3", "h3"),
        ("H4", "h4"),
    ] {
        if let Some(v) = p.param(key) {
            s.push_str(&format!("{label} = {v}\n"));
        }
    }
    s.push_str("\n[Peer]\n");
    if let Some(v) = p.param("public_key") {
        s.push_str(&format!("PublicKey = {v}\n"));
    }
    if let Some(v) = p.param("preshared_key") {
        s.push_str(&format!("PresharedKey = {v}\n"));
    }
    s.push_str(&format!("Endpoint = {}:{}\n", p.address, p.port));
    let allowed = p.param("allowed_ips").unwrap_or("0.0.0.0/0, ::/0");
    s.push_str(&format!("AllowedIPs = {allowed}\n"));
    if let Some(v) = p.param("persistent_keepalive") {
        s.push_str(&format!("PersistentKeepalive = {v}\n"));
    }
    s
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

/// Готовый пресет правил (для UI).
#[derive(Debug, Clone, Serialize)]
pub struct PresetInfo {
    pub id: String,
    pub name: String,
    pub description: String,
}

/// Список доступных пресетов правил.
pub fn list_presets() -> Vec<PresetInfo> {
    jammvpn_core::routing::presets()
        .into_iter()
        .map(|(id, name, description, _)| PresetInfo {
            id: id.to_string(),
            name: name.to_string(),
            description: description.to_string(),
        })
        .collect()
}

/// Применяет пресет: ЗАМЕНЯЕТ текущие правила набором пресета. Возвращает
/// число применённых правил. Err — неизвестный id.
pub fn apply_preset(id: &str) -> Result<usize, String> {
    let rules = jammvpn_core::routing::presets()
        .into_iter()
        .find(|(pid, ..)| *pid == id)
        .map(|(_, _, _, rules)| rules)
        .ok_or_else(|| format!("неизвестный пресет: {id}"))?;
    let n = rules.len();
    let path = config_path();
    let store = secret_store();
    let mut cfg = load_config(&path, store.as_ref());
    cfg.rules = rules;
    save_config(&path, &cfg, store.as_ref())?;
    Ok(n)
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

// --- Системный прокси Windows (WinINET) ---

/// Состояние системного прокси Windows (для UI).
#[derive(Debug, Clone, Serialize)]
pub struct SysProxyStatus {
    pub enabled: bool,
    pub server: Option<String>,
}

/// Включает системный прокси Windows на локальный `proxy` (`host:port`).
#[cfg(windows)]
pub fn set_system_proxy(proxy: &str) -> Result<(), String> {
    use jammvpn_platform_windows::sysproxy;
    sysproxy::set(proxy, sysproxy::DEFAULT_BYPASS)
}
#[cfg(not(windows))]
pub fn set_system_proxy(_proxy: &str) -> Result<(), String> {
    Err("системный прокси поддерживается только на Windows".into())
}

/// Выключает системный прокси Windows.
#[cfg(windows)]
pub fn clear_system_proxy() -> Result<(), String> {
    jammvpn_platform_windows::sysproxy::clear()
}
#[cfg(not(windows))]
pub fn clear_system_proxy() -> Result<(), String> {
    Err("системный прокси поддерживается только на Windows".into())
}

/// Текущее состояние системного прокси (на не-Windows — выключен).
#[cfg(windows)]
pub fn system_proxy_status() -> Result<SysProxyStatus, String> {
    let (enabled, server) = jammvpn_platform_windows::sysproxy::status()?;
    Ok(SysProxyStatus { enabled, server })
}
#[cfg(not(windows))]
pub fn system_proxy_status() -> Result<SysProxyStatus, String> {
    Ok(SysProxyStatus {
        enabled: false,
        server: None,
    })
}

// --- Раздельное туннелирование (split): конфиг + применение через драйвер ---

/// Порт локального транспарент-прокси, куда драйвер перенаправляет соединения
/// выбранных приложений (read original-dst → outbound).
pub const SPLIT_REDIRECT_PORT: u16 = 39001;

/// Драйвер-специфичные настройки split (приложения/маршруты — в [`list_rules`]).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SplitOptions {
    /// Kill-switch: не выпускать перенаправляемый трафик при неготовом тоннеле.
    pub kill_switch: bool,
    /// Приложения, которые будут перехвачены драйвером (выводятся из правил с
    /// действием «проксировать»; только для показа в UI).
    pub captured_apps: Vec<String>,
}

/// Строит конфиг драйвера из правил: перехватываются приложения, упомянутые в
/// правилах с действием «проксировать» (единый источник — [`AppConfig::rules`]).
/// Режим inclusive; hairpin-исключения — литеральные IP-адреса узлов. Маршрут
/// (узел/прямо/блок) для перехваченного трафика далее решает движок по правилам.
fn rules_to_split(cfg: &AppConfig) -> SplitConfig {
    let mut apps: Vec<AppMatcher> = Vec::new();
    // Источник 1: приложения, заданные напрямую в split-конфиге (панель split).
    for a in &cfg.split.apps {
        if !apps.contains(a) {
            apps.push(a.clone());
        }
    }
    // Источник 2: процессы из правил с действием «проксировать».
    for r in &cfg.rules {
        if matches!(r.action, RouteAction::Proxy(_)) {
            for p in &r.processes {
                if !apps.contains(p) {
                    apps.push(p.clone());
                }
            }
        }
    }
    // hairpin: адреса узлов, заданные литеральным IP (чтобы не зациклить трафик
    // самого VPN-сервера обратно в туннель).
    let endpoints = cfg
        .servers
        .iter()
        .filter(|s| s.address.parse::<std::net::IpAddr>().is_ok())
        .map(|s| s.address.clone())
        .collect();
    SplitConfig {
        mode: cfg.split.mode,
        apps,
        inherit_children: cfg.split.inherit_children,
        kill_switch: cfg.split.kill_switch,
        force_direct_cidrs: cfg.split.force_direct_cidrs.clone(),
        force_tunnel_cidrs: cfg.split.force_tunnel_cidrs.clone(),
        server_endpoints: endpoints,
    }
}

/// Текущие настройки split + предпросмотр перехватываемых приложений.
pub fn get_split_options() -> SplitOptions {
    let cfg = load();
    SplitOptions {
        kill_switch: cfg.split.kill_switch,
        captured_apps: rules_to_split(&cfg)
            .apps
            .iter()
            .map(process_to_string)
            .collect(),
    }
}

/// Авто-тест доступности сети через запущенный локальный прокси: подключается
/// SOCKS5-клиентом к `proxy_addr`, тянет `http://icanhazip.com` и возвращает
/// внешний IP (или ошибку — значит трафик через узел не идёт).
pub async fn proxy_self_test(proxy_addr: &str) -> Result<String, String> {
    use jammvpn_net::{Outbound, Socks5Config, Target};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let ob = Outbound::Socks5(Socks5Config {
        server: proxy_addr.to_string(),
        username: None,
        password: None,
    });
    let target = Target::Domain("icanhazip.com".to_string(), 80);
    let fut = async {
        let mut s = ob.connect_tcp(&target).await?;
        s.write_all(b"GET / HTTP/1.1\r\nHost: icanhazip.com\r\nConnection: close\r\nUser-Agent: curl/8\r\n\r\n")
            .await?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await?;
        Ok::<_, std::io::Error>(buf)
    };
    match tokio::time::timeout(std::time::Duration::from_secs(12), fut).await {
        Ok(Ok(buf)) => {
            let text = String::from_utf8_lossy(&buf);
            let ip = text.rsplit("\r\n\r\n").next().unwrap_or("").trim().to_string();
            if ip.is_empty() {
                Err("пустой ответ".into())
            } else {
                Ok(ip)
            }
        }
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("таймаут (12с)".into()),
    }
}

/// Сохраняет драйвер-настройки split (kill-switch).
pub fn set_split_options(kill_switch: bool) -> Result<(), String> {
    let path = config_path();
    let store = secret_store();
    let mut cfg = load_config(&path, store.as_ref());
    cfg.split.kill_switch = kill_switch;
    save_config(&path, &cfg, store.as_ref())
}

/// Применяет split к драйверу (`redirect_port` — порт транспарент-прокси).
/// Набор перехватываемых приложений выводится из правил. Требует загруженного
/// WFP-драйвера и прав администратора.
#[cfg(windows)]
pub fn apply_split(redirect_port: u16) -> Result<(), String> {
    use jammvpn_platform_windows::split::SplitController;
    use jammvpn_platform_windows::wfp::WfpDriverController;
    let cfg = load();
    let split = rules_to_split(&cfg);
    let mut ctrl = WfpDriverController::new(redirect_port);
    ctrl.apply(&split).map_err(|e| e.to_string())
}
#[cfg(not(windows))]
pub fn apply_split(_redirect_port: u16) -> Result<(), String> {
    Err("split-туннелирование поддерживается только на Windows".into())
}

/// Снимает split-правила в драйвере.
#[cfg(windows)]
pub fn clear_split() -> Result<(), String> {
    use jammvpn_platform_windows::wfp::WfpDriverController;
    use jammvpn_platform_windows::split::SplitController;
    let mut ctrl = WfpDriverController::new(0);
    ctrl.clear().map_err(|e| e.to_string())
}
#[cfg(not(windows))]
pub fn clear_split() -> Result<(), String> {
    Err("split-туннелирование поддерживается только на Windows".into())
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

/// Локальный транспарент-прокси для split-редиректа: принимает перенаправленные
/// драйвером соединения, восстанавливает original-dst и маршрутизирует движком.
pub struct SplitProxyController {
    handle: tokio::task::JoinHandle<()>,
}

impl SplitProxyController {
    /// Поднимает транспарент-сервер на `listen` (обычно `127.0.0.1:SPLIT_REDIRECT_PORT`).
    /// Маршрутизация — по правилам конфига. Только Windows (нужен redirect-context).
    #[cfg(windows)]
    pub async fn start(listen: &str) -> Result<Self, String> {
        use jammvpn_net::serve_transparent_redirect;
        use std::os::windows::io::AsRawSocket;
        let cfg = load();
        let engine = Arc::new(build_engine(&cfg, None)?);
        let listener = TcpListener::bind(listen).await.map_err(|e| e.to_string())?;
        let handle = tokio::spawn(async move {
            let _ = serve_transparent_redirect(listener, engine, |s: &tokio::net::TcpStream| {
                jammvpn_platform_windows::wfp::redirect::query_original_dst(
                    s.as_raw_socket() as usize,
                )
                .map_err(std::io::Error::other)
            })
            .await;
        });
        Ok(Self { handle })
    }
    #[cfg(not(windows))]
    pub async fn start(_listen: &str) -> Result<Self, String> {
        Err("split-редирект поддерживается только на Windows".into())
    }

    /// Останавливает транспарент-сервер.
    pub fn stop(self) {
        self.handle.abort();
    }
}

// ─────────────────────── Локальный WireGuard-сервер (inbound-шлюз) ───────────

/// Состояние локального WG-сервера для UI.
#[derive(Debug, Clone, Serialize)]
pub struct LocalWgInfo {
    /// Сконфигурирован ли (есть ключи).
    pub configured: bool,
    /// Запущен ли сейчас.
    pub running: bool,
    /// Фактический адрес прослушивания (если запущен).
    pub listen_addr: Option<String>,
    /// UDP-порт.
    pub port: u16,
    /// IP клиента в туннеле.
    pub client_ip: String,
    /// Публичный ключ сервера (для справки).
    pub server_public: String,
    /// Узел-апстрим (egress).
    pub upstream_node: Option<String>,
    /// Определённый LAN-IP для Endpoint в .conf.
    pub endpoint_host: Option<String>,
}

fn b64(bytes: &[u8]) -> String {
    jammvpn_core::base64::encode_standard(bytes)
}

fn decode32(s: &str) -> Result<[u8; 32], String> {
    let v = jammvpn_core::base64::decode_loose(s).map_err(|e| format!("base64: {e}"))?;
    if v.len() != 32 {
        return Err("ключ не 32 байта".into());
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&v);
    Ok(k)
}

/// Определяет основной LAN-IP машины (через UDP-connect без отправки пакетов).
fn detect_lan_ip() -> Option<std::net::IpAddr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    sock.local_addr().ok().map(|a| a.ip())
}

/// Гарантирует наличие конфигурации локального WG (генерирует ключи при первом
/// обращении) и возвращает её.
pub fn local_wg_ensure() -> Result<LocalWgConfig, String> {
    let path = config_path();
    let store = secret_store();
    let mut cfg = load_config(&path, store.as_ref());
    if let Some(lw) = &cfg.local_wg {
        return Ok(lw.clone());
    }
    let server_priv = gen_private_key();
    let client_priv = gen_private_key();
    let lw = LocalWgConfig {
        server_private: b64(&server_priv),
        server_public: b64(&wg_public_key(&server_priv)),
        client_private: b64(&client_priv),
        client_public: b64(&wg_public_key(&client_priv)),
        preshared_key: b64(&gen_preshared_key()),
        port: 51820,
        server_ip: "10.9.0.1".into(),
        client_ip: "10.9.0.2".into(),
        prefix: 24,
        upstream_node: None,
        dns: "1.1.1.1, 1.0.0.1".into(),
    };
    cfg.local_wg = Some(lw.clone());
    save_config(&path, &cfg, store.as_ref())?;
    Ok(lw)
}

/// Сохраняет порт/узел-апстрим локального WG.
pub fn local_wg_set(port: Option<u16>, upstream_node: Option<String>) -> Result<(), String> {
    local_wg_ensure()?;
    let path = config_path();
    let store = secret_store();
    let mut cfg = load_config(&path, store.as_ref());
    if let Some(lw) = cfg.local_wg.as_mut() {
        if let Some(p) = port {
            if p != 0 {
                lw.port = p;
            }
        }
        lw.upstream_node = upstream_node.filter(|s| !s.trim().is_empty());
    }
    save_config(&path, &cfg, store.as_ref())
}

/// Текущее состояние локального WG (с учётом запущенного контроллера).
pub fn local_wg_status(running_addr: Option<String>) -> LocalWgInfo {
    let cfg = load();
    match cfg.local_wg {
        Some(lw) => LocalWgInfo {
            configured: true,
            running: running_addr.is_some(),
            listen_addr: running_addr,
            port: lw.port,
            client_ip: lw.client_ip,
            server_public: lw.server_public,
            upstream_node: lw.upstream_node,
            endpoint_host: detect_lan_ip().map(|ip| ip.to_string()),
        },
        None => LocalWgInfo {
            configured: false,
            running: false,
            listen_addr: None,
            port: 51820,
            client_ip: "10.9.0.2".into(),
            server_public: String::new(),
            upstream_node: None,
            endpoint_host: detect_lan_ip().map(|ip| ip.to_string()),
        },
    }
}

/// Строит текст клиентского `.conf` локального WG (Endpoint = LAN-IP машины).
pub fn local_wg_client_conf() -> Result<String, String> {
    let lw = local_wg_ensure()?;
    let host = detect_lan_ip()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    Ok(format!(
        "[Interface]\n\
         PrivateKey = {privk}\n\
         Address = {cip}/{prefix}\n\
         DNS = {dns}\n\
         \n\
         [Peer]\n\
         PublicKey = {pubk}\n\
         PresharedKey = {psk}\n\
         Endpoint = {host}:{port}\n\
         AllowedIPs = 0.0.0.0/0, ::/0\n\
         PersistentKeepalive = 25\n",
        privk = lw.client_private,
        cip = lw.client_ip,
        prefix = lw.prefix,
        dns = lw.dns,
        pubk = lw.server_public,
        psk = lw.preshared_key,
        host = host,
        port = lw.port,
    ))
}

/// Генерирует клиентский `.conf` и пишет его рядом с конфигом; возвращает путь.
pub fn local_wg_export_conf() -> Result<String, String> {
    let conf = local_wg_client_conf()?;
    let dir = config_path()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let file = dir.join("jammvpn-local-wg.conf");
    std::fs::write(&file, conf).map_err(|e| e.to_string())?;
    Ok(file.to_string_lossy().to_string())
}

/// Запущен ли процесс от администратора.
pub fn is_admin() -> bool {
    #[cfg(windows)]
    {
        jammvpn_platform_windows::winpkfilter::is_elevated()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Перезапускает приложение от администратора (UAC). Текущий процесс должен
/// завершиться вызывающим.
pub fn relaunch_as_admin() -> Result<(), String> {
    #[cfg(windows)]
    {
        jammvpn_platform_windows::winpkfilter::relaunch_elevated()
    }
    #[cfg(not(windows))]
    {
        Err("только Windows".into())
    }
}

/// QR-код клиентского `.conf` локального WG в виде SVG-строки (для скана
/// WireGuard-приложением на телефоне).
pub fn local_wg_qr() -> Result<String, String> {
    let conf = local_wg_client_conf()?;
    let code = qrcode::QrCode::new(conf.as_bytes()).map_err(|e| e.to_string())?;
    let svg = code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(280, 280)
        .quiet_zone(true)
        .dark_color(qrcode::render::svg::Color("#0b0e14"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build();
    Ok(svg)
}

/// Best-effort: разрешает входящий UDP-порт в брандмауэре Windows (netsh).
/// Требует прав администратора; без них — тихо ничего не делает (UDP по LAN
/// тогда может блокироваться, подключайтесь к локальному WG от админа).
#[cfg(windows)]
fn firewall_allow_udp(port: u16) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let name = format!("JammVPN Local WG {port}");
    let _ = std::process::Command::new("netsh")
        .args(["advfirewall", "firewall", "delete", "rule", &format!("name={name}")])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let _ = std::process::Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={name}"),
            "dir=in",
            "action=allow",
            "protocol=UDP",
            &format!("localport={port}"),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}

/// Управляемый локальный WG-сервер (запуск/остановка из UI).
pub struct LocalWgController {
    server: WgServer,
    addr: SocketAddr,
}

impl LocalWgController {
    /// Поднимает сервер: egress через `upstream_node` (или по правилам, если
    /// `None`). Сохраняет выбор узла/порт в конфиг.
    pub async fn start(upstream_node: Option<String>) -> Result<Self, String> {
        let upstream = upstream_node.filter(|s| !s.trim().is_empty());
        local_wg_set(None, upstream.clone())?;
        let lw = local_wg_ensure()?;
        let cfg = load();
        let engine = build_engine(&cfg, upstream.as_deref())?;
        let server_ip: Ipv4Addr = lw
            .server_ip
            .parse()
            .map_err(|_| "некорректный server_ip".to_string())?;
        let params = WgServerParams {
            listen: format!("0.0.0.0:{}", lw.port)
                .parse()
                .map_err(|e| format!("listen: {e}"))?,
            server_private: decode32(&lw.server_private)?,
            client_public: decode32(&lw.client_public)?,
            preshared_key: Some(decode32(&lw.preshared_key)?),
            server_ip,
            prefix: lw.prefix,
        };
        // Открываем входящий UDP-порт в брандмауэре (best-effort; нужен админ —
        // иначе подключение по LAN блокируется).
        #[cfg(windows)]
        firewall_allow_udp(lw.port);

        let server = WgServer::start(params, Arc::new(engine))
            .await
            .map_err(|e| e.to_string())?;
        let addr = server.local_addr();
        Ok(Self { server, addr })
    }

    /// Адрес прослушивания.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Останавливает сервер.
    pub fn stop(self) {
        self.server.stop();
    }
}

// ───────────────── Split-туннелирование через Windows Packet Filter ──────────

/// Управляемый split-перехват: NDIS-захват приложений (ndisapi) + userspace
/// `netstack`, релеящий их трафик через выбранный путь.
#[cfg(windows)]
pub struct WinpkSplitController {
    // Держим netstack живым (Drop остановит стек и relay-задачи).
    _netstack: Arc<jammvpn_net::netstack::Netstack>,
    tunnel: Option<jammvpn_platform_windows::winpkfilter::SplitTunnel>,
    out_task: tokio::task::JoinHandle<()>,
}

#[cfg(windows)]
impl WinpkSplitController {
    /// Поднимает netstack (egress через выбранный на «Главной» узел или по
    /// правилам) и запускает NDIS-перехват приложений из split-набора (правила
    /// с действием Proxy). Требует драйвера `ndisrd` и админ-прав.
    pub async fn start() -> Result<Self, String> {
        let cfg = load();
        let split_cfg = rules_to_split(&cfg);
        let upstream = cfg.settings.proxy_node.clone();
        log_line(&format!(
            "split start: apps={:?} mode={:?} upstream={:?} elevated={}",
            split_cfg.apps,
            split_cfg.mode,
            upstream,
            jammvpn_platform_windows::winpkfilter::is_elevated()
        ));
        if split_cfg.apps.is_empty() {
            return Err("нет приложений для split: добавьте процесс в наборе split или \
                        правило с действием «проксировать»"
                .into());
        }
        let engine = Arc::new(build_engine(&cfg, upstream.as_deref())?);
        let (netstack, mut out) =
            jammvpn_net::netstack::Netstack::new(engine, Ipv4Addr::new(10, 9, 0, 1), 24);
        let netstack = Arc::new(netstack);
        let ns = netstack.clone();
        let logger: jammvpn_platform_windows::winpkfilter::Logger =
            std::sync::Arc::new(|m: String| log_line(&m));
        let tunnel = jammvpn_platform_windows::winpkfilter::SplitTunnel::start(
            split_cfg,
            Box::new(move |ip: &[u8]| ns.inject(ip)),
            logger,
        )?;
        let injector = tunnel.injector();
        // Ответы из netstack → реинъекция приложению.
        let out_task = tokio::spawn(async move {
            while let Some(ip) = out.recv().await {
                injector.inject(ip);
            }
        });
        Ok(Self {
            _netstack: netstack,
            tunnel: Some(tunnel),
            out_task,
        })
    }

    /// Останавливает перехват и стек.
    pub fn stop(mut self) {
        if let Some(t) = self.tunnel.take() {
            t.stop();
        }
        self.out_task.abort();
    }
}

/// Заглушка вне Windows (split доступен только на Windows).
#[cfg(not(windows))]
pub struct WinpkSplitController;

#[cfg(not(windows))]
impl WinpkSplitController {
    pub async fn start() -> Result<Self, String> {
        Err("split-туннелирование доступно только на Windows".into())
    }
    pub fn stop(self) {}
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
    fn wg_conf_export_roundtrips() {
        // Узел AmneziaWG → .conf → парсер: ключевые поля сохраняются.
        let conf = "\
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.8.1.3/32
DNS = 1.1.1.1, 1.0.0.1
Jc = 4
S1 = 71
H1 = 1882683096
[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
PresharedKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=
Endpoint = 192.0.2.10:32132
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
";
        let node = parse_awg_conf(conf).unwrap();
        let exported = node_to_wg_conf(&node);
        let reparsed = parse_awg_conf(&exported).unwrap();
        assert_eq!(reparsed.protocol, jammvpn_core::ProtocolKind::AmneziaWg);
        assert_eq!(reparsed.address, "192.0.2.10");
        assert_eq!(reparsed.port, 32132);
        assert_eq!(reparsed.param("private_key"), node.param("private_key"));
        assert_eq!(reparsed.param("public_key"), node.param("public_key"));
        assert_eq!(reparsed.param("preshared_key"), node.param("preshared_key"));
        assert_eq!(reparsed.param("h1"), Some("1882683096"));
        assert_eq!(reparsed.param("jc"), Some("4"));
        assert_eq!(reparsed.param("persistent_keepalive"), Some("25"));
        assert_eq!(reparsed.param("allowed_ips"), Some("0.0.0.0/0, ::/0"));
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
    fn rules_to_split_captures_proxy_apps() {
        let mut cfg = AppConfig::default();
        // процесс chrome.exe → проксировать ⇒ перехватывается драйвером.
        cfg.rules.push(Rule {
            processes: vec![AppMatcher::ProcessName("chrome.exe".into())],
            action: RouteAction::Proxy(Some("node".into())),
            ..Default::default()
        });
        // процесс game.exe → напрямую ⇒ НЕ перехватывается.
        cfg.rules.push(Rule {
            processes: vec![AppMatcher::ProcessName("game.exe".into())],
            action: RouteAction::Direct,
            ..Default::default()
        });
        // узел с литеральным IP → в endpoints (hairpin), доменный — нет.
        cfg.servers
            .push(parse_link("ss://YWVzLTI1Ni1nY206cGFzcw==@9.9.9.9:8388#S").unwrap());
        cfg.split.kill_switch = true;

        let split = rules_to_split(&cfg);
        assert_eq!(split.mode, SplitMode::Inclusive);
        assert!(split.kill_switch);
        assert_eq!(
            split.apps,
            vec![AppMatcher::ProcessName("chrome.exe".into())]
        );
        assert!(split.server_endpoints.contains(&"9.9.9.9".to_string()));
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
    fn import_config_detects_formats() {
        // Несколько ссылок построчно (с комментарием/пустой строкой).
        let (fmt, r) = parse_any_config(
            "ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#A\n# комментарий\n\nss://YWVzLTI1Ni1nY206cGFzcw==@5.6.7.8:8388#B",
        );
        assert_eq!(fmt, "ссылки");
        assert_eq!(r.iter().filter(|x| x.is_ok()).count(), 2);

        // AmneziaWG .conf — определяется по секции [Interface].
        let (fmt, _) = parse_any_config("[Interface]\nPrivateKey = x\n[Peer]\nEndpoint = h:51820");
        assert_eq!(fmt, "AmneziaWG .conf");

        // JSON — определяется по ведущей `{`.
        let (fmt, _) = parse_any_config("{ \"outbounds\": [] }");
        assert!(fmt == "JSON" || fmt == "sing-box JSON" || fmt == "Xray JSON");

        // Clash YAML — определяется по секции proxies:.
        let (fmt, r) = parse_any_config(
            "proxies:\n  - {name: a, type: ss, server: s.com, port: 8388, cipher: aes-256-gcm, password: p}\n",
        );
        assert_eq!(fmt, "Clash YAML");
        assert_eq!(r.iter().filter(|x| x.is_ok()).count(), 1);
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
