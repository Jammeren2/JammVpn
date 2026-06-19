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
pub use jammvpn_core::SocksProxy;
use jammvpn_net::{
    gen_preshared_key, gen_private_key, serve_socks_swappable, subscription,
    urltest, wg_public_key, ArcSwap, Engine, WgServer, WgServerParams,
};
// Реэкспорт для регистрации получателя уведомлений маршрутизации из app.
pub use jammvpn_net::{set_route_notifier, RouteNotice};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;

mod store;

/// Узел в списке (для UI/CLI).
#[derive(Debug, Clone, Serialize)]
pub struct NodeInfo {
    pub name: String,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    /// Группа узла = источник-подписка (первый тег) или `None` — свой ключ.
    pub group: Option<String>,
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
    /// Эффективный тег-группа (явный tag или хост из URL) — для связи с группой узлов.
    pub group: String,
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

/// Загружает конфиг из SQLite (расшифровывая секреты); при ошибке — пустой.
///
/// `path` — историческое имя JSON-файла (используется как якорь каталога). Само
/// хранилище — `store::db_path_for(path)` (рядом, `config.db`). При наличии только
/// старого JSON он одноразово мигрируется в БД, а файл переименовывается в `.bak`.
pub fn load_config(path: &Path, store: &dyn SecretStore) -> AppConfig {
    let db = store::db_path_for(path);
    let mut cfg = if db.exists() {
        store::load(&db, store).unwrap_or_else(|e| {
            eprintln!("предупреждение: не удалось загрузить БД ({e}); беру пустой");
            AppConfig::default()
        })
    } else if path.exists() {
        // Миграция со старого JSON-конфига в SQLite (одноразово).
        let c = AppConfig::load_protected(path, store).unwrap_or_else(|e| {
            eprintln!("предупреждение: не удалось загрузить старый конфиг ({e}); беру пустой");
            AppConfig::default()
        });
        if let Err(e) = store::save(&db, &c, store) {
            eprintln!("предупреждение: не удалось мигрировать конфиг в SQLite: {e}");
        } else {
            // Старый файл → .bak: и бэкап, и защита от повторной миграции.
            let _ = std::fs::rename(path, path.with_extension("json.bak"));
        }
        c
    } else {
        AppConfig::default()
    };
    sanitize_config(&mut cfg);
    cfg
}

/// Чинит заведомо-битые значения конфига (self-heal), чтобы не плодить
/// предупреждения. Сейчас: некорректный FakeIP-диапазон → дефолт.
fn sanitize_config(cfg: &mut AppConfig) {
    fn valid_cidr(s: &str) -> bool {
        match s.split_once('/') {
            Some((ip, pfx)) => {
                ip.trim().parse::<std::net::Ipv4Addr>().is_ok()
                    && pfx.trim().parse::<u8>().map(|p| p <= 32).unwrap_or(false)
            }
            None => false,
        }
    }
    if !valid_cidr(&cfg.dns.fakeip.range) {
        cfg.dns.fakeip.range = "198.18.0.0/15".to_string();
    }
}

/// Сохраняет конфиг в SQLite (шифруя секреты), создавая каталог при необходимости.
pub fn save_config(path: &Path, cfg: &AppConfig, store: &dyn SecretStore) -> Result<(), String> {
    let db = store::db_path_for(path);
    if let Some(dir) = db.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    store::save(&db, cfg, store)
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
    maybe_rotate_log(&path);
}

/// Хранимый максимум строк в файле лога.
const LOG_MAX_LINES: usize = 1000;

/// Раз в ~200 записей обрезает лог до последних [`LOG_MAX_LINES`] строк.
fn maybe_rotate_log(path: &Path) {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    if N.fetch_add(1, Ordering::Relaxed) % 200 != 0 {
        return;
    }
    if let Ok(content) = std::fs::read_to_string(path) {
        let lines: Vec<&str> = content.lines().collect();
        if lines.len() > LOG_MAX_LINES {
            let start = lines.len() - LOG_MAX_LINES;
            let _ = std::fs::write(path, lines[start..].join("\n") + "\n");
        }
    }
}

/// Путь к файлу лога.
fn log_path() -> PathBuf {
    config_path()
        .parent()
        .map(|p| p.join("jammvpn.log"))
        .unwrap_or_else(|| PathBuf::from("jammvpn.log"))
}

/// Последние `max_lines` строк лога (для вкладки «Логи»).
pub fn read_log(max_lines: usize) -> String {
    let content = std::fs::read_to_string(log_path()).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].join("\n")
}

/// Очищает файл лога.
pub fn clear_log() {
    let _ = std::fs::write(log_path(), b"");
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
            group: s.tags.first().cloned(),
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
        let mut sub = Subscription {
            url: arg.to_string(),
            tag: None,
            update_interval_hours: 12,
        };
        let (mut servers, title) =
            subscription::update_subscription(&sub, subscription::DEFAULT_TIMEOUT)
                .await
                .map_err(|e| e.to_string())?;
        sub.tag = title; // имя из Profile-Title (иначе хост)
        if !cfg.subscriptions.iter().any(|s| s.url == sub.url) {
            cfg.subscriptions.push(sub.clone());
        }
        ensure_distinct_sub_tags(&mut cfg);
        let stored = cfg
            .subscriptions
            .iter()
            .find(|s| s.url == arg)
            .cloned()
            .unwrap_or(sub);
        let tag = subscription::sub_tag(&stored);
        let host = subscription::sub_host(&stored.url);
        subscription::tag_servers(&mut servers, &tag);
        let n = servers.len();
        cfg.servers
            .retain(|s| !s.tags.iter().any(|t| t == &tag || t == &host));
        cfg.servers.extend(servers);
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
    // AmneziaWG / WireGuard .conf — проверяем ПЕРВЫМ: `[Interface]` тоже
    // начинается с `[`, иначе его перехватит ветка JSON-массива ниже.
    if text.contains("[Interface]") {
        return ("AmneziaWG .conf", vec![parse_awg_conf(text)]);
    }
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
/// Тест задержки одного узла по имени.
pub async fn test_node_latency(name: &str) -> LatencyResult {
    let cfg = load();
    let engine = Engine::from_config(&cfg);
    let ob = match engine.outbounds().get(name) {
        Some(o) => o.clone(),
        None => {
            return LatencyResult {
                name: name.to_string(),
                latency_ms: None,
                error: Some("узел не найден".into()),
            }
        }
    };
    let mut one = std::collections::HashMap::new();
    one.insert(name.to_string(), ob);
    let results =
        urltest::test_outbounds(&one, urltest::DEFAULT_TEST_URL, urltest::DEFAULT_TIMEOUT).await;
    match results.into_iter().next() {
        Some((n, res)) => LatencyResult {
            name: n,
            latency_ms: res.as_ref().ok().map(|d| d.as_millis() as u64),
            error: res.err().map(|e| e.to_string()),
        },
        None => LatencyResult {
            name: name.to_string(),
            latency_ms: None,
            error: Some("нет результата".into()),
        },
    }
}

/// Один шаг диагностики соединения (для UI «Тест соединения»).
#[derive(Debug, Clone, Serialize)]
pub struct DiagStep {
    pub name: String,
    pub ok: bool,
    pub detail: String,
    pub ms: u64,
}

/// Пошаговая диагностика узла по имени: где именно рвётся путь
/// (подключение к узлу → TLS через туннель → HTTP-ответ).
pub async fn diagnose_node(name: &str) -> Vec<DiagStep> {
    let cfg = load();
    let engine = Engine::from_config(&cfg);
    let ob = match engine.outbounds().get(name) {
        Some(o) => o.clone(),
        None => {
            return vec![DiagStep {
                name: "Узел".into(),
                ok: false,
                detail: format!("узел «{name}» не найден в конфигурации"),
                ms: 0,
            }]
        }
    };
    jammvpn_net::diagnose_outbound(&ob)
        .await
        .into_iter()
        .map(|s| DiagStep {
            name: s.name,
            ok: s.ok,
            detail: s.detail,
            ms: s.ms,
        })
        .collect()
}

/// Строит `vless://`-ссылку из узла (для копирования; в т.ч. узлы подписки).
fn node_to_vless_link(p: &ServerProfile) -> Option<String> {
    if p.protocol != jammvpn_core::ProtocolKind::Vless {
        return None;
    }
    let uuid = p.param("uuid")?;
    let keys = [
        "type",
        "security",
        "encryption",
        "flow",
        "sni",
        "pbk",
        "sid",
        "fp",
        "host",
        "path",
        "alpn",
        "serviceName",
    ];
    let mut q = Vec::new();
    for k in keys {
        if let Some(v) = p.param(k) {
            if !v.is_empty() {
                q.push(format!("{k}={}", pct(v)));
            }
        }
    }
    let query = if q.is_empty() {
        String::new()
    } else {
        format!("?{}", q.join("&"))
    };
    let frag = if p.name.is_empty() {
        String::new()
    } else {
        format!("#{}", pct(&p.name))
    };
    Some(format!(
        "vless://{uuid}@{}:{}{query}{frag}",
        p.address, p.port
    ))
}

/// Строит `ss://`-ссылку (SIP002: `ss://base64(method:password)@host:port?params#name`).
/// `password` для multi-user SS-2022 — это цепочка `iPSK:uPSK` (как в подписке).
fn node_to_ss_link(p: &ServerProfile) -> Option<String> {
    if p.protocol != jammvpn_core::ProtocolKind::Shadowsocks {
        return None;
    }
    let method = p.param("method")?;
    let password = p.param("password")?;
    let userinfo = jammvpn_core::base64::encode_standard(format!("{method}:{password}").as_bytes());
    // Параметры транспорта (если есть): security/sni/alpn/fp/type.
    let mut q = Vec::new();
    for k in ["security", "sni", "alpn", "fp", "type"] {
        if let Some(v) = p.param(k) {
            if !v.is_empty() {
                q.push(format!("{k}={}", pct(v)));
            }
        }
    }
    let query = if q.is_empty() {
        String::new()
    } else {
        format!("?{}", q.join("&"))
    };
    let frag = if p.name.is_empty() {
        String::new()
    } else {
        format!("#{}", pct(&p.name))
    };
    Some(format!(
        "ss://{userinfo}@{}:{}{query}{frag}",
        p.address, p.port
    ))
}

/// `ss://`-ссылка узла по имени (для копирования). Ошибка — если не Shadowsocks.
pub fn export_ss_link(name: &str) -> Result<String, String> {
    let cfg = load();
    let node = cfg
        .servers
        .iter()
        .find(|s| s.name == name)
        .ok_or_else(|| format!("узел не найден: {name}"))?;
    node_to_ss_link(node).ok_or_else(|| "ссылка ss:// доступна только для Shadowsocks-узлов".into())
}

/// Percent-encoding значения (всё, кроме unreserved RFC 3986).
fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `vless://`-ссылка узла по имени (для копирования). Ошибка — если не VLESS.
pub fn export_vless_link(name: &str) -> Result<String, String> {
    let cfg = load();
    let node = cfg
        .servers
        .iter()
        .find(|s| s.name == name)
        .ok_or_else(|| format!("узел не найден: {name}"))?;
    node_to_vless_link(node).ok_or_else(|| "ссылка vless:// доступна только для VLESS-узлов".into())
}

/// `hysteria2://`-ссылка узла (для копирования). `None`, если не Hysteria2.
fn node_to_hysteria2_link(p: &ServerProfile) -> Option<String> {
    if p.protocol != jammvpn_core::ProtocolKind::Hysteria2 {
        return None;
    }
    let auth = p.param("auth").unwrap_or("");
    // Все параметры, кроме auth, идут в query (auth → userinfo). `params` —
    // BTreeMap, порядок детерминированный.
    let q: Vec<String> = p
        .params
        .iter()
        .filter(|(k, v)| k.as_str() != "auth" && !v.is_empty())
        .map(|(k, v)| format!("{k}={}", pct(v)))
        .collect();
    let query = if q.is_empty() {
        String::new()
    } else {
        format!("?{}", q.join("&"))
    };
    let frag = if p.name.is_empty() {
        String::new()
    } else {
        format!("#{}", pct(&p.name))
    };
    let userinfo = if auth.is_empty() {
        String::new()
    } else {
        format!("{}@", pct(auth))
    };
    Some(format!(
        "hysteria2://{userinfo}{}:{}{query}{frag}",
        p.address, p.port
    ))
}

/// `hysteria2://`-ссылка узла по имени. Ошибка — если не Hysteria2.
pub fn export_hysteria2_link(name: &str) -> Result<String, String> {
    let cfg = load();
    let node = cfg
        .servers
        .iter()
        .find(|s| s.name == name)
        .ok_or_else(|| format!("узел не найден: {name}"))?;
    node_to_hysteria2_link(node)
        .ok_or_else(|| "ссылка hysteria2:// доступна только для Hysteria2-узлов".into())
}

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
/// Гарантирует уникальный тег у каждой подписки (для разделения групп и
/// корректных имён): база = явный `tag` или хост URL; коллизии получают суффикс
/// « (2)», « (3)»… Стабильна при повторных вызовах. Возвращает `true`, если
/// что-то изменилось. Сохранение — на вызывающем.
fn ensure_distinct_sub_tags(cfg: &mut AppConfig) -> bool {
    use std::collections::HashSet;
    let mut used: HashSet<String> = HashSet::new();
    let mut changed = false;
    for sub in &mut cfg.subscriptions {
        let base = sub
            .tag
            .clone()
            .filter(|t| !t.trim().is_empty())
            .unwrap_or_else(|| jammvpn_net::subscription::sub_host(&sub.url));
        let mut tag = base.clone();
        let mut n = 2;
        while used.contains(&tag) {
            tag = format!("{base} ({n})");
            n += 1;
        }
        used.insert(tag.clone());
        if sub.tag.as_deref() != Some(tag.as_str()) {
            sub.tag = Some(tag);
            changed = true;
        }
    }
    changed
}

pub async fn update_subscriptions() -> Result<Vec<SubUpdate>, String> {
    let path = config_path();
    let store = secret_store();
    let mut cfg = load_config(&path, store.as_ref());
    let n_subs = cfg.subscriptions.len();
    let mut out = Vec::with_capacity(n_subs);
    // Пасс 1: качаем все, имя из Profile-Title пишем в запись подписки.
    let mut fetched: Vec<Option<Vec<jammvpn_core::ServerProfile>>> = Vec::with_capacity(n_subs);
    for i in 0..n_subs {
        let sub = cfg.subscriptions[i].clone();
        match subscription::update_subscription(&sub, subscription::DEFAULT_TIMEOUT).await {
            Ok((servers, title)) => {
                if let Some(t) = title {
                    cfg.subscriptions[i].tag = Some(t);
                }
                let n = servers.len();
                log_line(&format!("подписка {}: {n} узлов", sub.url));
                fetched.push(Some(servers));
                out.push(SubUpdate { url: sub.url.clone(), count: Some(n), error: None });
            }
            Err(e) => {
                log_line(&format!("подписка {}: ОШИБКА {e}", sub.url));
                fetched.push(None);
                out.push(SubUpdate { url: sub.url.clone(), count: None, error: Some(e.to_string()) });
            }
        }
    }
    // Уникализируем теги ПОСЛЕ имён (дедуп одинаковых названий/хостов).
    ensure_distinct_sub_tags(&mut cfg);
    // Пасс 2: успешные — перетегировать узлы финальным тегом и влить (старые
    // узлы этой подписки сносим по тегу И хосту — ловим легаси-узлы).
    for (i, servers) in fetched.into_iter().enumerate() {
        let Some(mut servers) = servers else { continue };
        let sub = cfg.subscriptions[i].clone();
        let tag = subscription::sub_tag(&sub);
        let host = subscription::sub_host(&sub.url);
        subscription::tag_servers(&mut servers, &tag);
        cfg.servers
            .retain(|s| !s.tags.iter().any(|t| t == &tag || t == &host));
        cfg.servers.extend(servers);
    }
    save_config(&path, &cfg, store.as_ref())?;
    Ok(out)
}

/// Обновляет ОДНУ подписку по её URL. Возвращает число узлов.
pub async fn update_one_subscription(url: &str) -> Result<usize, String> {
    let path = config_path();
    let store = secret_store();
    let mut cfg = load_config(&path, store.as_ref());
    let idx = cfg
        .subscriptions
        .iter()
        .position(|s| s.url == url)
        .ok_or_else(|| format!("подписка не найдена: {url}"))?;
    let sub = cfg.subscriptions[idx].clone();
    let (mut servers, title) = subscription::update_subscription(&sub, subscription::DEFAULT_TIMEOUT)
        .await
        .map_err(|e| e.to_string())?;
    if let Some(t) = title {
        cfg.subscriptions[idx].tag = Some(t);
    }
    ensure_distinct_sub_tags(&mut cfg);
    let sub = cfg.subscriptions[idx].clone();
    let tag = subscription::sub_tag(&sub);
    let host = subscription::sub_host(&sub.url);
    subscription::tag_servers(&mut servers, &tag);
    cfg.servers
        .retain(|s| !s.tags.iter().any(|t| t == &tag || t == &host));
    let n = servers.len();
    cfg.servers.extend(servers);
    save_config(&path, &cfg, store.as_ref())?;
    log_line(&format!("подписка {url}: {n} узлов (обновление группы)"));
    Ok(n)
}

/// Удаляет из конфига узлы, полученные из подписок (по тегам подписок).
/// Возвращает число удалённых. Ручные ключи остаются.
pub fn clear_subscription_nodes() -> Result<usize, String> {
    let path = config_path();
    let store = secret_store();
    let mut cfg = load_config(&path, store.as_ref());
    let tags: Vec<String> = cfg
        .subscriptions
        .iter()
        .map(jammvpn_net::subscription::sub_tag)
        .collect();
    let before = cfg.servers.len();
    // Узел из подписки = есть тег подписки ИЛИ имя в формате «Группа · узел»
    // (легаси-узлы добавлялись без тега до введения тегирования).
    cfg.servers
        .retain(|s| !s.tags.iter().any(|t| tags.contains(t)) && !s.name.contains(" · "));
    let removed = before - cfg.servers.len();
    save_config(&path, &cfg, store.as_ref())?;
    Ok(removed)
}

/// Репозиторий релизов на GitHub (для проверки/скачивания обновлений).
const RELEASE_REPO: &str = "Jammeren2/JammVpn";

/// GUID клиента EdgeUpdate для Evergreen WebView2 Runtime.
const WEBVIEW2_GUID: &str = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";

/// Проверяет, доступен ли WebView2 Runtime текущему пользователю (системная
/// установка в HKLM или установка текущего пользователя в HKCU). Установка под
/// ДРУГИМ пользователем (чужой HKCU) намеренно не считается — Tauri её не увидит.
pub fn webview2_present() -> bool {
    let keys = [
        format!("HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\EdgeUpdate\\Clients\\{WEBVIEW2_GUID}"),
        format!("HKLM\\SOFTWARE\\Microsoft\\EdgeUpdate\\Clients\\{WEBVIEW2_GUID}"),
        format!("HKCU\\SOFTWARE\\Microsoft\\EdgeUpdate\\Clients\\{WEBVIEW2_GUID}"),
    ];
    for k in keys {
        let out = std::process::Command::new("reg")
            .args(["query", &k, "/v", "pv"])
            .output();
        if let Ok(out) = out {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                // pv присутствует и не нулевая версия (ключ-«заглушка»).
                if s.contains("pv") && !s.contains("0.0.0.0") {
                    return true;
                }
            }
        }
    }
    false
}

/// Гарантирует наличие WebView2 Runtime. Если есть — ничего не делает (`Ok(true)`).
/// Если нет — скачивает официальный Microsoft Evergreen Bootstrapper и ставит его
/// тихо, затем перепроверяет. Блокирующая (вызывать ДО создания окна GUI).
///
/// Установщик — официальный (go.microsoft.com), это штатный способ доставки
/// WebView2 (как `downloadBootstrapper` в Tauri). От админа ставит системно, без
/// прав — для текущего пользователя; в обоих случаях рантайм становится доступен.
pub fn ensure_webview2() -> Result<bool, String> {
    if webview2_present() {
        return Ok(true);
    }
    log_line("WebView2 Runtime не найден — скачиваю официальный установщик Microsoft");
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let bytes = rt
        .block_on(jammvpn_net::subscription::fetch_bytes(
            "https://go.microsoft.com/fwlink/p/?LinkId=2124703",
            std::time::Duration::from_secs(180),
        ))
        .map_err(|e| format!("скачивание WebView2: {e}"))?;
    if bytes.len() < 100_000 {
        return Err(format!("установщик WebView2 подозрительно мал ({} байт)", bytes.len()));
    }
    let path = std::env::temp_dir().join("MicrosoftEdgeWebview2Setup.exe");
    std::fs::write(&path, &bytes).map_err(|e| format!("запись установщика: {e}"))?;
    log_line("устанавливаю WebView2 Runtime (тихий режим)…");
    let status = std::process::Command::new(&path)
        .args(["/silent", "/install"])
        .status()
        .map_err(|e| format!("запуск установщика WebView2: {e}"))?;
    let _ = std::fs::remove_file(&path);
    if !status.success() {
        return Err(format!(
            "установщик WebView2 завершился с кодом {:?}",
            status.code()
        ));
    }
    let ok = webview2_present();
    log_line(&format!("WebView2 после установки доступен: {ok}"));
    Ok(ok)
}

/// Информация об обновлении (для сплеша).
#[derive(Debug, Clone, Serialize)]
pub struct UpdateInfo {
    pub current: String,
    pub latest: String,
    pub url: String,
    pub newer: bool,
    /// Прямая ссылка на .exe-ассет релиза (пусто, если ассета нет).
    pub download_url: String,
}

/// Проверяет последний релиз на GitHub (best-effort). `Ok(None)` — не удалось
/// проверить (приватный репозиторий / нет релизов / сеть) — стартап не блокируем.
/// `a > b` для версий вида `x.y.z` (сравнение по числовым компонентам;
/// недостающие = 0; нечисловые хвосты вроде `-pre` игнорируются покомпонентно).
fn version_gt(a: &str, b: &str) -> bool {
    fn parts(s: &str) -> Vec<u64> {
        s.split(['.', '-'])
            .map(|p| {
                p.chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse::<u64>()
                    .unwrap_or(0)
            })
            .collect()
    }
    let (pa, pb) = (parts(a), parts(b));
    for i in 0..pa.len().max(pb.len()) {
        let (x, y) = (pa.get(i).copied().unwrap_or(0), pb.get(i).copied().unwrap_or(0));
        if x != y {
            return x > y;
        }
    }
    false
}

pub async fn check_update(current: &str) -> Result<Option<UpdateInfo>, String> {
    let url = format!("https://api.github.com/repos/{RELEASE_REPO}/releases/latest");
    let body =
        match jammvpn_net::subscription::fetch_text(&url, std::time::Duration::from_secs(6)).await {
            Ok(b) => b,
            Err(_) => return Ok(None),
        };
    let Ok(root) = jammvpn_core::JsonValue::parse(&body) else {
        return Ok(None);
    };
    let Some(latest) = root.get("tag_name").and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    let html = root
        .get("html_url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    // Ищем .exe среди ассетов релиза для авто-обновления.
    let download_url = root
        .get("assets")
        .and_then(|a| a.as_array())
        .into_iter()
        .flatten()
        .find_map(|a| {
            let name = a.get("name").and_then(|v| v.as_str())?;
            if name.to_ascii_lowercase().ends_with(".exe") {
                a.get("browser_download_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();
    // «Новее» = версия релиза СТРОГО больше текущей (semver-сравнение по
    // числовым компонентам), а не просто «отличается» — иначе dev-сборка с
    // версией выше последнего релиза ложно предлагала бы «обновиться» назад.
    let newer = version_gt(latest.trim_start_matches('v'), current);
    Ok(Some(UpdateInfo {
        current: current.to_string(),
        latest: latest.to_string(),
        url: html,
        newer,
        download_url,
    }))
}

/// Скачивает новый .exe и подменяет текущий бинарник, затем запускает новую
/// версию. Возвращает `Ok(())` — после чего вызывающий должен завершить процесс
/// (новый уже запущен). Техника Windows: текущий запущенный exe нельзя
/// перезаписать, но можно переименовать — поэтому старый отодвигаем в `.old`.
pub async fn perform_update(download_url: &str) -> Result<(), String> {
    if download_url.is_empty() {
        return Err("у релиза нет .exe-ассета для авто-обновления".into());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = exe.parent().ok_or("нет родительской папки exe")?;
    let stem = exe
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("jammvpn-app");
    let new_path = dir.join(format!("{stem}.new.exe"));
    let old_path = dir.join(format!("{stem}.old.exe"));

    log_line(&format!("update: скачиваю {download_url}"));
    let bytes = jammvpn_net::subscription::fetch_bytes(download_url, std::time::Duration::from_secs(120))
        .await
        .map_err(|e| format!("не удалось скачать обновление: {e}"))?;
    if bytes.len() < 1_000_000 {
        return Err(format!("скачанный файл подозрительно мал ({} байт)", bytes.len()));
    }
    std::fs::write(&new_path, &bytes).map_err(|e| format!("запись {new_path:?}: {e}"))?;

    // Отодвигаем текущий exe и ставим новый на его место.
    let _ = std::fs::remove_file(&old_path);
    std::fs::rename(&exe, &old_path).map_err(|e| format!("переименование текущего exe: {e}"))?;
    if let Err(e) = std::fs::rename(&new_path, &exe) {
        // Откат: вернём старый exe на место.
        let _ = std::fs::rename(&old_path, &exe);
        return Err(format!("установка нового exe: {e}"));
    }
    log_line("update: новый exe установлен, перезапускаю");

    // Запускаем обновлённый бинарник (detached) и просим вызывающего выйти.
    std::process::Command::new(&exe)
        .spawn()
        .map_err(|e| format!("запуск обновлённого exe: {e}"))?;
    Ok(())
}

/// Удаляет временный `<stem>.old.exe`, оставшийся после авто-обновления.
/// Вызывается на старте; ошибки игнорируются (файл может быть ещё занят).
pub fn cleanup_after_update() {
    if let Ok(exe) = std::env::current_exe() {
        if let (Some(dir), Some(stem)) = (exe.parent(), exe.file_stem().and_then(|s| s.to_str())) {
            let _ = std::fs::remove_file(dir.join(format!("{stem}.old.exe")));
            let _ = std::fs::remove_file(dir.join(format!("{stem}.new.exe")));
        }
    }
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

/// Записывает `.conf` WG/AmneziaWG-узла в выбранный путь (диалог «Сохранить как»).
pub fn export_node_conf_to(name: &str, path: &str) -> Result<(), String> {
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
    std::fs::write(path, node_to_wg_conf(node)).map_err(|e| e.to_string())
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
            group: jammvpn_net::subscription::sub_tag(&s),
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
        // Сразу присваиваем уникальный тег (отделяет от подписок с тем же хостом).
        ensure_distinct_sub_tags(&mut cfg);
        save_config(&path, &cfg, store.as_ref())?;
    }
    Ok(added)
}

/// Удаляет подписку по URL (чистая логика): была ли удалена.
fn apply_remove_subscription(cfg: &mut AppConfig, url: &str) -> bool {
    let Some(sub) = cfg.subscriptions.iter().find(|s| s.url == url).cloned() else {
        return false;
    };
    let tag = jammvpn_net::subscription::sub_tag(&sub);
    cfg.subscriptions.retain(|s| s.url != url);
    // Удаляем и узлы этой подписки (по тегу).
    cfg.servers
        .retain(|s| !s.tags.iter().any(|t| t == &tag));
    true
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

/// Скачивает стандартные geo-базы (Loyalsoldier/v2ray-rules-dat) рядом с
/// конфигом и прописывает пути. Возвращает сообщение с размерами.
pub async fn download_geo() -> Result<String, String> {
    const BASE: &str =
        "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download";
    let dir = config_path()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let mut paths: Vec<(String, String)> = Vec::new(); // (имя, путь)
    let mut sizes = Vec::new();
    for name in ["geosite.dat", "geoip.dat"] {
        log_line(&format!("geo: загрузка {name}…"));
        let bytes = jammvpn_net::subscription::fetch_bytes(
            &format!("{BASE}/{name}"),
            std::time::Duration::from_secs(90),
        )
        .await
        .map_err(|e| format!("{name}: {e}"))?;
        if bytes.len() < 1024 {
            return Err(format!("{name}: подозрительно мал ({} Б)", bytes.len()));
        }
        let file = dir.join(name);
        std::fs::write(&file, &bytes).map_err(|e| e.to_string())?;
        sizes.push(format!("{name} {} КБ", bytes.len() / 1024));
        paths.push((name.to_string(), file.to_string_lossy().to_string()));
        log_line(&format!("geo: {name} сохранён ({} КБ)", bytes.len() / 1024));
    }
    let geosite = paths.iter().find(|(n, _)| n == "geosite.dat").map(|(_, p)| p.clone());
    let geoip = paths.iter().find(|(n, _)| n == "geoip.dat").map(|(_, p)| p.clone());
    set_geo_paths(geosite, geoip)?;
    Ok(format!("geo-базы загружены: {}", sizes.join(", ")))
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
        driver: cfg.split.driver,
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

/// Текущий драйвер split (`"winpkfilter"` | `"windivert"`).
pub fn get_split_driver() -> String {
    match load().split.driver {
        jammvpn_core::SplitDriver::WinDivert => "windivert".into(),
        jammvpn_core::SplitDriver::WinpkFilter => "winpkfilter".into(),
    }
}

/// Устанавливает драйвер split. Применяется при следующем запуске split.
pub fn set_split_driver(driver: &str) -> Result<(), String> {
    let d = match driver {
        "windivert" => jammvpn_core::SplitDriver::WinDivert,
        "winpkfilter" => jammvpn_core::SplitDriver::WinpkFilter,
        other => return Err(format!("неизвестный драйвер: {other}")),
    };
    let path = config_path();
    let store = secret_store();
    let mut cfg = load_config(&path, store.as_ref());
    cfg.split.driver = d;
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
    // Правила маршрутизации применяются ВСЕГДА и имеют приоритет: даже при
    // выбранном на «Главной» узле правило вида «процесс/домен → конкретный узел»
    // (Proxy(Some(tag))) направит трафик туда, а не в выбранный туннель. Сам
    // выбранный узел — лишь default для Proxy(None) и непокрытого правилами
    // трафика. (Раньше выбор узла строил single_proxy и игнорировал правила.)
    if let Some(name) = server {
        if !cfg.servers.iter().any(|s| s.name == name) {
            return Err(format!("узел не найден: {name}"));
        }
    }
    // Узел по умолчанию: выбранный на «Главной» (server) → явный default_proxy →
    // proxy_node.
    let default = server
        .map(str::to_string)
        .or_else(|| cfg.settings.default_proxy.clone())
        .or_else(|| cfg.settings.proxy_node.clone());
    let mut eff = cfg.clone();
    eff.settings.default_proxy = default;
    // КРИТИЧНО: при выбранном узле непокрытый правилами трафик ДОЛЖЕН идти через
    // узел (default_action = Proxy), иначе он утёк бы Direct (реальный IP). Раньше
    // выбор узла строил single_proxy (всё через узел); теперь правила в приоритете,
    // но дефолт обязан быть «через узел». Режим «по правилам» (server=None)
    // сохраняет настройку default_to_proxy пользователя.
    if server.is_some() {
        eff.settings.default_to_proxy = true;
    }
    let engine = Engine::from_config(&eff);
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

/// Управляемый локальный SOCKS5-прокси (для UI: запуск/остановка).
pub struct ProxyController {
    addr: SocketAddr,
    server: Option<String>,
    handle: tokio::task::JoinHandle<()>,
    /// Подменяемый на лету движок (для применения правил без перезапуска).
    engine: Arc<ArcSwap<Engine>>,
}

impl ProxyController {
    /// Запускает прокси: биндит `listen`, строит движок (через `server` или по
    /// правилам), спавнит обслуживание. Возвращается после успешного бинда.
    pub async fn start(listen: &str, server: Option<String>) -> Result<Self, String> {
        let cfg = load();
        let engine = build_engine(&cfg, server.as_deref()).inspect_err(|e| {
            log_line(&format!("прокси: ошибка движка (узел {server:?}): {e}"));
        })?;
        let listener = TcpListener::bind(listen).await.map_err(|e| {
            log_line(&format!("прокси: bind {listen} не удался: {e}"));
            e.to_string()
        })?;
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        log_line(&format!(
            "прокси запущен на {addr}; узел: {}",
            server.as_deref().unwrap_or("по правилам")
        ));
        let engine = Arc::new(ArcSwap::from_pointee(engine));
        let serve_engine = engine.clone();
        let handle = tokio::spawn(async move {
            let _ = serve_socks_swappable(listener, serve_engine).await;
        });
        Ok(Self {
            addr,
            server,
            handle,
            engine,
        })
    }

    /// Пересобирает движок из `cfg` и подменяет на лету: новые соединения сразу
    /// идут по новым правилам, перезапуск прокси не нужен. Активные соединения
    /// доживают на старом движке.
    pub fn reload(&self, cfg: &AppConfig) -> Result<(), String> {
        let engine = build_engine(cfg, self.server.as_deref())?;
        self.engine.store(Arc::new(engine));
        Ok(())
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

/// Несколько SOCKS5-листенеров сразу: каждый на своём `ip:port` ведёт на свой
/// узел (или по правилам с узлом по умолчанию = выбранный на «Главной»). Один
/// помеченный листенер прописывается системным прокси Windows.
pub struct MultiSocks {
    proxies: Vec<ProxyController>,
    primary: SocketAddr,
    system_set: bool,
}

impl MultiSocks {
    pub async fn start() -> Result<Self, String> {
        let cfg = load();
        let mut list = cfg.socks_proxies.clone();
        if list.is_empty() {
            // По умолчанию — один листенер на 127.0.0.1:1080, системный.
            list.push(jammvpn_core::SocksProxy {
                listen: "127.0.0.1:1080".into(),
                node: None,
                system: true,
            });
        }
        let mut proxies = Vec::new();
        let mut system_addr: Option<SocketAddr> = None;
        for sp in &list {
            // node=Some → весь трафик через узел; node=None → по правилам, узел по
            // умолчанию = выбранный на «Главной» (см. build_engine).
            match ProxyController::start(&sp.listen, sp.node.clone()).await {
                Ok(pc) => {
                    if sp.system && system_addr.is_none() {
                        system_addr = Some(pc.addr());
                    }
                    proxies.push(pc);
                }
                Err(e) => log_line(&format!("SOCKS {} не запущен: {e}", sp.listen)),
            }
        }
        if proxies.is_empty() {
            return Err("ни один SOCKS-листенер не запущен (проверьте адреса)".into());
        }
        let primary = system_addr.unwrap_or_else(|| proxies[0].addr());
        let mut system_set = false;
        if let Some(addr) = system_addr {
            // 0.0.0.0 в системном прокси не годится — указываем 127.0.0.1.
            let host = if addr.ip().is_unspecified() {
                format!("127.0.0.1:{}", addr.port())
            } else {
                addr.to_string()
            };
            match set_system_proxy(&host) {
                Ok(()) => system_set = true,
                Err(e) => log_line(&format!("системный прокси не установлен: {e}")),
            }
        }
        log_line(&format!(
            "SOCKS: листенеров {}, системный прокси={}",
            proxies.len(),
            system_set
        ));
        Ok(Self {
            proxies,
            primary,
            system_set,
        })
    }

    /// Адрес «главного» листенера (системного или первого) — для статуса/проверки.
    pub fn primary_addr(&self) -> SocketAddr {
        self.primary
    }

    /// Применяет текущие правила маршрутизации ко всем листенерам на лету
    /// (без перезапуска прокси). Вызывается после изменения правил/пресетов.
    pub fn reload(&self) -> Result<(), String> {
        let cfg = load();
        for p in &self.proxies {
            p.reload(&cfg)?;
        }
        log_line(&format!("SOCKS: правила перезагружены ({} листенеров)", self.proxies.len()));
        Ok(())
    }

    pub fn stop(self) {
        for p in self.proxies {
            p.stop();
        }
        if self.system_set {
            let _ = clear_system_proxy();
        }
    }
}

/// Список настроенных SOCKS-листенеров (для UI).
pub fn get_socks_proxies() -> Vec<jammvpn_core::SocksProxy> {
    load().socks_proxies
}

/// Сохраняет список SOCKS-листенеров. Нормализует: пустые адреса убираем,
/// системным остаётся только первый помеченный.
pub fn set_socks_proxies(mut list: Vec<jammvpn_core::SocksProxy>) -> Result<(), String> {
    let mut seen_system = false;
    for p in &mut list {
        p.listen = p.listen.trim().to_string();
        p.node = p.node.clone().filter(|n| !n.is_empty());
        if p.system {
            if seen_system {
                p.system = false;
            } else {
                seen_system = true;
            }
        }
    }
    list.retain(|p| !p.listen.is_empty());
    let path = config_path();
    let store = secret_store();
    let mut cfg = load_config(&path, store.as_ref());
    cfg.socks_proxies = list;
    save_config(&path, &cfg, store.as_ref())
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

/// Записывает клиентский `.conf` локального WG в выбранный путь.
pub fn local_wg_export_conf_to(path: &str) -> Result<(), String> {
    let conf = local_wg_client_conf()?;
    std::fs::write(path, conf).map_err(|e| e.to_string())
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

/// Установлен ли драйвер раздельного туннелирования (WinpkFilter / `ndisrd`).
pub fn split_driver_installed() -> bool {
    #[cfg(windows)]
    {
        // WinDivert ставит свою службу сам при первом запуске split (драйвер вшит),
        // отдельная пред-установка не нужна — считаем «готов».
        if matches!(load().split.driver, jammvpn_core::SplitDriver::WinDivert) {
            return true;
        }
        jammvpn_platform_windows::winpkfilter::driver::is_installed()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Устанавливает вшитый в exe драйвер `ndisrd` (если ещё не установлен). Требует
/// прав администратора. Возвращает сообщение для UI.
pub fn install_split_driver() -> Result<String, String> {
    #[cfg(windows)]
    {
        let log = |m: String| log_line(&m);
        match jammvpn_platform_windows::winpkfilter::driver::ensure_installed(&log)? {
            true => Ok("драйвер установлен".into()),
            false => Ok("драйвер уже установлен".into()),
        }
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

/// Первый ли это запуск версии `current` (для показа «что нового» после
/// обновления). Обновляет сохранённую версию в хранилище.
pub fn first_run_of_version(current: &str) -> bool {
    store::mark_version_seen(&config_path(), current)
}

/// Создаёт ярлык JammVPN на рабочем столе пользователя (Windows).
#[cfg(windows)]
pub fn create_desktop_shortcut() -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe_s = exe.to_string_lossy().replace('\'', "''");
    let dir_s = exe
        .parent()
        .map(|p| p.to_string_lossy().replace('\'', "''"))
        .unwrap_or_default();
    // Создаём .lnk через WScript.Shell (надёжнее COM-боилерплейта из Rust).
    let ps = format!(
        "$d=[Environment]::GetFolderPath('Desktop'); \
         $w=New-Object -ComObject WScript.Shell; \
         $s=$w.CreateShortcut([IO.Path]::Combine($d,'JammVPN.lnk')); \
         $s.TargetPath='{exe_s}'; $s.WorkingDirectory='{dir_s}'; \
         $s.IconLocation='{exe_s},0'; $s.Description='JammVPN'; $s.Save()"
    );
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            &ps,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "ярлык не создан: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Ярлык на рабочий стол — только Windows.
#[cfg(not(windows))]
pub fn create_desktop_shortcut() -> Result<(), String> {
    Err("ярлык поддерживается только на Windows".into())
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
    tunnel: Option<SplitTunnelBackend>,
    out_task: tokio::task::JoinHandle<()>,
}

/// Активный split-перехват одного из драйверов (выбор — `cfg.split.driver`).
#[cfg(windows)]
enum SplitTunnelBackend {
    Winpk(jammvpn_platform_windows::winpkfilter::SplitTunnel),
    Divert(jammvpn_platform_windows::windivert::SplitTunnel),
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
        let driver = cfg.split.driver;
        log_line(&format!(
            "split start: apps={:?} mode={:?} driver={:?} upstream={:?} elevated={}",
            split_cfg.apps,
            split_cfg.mode,
            driver,
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

        // Выбор драйвера захвата. Оба бэкенда имеют одинаковый API
        // (start/injector/stop), поэтому ветвим целиком.
        let (backend, out_task) = match driver {
            jammvpn_core::SplitDriver::WinDivert => {
                let tunnel = jammvpn_platform_windows::windivert::SplitTunnel::start(
                    split_cfg,
                    Box::new(move |ip: &[u8]| ns.inject(ip)),
                    logger,
                )?;
                let injector = tunnel.injector();
                let out_task = tokio::spawn(async move {
                    while let Some(ip) = out.recv().await {
                        injector.inject(ip);
                    }
                });
                (SplitTunnelBackend::Divert(tunnel), out_task)
            }
            jammvpn_core::SplitDriver::WinpkFilter => {
                let tunnel = jammvpn_platform_windows::winpkfilter::SplitTunnel::start(
                    split_cfg,
                    Box::new(move |ip: &[u8]| ns.inject(ip)),
                    logger,
                )?;
                let injector = tunnel.injector();
                let out_task = tokio::spawn(async move {
                    while let Some(ip) = out.recv().await {
                        injector.inject(ip);
                    }
                });
                (SplitTunnelBackend::Winpk(tunnel), out_task)
            }
        };
        Ok(Self {
            _netstack: netstack,
            tunnel: Some(backend),
            out_task,
        })
    }

    /// `false`, если split-драйвер сейчас в сбое/восстановлении (для уведомления
    /// в UI). WinpkFilter самовосстановления не имеет — всегда `true`.
    pub fn is_healthy(&self) -> bool {
        match &self.tunnel {
            Some(SplitTunnelBackend::Divert(t)) => t.is_healthy(),
            _ => true,
        }
    }

    /// Останавливает перехват и стек.
    pub fn stop(mut self) {
        if let Some(t) = self.tunnel.take() {
            match t {
                SplitTunnelBackend::Winpk(x) => x.stop(),
                SplitTunnelBackend::Divert(x) => x.stop(),
            }
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
    pub fn is_healthy(&self) -> bool {
        true
    }
    pub fn stop(self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_engine_keeps_all_nodes_with_selected_main() {
        // Регресс: при выбранном узле движок должен содержать ВСЕ узлы как
        // outbound'ы (чтобы правило Proxy(Some("node-b")) сработало), а узел —
        // лишь default. Раньше строился single_proxy и правила игнорировались.
        use jammvpn_core::parse_link;
        let mut cfg = AppConfig::default();
        let mut a = parse_link("trojan://pa@1.1.1.1:443?sni=a#node-a").unwrap();
        a.name = "node-a".into();
        let mut b = parse_link("trojan://pb@2.2.2.2:443?sni=b#node-b").unwrap();
        b.name = "node-b".into();
        cfg.servers = vec![a, b];
        let engine = build_engine(&cfg, Some("node-a")).unwrap();
        assert!(engine.outbounds().contains_key("node-a"));
        assert!(
            engine.outbounds().contains_key("node-b"),
            "правило должно мочь указать любой узел, не только выбранный"
        );
    }

    #[test]
    fn distinct_sub_tags_separate_same_host() {
        let mut cfg = AppConfig::default();
        cfg.subscriptions = vec![
            Subscription {
                url: "https://1.2.3.4:8443/subA".into(),
                tag: None,
                update_interval_hours: 12,
            },
            Subscription {
                url: "https://1.2.3.4:8443/subB".into(),
                tag: None,
                update_interval_hours: 12,
            },
        ];
        ensure_distinct_sub_tags(&mut cfg);
        let t0 = cfg.subscriptions[0].tag.clone().unwrap();
        let t1 = cfg.subscriptions[1].tag.clone().unwrap();
        assert_ne!(t0, t1, "подписки с одного хоста должны разделяться");
        assert_eq!(t0, "1.2.3.4:8443");
        assert_eq!(t1, "1.2.3.4:8443 (2)");
    }

    #[test]
    fn version_compare() {
        assert!(version_gt("0.1.7", "0.1.6"));
        assert!(!version_gt("0.1.6", "0.1.7")); // релиз старее текущего → не «новее»
        assert!(!version_gt("0.1.7", "0.1.7")); // равны
        assert!(version_gt("0.2.0", "0.1.9"));
        assert!(version_gt("1.0.0", "0.9.9"));
        assert!(!version_gt("0.1.7-pre", "0.1.7")); // pre = тот же набор чисел
    }

    #[test]
    fn build_engine_selected_node_routes_unmatched_via_node() {
        // Регресс (утечка IP): при выбранном узле непокрытый правилами трафик
        // ДОЛЖЕН идти через узел, а не Direct — даже если default_to_proxy=false.
        use jammvpn_core::parse_link;
        use jammvpn_net::{Decision, Outbound, Target};
        let mut cfg = AppConfig::default();
        cfg.settings.default_to_proxy = false;
        let mut a = parse_link("trojan://pa@1.1.1.1:443?sni=a#node-a").unwrap();
        a.name = "node-a".into();
        cfg.servers = vec![a];
        let engine = build_engine(&cfg, Some("node-a")).unwrap();
        let d = engine.resolve_target(&Target::Domain("example.com".into(), 443));
        match d {
            Decision::Connect(Outbound::Direct) => {
                panic!("утечка: непокрытый трафик идёт Direct при выбранном узле")
            }
            Decision::Connect(_) => {} // через узел — ок
            Decision::Block => panic!("неожиданный Block"),
        }
    }

    #[test]
    fn hysteria2_link_roundtrips() {
        use jammvpn_core::parse_link;
        let p = parse_link("hysteria2://Secret123@1.2.3.4:8443?insecure=1&sni=ex.com#MyНода").unwrap();
        let link = node_to_hysteria2_link(&p).expect("должна быть hy2-ссылка");
        let p2 = parse_link(&link).unwrap();
        assert_eq!(p2.protocol, jammvpn_core::ProtocolKind::Hysteria2);
        assert_eq!(p2.address, "1.2.3.4");
        assert_eq!(p2.port, 8443);
        assert_eq!(p2.param("auth"), Some("Secret123"));
        assert_eq!(p2.param("sni"), Some("ex.com"));
        assert_eq!(p2.param("insecure"), Some("1"));
        assert_eq!(p2.name, "MyНода");
        // Не-Hysteria2 узел → None.
        let v = parse_link("vless://uuid@h:443#x").unwrap();
        assert!(node_to_hysteria2_link(&v).is_none());
    }
    use jammvpn_core::NoopStore;
    use jammvpn_core::SplitMode;

    #[test]
    fn config_path_ends_correctly() {
        let p = config_path();
        assert!(p.ends_with("jammvpn/config.json") || p.ends_with("jammvpn\\config.json"));
    }

    #[test]
    fn wg_conf_export_roundtrips() {
        // Узел AmneziaWG → .conf → парсер: ключевые поля сохраняются.
        // Синтетические значения (TEST-NET-1 192.0.2.0/24, фейковые ключи).
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
        let _ = std::fs::remove_file(store::db_path_for(&path)); // SQLite-хранилище
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
