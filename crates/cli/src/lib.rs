//! Контроллер JammVPN: переиспользуемая логика управления узлами и локальным
//! прокси. Общая для CLI (`bin jammvpn`) и Tauri-UI.
//!
//! Связывает `core` (конфиг/парсеры), `net` (движок/прокси/url-test/подписки) и
//! `platform-windows` (DPAPI). Конфиг — `%APPDATA%/jammvpn/config.json`, секреты
//! в нём шифруются (DPAPI на Windows). Операции возвращают ДАННЫЕ (не печатают),
//! ошибки — человекочитаемой строкой; UI/CLI форматируют сами.

use jammvpn_core::{parse_link, AppConfig, SecretStore, Subscription};
use jammvpn_net::{outbound_from_profile, serve_socks_routed, subscription, urltest, Engine};
use serde::Serialize;
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
