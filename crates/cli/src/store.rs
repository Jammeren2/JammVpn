//! SQLite-хранилище конфига (ТЗ, раздел 7).
//!
//! Заменяет цельный JSON-файл реляционным хранилищем: каждый сервер/подписка/
//! правило — отдельная строка (порядок хранится через `ord`), синглтоны
//! (settings/split/dns/geo/local_wg) — в key-value таблице `kv`. Все записи в
//! одной транзакции → атомарно, без «рваных» записей при сбое посреди сохранения.
//!
//! Секреты шифруются тем же `SecretStore` (DPAPI на Windows), что и раньше для
//! JSON: перед записью конфиг клонируется и `protect_config` метит секреты
//! префиксом `enc:` внутри хранимого JSON; при загрузке `unprotect_config`
//! расшифровывает. БД на диске не содержит плейнтекст-секретов.

use jammvpn_core::config::{
    AppConfig, DnsConfig, GeoConfig, LocalWgConfig, Settings, SocksProxy, Subscription,
};
use jammvpn_core::model::ServerProfile;
use jammvpn_core::routing::Rule;
use jammvpn_core::secret::{protect_config, unprotect_config, SecretStore};
use jammvpn_core::split::SplitConfig;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};

/// Путь к БД рядом с конфигом: `config.json` → `config.db`.
pub fn db_path_for(config_path: &Path) -> PathBuf {
    config_path.with_extension("db")
}

/// Открывает БД и создаёт схему (идемпотентно).
fn open(path: &Path) -> Result<Connection, String> {
    let conn = Connection::open(path).map_err(|e| e.to_string())?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS servers (ord INTEGER PRIMARY KEY, name TEXT NOT NULL, json TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS subscriptions (ord INTEGER PRIMARY KEY, url TEXT NOT NULL, json TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS rules (ord INTEGER PRIMARY KEY, json TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, json TEXT NOT NULL);",
    )
    .map_err(|e| e.to_string())?;
    Ok(conn)
}

/// Читает упорядоченный список (десериализуя JSON каждой строки).
fn load_vec<T: serde::de::DeserializeOwned>(conn: &Connection, sql: &str) -> Result<Vec<T>, String> {
    let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows {
        let s = r.map_err(|e| e.to_string())?;
        out.push(serde_json::from_str(&s).map_err(|e| e.to_string())?);
    }
    Ok(out)
}

/// Читает синглтон из `kv` (отсутствует → значение по умолчанию).
fn kv_get<T: serde::de::DeserializeOwned + Default>(
    conn: &Connection,
    key: &str,
) -> Result<T, String> {
    let s: Option<String> = conn
        .query_row("SELECT json FROM kv WHERE key=?1", params![key], |r| {
            r.get(0)
        })
        .optional()
        .map_err(|e| e.to_string())?;
    match s {
        Some(s) => serde_json::from_str(&s).map_err(|e| e.to_string()),
        None => Ok(T::default()),
    }
}

/// Пишет синглтон в `kv`.
fn kv_set<T: serde::Serialize>(conn: &Connection, key: &str, v: &T) -> Result<(), String> {
    let json = serde_json::to_string(v).map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT OR REPLACE INTO kv (key, json) VALUES (?1, ?2)",
        params![key, json],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Загружает конфиг из БД и расшифровывает секреты.
pub fn load(path: &Path, store: &dyn SecretStore) -> Result<AppConfig, String> {
    let conn = open(path)?;
    let mut cfg = AppConfig {
        servers: load_vec::<ServerProfile>(&conn, "SELECT json FROM servers ORDER BY ord")?,
        subscriptions: load_vec::<Subscription>(
            &conn,
            "SELECT json FROM subscriptions ORDER BY ord",
        )?,
        rules: load_vec::<Rule>(&conn, "SELECT json FROM rules ORDER BY ord")?,
        split: kv_get::<SplitConfig>(&conn, "split")?,
        settings: kv_get::<Settings>(&conn, "settings")?,
        dns: kv_get::<DnsConfig>(&conn, "dns")?,
        geo: kv_get::<GeoConfig>(&conn, "geo")?,
        local_wg: kv_get::<Option<LocalWgConfig>>(&conn, "local_wg")?,
        socks_proxies: kv_get::<Vec<SocksProxy>>(&conn, "socks_proxies")?,
    };
    unprotect_config(&mut cfg, store).map_err(|e| e.to_string())?;
    Ok(cfg)
}

/// Сохраняет конфиг в БД (шифруя секреты) одной транзакцией.
pub fn save(path: &Path, cfg: &AppConfig, store: &dyn SecretStore) -> Result<(), String> {
    let mut protected = cfg.clone();
    protect_config(&mut protected, store).map_err(|e| e.to_string())?;

    let mut conn = open(path)?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute("DELETE FROM servers", []).map_err(|e| e.to_string())?;
    tx.execute("DELETE FROM subscriptions", [])
        .map_err(|e| e.to_string())?;
    tx.execute("DELETE FROM rules", []).map_err(|e| e.to_string())?;

    for (i, s) in protected.servers.iter().enumerate() {
        let json = serde_json::to_string(s).map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO servers (ord, name, json) VALUES (?1, ?2, ?3)",
            params![i as i64, s.name.as_str(), json],
        )
        .map_err(|e| e.to_string())?;
    }
    for (i, s) in protected.subscriptions.iter().enumerate() {
        let json = serde_json::to_string(s).map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO subscriptions (ord, url, json) VALUES (?1, ?2, ?3)",
            params![i as i64, s.url.as_str(), json],
        )
        .map_err(|e| e.to_string())?;
    }
    for (i, r) in protected.rules.iter().enumerate() {
        let json = serde_json::to_string(r).map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO rules (ord, json) VALUES (?1, ?2)",
            params![i as i64, json],
        )
        .map_err(|e| e.to_string())?;
    }
    kv_set(&tx, "settings", &protected.settings)?;
    kv_set(&tx, "split", &protected.split)?;
    kv_set(&tx, "dns", &protected.dns)?;
    kv_set(&tx, "geo", &protected.geo)?;
    kv_set(&tx, "local_wg", &protected.local_wg)?;
    kv_set(&tx, "socks_proxies", &protected.socks_proxies)?;

    tx.commit().map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jammvpn_core::routing::{DomainRule, RouteAction};
    use jammvpn_core::NoopStore;

    fn tmp_db() -> PathBuf {
        std::env::temp_dir().join(format!(
            "jammvpn-store-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    #[test]
    fn roundtrip_preserves_order_and_singletons() {
        let path = tmp_db();
        let store = NoopStore;

        let mut cfg = AppConfig::default();
        cfg.servers.push(
            jammvpn_core::parse_link(
                "vless://11111111-2222-3333-4444-555555555555@h:443#first",
            )
            .unwrap(),
        );
        cfg.servers
            .push(jammvpn_core::parse_link("ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#second").unwrap());
        cfg.subscriptions.push(Subscription {
            url: "https://example/sub".to_string(),
            tag: Some("main".to_string()),
            update_interval_hours: 6,
        });
        cfg.rules.push(Rule {
            domains: vec![DomainRule::Suffix("example.com".to_string())],
            action: RouteAction::Proxy(Some("first".to_string())),
            ..Default::default()
        });
        cfg.settings.default_to_proxy = true;
        cfg.settings.proxy_node = Some("second".to_string());

        save(&path, &cfg, &store).unwrap();
        let loaded = load(&path, &store).unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(loaded.servers.len(), 2);
        assert_eq!(loaded.servers[0].name, "first"); // порядок сохранён
        assert_eq!(loaded.servers[1].name, "second");
        assert_eq!(loaded.subscriptions.len(), 1);
        assert_eq!(loaded.subscriptions[0].update_interval_hours, 6);
        assert_eq!(loaded.rules.len(), 1);
        assert!(loaded.settings.default_to_proxy);
        assert_eq!(loaded.settings.proxy_node.as_deref(), Some("second"));
        assert_eq!(loaded, cfg);
    }

    #[test]
    fn overwrite_replaces_rows() {
        // Повторное сохранение не накапливает строки (DELETE + INSERT в транзакции).
        let path = tmp_db();
        let store = NoopStore;

        let mut cfg = AppConfig::default();
        cfg.servers
            .push(jammvpn_core::parse_link("ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#A").unwrap());
        save(&path, &cfg, &store).unwrap();

        cfg.servers.clear();
        cfg.servers
            .push(jammvpn_core::parse_link("ss://YWVzLTI1Ni1nY206cGFzcw==@5.6.7.8:8388#B").unwrap());
        save(&path, &cfg, &store).unwrap();

        let loaded = load(&path, &store).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(loaded.servers.len(), 1);
        assert_eq!(loaded.servers[0].name, "B");
    }
}
