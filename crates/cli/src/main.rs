//! JammVPN CLI: импорт узлов, тест задержек, обновление подписок, локальный прокси.
//!
//! Связывает `core` (конфиг/парсеры), `net` (движок/прокси/url-test/подписки) и
//! `platform-windows` (DPAPI). Конфиг — `%APPDATA%/jammvpn/config.json`, секреты
//! в нём шифруются (DPAPI на Windows).

use jammvpn_core::{parse_link, AppConfig, SecretStore, Subscription};
use jammvpn_net::{outbound_from_profile, serve_socks_routed, subscription, urltest, Engine};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;

type R = Result<(), Box<dyn Error>>;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");
    let rest = &args[args.len().min(2)..];

    let result: R = match cmd {
        "import" => cmd_import(rest).await,
        "list" => cmd_list(),
        "test" => cmd_test(rest).await,
        "update" => cmd_update().await,
        "run" => cmd_run(rest).await,
        "config-path" => {
            println!("{}", config_path().display());
            Ok(())
        }
        "help" | "-h" | "--help" => {
            usage();
            Ok(())
        }
        other => {
            eprintln!("неизвестная команда: {other}\n");
            usage();
            std::process::exit(2);
        }
    };

    if let Err(e) = result {
        eprintln!("ошибка: {e}");
        std::process::exit(1);
    }
}

fn usage() {
    eprintln!(
        "jammvpn — управление узлами и локальный прокси\n\n\
Команды:\n  \
import <ссылка|URL-подписки>   импортировать узел или подписку\n  \
list                           список узлов\n  \
test [url]                     тест задержек всех узлов (по умолчанию generate_204)\n  \
update                         обновить подписки\n  \
run [узел] [--listen addr]     локальный SOCKS5 (через узел или по правилам конфига)\n  \
config-path                    путь к конфигу"
    );
}

/// Путь к конфигу: `%APPDATA%/jammvpn/config.json` (или `$HOME/.config/...`).
fn config_path() -> PathBuf {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("jammvpn").join("config.json")
}

#[cfg(windows)]
fn secret_store() -> Box<dyn SecretStore> {
    Box::new(jammvpn_platform_windows::DpapiStore)
}
#[cfg(not(windows))]
fn secret_store() -> Box<dyn SecretStore> {
    Box::new(jammvpn_core::NoopStore)
}

fn load_config(path: &Path, store: &dyn SecretStore) -> AppConfig {
    if path.exists() {
        AppConfig::load_protected(path, store).unwrap_or_else(|e| {
            eprintln!("предупреждение: не удалось загрузить конфиг ({e}); беру пустой");
            AppConfig::default()
        })
    } else {
        AppConfig::default()
    }
}

fn save_config(path: &Path, cfg: &AppConfig, store: &dyn SecretStore) -> R {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    cfg.save_protected(path, store)?;
    Ok(())
}

async fn cmd_import(args: &[String]) -> R {
    let arg = args
        .first()
        .ok_or("import: укажите ссылку или URL подписки")?;
    let path = config_path();
    let store = secret_store();
    let mut cfg = load_config(&path, store.as_ref());

    if arg.starts_with("http://") || arg.starts_with("https://") {
        let sub = Subscription {
            url: arg.clone(),
            tag: Some("subscription".to_string()),
            update_interval_hours: 12,
        };
        let servers =
            subscription::update_subscription(&sub, subscription::DEFAULT_TIMEOUT).await?;
        let n = servers.len();
        subscription::merge_subscription(&mut cfg, &sub, servers);
        if !cfg.subscriptions.iter().any(|s| s.url == sub.url) {
            cfg.subscriptions.push(sub);
        }
        println!("импортировано узлов из подписки: {n}");
    } else {
        let profile = parse_link(arg)?;
        println!("импортирован узел: {} [{}]", profile.name, profile.protocol);
        cfg.servers.push(profile);
    }
    save_config(&path, &cfg, store.as_ref())?;
    Ok(())
}

fn cmd_list() -> R {
    let store = secret_store();
    let cfg = load_config(&config_path(), store.as_ref());
    if cfg.servers.is_empty() {
        println!("узлов нет (импортируйте: jammvpn import <ссылка>)");
        return Ok(());
    }
    for (i, s) in cfg.servers.iter().enumerate() {
        println!(
            "{:>2}. {}  [{}]  {}:{}",
            i + 1,
            s.name,
            s.protocol,
            s.address,
            s.port
        );
    }
    Ok(())
}

async fn cmd_test(args: &[String]) -> R {
    let url = args
        .first()
        .map(String::as_str)
        .unwrap_or(urltest::DEFAULT_TEST_URL);
    let store = secret_store();
    let cfg = load_config(&config_path(), store.as_ref());
    let engine = Engine::from_config(&cfg);

    let mut results =
        urltest::test_outbounds(engine.outbounds(), url, urltest::DEFAULT_TIMEOUT).await;
    // успешные — по возрастанию задержки, ошибки — в конце.
    results.sort_by(|a, b| match (&a.1, &b.1) {
        (Ok(x), Ok(y)) => x.cmp(y),
        (Ok(_), Err(_)) => std::cmp::Ordering::Less,
        (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
        (Err(_), Err(_)) => std::cmp::Ordering::Equal,
    });
    if results.is_empty() {
        println!("узлов нет");
    }
    for (name, res) in &results {
        match res {
            Ok(d) => println!("{:>6} ms  {name}", d.as_millis()),
            Err(e) => println!("   ошибка  {name}  ({e})"),
        }
    }
    Ok(())
}

async fn cmd_update() -> R {
    let path = config_path();
    let store = secret_store();
    let mut cfg = load_config(&path, store.as_ref());
    let subs = cfg.subscriptions.clone();
    if subs.is_empty() {
        println!("подписок нет");
        return Ok(());
    }
    for sub in &subs {
        match subscription::update_subscription(sub, subscription::DEFAULT_TIMEOUT).await {
            Ok(servers) => {
                let n = servers.len();
                subscription::merge_subscription(&mut cfg, sub, servers);
                println!("{}: {n} узлов", sub.url);
            }
            Err(e) => eprintln!("{}: ошибка {e}", sub.url),
        }
    }
    save_config(&path, &cfg, store.as_ref())?;
    Ok(())
}

async fn cmd_run(args: &[String]) -> R {
    let mut server: Option<&str> = None;
    let mut listen = "127.0.0.1:1080".to_string();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--listen" {
            listen = it.next().ok_or("--listen: укажите адрес")?.clone();
        } else if !a.starts_with("--") {
            server = Some(a);
        }
    }

    let store = secret_store();
    let cfg = load_config(&config_path(), store.as_ref());

    let engine = if let Some(name) = server {
        let profile = cfg
            .servers
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| format!("узел не найден: {name}"))?;
        let outbound = outbound_from_profile(profile)?;
        println!("[+] весь трафик через узел: {name}");
        Engine::single_proxy(outbound)
    } else {
        println!("[+] маршрутизация по правилам конфига");
        let engine = Engine::from_config(&cfg);
        // Fail-closed: правила ссылаются на geo-базы, которые не загрузились →
        // geo-критерий никогда не совпал бы и Block молча выродился бы в пропуск.
        // Не запускаем такой набор правил.
        let missing = engine.missing_geo_refs();
        if !missing.is_empty() {
            return Err(format!(
                "geo-базы не загружены для части правил:\n  {}\n\
                 проверьте geo.geosite_path / geo.geoip_path в конфиге ({})",
                missing.join("\n  "),
                config_path().display()
            )
            .into());
        }
        engine
    };

    let listener = TcpListener::bind(&listen).await?;
    println!("[+] SOCKS5 на {listen}");
    println!("    проверка: curl --socks5-hostname {listen} https://icanhazip.com");
    println!("    (Ctrl+C для остановки)");

    let engine = Arc::new(engine);
    tokio::select! {
        r = serve_socks_routed(listener, engine) => { r?; }
        _ = tokio::signal::ctrl_c() => { println!("\nостановка"); }
    }
    Ok(())
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
        let path = dir.join(format!("jammvpn-cli-test-{}.json", std::process::id()));
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
}
