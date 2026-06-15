//! JammVPN CLI: тонкая обёртка над контроллером [`jammvpn_cli`].
//!
//! Команды форматируют вывод; вся логика — в библиотеке (общей с Tauri-UI).

use jammvpn_cli as ctl;

type R = Result<(), String>;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");
    let rest = &args[args.len().min(2)..];

    let result: R = match cmd {
        "import" => cmd_import(rest).await,
        "list" => {
            print_list();
            Ok(())
        }
        "test" => cmd_test(rest).await,
        "update" => cmd_update().await,
        "run" => cmd_run(rest).await,
        "config-path" => {
            println!("{}", ctl::config_path().display());
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

async fn cmd_import(args: &[String]) -> R {
    let arg = args
        .first()
        .ok_or_else(|| "import: укажите ссылку или URL подписки".to_string())?;
    println!("{}", ctl::import(arg).await?);
    Ok(())
}

fn print_list() {
    let nodes = ctl::list_nodes();
    if nodes.is_empty() {
        println!("узлов нет (импортируйте: jammvpn import <ссылка>)");
        return;
    }
    for (i, n) in nodes.iter().enumerate() {
        println!(
            "{:>2}. {}  [{}]  {}:{}",
            i + 1,
            n.name,
            n.protocol,
            n.address,
            n.port
        );
    }
}

async fn cmd_test(args: &[String]) -> R {
    let url = args.first().map(String::as_str);
    let results = ctl::test_latencies(url).await;
    if results.is_empty() {
        println!("узлов нет");
    }
    for r in &results {
        match (&r.latency_ms, &r.error) {
            (Some(ms), _) => println!("{ms:>6} ms  {}", r.name),
            (None, Some(e)) => println!("   ошибка  {}  ({e})", r.name),
            (None, None) => println!("   ошибка  {}", r.name),
        }
    }
    Ok(())
}

async fn cmd_update() -> R {
    let ups = ctl::update_subscriptions().await?;
    if ups.is_empty() {
        println!("подписок нет");
    }
    for u in &ups {
        match (&u.count, &u.error) {
            (Some(n), _) => println!("{}: {n} узлов", u.url),
            (None, Some(e)) => eprintln!("{}: ошибка {e}", u.url),
            (None, None) => {}
        }
    }
    Ok(())
}

async fn cmd_run(args: &[String]) -> R {
    let mut server: Option<String> = None;
    let mut listen = "127.0.0.1:1080".to_string();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--listen" {
            listen = it
                .next()
                .ok_or_else(|| "--listen: укажите адрес".to_string())?
                .clone();
        } else if !a.starts_with("--") {
            server = Some(a.clone());
        }
    }

    let proxy = ctl::ProxyController::start(&listen, server).await?;
    let addr = proxy.addr();
    match proxy.server() {
        Some(s) => println!("[+] весь трафик через узел: {s}"),
        None => println!("[+] маршрутизация по правилам конфига"),
    }
    println!("[+] SOCKS5 на {addr}");
    println!("    проверка: curl --socks5-hostname {addr} https://icanhazip.com");
    println!("    (Ctrl+C для остановки)");

    tokio::signal::ctrl_c().await.map_err(|e| e.to_string())?;
    println!("\nостановка");
    proxy.stop();
    Ok(())
}
