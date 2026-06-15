//! JammVPN — десктопный GUI на Tauri. Тонкая оболочка: команды Tauri вызывают
//! контроллер [`jammvpn_cli`] (та же логика, что у CLI), фронтенд — `../ui`.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use jammvpn_cli as ctl;
use std::sync::Mutex;
use tauri::State;

/// Состояние приложения: запущенный локальный прокси (или его отсутствие).
#[derive(Default)]
struct ProxyState(Mutex<Option<ctl::ProxyController>>);

#[tauri::command]
fn list_nodes() -> Vec<ctl::NodeInfo> {
    ctl::list_nodes()
}

#[tauri::command]
fn config_path() -> String {
    ctl::config_path().display().to_string()
}

#[tauri::command]
async fn import(arg: String) -> Result<String, String> {
    ctl::import(&arg).await
}

#[tauri::command]
async fn test_latencies() -> Vec<ctl::LatencyResult> {
    ctl::test_latencies(None).await
}

#[tauri::command]
async fn update_subscriptions() -> Result<Vec<ctl::SubUpdate>, String> {
    ctl::update_subscriptions().await
}

#[tauri::command]
async fn proxy_start(
    state: State<'_, ProxyState>,
    listen: String,
    server: Option<String>,
) -> Result<String, String> {
    // Уже запущен? (гард временный — не держим через await).
    if state.0.lock().unwrap().is_some() {
        return Err("прокси уже запущен".into());
    }
    let proxy = ctl::ProxyController::start(&listen, server).await?;
    let addr = proxy.addr().to_string();
    *state.0.lock().unwrap() = Some(proxy);
    Ok(addr)
}

#[tauri::command]
fn proxy_stop(state: State<'_, ProxyState>) {
    if let Some(proxy) = state.0.lock().unwrap().take() {
        proxy.stop();
    }
}

/// Адрес работающего прокси (`None` — не запущен).
#[tauri::command]
fn proxy_status(state: State<'_, ProxyState>) -> Option<String> {
    state
        .0
        .lock()
        .unwrap()
        .as_ref()
        .map(|p| p.addr().to_string())
}

fn main() {
    tauri::Builder::default()
        .manage(ProxyState::default())
        .invoke_handler(tauri::generate_handler![
            list_nodes,
            config_path,
            import,
            test_latencies,
            update_subscriptions,
            proxy_start,
            proxy_stop,
            proxy_status,
        ])
        .run(tauri::generate_context!())
        .expect("ошибка запуска приложения Tauri");
}
