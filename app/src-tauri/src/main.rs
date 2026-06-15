//! JammVPN — десктопный GUI на Tauri. Тонкая оболочка: команды Tauri вызывают
//! контроллер [`jammvpn_cli`] (та же логика, что у CLI), фронтенд — `../ui`.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use jammvpn_cli as ctl;
use std::sync::Mutex;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Manager, State, WindowEvent};

/// Состояние приложения: запущенный локальный прокси (или его отсутствие).
#[derive(Default)]
struct ProxyState(Mutex<Option<ctl::ProxyController>>);

/// Активно ли сейчас раздельное туннелирование (правила применены к драйверу).
#[derive(Default)]
struct SplitState(Mutex<bool>);

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

/// Удалить узел по имени. `true` — удалён, `false` — не найден.
#[tauri::command]
fn remove_node(name: String) -> Result<bool, String> {
    ctl::remove_node(&name)
}

/// Текущие настройки маршрутизации (для панели «Настройки»).
#[tauri::command]
fn get_settings() -> ctl::SettingsInfo {
    ctl::get_settings()
}

/// Сохранить настройки маршрутизации.
#[tauri::command]
fn set_settings(default_to_proxy: bool, default_proxy: Option<String>) -> Result<(), String> {
    ctl::set_settings(default_to_proxy, default_proxy)
}

/// Список сохранённых подписок.
#[tauri::command]
fn list_subscriptions() -> Vec<ctl::SubscriptionInfo> {
    ctl::list_subscriptions()
}

/// Добавить подписку (без скачивания). `false` — уже есть.
#[tauri::command]
fn add_subscription(
    url: String,
    tag: Option<String>,
    interval_hours: u32,
) -> Result<bool, String> {
    ctl::add_subscription(&url, tag, interval_hours)
}

/// Удалить подписку по URL. `false` — не было.
#[tauri::command]
fn remove_subscription(url: String) -> Result<bool, String> {
    ctl::remove_subscription(&url)
}

/// Статус geo-баз (пути + наличие файлов).
#[tauri::command]
fn geo_status() -> ctl::GeoStatus {
    ctl::geo_status()
}

/// Сохранить пути к geo-базам (пустые → сброс).
#[tauri::command]
fn set_geo_paths(geosite: Option<String>, geoip: Option<String>) -> Result<(), String> {
    ctl::set_geo_paths(geosite, geoip)
}

/// Список правил маршрутизации (в порядке применения).
#[tauri::command]
fn list_rules() -> Vec<ctl::RuleInfo> {
    ctl::list_rules()
}

/// Добавить правило в конец списка.
#[tauri::command]
fn add_rule(rule: ctl::RuleInfo) -> Result<(), String> {
    ctl::add_rule(rule)
}

/// Заменить правило по индексу.
#[tauri::command]
fn update_rule(index: usize, rule: ctl::RuleInfo) -> Result<(), String> {
    ctl::update_rule(index, rule)
}

/// Удалить правило по индексу. `false` — индекс вне диапазона.
#[tauri::command]
fn remove_rule(index: usize) -> Result<bool, String> {
    ctl::remove_rule(index)
}

/// Переместить правило вверх (`up=true`) или вниз. `false` — двигать некуда.
#[tauri::command]
fn move_rule(index: usize, up: bool) -> Result<bool, String> {
    ctl::move_rule(index, up)
}

/// Включён ли автозапуск приложения при входе в систему.
#[tauri::command]
fn autostart_status() -> Result<bool, String> {
    ctl::autostart_status()
}

/// Включить/выключить автозапуск при входе в систему.
#[tauri::command]
fn set_autostart(enabled: bool) -> Result<(), String> {
    ctl::set_autostart(enabled)
}

/// Текущая конфигурация раздельного туннелирования.
#[tauri::command]
fn get_split() -> ctl::SplitInfo {
    ctl::get_split()
}

/// Сохранить конфигурацию split.
#[tauri::command]
fn set_split(split: ctl::SplitInfo) -> Result<(), String> {
    ctl::set_split(split)
}

/// Применить split к драйверу (требует загруженного WFP-драйвера и админ-прав).
#[tauri::command]
fn split_apply(state: State<'_, SplitState>) -> Result<(), String> {
    ctl::apply_split(ctl::SPLIT_REDIRECT_PORT)?;
    *state.0.lock().unwrap() = true;
    Ok(())
}

/// Снять split-правила в драйвере.
#[tauri::command]
fn split_clear(state: State<'_, SplitState>) -> Result<(), String> {
    ctl::clear_split()?;
    *state.0.lock().unwrap() = false;
    Ok(())
}

/// Активно ли сейчас раздельное туннелирование.
#[tauri::command]
fn split_status(state: State<'_, SplitState>) -> bool {
    *state.0.lock().unwrap()
}

/// Показать главное окно и вывести его на передний план.
fn show_main(app: &tauri::AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
    }
}

/// Собрать иконку в системном трее: меню «Показать / Выход», клик по иконке —
/// показать окно. Закрытие окна прячет его в трей (`prevent_close`).
fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "Показать", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &quit])?;

    TrayIconBuilder::new()
        .icon(app.default_window_icon().unwrap().clone())
        .tooltip("JammVPN")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => show_main(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .manage(ProxyState::default())
        .manage(SplitState::default())
        .setup(|app| {
            setup_tray(app)?;
            // Автозапуск (флаг --minimized) — стартуем сразу в трей, без окна.
            if std::env::args().any(|a| a == "--minimized") {
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.hide();
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Крестик окна прячет в трей вместо завершения процесса.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            list_nodes,
            config_path,
            import,
            test_latencies,
            update_subscriptions,
            proxy_start,
            proxy_stop,
            proxy_status,
            remove_node,
            get_settings,
            set_settings,
            list_subscriptions,
            add_subscription,
            remove_subscription,
            geo_status,
            set_geo_paths,
            list_rules,
            add_rule,
            update_rule,
            remove_rule,
            move_rule,
            autostart_status,
            set_autostart,
            get_split,
            set_split,
            split_apply,
            split_clear,
            split_status,
        ])
        .run(tauri::generate_context!())
        .expect("ошибка запуска приложения Tauri");
}
