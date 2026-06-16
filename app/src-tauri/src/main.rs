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

/// Активный split: работающий локальный редирект-прокси (или его отсутствие).
/// `Some` ⇔ split применён (конфиг в драйвере + прокси поднят).
#[derive(Default)]
struct SplitState(Mutex<Option<ctl::WinpkSplitController>>);

/// Включён ли системный прокси Windows нами (для авто-снятия при остановке).
#[derive(Default)]
struct SysProxyState(Mutex<bool>);

/// Запущенный локальный WG-сервер (inbound-шлюз).
#[derive(Default)]
struct LocalWgState(Mutex<Option<ctl::LocalWgController>>);

#[tauri::command]
fn list_nodes() -> Vec<ctl::NodeInfo> {
    ctl::list_nodes()
}

/// Активные проксируемые соединения (для монитора статистики).
#[tauri::command]
fn list_connections() -> Vec<ctl::ConnectionInfo> {
    ctl::list_connections()
}

/// Принудительно закрыть соединение по id (кнопка «дропнуть» в статистике).
#[tauri::command]
fn drop_connection(id: u64) -> bool {
    ctl::drop_connection(id)
}

#[tauri::command]
fn config_path() -> String {
    ctl::config_path().display().to_string()
}

#[tauri::command]
async fn import(arg: String) -> Result<String, String> {
    ctl::import(&arg).await
}

/// Импорт из вставленного текста конфига (ссылки / Xray|sing-box JSON / AWG).
#[tauri::command]
fn import_config(text: String) -> Result<String, String> {
    ctl::import_config(&text)
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
fn proxy_stop(state: State<'_, ProxyState>, sysproxy: State<'_, SysProxyState>) {
    if let Some(proxy) = state.0.lock().unwrap().take() {
        proxy.stop();
    }
    // Если мы включали системный прокси — снимаем, чтобы он не указывал на
    // остановленный локальный прокси.
    let mut on = sysproxy.0.lock().unwrap();
    if *on {
        let _ = ctl::clear_system_proxy();
        *on = false;
    }
}

/// Включить системный прокси Windows на работающий локальный прокси.
#[tauri::command]
fn set_system_proxy(
    proxy: State<'_, ProxyState>,
    sysproxy: State<'_, SysProxyState>,
) -> Result<(), String> {
    let port = proxy
        .0
        .lock()
        .unwrap()
        .as_ref()
        .map(|p| p.addr().port())
        .ok_or("сначала запустите локальный прокси")?;
    ctl::set_system_proxy(&format!("127.0.0.1:{port}"))?;
    *sysproxy.0.lock().unwrap() = true;
    Ok(())
}

/// Выключить системный прокси Windows.
#[tauri::command]
fn clear_system_proxy(sysproxy: State<'_, SysProxyState>) -> Result<(), String> {
    ctl::clear_system_proxy()?;
    *sysproxy.0.lock().unwrap() = false;
    Ok(())
}

/// Текущее состояние системного прокси Windows.
#[tauri::command]
fn system_proxy_status() -> Result<ctl::SysProxyStatus, String> {
    ctl::system_proxy_status()
}

/// Авто-тест: через запущенный прокси тянет внешний IP (проверка, что трафик
/// реально идёт через узел).
#[tauri::command]
async fn proxy_self_test(state: State<'_, ProxyState>) -> Result<String, String> {
    let addr: Option<String> = state
        .0
        .lock()
        .unwrap()
        .as_ref()
        .map(|p| p.addr().to_string());
    let addr = addr.ok_or("прокси не запущен")?;
    ctl::proxy_self_test(&addr).await
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

/// Сохранить настройки подключения (адрес прокси и выбранный узел).
#[tauri::command]
fn set_connection(listen: Option<String>, proxy_node: Option<String>) -> Result<(), String> {
    ctl::set_connection(listen, proxy_node)
}

/// Экспортировать WG/AmneziaWG-узел в `.conf` на диск; возвращает путь к файлу.
#[tauri::command]
fn export_node_conf(name: String) -> Result<String, String> {
    ctl::export_node_conf(&name)
}

/// Состояние локального WG-сервера (inbound-шлюз).
#[tauri::command]
fn local_wg_status(state: State<'_, LocalWgState>) -> ctl::LocalWgInfo {
    let addr = state
        .0
        .lock()
        .unwrap()
        .as_ref()
        .map(|c| c.addr().to_string());
    ctl::local_wg_status(addr)
}

/// Запустить локальный WG-сервер; egress через `upstream_node` (или по правилам).
#[tauri::command]
async fn local_wg_start(
    state: State<'_, LocalWgState>,
    upstream_node: Option<String>,
) -> Result<String, String> {
    if state.0.lock().unwrap().is_some() {
        return Err("локальный WG уже запущен".into());
    }
    let controller = ctl::LocalWgController::start(upstream_node).await?;
    let addr = controller.addr().to_string();
    *state.0.lock().unwrap() = Some(controller);
    Ok(addr)
}

/// Остановить локальный WG-сервер.
#[tauri::command]
fn local_wg_stop(state: State<'_, LocalWgState>) {
    if let Some(c) = state.0.lock().unwrap().take() {
        c.stop();
    }
}

/// Сохранить порт/узел-апстрим локального WG (до запуска).
#[tauri::command]
fn local_wg_set(port: Option<u16>, upstream_node: Option<String>) -> Result<(), String> {
    ctl::local_wg_set(port, upstream_node)
}

/// Сгенерировать и сохранить клиентский `.conf` локального WG; вернуть путь.
#[tauri::command]
fn local_wg_export_conf() -> Result<String, String> {
    ctl::local_wg_export_conf()
}

/// QR-код клиентского `.conf` локального WG (SVG-строка) для скана телефоном.
#[tauri::command]
fn local_wg_qr() -> Result<String, String> {
    ctl::local_wg_qr()
}

/// Последние строки лога (вкладка «Логи»).
#[tauri::command]
fn read_log() -> String {
    ctl::read_log(2000)
}

/// Очистить лог.
#[tauri::command]
fn clear_log() {
    ctl::clear_log()
}

/// Запущен ли процесс от администратора (для подсказки про split).
#[tauri::command]
fn is_admin() -> bool {
    ctl::is_admin()
}

/// Перезапустить приложение от администратора (UAC) и закрыть текущее.
#[tauri::command]
fn relaunch_as_admin() -> Result<(), String> {
    ctl::relaunch_as_admin()?;
    // Даём новому (elevated) процессу стартовать и выходим.
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_millis(400));
        std::process::exit(0);
    });
    Ok(())
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

/// Список готовых пресетов правил.
#[tauri::command]
fn list_presets() -> Vec<ctl::PresetInfo> {
    ctl::list_presets()
}

/// Применить пресет (заменяет текущие правила). Возвращает число правил.
#[tauri::command]
fn apply_preset(id: String) -> Result<usize, String> {
    ctl::apply_preset(&id)
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

/// Драйвер-настройки split + предпросмотр перехватываемых приложений.
#[tauri::command]
fn get_split() -> ctl::SplitOptions {
    ctl::get_split_options()
}

/// Сохранить драйвер-настройки split (kill-switch).
#[tauri::command]
fn set_split(kill_switch: bool) -> Result<(), String> {
    ctl::set_split_options(kill_switch)
}

/// Применить split: поднять NDIS-перехват приложений (Windows Packet Filter) +
/// userspace netstack. Требует установленного драйвера `ndisrd` и админ-прав.
#[tauri::command]
async fn split_apply(state: State<'_, SplitState>) -> Result<(), String> {
    if state.0.lock().unwrap().is_some() {
        return Err("split уже применён".into());
    }
    let controller = ctl::WinpkSplitController::start().await?;
    *state.0.lock().unwrap() = Some(controller);
    Ok(())
}

/// Снять split: остановить перехват и стек.
#[tauri::command]
fn split_clear(state: State<'_, SplitState>) -> Result<(), String> {
    if let Some(controller) = state.0.lock().unwrap().take() {
        controller.stop();
    }
    Ok(())
}

/// Активно ли сейчас раздельное туннелирование.
#[tauri::command]
fn split_status(state: State<'_, SplitState>) -> bool {
    state.0.lock().unwrap().is_some()
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
        .manage(SysProxyState::default())
        .manage(LocalWgState::default())
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
            list_connections,
            drop_connection,
            config_path,
            import,
            import_config,
            test_latencies,
            update_subscriptions,
            proxy_start,
            proxy_stop,
            proxy_status,
            proxy_self_test,
            remove_node,
            get_settings,
            set_settings,
            set_connection,
            export_node_conf,
            local_wg_status,
            local_wg_start,
            local_wg_stop,
            local_wg_set,
            local_wg_export_conf,
            local_wg_qr,
            is_admin,
            relaunch_as_admin,
            read_log,
            clear_log,
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
            list_presets,
            apply_preset,
            set_system_proxy,
            clear_system_proxy,
            system_proxy_status,
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
