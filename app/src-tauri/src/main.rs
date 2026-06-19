//! JammVPN — десктопный GUI на Tauri. Тонкая оболочка: команды Tauri вызывают
//! контроллер [`jammvpn_cli`] (та же логика, что у CLI), фронтенд — `../ui`.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use jammvpn_cli as ctl;
use std::sync::Mutex;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Emitter, Manager, State, WindowEvent};

/// Полезная нагрузка уведомления в UI (событие `notify` → тост в окне).
#[derive(Clone, serde::Serialize)]
struct NotifyPayload {
    /// `info` | `warn` | `error` — стиль тоста.
    kind: &'static str,
    title: String,
    body: String,
}

/// Состояние приложения: запущенный локальный прокси (или его отсутствие).
#[derive(Default)]
struct ProxyState(Mutex<Option<ctl::MultiSocks>>);

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
    // Хранилище — SQLite рядом с историческим JSON-путём (config.db).
    ctl::config_path().with_extension("db").display().to_string()
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

/// Тест задержки одного узла.
#[tauri::command]
async fn test_node_latency(name: String) -> ctl::LatencyResult {
    ctl::test_node_latency(&name).await
}

/// `vless://`-ссылка узла (для копирования).
#[tauri::command]
fn export_vless_link(name: String) -> Result<String, String> {
    ctl::export_vless_link(&name)
}

/// `ss://`-ссылка узла Shadowsocks (для копирования).
#[tauri::command]
fn export_ss_link(name: String) -> Result<String, String> {
    ctl::export_ss_link(&name)
}

/// `hysteria2://`-ссылка узла (для копирования).
#[tauri::command]
fn export_hysteria2_link(name: String) -> Result<String, String> {
    ctl::export_hysteria2_link(&name)
}

/// Открывает URL в браузере по умолчанию (для кнопки версии → страница проекта).
#[tauri::command]
fn open_url(url: String) -> Result<(), String> {
    // Разрешаем только http/https — не запускаем произвольные команды.
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("недопустимый URL".into());
    }
    std::process::Command::new("rundll32")
        .args(["url.dll,FileProtocolHandler", &url])
        .spawn()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Записать `.conf` узла в выбранный путь (после диалога «Сохранить как»).
#[tauri::command]
fn export_node_conf_to(name: String, path: String) -> Result<(), String> {
    ctl::export_node_conf_to(&name, &path)
}

/// Записать клиентский `.conf` локального WG в выбранный путь.
#[tauri::command]
fn local_wg_export_conf_to(path: String) -> Result<(), String> {
    ctl::local_wg_export_conf_to(&path)
}

#[tauri::command]
async fn update_subscriptions() -> Result<Vec<ctl::SubUpdate>, String> {
    ctl::update_subscriptions().await
}

#[tauri::command]
async fn proxy_start(
    state: State<'_, ProxyState>,
    listen: Option<String>,
    server: Option<String>,
) -> Result<String, String> {
    let _ = (listen, server); // адрес/узел берём из конфига SOCKS-листенеров
    // Уже запущен? (гард временный — не держим через await).
    if state.0.lock().unwrap().is_some() {
        return Err("прокси уже запущен".into());
    }
    let proxy = ctl::MultiSocks::start().await?;
    let addr = proxy.primary_addr().to_string();
    *state.0.lock().unwrap() = Some(proxy);
    Ok(addr)
}

/// Список SOCKS5-листенеров.
#[tauri::command]
fn get_socks_proxies() -> Vec<ctl::SocksProxy> {
    ctl::get_socks_proxies()
}

/// Сохраняет список SOCKS5-листенеров (применится при следующем старте SOCKS).
#[tauri::command]
fn set_socks_proxies(list: Vec<ctl::SocksProxy>) -> Result<(), String> {
    ctl::set_socks_proxies(list)
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
        .map(|p| p.primary_addr().port())
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
        .map(|p| p.primary_addr().to_string());
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
        .map(|p| p.primary_addr().to_string())
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
fn set_settings(
    default_to_proxy: bool,
    default_proxy: Option<String>,
    state: State<'_, ProxyState>,
) -> Result<(), String> {
    ctl::set_settings(default_to_proxy, default_proxy)?;
    reload_running_proxy(&state);
    Ok(())
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

/// Обновить одну подписку по URL; вернуть число узлов.
#[tauri::command]
async fn update_one_subscription(url: String) -> Result<usize, String> {
    ctl::update_one_subscription(&url).await
}

/// Удалить из конфига узлы подписок (оставить ручные ключи); вернуть число.
#[tauri::command]
fn clear_subscription_nodes() -> Result<usize, String> {
    ctl::clear_subscription_nodes()
}

/// Скачать стандартные geo-базы и прописать пути.
#[tauri::command]
async fn download_geo() -> Result<String, String> {
    ctl::download_geo().await
}

/// Версия приложения.
#[tauri::command]
fn app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Первый ли это запуск текущей версии (показать «что нового» + предложить
/// ярлык). Отмечает версию как просмотренную.
#[tauri::command]
fn first_run_of_version() -> bool {
    ctl::first_run_of_version(env!("CARGO_PKG_VERSION"))
}

/// Создаёт ярлык JammVPN на рабочем столе.
#[tauri::command]
fn create_desktop_shortcut() -> Result<(), String> {
    ctl::create_desktop_shortcut()
}

/// Проверка обновления (последний релиз на GitHub; best-effort).
#[tauri::command]
async fn check_update() -> Result<Option<ctl::UpdateInfo>, String> {
    ctl::check_update(env!("CARGO_PKG_VERSION")).await
}

/// Скачать и установить обновление, затем перезапустить приложение.
#[tauri::command]
async fn perform_update(download_url: String) -> Result<(), String> {
    ctl::perform_update(&download_url).await?;
    // Новый процесс уже запущен — закрываем текущий.
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_millis(400));
        std::process::exit(0);
    });
    Ok(())
}

/// Последние `lines` строк лога (вкладка «Логи»; по умолчанию 100).
#[tauri::command]
fn read_log(lines: Option<usize>) -> String {
    ctl::read_log(lines.unwrap_or(100).clamp(10, 1000))
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

/// Установлен ли драйвер раздельного туннелирования (WinpkFilter / ndisrd).
#[tauri::command]
fn split_driver_installed() -> bool {
    ctl::split_driver_installed()
}

/// Установить вшитый драйвер раздельного туннелирования (требует админ-прав).
#[tauri::command]
fn install_split_driver() -> Result<String, String> {
    ctl::install_split_driver()
}

/// Текущий драйвер split (`winpkfilter` | `windivert`).
#[tauri::command]
fn get_split_driver() -> String {
    ctl::get_split_driver()
}

/// Выбрать драйвер split (применится при следующем запуске split).
#[tauri::command]
fn set_split_driver(driver: String) -> Result<(), String> {
    ctl::set_split_driver(&driver)
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

/// Применяет правила к работающему прокси на лету (если запущен) — чтобы
/// изменения маршрутизации действовали без перезапуска VPN.
fn reload_running_proxy(state: &State<'_, ProxyState>) {
    if let Ok(guard) = state.0.lock() {
        if let Some(ms) = guard.as_ref() {
            if let Err(e) = ms.reload() {
                ctl::log_line(&format!("перезагрузка правил на лету не удалась: {e}"));
            }
        }
    }
}

/// Добавить правило в конец списка.
#[tauri::command]
fn add_rule(rule: ctl::RuleInfo, state: State<'_, ProxyState>) -> Result<(), String> {
    ctl::add_rule(rule)?;
    reload_running_proxy(&state);
    Ok(())
}

/// Заменить правило по индексу.
#[tauri::command]
fn update_rule(index: usize, rule: ctl::RuleInfo, state: State<'_, ProxyState>) -> Result<(), String> {
    ctl::update_rule(index, rule)?;
    reload_running_proxy(&state);
    Ok(())
}

/// Удалить правило по индексу. `false` — индекс вне диапазона.
#[tauri::command]
fn remove_rule(index: usize, state: State<'_, ProxyState>) -> Result<bool, String> {
    let r = ctl::remove_rule(index)?;
    reload_running_proxy(&state);
    Ok(r)
}

/// Переместить правило вверх (`up=true`) или вниз. `false` — двигать некуда.
#[tauri::command]
fn move_rule(index: usize, up: bool, state: State<'_, ProxyState>) -> Result<bool, String> {
    let r = ctl::move_rule(index, up)?;
    reload_running_proxy(&state);
    Ok(r)
}

/// Список готовых пресетов правил.
#[tauri::command]
fn list_presets() -> Vec<ctl::PresetInfo> {
    ctl::list_presets()
}

/// Применить пресет (заменяет текущие правила). Возвращает число правил.
#[tauri::command]
fn apply_preset(id: String, state: State<'_, ProxyState>) -> Result<usize, String> {
    let n = ctl::apply_preset(&id)?;
    reload_running_proxy(&state);
    Ok(n)
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
    // Авто-запрос прав администратора при запуске БЕЗ них (нужны для split).
    // Если пользователь подтвердит UAC — текущий процесс закрываем (запустится
    // элевированный). Если отклонит — продолжаем работу без прав (split будет
    // недоступен, остальное работает). На автозапуске (--minimized) не спрашиваем,
    // чтобы не показывать UAC на каждой загрузке системы.
    let autostart = std::env::args().any(|a| a == "--minimized");
    if !autostart && !ctl::is_admin() {
        match ctl::relaunch_as_admin() {
            Ok(()) => return, // элевированный экземпляр запускается — выходим
            Err(e) => ctl::log_line(&format!(
                "запуск от администратора отклонён/недоступен ({e}) — работаем без прав"
            )),
        }
    }

    // Гарантируем WebView2 Runtime ДО создания окна: на ПК без него Tauri иначе
    // падает с «Could not find the WebView2 Runtime». Если рантайма нет —
    // тихо ставим официальный установщик Microsoft; если есть — используем его.
    match ctl::ensure_webview2() {
        Ok(true) => {}
        Ok(false) => ctl::log_line("WebView2 поставить не удалось — окно может не открыться"),
        Err(e) => ctl::log_line(&format!("проверка/установка WebView2: {e}")),
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(ProxyState::default())
        .manage(SplitState::default())
        .manage(SysProxyState::default())
        .manage(LocalWgState::default())
        .setup(|app| {
            // Убираем временные файлы, оставшиеся после авто-обновления.
            ctl::cleanup_after_update();
            setup_tray(app)?;
            // Автозапуск (флаг --minimized) — стартуем сразу в трей, без окна.
            if std::env::args().any(|a| a == "--minimized") {
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.hide();
                }
            }
            // Сторож здоровья split-драйвера: при сбое/восстановлении WinDivert
            // шлём уведомление в UI (тост). Опрос раз в 2 с, событие — только на
            // переходе состояния.
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                let mut last_healthy = true;
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    let healthy = handle
                        .state::<SplitState>()
                        .0
                        .lock()
                        .ok()
                        .map(|g| g.as_ref().map(|c| c.is_healthy()).unwrap_or(true))
                        .unwrap_or(true);
                    if healthy != last_healthy {
                        last_healthy = healthy;
                        let payload = if healthy {
                            NotifyPayload {
                                kind: "info",
                                title: "Раздельный туннель".into(),
                                body: "Драйвер WinDivert восстановлен, перехват возобновлён.".into(),
                            }
                        } else {
                            NotifyPayload {
                                kind: "error",
                                title: "Раздельный туннель".into(),
                                body: "Сбой драйвера WinDivert — идёт автоматическое восстановление…"
                                    .into(),
                            }
                        };
                        let _ = handle.emit("notify", payload);
                    }
                }
            });
            // Уведомление при недоступности узла, выбранного правилом: трафик
            // откатывается на узел по умолчанию, пользователю — тост.
            let nh = app.handle().clone();
            ctl::set_route_notifier(move |n: ctl::RouteNotice| {
                let _ = nh.emit(
                    "notify",
                    NotifyPayload {
                        kind: "warn",
                        title: "Маршрутизация".into(),
                        body: format!(
                            "Узел «{}» недоступен для {} — направлено через «{}».",
                            n.failed_node, n.host, n.via
                        ),
                    },
                );
            });
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
            split_driver_installed,
            install_split_driver,
            get_split_driver,
            set_split_driver,
            read_log,
            clear_log,
            app_version,
            first_run_of_version,
            create_desktop_shortcut,
            check_update,
            perform_update,
            update_one_subscription,
            clear_subscription_nodes,
            download_geo,
            test_node_latency,
            export_vless_link,
            export_ss_link,
            export_hysteria2_link,
            open_url,
            get_socks_proxies,
            set_socks_proxies,
            export_node_conf_to,
            local_wg_export_conf_to,
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
