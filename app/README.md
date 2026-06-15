# JammVPN — десктопный GUI (Tauri 2)

Тонкая оболочка поверх контроллера [`jammvpn_cli`](../crates/cli) — та же логика,
что у CLI (`bin jammvpn`). Конфиг общий: `%APPDATA%/jammvpn/config.json`, секреты
шифруются DPAPI.

- `src-tauri/` — Rust-бэкенд (команды Tauri → контроллер; `gen/` генерируется).
- `ui/` — фронтенд (vanilla HTML/JS/CSS, без бандлера; Tauri API через
  `window.__TAURI__`).

## Возможности UI
Список узлов, импорт ссылки/подписки, тест задержек, запуск/остановка локального
SOCKS5 (через узел или по правилам конфига).

## Запуск (нужны рабочий стол + WebView2 Runtime)
- Dev-окно: `npx @tauri-apps/cli dev` из `app/src-tauri` (фронтенд — `app/ui`).
- Только бэкенд (проверка сборки): `cargo build -p jammvpn-app`.
- Инсталлятор: `npx @tauri-apps/cli build` (требует NSIS/WiX для Windows).

> GUI собирается явно (`cargo build -p jammvpn-app`); рутинные
> `cargo build`/`test` его не трогают (`default-members` в корневом манифесте).
