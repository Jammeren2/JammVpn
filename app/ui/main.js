// Фронтенд JammVPN: вызывает Tauri-команды (поверх контроллера jammvpn_cli).
const { invoke } = window.__TAURI__.core;

const $ = (id) => document.getElementById(id);

// --- Режимы (SOCKS5 / Split / WG-сервер) ---
const DEFAULT_MODES = { socks: true, split: false, wg: false };
function getModes() {
  try {
    return Object.assign(
      {},
      DEFAULT_MODES,
      JSON.parse(localStorage.getItem("jamm_modes") || "{}")
    );
  } catch (e) {
    return { ...DEFAULT_MODES };
  }
}
function saveModes(m) {
  localStorage.setItem("jamm_modes", JSON.stringify(m));
}
function renderModes() {
  const m = getModes();
  for (const k of ["socks", "split", "wg"]) {
    const el = $("mode-" + k);
    if (el) el.classList.toggle("on", !!m[k]);
  }
}
function toggleMode(k) {
  const m = getModes();
  m[k] = !m[k];
  saveModes(m);
  renderModes();
}

// Что реально запущено сейчас.
async function runningModes() {
  const out = { socks: null, split: false, wg: false };
  try {
    out.socks = await invoke("proxy_status");
  } catch (e) {}
  try {
    out.split = await invoke("split_status");
  } catch (e) {}
  try {
    const i = await invoke("local_wg_status");
    out.wg = !!(i && i.running);
  } catch (e) {}
  return out;
}

async function updateHeroStatus() {
  const r = await runningModes();
  const parts = [];
  if (r.socks) parts.push("SOCKS5 " + r.socks);
  if (r.split) parts.push("Split");
  if (r.wg) parts.push("WG-сервер");
  const on = parts.length > 0;
  const el = $("status");
  el.textContent = on ? parts.join(" · ") : "остановлено";
  el.className = "status " + (on ? "on" : "off");
  $("btn-stop").disabled = !on;
}

async function refreshNodes() {
  const nodes = await invoke("list_nodes");
  const body = $("nodes-body");
  body.innerHTML = "";
  const sel = $("server");
  const dsel = $("default-proxy");
  const lsel = $("lwg-node");
  // сохраняем выбранные значения
  const prev = sel.value;
  const prevDefault = dsel ? dsel.value : "";
  const prevLwg = lsel ? lsel.value : "";
  sel.innerHTML = '<option value="">— по правилам конфига —</option>';
  if (dsel) dsel.innerHTML = '<option value="">— первый доступный —</option>';
  if (lsel) lsel.innerHTML = '<option value="">— по правилам конфига —</option>';

  // Группируем: свои ключи отдельно, узлы подписок — по источнику.
  const own = nodes.filter((n) => !n.group);
  const groups = new Map();
  for (const n of nodes) {
    if (!n.group) continue;
    if (!groups.has(n.group)) groups.set(n.group, []);
    groups.get(n.group).push(n);
  }
  const sections = [];
  if (own.length) sections.push(["🔑 Свои ключи", own]);
  for (const [g, list] of groups) sections.push(["📡 " + g, list]);

  let idx = 0;
  for (const [title, list] of sections) {
    if (sections.length > 1) {
      const head = document.createElement("tr");
      head.className = "group-head";
      head.innerHTML = `<td colspan="6">${esc(title)} <span class="group-count">${list.length}</span></td>`;
      body.appendChild(head);
    }
    for (const n of list) {
      idx++;
      const isWg = /wireguard|amnezia|awg/i.test(n.protocol);
      const exportBtn = isWg
        ? `<button class="x" title="Сохранить .conf" data-export="${esc(n.name)}">⤓</button>`
        : "";
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${idx}</td><td>${esc(n.name)}</td><td>${esc(
        n.protocol
      )}</td><td>${esc(n.address)}:${n.port}</td><td class="lat" data-name="${esc(
        n.name
      )}">—</td><td class="del">${exportBtn}<button class="x" title="Удалить" data-name="${esc(
        n.name
      )}">✕</button></td>`;
      body.appendChild(tr);

      const opt = document.createElement("option");
      opt.value = n.name;
      opt.textContent = n.name;
      sel.appendChild(opt);
      if (dsel) dsel.appendChild(opt.cloneNode(true));
      if (lsel) lsel.appendChild(opt.cloneNode(true));
    }
  }
  sel.value = prev;
  if (dsel) dsel.value = prevDefault;
  if (lsel) lsel.value = prevLwg;
  for (const btn of body.querySelectorAll("button.x[data-name]")) {
    btn.addEventListener("click", () => removeNode(btn.dataset.name));
  }
  for (const btn of body.querySelectorAll("button.x[data-export]")) {
    btn.addEventListener("click", () => exportNode(btn.dataset.export));
  }
  // datalist имён узлов — для автодополнения тега в редакторе правил.
  const dl = $("node-names");
  if (dl) {
    dl.innerHTML = "";
    for (const n of nodes) {
      const o = document.createElement("option");
      o.value = n.name;
      dl.appendChild(o);
    }
  }
  $("nodes-empty").style.display = nodes.length ? "none" : "block";
}

async function removeNode(name) {
  if (!confirm(`Удалить узел «${name}»?`)) return;
  try {
    await invoke("remove_node", { name });
    await refreshNodes();
    await loadSettings();
  } catch (e) {
    $("settings-msg").textContent = "ошибка удаления: " + e;
    $("settings-msg").className = "hint err";
  }
}

async function loadSettings() {
  const s = await invoke("get_settings");
  $("default-to-proxy").checked = !!s.default_to_proxy;
  $("default-proxy").value = s.default_proxy || "";
  // Сохранённые адрес прокси и выбранный узел (если заданы — иначе дефолты).
  if (s.listen) $("listen").value = s.listen;
  if (s.proxy_node) {
    $("server").value = s.proxy_node;
    // Уведомляем node-picker (ui.js) перерисовать выбор.
    $("server").dispatchEvent(new Event("change", { bubbles: true }));
  }
}

// Персист настроек подключения (адрес прокси + выбранный узел). Тихо игнорируем
// ошибки записи — это фоновое сохранение по мере правок.
async function saveConnection() {
  try {
    await invoke("set_connection", {
      listen: $("listen").value.trim() || null,
      proxyNode: $("server").value || null,
    });
  } catch (e) {
    /* фон: не мешаем пользователю */
  }
}

// Экспорт узла (WG/AmneziaWG) в .conf на диск. Сообщение — в строку статуса узлов.
async function exportNode(name) {
  const msg = $("import-msg");
  try {
    const path = await invoke("export_node_conf", { name });
    if (msg) {
      msg.textContent = "конфиг сохранён: " + path;
      msg.className = "hint ok";
    }
  } catch (e) {
    if (msg) {
      msg.textContent = "ошибка экспорта: " + e;
      msg.className = "hint err";
    }
  }
}

// --- Локальный WireGuard-сервер (inbound-шлюз) ---
function setLocalWgStatus(info, addr) {
  const el = $("lwg-status");
  const running = !!addr || (info && info.running);
  if (el) {
    el.textContent = running ? "запущен" : "остановлен";
    el.className = "status " + (running ? "on" : "off");
  }
  $("btn-lwg-start").disabled = running;
  $("btn-lwg-stop").disabled = !running;
  const ep = $("lwg-endpoint");
  if (ep && info) {
    const host = info.endpoint_host || "<IP-этой-машины>";
    ep.textContent = `Клиент подключается на Endpoint ${host}:${info.port} (адрес клиента ${info.client_ip}). Экспортируй .conf и импортируй его в WireGuard на приложении/устройстве.`;
  }
}

async function loadLocalWg() {
  try {
    const info = await invoke("local_wg_status");
    if (info.port) $("lwg-port").value = info.port;
    if (info.upstream_node) $("lwg-node").value = info.upstream_node;
    setLocalWgStatus(info, info.listen_addr);
  } catch (e) {
    /* нет данных */
  }
}

async function startLocalWg() {
  const hint = $("lwg-hint");
  hint.className = "hint";
  hint.textContent = "запуск…";
  const node = $("lwg-node").value || null;
  const port = parseInt($("lwg-port").value, 10) || 51820;
  try {
    // Порт сохраняем заранее (start читает его из конфига).
    await invoke("local_wg_set", { port, upstreamNode: node });
  } catch (e) {
    /* set может отсутствовать как команда — порт всё равно в конфиге по умолчанию */
  }
  try {
    const addr = await invoke("local_wg_start", { upstreamNode: node });
    hint.textContent = "сервер слушает на " + addr;
    await loadLocalWg();
    setLocalWgStatus(await invoke("local_wg_status"), addr);
  } catch (e) {
    hint.textContent = "ошибка: " + e;
    hint.className = "hint err";
  }
}

async function stopLocalWg() {
  await invoke("local_wg_stop");
  $("lwg-hint").textContent = "";
  $("lwg-hint").className = "hint";
  await loadLocalWg();
}

async function exportLocalWgConf() {
  const hint = $("lwg-hint");
  hint.className = "hint";
  try {
    const path = await invoke("local_wg_export_conf");
    hint.textContent = "клиентский .conf сохранён: " + path;
  } catch (e) {
    hint.textContent = "ошибка экспорта: " + e;
    hint.className = "hint err";
  }
}

// QR-код клиентского .conf для скана WireGuard-приложением на телефоне.
async function showLocalWgQr() {
  const box = $("lwg-qr");
  const hint = $("lwg-hint");
  hint.className = "hint";
  if (box && box.innerHTML) {
    box.innerHTML = ""; // повторный клик — скрыть
    return;
  }
  try {
    const svg = await invoke("local_wg_qr");
    if (box) box.innerHTML = svg;
    hint.textContent =
      "Открой WireGuard на телефоне → «+» → «Сканировать QR-код». Endpoint = LAN-IP этой машины — телефон должен быть в той же сети, сервер запущен.";
  } catch (e) {
    hint.textContent = "ошибка QR: " + e;
    hint.className = "hint err";
  }
}

async function saveSettings() {
  const msg = $("settings-msg");
  try {
    await invoke("set_settings", {
      defaultToProxy: $("default-to-proxy").checked,
      defaultProxy: $("default-proxy").value || null,
    });
    msg.textContent = "сохранено";
    msg.className = "hint ok";
  } catch (e) {
    msg.textContent = "ошибка: " + e;
    msg.className = "hint err";
  }
}

async function testLatencies() {
  const btn = $("btn-test");
  btn.disabled = true;
  btn.textContent = "Тестирую…";
  try {
    const results = await invoke("test_latencies");
    const byName = new Map(results.map((r) => [r.name, r]));
    for (const cell of document.querySelectorAll(".lat")) {
      const r = byName.get(cell.dataset.name);
      if (!r) continue;
      if (r.latency_ms != null) {
        cell.textContent = `${r.latency_ms} ms`;
        cell.className = "lat ok";
      } else {
        cell.textContent = "ошибка";
        cell.className = "lat err";
        cell.title = r.error || "";
      }
    }
  } finally {
    btn.disabled = false;
    btn.textContent = "Тест задержек";
  }
}

async function doImport() {
  const arg = $("import-arg").value.trim();
  if (!arg) return;
  const msg = $("import-msg");
  try {
    msg.textContent = await invoke("import", { arg });
    msg.className = "hint ok";
    $("import-arg").value = "";
    await refreshNodes();
    await refreshSubs();
  } catch (e) {
    msg.textContent = "ошибка: " + e;
    msg.className = "hint err";
  }
}

async function importConfig() {
  const text = $("import-config-text").value.trim();
  if (!text) return;
  const msg = $("import-msg");
  try {
    msg.textContent = await invoke("import_config", { text });
    msg.className = "hint ok";
    $("import-config-text").value = "";
    await refreshNodes();
  } catch (e) {
    msg.textContent = "ошибка: " + e;
    msg.className = "hint err";
  }
}

async function updateSubs() {
  const msg = $("import-msg");
  try {
    const ups = await invoke("update_subscriptions");
    msg.textContent = ups.length
      ? ups
          .map((u) => (u.count != null ? `${u.url}: ${u.count}` : `${u.url}: ошибка`))
          .join("; ")
      : "подписок нет";
    msg.className = "hint ok";
    await refreshNodes();
  } catch (e) {
    msg.textContent = "ошибка: " + e;
    msg.className = "hint err";
  }
}

// Запускает только SOCKS5-прокси (внутреннее). Бросает при ошибке.
async function startProxy() {
  const listen = $("listen").value.trim() || "127.0.0.1:1080";
  const server = $("server").value || null;
  const addr = await invoke("proxy_start", { listen, server });
  checkConnectivity(addr);
  return addr;
}

// Старт всех включённых режимов через выбранный узел.
async function startAll() {
  const m = getModes();
  const node = $("server").value || null;
  const errs = [];
  const hint = $("proxy-hint");
  hint.className = "hint";
  hint.textContent = "запуск…";

  if (m.socks) {
    try {
      await startProxy();
    } catch (e) {
      if (!String(e).includes("уже запущен")) errs.push("SOCKS5: " + e);
    }
  }
  if (m.split) {
    try {
      await invoke("split_apply");
      setSplitState(true);
    } catch (e) {
      if (!String(e).includes("уже применён")) errs.push("Split: " + e);
    }
  }
  if (m.wg) {
    try {
      await invoke("local_wg_start", { upstreamNode: node });
    } catch (e) {
      if (!String(e).includes("уже запущен")) errs.push("WG-сервер: " + e);
    }
  }

  await updateHeroStatus();
  await loadLocalWg();
  if (errs.length) {
    hint.textContent = "не всё запустилось — " + errs.join("; ");
    hint.className = "hint err";
  } else if (!m.socks) {
    hint.textContent = "";
  }
}

// Стоп всех режимов.
async function stopAll() {
  try {
    await invoke("proxy_stop");
  } catch (e) {}
  try {
    await invoke("split_clear");
    setSplitState(false);
  } catch (e) {}
  try {
    await invoke("local_wg_stop");
  } catch (e) {}
  $("proxy-hint").textContent = "";
  $("proxy-hint").className = "hint";
  await updateHeroStatus();
  await loadSysProxy();
  await loadLocalWg();
}

// Смена узла: если что-то запущено — перезапускаем всё на новый узел, чтобы
// трафик во всех режимах (SOCKS/Split/WG) пошёл через него.
async function onNodeChange() {
  await saveConnection();
  const r = await runningModes();
  if (r.socks || r.split || r.wg) {
    await stopAll();
    await startAll();
  }
}

// Авто-проверка доступности сети через запущенный прокси (показывает exit-IP).
async function checkConnectivity(addr) {
  const hint = $("proxy-hint");
  hint.className = "hint";
  hint.textContent = `SOCKS5 на ${addr} · проверка сети…`;
  try {
    const ip = await invoke("proxy_self_test");
    hint.textContent = `сеть доступна ✓ внешний IP: ${ip} (SOCKS5 ${addr})`;
    hint.className = "hint ok";
  } catch (e) {
    hint.textContent = `SOCKS5 на ${addr}, но сеть недоступна: ${e}`;
    hint.className = "hint err";
  }
}

async function refreshSubs() {
  const subs = await invoke("list_subscriptions");
  const body = $("subs-body");
  body.innerHTML = "";
  for (const s of subs) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="url">${esc(s.url)}</td><td>${esc(
      s.tag || "—"
    )}</td><td>${s.update_interval_hours}</td><td class="del"><button class="x" title="Удалить" data-url="${esc(
      s.url
    )}">✕</button></td>`;
    body.appendChild(tr);
  }
  for (const btn of body.querySelectorAll("button.x")) {
    btn.addEventListener("click", () => removeSub(btn.dataset.url));
  }
  $("subs-empty").style.display = subs.length ? "none" : "block";
}

async function addSub() {
  const url = $("sub-url").value.trim();
  const tag = $("sub-tag").value.trim() || null;
  // Клампим в [1, 8760] — параметр уходит в u32 (отрицательное сломало бы вызов).
  const intervalHours = Math.min(8760, Math.max(1, parseInt($("sub-interval").value, 10) || 12));
  const msg = $("subs-msg");
  if (!url) return;
  try {
    const added = await invoke("add_subscription", { url, tag, intervalHours });
    msg.textContent = added ? "добавлено" : "такая подписка уже есть";
    msg.className = "hint " + (added ? "ok" : "");
    if (added) {
      $("sub-url").value = "";
      $("sub-tag").value = "";
      await refreshSubs();
    }
  } catch (e) {
    msg.textContent = "ошибка: " + e;
    msg.className = "hint err";
  }
}

async function removeSub(url) {
  if (!confirm("Удалить подписку?\n" + url)) return;
  try {
    await invoke("remove_subscription", { url });
    await refreshSubs();
  } catch (e) {
    $("subs-msg").textContent = "ошибка удаления: " + e;
    $("subs-msg").className = "hint err";
  }
}

function setGeoInd(id, path, exists) {
  const el = $(id);
  if (!path) {
    el.textContent = "—";
    el.className = "geo-ind";
    el.title = "путь не задан";
  } else if (exists) {
    el.textContent = "✓ есть";
    el.className = "geo-ind ok";
    el.title = "файл найден";
  } else {
    el.textContent = "✗ нет файла";
    el.className = "geo-ind err";
    el.title = "файл по указанному пути не найден";
  }
}

async function loadGeo() {
  const g = await invoke("geo_status");
  $("geo-site").value = g.geosite_path || "";
  $("geo-ip").value = g.geoip_path || "";
  setGeoInd("geo-site-ind", g.geosite_path, g.geosite_exists);
  setGeoInd("geo-ip-ind", g.geoip_path, g.geoip_exists);
}

async function saveGeo() {
  const msg = $("geo-msg");
  try {
    await invoke("set_geo_paths", {
      geosite: $("geo-site").value.trim() || null,
      geoip: $("geo-ip").value.trim() || null,
    });
    await loadGeo();
    msg.textContent = "пути сохранены";
    msg.className = "hint ok";
  } catch (e) {
    msg.textContent = "ошибка: " + e;
    msg.className = "hint err";
  }
}

async function loadAutostart() {
  try {
    $("autostart").checked = await invoke("autostart_status");
  } catch (e) {
    $("autostart").checked = false;
    $("autostart-msg").textContent = "не удалось прочитать статус: " + e;
    $("autostart-msg").className = "hint err";
  }
}

async function toggleAutostart() {
  const enabled = $("autostart").checked;
  const msg = $("autostart-msg");
  try {
    await invoke("set_autostart", { enabled });
    msg.textContent = enabled ? "автозапуск включён" : "автозапуск выключен";
    msg.className = "hint ok";
  } catch (e) {
    // Откат чекбокса к фактическому состоянию.
    await loadAutostart();
    msg.textContent = "ошибка: " + e;
    msg.className = "hint err";
  }
}

async function loadSysProxy() {
  try {
    const s = await invoke("system_proxy_status");
    // Считаем «нашим», если включён и указывает на loopback.
    $("sysproxy").checked = !!s.enabled && !!(s.server && s.server.includes("127.0.0.1"));
  } catch (e) {
    $("sysproxy").checked = false;
  }
}

async function toggleSysProxy() {
  const on = $("sysproxy").checked;
  const msg = $("sysproxy-msg");
  try {
    await invoke(on ? "set_system_proxy" : "clear_system_proxy");
    msg.textContent = on ? "системный прокси включён" : "системный прокси выключен";
    msg.className = "hint ok";
  } catch (e) {
    await loadSysProxy(); // откат к фактическому состоянию
    msg.textContent = "ошибка: " + e;
    msg.className = "hint err";
  }
}

// --- Раздельное туннелирование (split) ---

function setSplitState(active) {
  const el = $("split-state");
  el.textContent = active ? "применено" : "снято";
  el.className = "split-state " + (active ? "on" : "off");
}

async function loadSplit() {
  const s = await invoke("get_split");
  $("sp-kill").checked = !!s.kill_switch;
  const apps = s.captured_apps || [];
  $("sp-captured").textContent =
    "Перехватываемые приложения: " +
    (apps.length ? apps.join(", ") : "— (добавьте правило с процессом и действием «проксировать»)");
  setSplitState(await invoke("split_status"));
}

async function saveSplit() {
  const msg = $("split-msg");
  try {
    await invoke("set_split", { killSwitch: $("sp-kill").checked });
    await loadSplit();
    msg.textContent = "сохранено";
    msg.className = "hint ok";
  } catch (e) {
    msg.textContent = "ошибка: " + e;
    msg.className = "hint err";
  }
}

async function applySplit() {
  const msg = $("split-msg");
  try {
    await invoke("set_split", { killSwitch: $("sp-kill").checked }); // сохранить перед применением
    await invoke("split_apply");
    setSplitState(true);
    await updateHeroStatus();
    msg.textContent = "split применён";
    msg.className = "hint ok";
  } catch (e) {
    msg.textContent = "не удалось применить: " + e;
    msg.className = "hint err";
  }
}

async function clearSplit() {
  const msg = $("split-msg");
  try {
    await invoke("split_clear");
    setSplitState(false);
    await updateHeroStatus();
    msg.textContent = "split снят";
    msg.className = "hint ok";
  } catch (e) {
    msg.textContent = "не удалось снять: " + e;
    msg.className = "hint err";
  }
}

// Проверка прав администратора: если не от админа — показываем кнопку
// перезапуска и предупреждение (split без админа не работает).
async function loadAdminState() {
  let admin = true;
  try {
    admin = await invoke("is_admin");
  } catch (e) {
    return;
  }
  const btn = $("btn-split-elevate");
  if (btn) btn.style.display = admin ? "none" : "";
  if (!admin) {
    const msg = $("split-msg");
    if (msg) {
      msg.textContent =
        "JammVPN запущен НЕ от администратора — split работать не будет. Нажмите «Перезапустить от админа».";
      msg.className = "hint err";
    }
  }
}

async function relaunchAsAdmin() {
  try {
    await invoke("relaunch_as_admin");
  } catch (e) {
    const msg = $("split-msg");
    if (msg) {
      msg.textContent = "не удалось: " + e;
      msg.className = "hint err";
    }
  }
}

// --- Логи ---
async function loadLog() {
  const view = $("log-view");
  if (!view) return;
  const lines = parseInt(($("log-lines") || {}).value, 10) || 100;
  try {
    const text = await invoke("read_log", { lines });
    const atBottom =
      view.scrollHeight - view.scrollTop - view.clientHeight < 40;
    view.textContent = text || "(лог пуст)";
    if (atBottom) view.scrollTop = view.scrollHeight; // держим прокрутку внизу
  } catch (e) {
    view.textContent = "ошибка чтения лога: " + e;
  }
}

async function clearLog() {
  try {
    await invoke("clear_log");
    await loadLog();
  } catch (e) {
    /* ignore */
  }
}

function logsTabActive() {
  const p = document.querySelector('[data-tab-panel="logs"]');
  return p && p.classList.contains("active");
}

// --- Правила маршрутизации ---

let rulesCache = [];
let editingRule = null; // индекс редактируемого правила или null (добавление).

function splitList(str) {
  return str
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function parsePorts(str) {
  const out = [];
  for (const part of splitList(str)) {
    const n = parseInt(part, 10);
    if (Number.isInteger(n) && n >= 1 && n <= 65535) out.push(n);
  }
  return out;
}

function buildRuleInfo() {
  const action = $("r-action").value;
  return {
    domains: splitList($("r-domains").value),
    ip_cidrs: splitList($("r-cidrs").value),
    processes: splitList($("r-procs").value),
    ports: parsePorts($("r-ports").value),
    geosite: splitList($("r-geosite").value),
    geoip: splitList($("r-geoip").value),
    action,
    proxy_tag: action === "proxy" ? $("r-tag").value.trim() || null : null,
  };
}

function ruleSummary(r) {
  const parts = [];
  if (r.domains.length) parts.push("дом: " + r.domains.join(", "));
  if (r.ip_cidrs.length) parts.push("ip: " + r.ip_cidrs.join(", "));
  if (r.processes.length) parts.push("proc: " + r.processes.join(", "));
  if (r.ports.length) parts.push("порт: " + r.ports.join(", "));
  if (r.geosite.length) parts.push("geosite: " + r.geosite.join(", "));
  if (r.geoip.length) parts.push("geoip: " + r.geoip.join(", "));
  return parts.length ? parts.join(" · ") : "любой трафик (catch-all)";
}

function actionLabel(r) {
  if (r.action === "proxy")
    return "→ proxy" + (r.proxy_tag ? `(${r.proxy_tag})` : "");
  if (r.action === "block") return "✖ block";
  return "→ direct";
}

async function refreshRules() {
  rulesCache = await invoke("list_rules");
  const body = $("rules-body");
  body.innerHTML = "";
  rulesCache.forEach((r, i) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${i + 1}</td><td class="crit">${esc(
      ruleSummary(r)
    )}</td><td class="act ${esc(r.action)}">${esc(
      actionLabel(r)
    )}</td><td class="rule-ctl">
      <button class="mini" data-i="${i}" data-act="up" title="выше">▲</button>
      <button class="mini" data-i="${i}" data-act="down" title="ниже">▼</button>
      <button class="mini" data-i="${i}" data-act="edit" title="изменить">✎</button>
      <button class="x" data-i="${i}" data-act="del" title="удалить">✕</button>
    </td>`;
    body.appendChild(tr);
  });
  $("rules-empty").style.display = rulesCache.length ? "none" : "block";
}

function fillRuleForm(r) {
  $("r-domains").value = (r.domains || []).join(", ");
  $("r-cidrs").value = (r.ip_cidrs || []).join(", ");
  $("r-procs").value = (r.processes || []).join(", ");
  $("r-ports").value = (r.ports || []).join(", ");
  $("r-geosite").value = (r.geosite || []).join(", ");
  $("r-geoip").value = (r.geoip || []).join(", ");
  $("r-action").value = r.action || "proxy";
  $("r-tag").value = r.proxy_tag || "";
  updateTagVisibility();
}

function resetRuleForm() {
  editingRule = null;
  fillRuleForm({ action: "proxy" });
  $("rule-form-title").textContent = "Новое правило";
  $("btn-rule-save").textContent = "Добавить";
  $("btn-rule-cancel").style.display = "none";
}

function updateTagVisibility() {
  $("r-tag-wrap").style.display = $("r-action").value === "proxy" ? "" : "none";
}

function startEditRule(i) {
  editingRule = i;
  fillRuleForm(rulesCache[i]);
  $("rule-form-title").textContent = `Изменить правило #${i + 1}`;
  $("btn-rule-save").textContent = "Сохранить";
  $("btn-rule-cancel").style.display = "";
  $("r-domains").focus();
}

async function saveRule() {
  const rule = buildRuleInfo();
  const msg = $("rules-msg");
  try {
    if (editingRule === null) {
      await invoke("add_rule", { rule });
    } else {
      await invoke("update_rule", { index: editingRule, rule });
    }
    resetRuleForm();
    await refreshRules();
    await loadSplit(); // перехватываемые приложения выводятся из правил
    msg.textContent = "сохранено";
    msg.className = "hint ok";
  } catch (e) {
    msg.textContent = "ошибка: " + e;
    msg.className = "hint err";
  }
}

async function removeRule(i) {
  if (!confirm(`Удалить правило #${i + 1}?`)) return;
  try {
    await invoke("remove_rule", { index: i });
    // Индексы сместились — сбрасываем форму, чтобы правка не попала не в то правило.
    if (editingRule !== null) resetRuleForm();
    await refreshRules();
    await loadSplit();
  } catch (e) {
    $("rules-msg").textContent = "ошибка удаления: " + e;
    $("rules-msg").className = "hint err";
  }
}

async function moveRule(i, up) {
  try {
    const moved = await invoke("move_rule", { index: i, up });
    if (moved) {
      if (editingRule !== null) resetRuleForm();
      await refreshRules();
    }
  } catch (e) {
    $("rules-msg").textContent = "ошибка: " + e;
    $("rules-msg").className = "hint err";
  }
}

function onRulesClick(e) {
  const btn = e.target.closest("button[data-act]");
  if (!btn) return;
  const i = parseInt(btn.dataset.i, 10);
  switch (btn.dataset.act) {
    case "up":
      return moveRule(i, true);
    case "down":
      return moveRule(i, false);
    case "edit":
      return startEditRule(i);
    case "del":
      return removeRule(i);
  }
}

// --- Пресеты правил ---

async function loadPresets() {
  const box = $("presets");
  if (!box) return;
  const presets = await invoke("list_presets");
  box.innerHTML = "";
  for (const p of presets) {
    const b = document.createElement("button");
    b.className = "ghost preset-btn";
    b.textContent = p.name;
    b.title = p.description;
    b.dataset.id = p.id;
    box.appendChild(b);
  }
}

async function applyPreset(id, name) {
  if (!confirm(`Применить пресет «${name}»?\nТекущие правила будут заменены.`)) return;
  const msg = $("rules-msg");
  try {
    const n = await invoke("apply_preset", { id });
    await refreshRules();
    msg.textContent = `применён пресет «${name}» (${n} правил)`;
    msg.className = "hint ok";
  } catch (e) {
    msg.textContent = "ошибка: " + e;
    msg.className = "hint err";
  }
}

function onPresetClick(e) {
  const b = e.target.closest("button[data-id]");
  if (b) applyPreset(b.dataset.id, b.textContent);
}

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])
  );
}

async function init() {
  $("btn-start").addEventListener("click", startAll);
  $("btn-stop").addEventListener("click", stopAll);
  for (const k of ["socks", "split", "wg"]) {
    const el = $("mode-" + k);
    if (el) el.addEventListener("click", () => toggleMode(k));
  }
  $("btn-refresh").addEventListener("click", refreshNodes);
  $("btn-test").addEventListener("click", testLatencies);
  $("btn-import").addEventListener("click", doImport);
  $("btn-import-config").addEventListener("click", importConfig);
  $("btn-update").addEventListener("click", updateSubs);
  $("btn-save-settings").addEventListener("click", saveSettings);
  $("btn-add-sub").addEventListener("click", addSub);
  $("btn-save-geo").addEventListener("click", saveGeo);
  $("btn-rule-save").addEventListener("click", saveRule);
  $("btn-rule-cancel").addEventListener("click", resetRuleForm);
  $("r-action").addEventListener("change", updateTagVisibility);
  $("rules-body").addEventListener("click", onRulesClick);
  $("presets").addEventListener("click", onPresetClick);
  $("autostart").addEventListener("change", toggleAutostart);
  $("sysproxy").addEventListener("change", toggleSysProxy);
  $("btn-split-save").addEventListener("click", saveSplit);
  $("btn-split-apply").addEventListener("click", applySplit);
  $("btn-split-clear").addEventListener("click", clearSplit);
  // Автосохранение адреса прокси и выбранного узла при изменении.
  $("listen").addEventListener("change", saveConnection);
  $("server").addEventListener("change", onNodeChange);
  // Локальный WG-сервер.
  $("btn-lwg-start").addEventListener("click", startLocalWg);
  $("btn-lwg-stop").addEventListener("click", stopLocalWg);
  $("btn-lwg-export").addEventListener("click", exportLocalWgConf);
  $("btn-lwg-qr").addEventListener("click", showLocalWgQr);
  $("btn-split-elevate").addEventListener("click", relaunchAsAdmin);
  $("btn-log-refresh").addEventListener("click", loadLog);
  $("btn-log-clear").addEventListener("click", clearLog);
  $("log-lines").addEventListener("change", loadLog);
  // Загрузка лога при открытии вкладки + авто-обновление, пока она активна.
  const logsTab = document.querySelector('.tab[data-tab="logs"]');
  if (logsTab) logsTab.addEventListener("click", loadLog);
  setInterval(() => {
    if (logsTabActive() && $("log-auto") && $("log-auto").checked) loadLog();
  }, 2000);
  $("import-arg").addEventListener("keydown", (e) => {
    if (e.key === "Enter") doImport();
  });
  $("sub-url").addEventListener("keydown", (e) => {
    if (e.key === "Enter") addSub();
  });

  $("config-path").textContent = await invoke("config_path");
  await refreshNodes();
  await loadSettings();
  await refreshSubs();
  await loadGeo();
  await refreshRules();
  await loadPresets();
  resetRuleForm();
  await loadAutostart();
  await loadSplit();
  await loadSysProxy();
  await loadLocalWg();
  await loadAdminState();
  renderModes();
  await updateHeroStatus();
}

window.addEventListener("DOMContentLoaded", init);
