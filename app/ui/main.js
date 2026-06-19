// Фронтенд JammVPN: вызывает Tauri-команды (поверх контроллера jammvpn_cli).
const { invoke } = window.__TAURI__.core;

const $ = (id) => document.getElementById(id);

// Кастомное модальное подтверждение (Promise<bool>).
let _confirmResolve = null;
function customConfirm(text, okLabel) {
  return new Promise((resolve) => {
    _confirmResolve = resolve;
    $("confirm-text").textContent = text;
    $("confirm-ok").textContent = okLabel || "Удалить";
    $("confirm-modal").style.display = "flex";
  });
}
function closeConfirm(result) {
  $("confirm-modal").style.display = "none";
  const r = _confirmResolve;
  _confirmResolve = null;
  if (r) r(result);
}

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

// Маппинг группа(тег подписки) → URL, для кнопки обновления группы (читает ui.js).
window.SUB_URLS = {};

async function refreshNodes() {
  const nodes = await invoke("list_nodes");
  try {
    const subs = await invoke("list_subscriptions");
    window.SUB_URLS = Object.fromEntries(subs.map((s) => [s.group, s.url]));
  } catch (e) {}
  const body = $("nodes-body");
  body.innerHTML = "";
  const sel = $("server");
  const dsel = $("default-proxy");
  const lsel = $("lwg-node");
  const tsel = $("r-tag"); // тег узла в редакторе правил (теперь это <select>)
  const spsel = $("sp-node"); // узел для SOCKS-листенера
  // сохраняем выбранные значения
  const prev = sel.value;
  const prevDefault = dsel ? dsel.value : "";
  const prevLwg = lsel ? lsel.value : "";
  const prevTag = tsel ? tsel.value : "";
  const prevSp = spsel ? spsel.value : "";
  sel.innerHTML = '<option value="">— по правилам конфига —</option>';
  if (dsel) dsel.innerHTML = '<option value="">— первый доступный —</option>';
  if (lsel) lsel.innerHTML = '<option value="">— по правилам конфига —</option>';
  if (tsel) tsel.innerHTML = '<option value="">— дефолтный —</option>';
  if (spsel) spsel.innerHTML = '<option value="">— по правилам (узел по умолчанию) —</option>';

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
      tr.dataset.group = n.group || "";
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
      if (tsel) tsel.appendChild(opt.cloneNode(true));
      if (spsel) spsel.appendChild(opt.cloneNode(true));
    }
  }
  sel.value = prev;
  if (dsel) dsel.value = prevDefault;
  if (lsel) lsel.value = prevLwg;
  if (tsel) tsel.value = prevTag;
  if (spsel) spsel.value = prevSp;
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
  // После любого обновления списка — тест задержек (бейджи в списке).
  testLatencies();
}

async function removeNode(name) {
  if (!(await customConfirm(`Удалить узел «${name}»?`))) return;
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
  // Узел по умолчанию = выбранный на «Главной» (отдельного селектора больше нет).
  // Локальный адрес SOCKS фиксирован (127.0.0.1:1080) — поле убрано из UI.
  if (s.proxy_node) {
    $("server").value = s.proxy_node;
    // Уведомляем node-picker (ui.js) перерисовать выбор.
    $("server").dispatchEvent(new Event("change", { bubbles: true }));
  }
  window.syncToggles && window.syncToggles(); // отразить чекбоксы в тумблерах UI
}

// Персист настроек подключения (адрес прокси + выбранный узел). Тихо игнорируем
// ошибки записи — это фоновое сохранение по мере правок.
async function saveConnection() {
  try {
    await invoke("set_connection", {
      listen: null, // фиксированный дефолт на бэкенде (127.0.0.1:1080)
      proxyNode: $("server").value || null,
    });
  } catch (e) {
    /* фон: не мешаем пользователю */
  }
}

// Безопасное имя файла из имени узла.
function safeFileName(name) {
  return (name || "node").replace(/[^a-zA-Z0-9._-]+/g, "_");
}
// Диалог «Сохранить как» (плагин dialog). null — отмена/недоступен.
async function pickSavePath(defaultName) {
  const dialog = window.__TAURI__ && window.__TAURI__.dialog;
  if (!dialog || !dialog.save) return undefined; // плагин недоступен
  return await dialog.save({
    defaultPath: defaultName,
    filters: [{ name: "WireGuard config", extensions: ["conf"] }],
  });
}

// Экспорт узла (WG/AmneziaWG) в .conf — с диалогом выбора места.
async function exportNode(name) {
  const msg = $("nodes-msg");
  try {
    const path = await pickSavePath(safeFileName(name) + ".conf");
    if (path === undefined) {
      // плагин недоступен — фолбэк в каталог конфига
      const p = await invoke("export_node_conf", { name });
      if (msg) msg.textContent = "конфиг сохранён: " + p;
    } else {
      if (!path) return; // отмена
      await invoke("export_node_conf_to", { name, path });
      if (msg) msg.textContent = "конфиг сохранён: " + path;
    }
    if (msg) msg.className = "hint ok";
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
    const path = await pickSavePath("jammvpn-local-wg.conf");
    if (path === undefined) {
      const p = await invoke("local_wg_export_conf"); // фолбэк
      hint.textContent = "клиентский .conf сохранён: " + p;
    } else {
      if (!path) return; // отмена
      await invoke("local_wg_export_conf_to", { path });
      hint.textContent = "клиентский .conf сохранён: " + path;
    }
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
      defaultProxy: null, // узел по умолчанию = выбранный на «Главной»
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

// --- Модалка добавления узла/подписки ---
const ADD_PLACEHOLDERS = {
  vless: "vless://uuid@host:443?security=reality&pbk=...&sid=...&sni=...#Имя",
  shadowsocks: "ss://base64@host:port#Имя   (поддерживается Outline-ссылка)",
  trojan: "trojan://password@host:443?sni=...#Имя",
  wireguard:
    "[Interface]\nPrivateKey = ...\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = ...\nPresharedKey = ...\nEndpoint = host:51820\nAllowedIPs = 0.0.0.0/0, ::/0",
  tuic: "tuic://uuid:password@host:443?sni=...#Имя",
  socks: "socks5://user:pass@host:1080#Имя   (или http://user:pass@host:8080)",
  sub: "https://example.com/sub  — ссылка на подписку",
};
let addProto = "vless";

function openAddModal() {
  $("add-modal").style.display = "flex";
  $("add-msg").textContent = "";
  $("add-input").value = "";
  setAddProto("vless");
  $("add-input").focus();
}
function closeAddModal() {
  $("add-modal").style.display = "none";
}
function setAddProto(p) {
  addProto = p;
  for (const c of document.querySelectorAll("#add-proto .proto-chip"))
    c.classList.toggle("on", c.dataset.proto === p);
  $("add-input").placeholder = ADD_PLACEHOLDERS[p] || "";
}
async function submitAdd() {
  const text = $("add-input").value.trim();
  const msg = $("add-msg");
  if (!text) {
    msg.textContent = "вставьте ключ / конфиг / ссылку";
    msg.className = "hint err";
    return;
  }
  msg.className = "hint";
  msg.textContent = "добавляю…";
  try {
    if (addProto === "sub") {
      await invoke("add_subscription", { url: text, tag: null, intervalHours: 12 });
      const ups = await invoke("update_subscriptions");
      const n = ups.reduce((s, u) => s + (u.count || 0), 0);
      msg.textContent = `подписка добавлена: ${n} узлов`;
      await refreshSubs();
    } else {
      msg.textContent = await invoke("import_config", { text });
    }
    msg.className = "hint ok";
    await refreshNodes();
    setTimeout(closeAddModal, 1000);
  } catch (e) {
    msg.textContent = "ошибка: " + e;
    msg.className = "hint err";
  }
}

async function updateSubs() {
  const msg = $("subs-msg");
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
  const listen = "127.0.0.1:1080"; // фиксированный локальный адрес SOCKS
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
  const body = $("subs-body");
  if (!body) return; // панель подписок убрана — подписки видны в списке узлов
  const subs = await invoke("list_subscriptions");
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

async function downloadGeo() {
  const msg = $("geo-msg");
  const btn = $("btn-geo-download");
  btn.disabled = true;
  msg.textContent = "загрузка geo-баз… (несколько МБ)";
  msg.className = "hint";
  try {
    msg.textContent = await invoke("download_geo");
    msg.className = "hint ok";
    await loadGeo();
  } catch (e) {
    msg.textContent = "ошибка загрузки: " + e;
    msg.className = "hint err";
  } finally {
    btn.disabled = false;
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
  window.syncToggles && window.syncToggles();
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

// Системный прокси теперь задаётся флагом у SOCKS-листенера (см. ниже), отдельного
// глобального тумблера нет. Оставлена заглушка — её зовут из stopAll/init.
async function loadSysProxy() {}

// --- SOCKS5-листенеры (мульти-прокси) ---
let socksCache = [];

async function loadSocksProxies() {
  const box = $("socks-list");
  if (!box) return;
  try {
    socksCache = await invoke("get_socks_proxies");
  } catch (e) {
    socksCache = [];
  }
  box.innerHTML = "";
  if (!socksCache.length) {
    box.innerHTML =
      '<p class="hint" style="margin:0 2px">Листенеров нет — при запуске SOCKS поднимется один на 127.0.0.1:1080 (системный, по правилам).</p>';
    return;
  }
  socksCache.forEach((p, i) => {
    const row = document.createElement("div");
    row.className = "rule";
    const node = p.node || "по правилам (узел по умолчанию)";
    const sys = p.system ? '<span class="chip">системный</span>' : "";
    row.innerHTML = `<span class="n">${i + 1}</span>
      <div class="crit"><span class="chip">${esc(p.listen)}</span><span class="chip">→ ${esc(node)}</span>${sys}</div>
      <span class="rule-ctl">
        <button class="mini" data-i="${i}" data-sa="sys" title="сделать системным">★</button>
        <button class="x" data-i="${i}" data-sa="del" title="удалить">✕</button>
      </span>`;
    box.appendChild(row);
  });
}

async function saveSocksProxies(list, note) {
  const msg = $("socks-msg");
  try {
    await invoke("set_socks_proxies", { list });
    await loadSocksProxies();
    if (msg) {
      msg.textContent = note || "сохранено (применится при следующем запуске SOCKS)";
      msg.className = "hint ok";
    }
  } catch (e) {
    if (msg) {
      msg.textContent = "ошибка: " + e;
      msg.className = "hint err";
    }
  }
}

async function addSocksProxy() {
  const listen = $("sp-listen").value.trim();
  const node = $("sp-node").value || null;
  const system = $("sp-system").checked;
  const msg = $("socks-msg");
  if (!/^[\w.:\[\]-]+:\d{1,5}$/.test(listen)) {
    if (msg) { msg.textContent = "укажите адрес вида ip:port (напр. 0.0.0.0:1082)"; msg.className = "hint err"; }
    return;
  }
  const list = socksCache.slice();
  // Системный — только у одного: сбрасываем у остальных, если новый системный.
  if (system) list.forEach((p) => (p.system = false));
  list.push({ listen, node, system });
  $("sp-listen").value = "";
  $("sp-system").checked = false;
  window.syncToggles && window.syncToggles();
  await saveSocksProxies(list, "листенер добавлен (применится при следующем запуске SOCKS)");
}

async function onSocksListClick(e) {
  const btn = e.target.closest("button[data-sa]");
  if (!btn) return;
  const i = parseInt(btn.dataset.i, 10);
  const list = socksCache.slice();
  if (btn.dataset.sa === "del") {
    if (!(await customConfirm("Удалить SOCKS-листенер " + (list[i] && list[i].listen) + "?", "Удалить"))) return;
    list.splice(i, 1);
    await saveSocksProxies(list);
  } else if (btn.dataset.sa === "sys") {
    list.forEach((p, j) => (p.system = j === i)); // системный — только этот
    await saveSocksProxies(list, "системный прокси: " + (list[i] && list[i].listen));
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
  try {
    const drv = await invoke("get_split_driver");
    const sel = $("sp-driver");
    if (sel) sel.value = drv;
  } catch (_) {}
  setSplitState(await invoke("split_status"));
  window.syncToggles && window.syncToggles();
}

async function onSplitDriverChange() {
  const sel = $("sp-driver");
  const msg = $("split-msg");
  try {
    await invoke("set_split_driver", { driver: sel.value });
    if (msg) {
      msg.textContent =
        sel.value === "windivert"
          ? "драйвер: WinDivert (экспериментально). Применится при следующем «Применить»."
          : "драйвер: WinpkFilter. Применится при следующем «Применить».";
      msg.className = "hint ok";
    }
  } catch (e) {
    if (msg) { msg.textContent = "ошибка смены драйвера: " + e; msg.className = "hint err"; }
  }
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
  const banner = $("admin-banner");
  if (banner) banner.style.display = admin ? "none" : "flex";
  if (!admin) {
    const msg = $("split-msg");
    if (msg) {
      msg.textContent =
        "JammVPN запущен НЕ от администратора — split работать не будет. Нажмите «Перезапустить от админа».";
      msg.className = "hint err";
    }
  }
  await loadDriverState(admin);
}

// Баннер драйвера раздельного туннелирования: показываем, только если запущены
// от админа (иначе сначала нужен перезапуск) и драйвер ещё не установлен.
async function loadDriverState(admin) {
  const banner = $("driver-banner");
  if (!banner) return;
  if (!admin) {
    banner.style.display = "none";
    return;
  }
  let installed = true;
  try {
    installed = await invoke("split_driver_installed");
  } catch (e) {
    return;
  }
  banner.style.display = installed ? "none" : "flex";
}

async function installDriver() {
  const btn = $("btn-install-driver");
  const txt = $("driver-banner-text");
  if (btn) btn.disabled = true;
  if (txt) txt.textContent = "⏳ Устанавливаю драйвер…";
  try {
    const r = await invoke("install_split_driver");
    if (txt) txt.textContent = "✅ " + r;
    setTimeout(() => {
      const banner = $("driver-banner");
      if (banner) banner.style.display = "none";
    }, 1500);
  } catch (e) {
    if (txt) txt.textContent = "❌ Не удалось установить драйвер: " + e;
    if (btn) btn.disabled = false;
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
  const app = document.getElementById("app");
  return !!(app && app.dataset.tab === "logs");
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

const ACT_LABEL = { proxy: "проксировать", direct: "напрямую", block: "блокировать" };

// Критерии правила → отдельные чипы (для карточки на вкладке «Маршруты»).
function ruleChips(r) {
  const out = [];
  (r.domains || []).forEach((d) => out.push("domain: " + d));
  (r.ip_cidrs || []).forEach((d) => out.push("ip: " + d));
  (r.processes || []).forEach((d) => out.push("process: " + d));
  (r.ports || []).forEach((d) => out.push("port: " + d));
  (r.geosite || []).forEach((d) => out.push("geosite: " + d));
  (r.geoip || []).forEach((d) => out.push("geoip: " + d));
  return out.length ? out : ["любой трафик (catch-all)"];
}

async function refreshRules() {
  rulesCache = await invoke("list_rules");
  const box = $("rules");
  box.innerHTML = "";
  rulesCache.forEach((r, i) => {
    const div = document.createElement("div");
    div.className = "rule";
    const chips = ruleChips(r).map((c) => `<span class="chip">${esc(c)}</span>`).join("");
    const node = r.action === "proxy" ? r.proxy_tag || "дефолт" : "—";
    div.innerHTML = `<span class="n">${i + 1}</span>
      <div class="crit">${chips}</div>
      <span class="node">${esc(node)}</span>
      <span class="act ${esc(r.action)}">${esc(ACT_LABEL[r.action] || r.action)}</span>
      <span class="rule-ctl">
        <button class="mini" data-i="${i}" data-act="up" title="выше">▲</button>
        <button class="mini" data-i="${i}" data-act="down" title="ниже">▼</button>
        <button class="mini" data-i="${i}" data-act="edit" title="изменить">✎</button>
        <button class="x" data-i="${i}" data-act="del" title="удалить">✕</button>
      </span>`;
    box.appendChild(div);
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

// --- Сплеш-экран ---
function splashStatus(t) {
  const el = $("splash-status");
  if (el) el.textContent = t;
}
function hideSplash() {
  const el = $("splash");
  if (!el) return;
  el.classList.add("hide");
  setTimeout(() => {
    el.style.display = "none";
  }, 600);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// --- «Что нового» (первый запуск версии) ---
// Заметки к текущей версии. Обновляются вместе с версией перед релизом.
const RELEASE_NOTES = [
  "Новый протокол Hysteria2 — проксирование TCP и UDP (QUIC + HTTP/3).",
  "Исправлена высокая загрузка процессора в простое.",
  "Раздельный туннель (WinpkFilter): пересчёт контрольных сумм пакетов.",
];

let whatsnewChecked = false;
async function maybeShowWhatsNew() {
  if (whatsnewChecked) return;
  // Окно скрыто в трее (автозапуск --minimized): откладываем — иначе пометили
  // бы версию просмотренной, и пользователь не увидел бы модалку. Покажем при
  // разворачивании окна (слушатель visibilitychange ниже).
  if (document.hidden) return;
  whatsnewChecked = true;
  let isNew = false;
  try {
    isNew = await invoke("first_run_of_version");
  } catch (e) {
    return;
  }
  if (!isNew) return;
  let ver = "";
  try {
    ver = await invoke("app_version");
  } catch (e) {}
  showWhatsNew(ver, RELEASE_NOTES);
}

function showWhatsNew(version, notes) {
  const modal = $("whatsnew-modal");
  if (!modal) return;
  $("whatsnew-title").textContent = version ? `Что нового · v${version}` : "Что нового";
  const list = $("whatsnew-list");
  list.innerHTML = "";
  for (const n of notes) {
    const li = document.createElement("li");
    li.textContent = n;
    list.appendChild(li);
  }
  $("whatsnew-msg").textContent = "";
  modal.style.display = "flex";
}

function hideWhatsNew() {
  const modal = $("whatsnew-modal");
  if (modal) modal.style.display = "none";
}

async function createShortcut() {
  const msg = $("whatsnew-msg");
  try {
    await invoke("create_desktop_shortcut");
    if (msg) msg.textContent = "✓ Ярлык создан на рабочем столе.";
  } catch (e) {
    if (msg) msg.textContent = "✗ Не удалось создать ярлык: " + e;
  }
}

const GITHUB_URL = "https://github.com/Jammeren2/JammVpn";

async function startupChecks() {
  let v = "";
  try {
    v = await invoke("app_version");
    // Отображение версии в кнопке делает ui.js (setupVersion) — не дублируем.
  } catch (e) {}
  try {
    const nodes = await invoke("list_nodes");
    splashStatus(`v${v} · узлов: ${nodes.length} · проверка обновлений…`);
  } catch (e) {
    splashStatus(`v${v} · проверка обновлений…`);
  }
  try {
    const u = await invoke("check_update");
    if (u && u.newer) {
      splashStatus(`доступно обновление ${u.latest} (у вас v${v})`);
      showUpdateBanner(u);
      // показываем чуть дольше, чтобы заметили
      await sleep(1200);
    } else {
      splashStatus(`v${v} — версия актуальна`);
    }
  } catch (e) {
    splashStatus(`v${v}`);
  }
}

let pendingUpdate = null;

function showUpdateBanner(u) {
  pendingUpdate = u;
  const banner = $("update-banner");
  const txt = $("update-banner-text");
  const btn = $("btn-do-update");
  if (!banner) return;
  if (u.download_url) {
    if (txt) txt.textContent = `🔄 Доступна версия ${u.latest} (у вас v${u.current}).`;
    if (btn) {
      btn.style.display = "";
      btn.textContent = "Обновить";
      btn.disabled = false;
    }
  } else {
    // У релиза нет .exe — авто-обновление невозможно, ведём на страницу релиза.
    if (txt) txt.textContent = `🔄 Доступна версия ${u.latest} — откройте страницу релиза.`;
    if (btn) btn.style.display = "none";
  }
  banner.style.display = "flex";
}

async function doUpdate() {
  if (!pendingUpdate || !pendingUpdate.download_url) return;
  const ok = await customConfirm(
    `Скачать и установить ${pendingUpdate.latest}? Приложение перезапустится.`,
    "Обновить"
  );
  if (!ok) return;
  const txt = $("update-banner-text");
  const btn = $("btn-do-update");
  if (btn) btn.disabled = true;
  if (txt) txt.textContent = "⏳ Скачиваю и устанавливаю обновление…";
  try {
    await invoke("perform_update", { downloadUrl: pendingUpdate.download_url });
    if (txt) txt.textContent = "✅ Обновление установлено, перезапуск…";
    // Процесс будет завершён бэкендом, новый уже запускается.
  } catch (e) {
    if (txt) txt.textContent = "❌ Не удалось обновить: " + e;
    if (btn) btn.disabled = false;
  }
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
  // Клик по кнопке версии (открытие GitHub) вешает ui.js (setupVersion).
  // Модалка «Добавить».
  $("btn-add-node").addEventListener("click", openAddModal);
  $("add-close").addEventListener("click", closeAddModal);
  $("add-submit").addEventListener("click", submitAdd);
  $("add-proto").addEventListener("click", (e) => {
    const c = e.target.closest(".proto-chip");
    if (c) setAddProto(c.dataset.proto);
  });
  $("add-modal").addEventListener("click", (e) => {
    if (e.target === $("add-modal")) closeAddModal();
  });
  // Модалка подтверждения.
  $("confirm-ok").addEventListener("click", () => closeConfirm(true));
  $("confirm-cancel").addEventListener("click", () => closeConfirm(false));
  $("confirm-modal").addEventListener("click", (e) => {
    if (e.target === $("confirm-modal")) closeConfirm(false);
  });
  $("whatsnew-close").addEventListener("click", hideWhatsNew);
  $("whatsnew-skip").addEventListener("click", hideWhatsNew);
  $("whatsnew-shortcut").addEventListener("click", createShortcut);
  $("whatsnew-modal").addEventListener("click", (e) => {
    if (e.target === $("whatsnew-modal")) hideWhatsNew();
  });
  // Если стартовали в трее — покажем «что нового» при первом разворачивании.
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) maybeShowWhatsNew();
  });
  $("btn-save-settings").addEventListener("click", saveSettings);
  $("btn-save-geo").addEventListener("click", saveGeo);
  $("btn-geo-download").addEventListener("click", downloadGeo);
  $("btn-rule-save").addEventListener("click", saveRule);
  $("btn-rule-cancel").addEventListener("click", resetRuleForm);
  $("r-action").addEventListener("change", updateTagVisibility);
  $("rules").addEventListener("click", onRulesClick);
  $("presets").addEventListener("click", onPresetClick);
  $("autostart").addEventListener("change", toggleAutostart);
  if ($("btn-socks-add")) $("btn-socks-add").addEventListener("click", addSocksProxy);
  if ($("socks-list")) $("socks-list").addEventListener("click", onSocksListClick);
  $("btn-split-save").addEventListener("click", saveSplit);
  $("btn-split-apply").addEventListener("click", applySplit);
  if ($("sp-driver")) $("sp-driver").addEventListener("change", onSplitDriverChange);
  $("btn-split-clear").addEventListener("click", clearSplit);
  // Автосохранение выбранного узла при изменении.
  $("server").addEventListener("change", onNodeChange);
  // Локальный WG-сервер.
  $("btn-lwg-start").addEventListener("click", startLocalWg);
  $("btn-lwg-stop").addEventListener("click", stopLocalWg);
  $("btn-lwg-export").addEventListener("click", exportLocalWgConf);
  $("btn-lwg-qr").addEventListener("click", showLocalWgQr);
  $("btn-split-elevate").addEventListener("click", relaunchAsAdmin);
  $("btn-admin-relaunch").addEventListener("click", relaunchAsAdmin);
  $("btn-install-driver").addEventListener("click", installDriver);
  $("btn-do-update").addEventListener("click", doUpdate);
  $("btn-log-refresh").addEventListener("click", loadLog);
  $("btn-log-clear").addEventListener("click", clearLog);
  $("log-lines").addEventListener("change", loadLog);
  // Загрузка лога при открытии вкладки + авто-обновление, пока она активна.
  // (Переключение на вкладку «Логи» дергает loadLog из ui.js — слоя навигации.)
  setInterval(() => {
    if (logsTabActive() && $("log-auto") && $("log-auto").checked) loadLog();
  }, 2000);

  $("config-path").textContent = await invoke("config_path");
  await refreshNodes();
  await loadSettings();
  await refreshSubs();
  await loadGeo();
  await refreshRules();
  await loadPresets();
  await loadSocksProxies();
  resetRuleForm();
  await loadAutostart();
  await loadSplit();
  await loadSysProxy();
  await loadLocalWg();
  await loadAdminState();
  renderModes();
  await updateHeroStatus();
  // Сплеш: проверки при старте (с ограничением по времени), затем скрыть.
  await Promise.race([startupChecks(), sleep(2800)]);
  hideSplash();
  // После сплеша — если это первый запуск новой версии, показать «что нового».
  await maybeShowWhatsNew();
}

window.addEventListener("DOMContentLoaded", init);
