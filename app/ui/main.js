// Фронтенд JammVPN: вызывает Tauri-команды (поверх контроллера jammvpn_cli).
const { invoke } = window.__TAURI__.core;

const $ = (id) => document.getElementById(id);

function setStatus(addr) {
  const el = $("status");
  const running = !!addr;
  el.textContent = running ? `прокси на ${addr}` : "прокси остановлен";
  el.className = "status " + (running ? "on" : "off");
  $("btn-start").disabled = running;
  $("btn-stop").disabled = !running;
  $("proxy-hint").textContent = running
    ? `проверка: curl --socks5-hostname ${addr} https://icanhazip.com`
    : "";
}

async function refreshNodes() {
  const nodes = await invoke("list_nodes");
  const body = $("nodes-body");
  body.innerHTML = "";
  const sel = $("server");
  const dsel = $("default-proxy");
  const tsel = $("tunnel-node");
  // сохраняем выбранные значения
  const prev = sel.value;
  const prevDefault = dsel ? dsel.value : "";
  const prevTunnel = tsel ? tsel.value : "";
  sel.innerHTML = '<option value="">— по правилам конфига —</option>';
  if (dsel) dsel.innerHTML = '<option value="">— первый доступный —</option>';
  if (tsel) tsel.innerHTML = '<option value="">— выберите узел —</option>';
  for (const [i, n] of nodes.entries()) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${i + 1}</td><td>${esc(n.name)}</td><td>${esc(
      n.protocol
    )}</td><td>${esc(n.address)}:${n.port}</td><td class="lat" data-name="${esc(
      n.name
    )}">—</td><td class="del"><button class="x" title="Удалить" data-name="${esc(
      n.name
    )}">✕</button></td>`;
    body.appendChild(tr);

    const opt = document.createElement("option");
    opt.value = n.name;
    opt.textContent = n.name;
    sel.appendChild(opt);
    if (dsel) dsel.appendChild(opt.cloneNode(true));
    if (tsel) tsel.appendChild(opt.cloneNode(true));
  }
  sel.value = prev;
  if (dsel) dsel.value = prevDefault;
  if (tsel) tsel.value = prevTunnel;
  for (const btn of body.querySelectorAll("button.x")) {
    btn.addEventListener("click", () => removeNode(btn.dataset.name));
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
  // Сохранённые адреса/узел подключения (если заданы — иначе остаются дефолты).
  if (s.listen) $("listen").value = s.listen;
  if (s.tunnel_listen) $("tunnel-listen").value = s.tunnel_listen;
  if (s.tunnel_node) $("tunnel-node").value = s.tunnel_node;
}

// Персист настроек подключения (адреса прокси + узел туннеля). Тихо игнорируем
// ошибки записи — это фоновое сохранение по мере правок полей.
async function saveConnection() {
  try {
    await invoke("set_connection", {
      listen: $("listen").value.trim() || null,
      tunnelNode: $("tunnel-node").value || null,
      tunnelListen: $("tunnel-listen").value.trim() || null,
    });
  } catch (e) {
    /* фон: не мешаем пользователю */
  }
}

// Экспорт выбранного узла туннеля в .conf на диск.
async function exportTunnelConf() {
  const node = $("tunnel-node").value;
  const hint = $("tunnel-hint");
  hint.className = "hint";
  if (!node) {
    hint.textContent = "выберите узел для экспорта .conf";
    hint.className = "hint err";
    return;
  }
  try {
    const path = await invoke("export_node_conf", { name: node });
    hint.textContent = "конфиг сохранён: " + path;
  } catch (e) {
    hint.textContent = "ошибка экспорта: " + e;
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

async function startProxy() {
  const listen = $("listen").value.trim() || "127.0.0.1:1080";
  const server = $("server").value || null;
  $("proxy-hint").textContent = "запуск…";
  try {
    const addr = await invoke("proxy_start", { listen, server });
    setStatus(addr);
  } catch (e) {
    $("proxy-hint").textContent = "ошибка: " + e;
    $("proxy-hint").className = "hint err";
  }
}

async function stopProxy() {
  await invoke("proxy_stop");
  setStatus(null);
  await loadSysProxy(); // бэкенд снимает системный прокси при остановке
}

function setTunnelStatus(addr) {
  const el = $("tunnel-status");
  const running = !!addr;
  if (el) {
    el.textContent = running ? `на ${addr}` : "остановлен";
    el.className = "status " + (running ? "on" : "off");
  }
  $("btn-tunnel-start").disabled = running;
  $("btn-tunnel-stop").disabled = !running;
  $("tunnel-hint").textContent = running
    ? `весь трафик на ${addr} идёт через узел; проверка: curl --socks5-hostname ${addr} https://icanhazip.com`
    : "";
}

async function startTunnelProxy() {
  const listen = $("tunnel-listen").value.trim() || "127.0.0.1:1081";
  const node = $("tunnel-node").value || "";
  const hint = $("tunnel-hint");
  hint.className = "hint";
  if (!node) {
    hint.textContent = "выберите узел для туннеля";
    hint.className = "hint err";
    return;
  }
  hint.textContent = "запуск…";
  try {
    const addr = await invoke("tunnel_proxy_start", { listen, node });
    setTunnelStatus(addr);
  } catch (e) {
    hint.textContent = "ошибка: " + e;
    hint.className = "hint err";
  }
}

async function stopTunnelProxy() {
  await invoke("tunnel_proxy_stop");
  setTunnelStatus(null);
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
    msg.textContent = "split снят";
    msg.className = "hint ok";
  } catch (e) {
    msg.textContent = "не удалось снять: " + e;
    msg.className = "hint err";
  }
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
  $("btn-start").addEventListener("click", startProxy);
  $("btn-stop").addEventListener("click", stopProxy);
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
  $("btn-tunnel-start").addEventListener("click", startTunnelProxy);
  $("btn-tunnel-stop").addEventListener("click", stopTunnelProxy);
  $("btn-tunnel-export").addEventListener("click", exportTunnelConf);
  // Автосохранение адресов/узла подключения при изменении.
  $("listen").addEventListener("change", saveConnection);
  $("tunnel-listen").addEventListener("change", saveConnection);
  $("tunnel-node").addEventListener("change", saveConnection);
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
  setStatus(await invoke("proxy_status"));
  setTunnelStatus(await invoke("tunnel_proxy_status"));
}

window.addEventListener("DOMContentLoaded", init);
