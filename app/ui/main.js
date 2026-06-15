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
  // сохраняем выбранные значения
  const prev = sel.value;
  const prevDefault = dsel ? dsel.value : "";
  sel.innerHTML = '<option value="">— по правилам конфига —</option>';
  if (dsel) dsel.innerHTML = '<option value="">— первый доступный —</option>';
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
  }
  sel.value = prev;
  if (dsel) dsel.value = prevDefault;
  for (const btn of body.querySelectorAll("button.x")) {
    btn.addEventListener("click", () => removeNode(btn.dataset.name));
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
  $("btn-update").addEventListener("click", updateSubs);
  $("btn-save-settings").addEventListener("click", saveSettings);
  $("btn-add-sub").addEventListener("click", addSub);
  $("btn-save-geo").addEventListener("click", saveGeo);
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
  setStatus(await invoke("proxy_status"));
}

window.addEventListener("DOMContentLoaded", init);
