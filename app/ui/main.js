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
  $("import-arg").addEventListener("keydown", (e) => {
    if (e.key === "Enter") doImport();
  });

  $("config-path").textContent = await invoke("config_path");
  await refreshNodes();
  await loadSettings();
  setStatus(await invoke("proxy_status"));
}

window.addEventListener("DOMContentLoaded", init);
