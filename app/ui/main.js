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
  // сохраняем выбранное значение
  const prev = sel.value;
  sel.innerHTML = '<option value="">— по правилам конфига —</option>';
  for (const [i, n] of nodes.entries()) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${i + 1}</td><td>${esc(n.name)}</td><td>${esc(
      n.protocol
    )}</td><td>${esc(n.address)}:${n.port}</td><td class="lat" data-name="${esc(
      n.name
    )}">—</td>`;
    body.appendChild(tr);

    const opt = document.createElement("option");
    opt.value = n.name;
    opt.textContent = n.name;
    sel.appendChild(opt);
  }
  sel.value = prev;
  $("nodes-empty").style.display = nodes.length ? "none" : "block";
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
  $("import-arg").addEventListener("keydown", (e) => {
    if (e.key === "Enter") doImport();
  });

  $("config-path").textContent = await invoke("config_path");
  await refreshNodes();
  setStatus(await invoke("proxy_status"));
}

window.addEventListener("DOMContentLoaded", init);
