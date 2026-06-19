// JammVPN — слой представления поверх main.js (бэкенд через Tauri).
// main.js — канонический источник: пишет в скрытые #status / #server / #nodes-body
// и владеет всеми invoke-командами. Этот файл рисует дизайн «Атлас/Центр/Минимал»:
// сайдбар-навигация, мировая карта с пинами, варианты главной, слайд-овер узлов,
// статистика с графиком, переключатели. Данные берём из бэкенда, не из моков.
(function () {
  const app = document.getElementById("app");
  const $ = (id) => document.getElementById(id);
  const tauriCore = window.__TAURI__ && window.__TAURI__.core;
  const invoke = tauriCore ? tauriCore.invoke : null;

  function ready(fn) {
    if (document.readyState !== "loading") fn();
    else document.addEventListener("DOMContentLoaded", fn);
  }
  function esc(s) {
    return String(s).replace(/[&<>"]/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])
    );
  }
  // Копирование с фолбэком: navigator.clipboard может молча не работать в webview
  // (контекст/права), поэтому при сбое — скрытый textarea + execCommand("copy").
  async function copyText(text) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (_) {}
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      if (ok) return true;
    } catch (_) {}
    throw new Error("clipboard unavailable");
  }

  // --- Проекция карты (как в дизайне) ---
  const LON0 = -170, LON1 = 190, LAT0 = -56, LAT1 = 80;
  function proj(lon, lat) {
    return { x: (lon - LON0) / (LON1 - LON0), y: (LAT1 - lat) / (LAT1 - LAT0) };
  }
  // «Точка отправления» (наша геопозиция). По умолчанию — центр, затем уточняем по IP.
  let USER = { lon: 10, lat: 30 };

  // Реальная гео-привязка по IP (онлайн, geojs.io; домены резолвим через DoH):
  // кешируем host → {lon,lat}. Недоступен (офлайн/блокировка) — фолбэк на хеш.
  const GEO_CACHE_KEY = "jamm_geo";
  let geoCache = {};
  try { geoCache = JSON.parse(localStorage.getItem(GEO_CACHE_KEY) || "{}") || {}; } catch (e) {}
  function saveGeoCache() {
    try { localStorage.setItem(GEO_CACHE_KEY, JSON.stringify(geoCache)); } catch (e) {}
  }
  function hostOf(addr) {
    return String(addr || "").trim().replace(/^\[/, "").replace(/\]?:\d+$/, "").replace(/\]$/, "");
  }
  function hashStr(s) {
    let h = 2166136261;
    for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
    return h >>> 0;
  }
  // Запасная (декоративная) позиция, пока/если реальная неизвестна.
  function hashedPos(key) {
    const h = hashStr(key || "x");
    return { lon: -160 + (h % 320), lat: -40 + ((h >> 9) % 95) };
  }
  function nodeGeo(addr) {
    const h = hostOf(addr);
    if (h && geoCache[h]) return geoCache[h];
    return hashedPos(h || addr || "x");
  }

  // Домен → IP через DNS-over-HTTPS (geojs принимает только IP). IP отдаём как есть.
  const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
  async function resolveIp(host) {
    if (!host) return "";
    if (IPV4_RE.test(host) || host.includes(":")) return host; // уже IP-литерал
    try {
      const r = await fetch("https://dns.google/resolve?name=" + encodeURIComponent(host) + "&type=A", { cache: "no-store" });
      const j = await r.json();
      const a = (j.Answer || []).find((x) => x.type === 1 && x.data);
      if (a) return a.data;
    } catch (e) {}
    return null;
  }

  // Запрос гео по IP/домену; "" → наш собственный IP. Кешируется.
  async function geoLookup(host) {
    const key = host || "__self__";
    if (geoCache[key]) return geoCache[key];
    try {
      let url = "https://get.geojs.io/v1/ip/geo.json"; // свой IP
      if (host) {
        const ip = await resolveIp(host);
        if (!ip) return null;
        url = "https://get.geojs.io/v1/ip/geo/" + encodeURIComponent(ip) + ".json";
      }
      const r = await fetch(url, { cache: "no-store" });
      if (!r.ok) return null;
      const j = await r.json();
      const lat = parseFloat(j && j.latitude);
      const lon = parseFloat(j && j.longitude);
      if (isFinite(lat) && isFinite(lon)) {
        const pos = { lon, lat };
        geoCache[key] = pos;
        if (host) geoCache[host] = pos;
        saveGeoCache();
        return pos;
      }
    } catch (e) {}
    return null;
  }

  let lastGeoKey = "";
  async function geolocateAll() {
    const self = await geoLookup("");
    if (self) USER = self;
    const hosts = [...new Set(rows().map((r) => hostOf(r.addr)).filter(Boolean))];
    for (const h of hosts) {
      if (!geoCache[h]) await geoLookup(h);
    }
    buildPins(); // переставить пины на реальные координаты (дуга обновится сама в loop)
  }
  // Запускаем гео-привязку при появлении новых хостов (с кешем — без лишних запросов).
  function maybeGeolocate() {
    const key = rows().map((r) => hostOf(r.addr)).sort().join(",");
    if (key === lastGeoKey) return;
    lastGeoKey = key;
    geolocateAll();
  }

  // ----------------------------------------------------------------
  // Данные узлов из скрытой таблицы (#nodes-body), которую ведёт main.js.
  // ----------------------------------------------------------------
  function rows() {
    const body = $("nodes-body");
    const trs = body
      ? [...body.querySelectorAll("tr")].filter((tr) => !tr.classList.contains("group-head"))
      : [];
    if (trs.length) {
      return trs.map((tr) => {
        const td = tr.querySelectorAll("td");
        const lat = tr.querySelector(".lat");
        return {
          value: td[1] ? td[1].textContent : "",
          name: td[1] ? td[1].textContent : "",
          proto: td[2] ? td[2].textContent : "",
          addr: td[3] ? td[3].textContent : "",
          lat: lat ? lat.textContent.trim() : "",
          latClass: lat
            ? lat.classList.contains("ok") ? "ok" : lat.classList.contains("err") ? "err" : ""
            : "",
          group: tr.dataset.group || "",
        };
      });
    }
    // Фолбэк: из опций скрытого #server (без бэкенда / до первой отрисовки).
    const sel = $("server");
    return sel
      ? [...sel.options]
          .filter((o) => o.value !== "")
          .map((o) => ({ value: o.value, name: o.textContent, proto: "", addr: "", lat: "", latClass: "", group: "" }))
      : [];
  }
  function curRow() {
    const v = ($("server") || {}).value || "";
    if (!v) return null;
    return rows().find((r) => r.value === v) || null;
  }
  function ccFromName(name) {
    const letters = String(name).replace(/[^A-Za-zА-Яа-я]/g, "");
    return (letters.slice(0, 2) || "··").toUpperCase();
  }

  // ----------------------------------------------------------------
  // Статус: зеркало скрытого #status (его пишет main.js) во весь UI.
  // ----------------------------------------------------------------
  let connecting = false;
  let connectedSince = null;

  function statusOn() {
    const s = $("status");
    return !!(s && s.classList.contains("on"));
  }
  function applyStatus() {
    const on = statusOn();
    const state = connecting ? "connecting" : on ? "on" : "off";
    app.dataset.state = state;
    if (state === "on" && !connectedSince) connectedSince = Date.now();
    if (state === "off") connectedSince = null;

    const friendly = state === "on" ? "Защищено" : state === "connecting" ? "Подключение…" : "Не защищено";
    const txtCol = state === "on" ? "#6ee7b7" : state === "connecting" ? "#fde047" : "#fca5a5";
    const glow = state === "on" ? "#34d399" : state === "connecting" ? "#facc15" : "#f87171";

    document.querySelectorAll("[data-statusdot]").forEach((e) => {
      e.style.background = glow;
      e.style.boxShadow = "0 0 9px " + glow;
      e.style.animation = state === "connecting" ? "blink 1s infinite" : "none";
    });
    document.querySelectorAll("[data-statustext], [data-statustext-c]").forEach((e) => {
      e.textContent = friendly;
      e.style.color = txtCol;
    });
    document.querySelectorAll("[data-statuspill]").forEach((e) => {
      e.style.background =
        state === "on" ? "rgba(52,211,153,.13)" : state === "connecting" ? "rgba(250,204,21,.12)" : "rgba(248,113,113,.12)";
      e.style.border =
        "1px solid " + (state === "on" ? "rgba(52,211,153,.28)" : state === "connecting" ? "rgba(250,204,21,.28)" : "rgba(248,113,113,.26)");
    });
    document.querySelectorAll("[data-connect].btn-connect").forEach((e) => {
      e.textContent = state === "on" ? "Отключиться" : state === "connecting" ? "Подключение…" : "Подключиться";
    });
    document.querySelectorAll("[data-ringtitle]").forEach((e) => {
      e.textContent = state === "on" ? "Вкл" : state === "connecting" ? "…" : "Выкл";
    });
    const sc = state === "on" ? "#22d3ee" : state === "connecting" ? "#facc15" : "#5b6479";
    document.querySelectorAll("[data-shield]").forEach((e) => e.setAttribute("stroke", sc));
    markDirty(); // состояние сменилось — перерисовать карту/график
  }

  async function onConnect() {
    if (connecting) return;
    if (statusOn()) {
      if (window.stopAll) await window.stopAll();
    } else {
      connecting = true;
      applyStatus();
      try {
        if (window.startAll) await window.startAll();
      } finally {
        connecting = false;
        applyStatus();
      }
    }
  }

  // ----------------------------------------------------------------
  // Режимы (SOCKS5 / Split / WG-сервер) — UI поверх getModes/toggleMode.
  // ----------------------------------------------------------------
  const MODE_DEFS = [["socks", "SOCKS5"], ["split", "Split"], ["wg", "WG-сервер"]];
  function curModes() {
    return window.getModes ? window.getModes() : { socks: true, split: false, wg: false };
  }
  function buildModes() {
    const m = curModes();
    document.querySelectorAll("[data-modes]").forEach((box) => {
      const lbl = box.querySelector(".mlbl");
      box.innerHTML = "";
      if (lbl) box.appendChild(lbl);
      MODE_DEFS.forEach(([k, label]) => {
        const b = document.createElement("button");
        b.className = "mode" + (m[k] ? " on" : "");
        b.dataset.mode = k;
        b.textContent = label;
        b.addEventListener("click", () => {
          if (window.toggleMode) window.toggleMode(k);
          syncModes();
        });
        box.appendChild(b);
      });
    });
  }
  function syncModes() {
    const m = curModes();
    document.querySelectorAll("[data-mode]").forEach((b) => b.classList.toggle("on", !!m[b.dataset.mode]));
  }

  // ----------------------------------------------------------------
  // Слайд-овер «Серверы и узлы» (#nodeList) + пины на карте.
  // ----------------------------------------------------------------
  const expanded = new Set();

  function nodeRowHtml(r, selected) {
    const isWg = /wireguard|amnezia|awg/i.test(r.proto);
    const isVless = /vless/i.test(r.proto);
    const isSs = /shadowsocks|ss-?2022/i.test(r.proto);
    const isHy2 = /hysteria/i.test(r.proto);
    let acts = `<span class="node-act" data-ping="${esc(r.name)}" title="Тест задержки">⚡</span>`;
    if (isVless) acts += `<span class="node-act" data-vless="${esc(r.name)}" title="Копировать vless://">⧉</span>`;
    if (isSs) acts += `<span class="node-act" data-ss="${esc(r.name)}" title="Копировать ss://">⧉</span>`;
    if (isHy2) acts += `<span class="node-act" data-hy2="${esc(r.name)}" title="Копировать hysteria2://">⧉</span>`;
    if (!r.group) {
      if (isWg) acts += `<span class="node-act" data-export="${esc(r.name)}" title="Экспорт .conf">⤓</span>`;
      acts += `<span class="node-act del" data-del="${esc(r.name)}" title="Удалить">✕</span>`;
    }
    const lat = r.lat && r.lat !== "—" ? `<span class="node-lat ${r.latClass}">${esc(r.lat)}</span>` : "";
    const sub = [r.proto, r.addr].filter(Boolean).join(" · ");
    return `<div class="node-row${selected ? " sel" : ""}" data-pick="${esc(r.value)}">
      <span class="node-radio"></span>
      <span class="node-nm"><span class="c">${esc(r.name)}</span><span class="k">${esc(sub)}</span></span>
      ${lat}<span class="node-acts">${acts}</span></div>`;
  }

  function renderNodes() {
    const list = $("nodeList");
    if (!list) return;
    const val = ($("server") || {}).value || "";
    const all = rows();
    const own = all.filter((r) => !r.group);
    const groups = new Map();
    for (const g of Object.keys(window.SUB_URLS || {})) groups.set(g, []);
    for (const r of all) {
      if (!r.group) continue;
      if (!groups.has(r.group)) groups.set(r.group, []);
      groups.get(r.group).push(r);
    }

    let html = `<div class="node-row auto${val === "" ? " sel" : ""}" data-pick="">
      <span class="node-radio"></span>
      <span class="node-nm"><span class="c">Авто</span><span class="k">по правилам конфига</span></span></div>`;
    if (own.length) {
      html += `<div class="node-sec">🔑 Свои ключи</div>`;
      for (const r of own) html += nodeRowHtml(r, val === r.value);
    }
    for (const [g, gl] of groups) {
      const open = expanded.has(g);
      const hasSel = gl.some((r) => r.value === val);
      html += `<div class="sub-head${hasSel ? " has-sel" : ""}" data-sub="${esc(g)}">
        <span class="sub-caret">${open ? "▾" : "▸"}</span>
        <span class="sub-name">📡 ${esc(g)}</span>
        <span class="sub-count">${gl.length}</span>
        <span class="sub-icon" data-copysub="${esc(g)}" title="Копировать ссылку подписки">⧉</span>
        <span class="sub-icon" data-refresh="${esc(g)}" title="Обновить подписку">⟳</span>
        <span class="sub-icon" data-delsub="${esc(g)}" title="Удалить подписку">✕</span></div>`;
      if (open) {
        html += `<div class="sub-kids">`;
        for (const r of gl) html += nodeRowHtml(r, val === r.value);
        html += `</div>`;
      }
    }
    if (!all.length && !Object.keys(window.SUB_URLS || {}).length) {
      html += `<p class="np-empty">Узлов нет — нажмите «+ Добавить».</p>`;
    }
    list.innerHTML = html;
  }

  function selectByValue(v) {
    const sel = $("server");
    if (!sel) return;
    sel.value = v;
    sel.dispatchEvent(new Event("change", { bubbles: true })); // main.js: onNodeChange
    app.classList.remove("sp-open");
  }

  function setupNodeList() {
    const list = $("nodeList");
    if (!list) return;
    list.addEventListener("click", async (e) => {
      const t = e.target;
      let a;
      if ((a = t.closest(".node-act[data-ping]"))) {
        e.stopPropagation();
        if (!invoke) return;
        const name = a.dataset.ping;
        const row = a.closest(".node-row");
        // Показываем "…" в ячейке задержки рядом с узлом на время проверки.
        let latEl = row && row.querySelector(".node-lat");
        if (row && !latEl) {
          latEl = document.createElement("span");
          row.insertBefore(latEl, row.querySelector(".node-acts"));
        }
        if (latEl) { latEl.className = "node-lat"; latEl.textContent = "…"; }
        try {
          const r = await invoke("test_node_latency", { name });
          if (latEl) {
            if (r.latency_ms != null) { latEl.textContent = r.latency_ms + " ms"; latEl.className = "node-lat ok"; }
            else { latEl.textContent = "ошибка"; latEl.className = "node-lat err"; }
          }
        } catch (_) {
          if (latEl) { latEl.textContent = "ошибка"; latEl.className = "node-lat err"; }
        }
        return;
      }
      if ((a = t.closest(".node-act[data-vless], .node-act[data-ss], .node-act[data-hy2]"))) {
        e.stopPropagation();
        if (!invoke) return;
        let cmd, name;
        if (a.hasAttribute("data-ss")) {
          cmd = "export_ss_link";
          name = a.dataset.ss;
        } else if (a.hasAttribute("data-hy2")) {
          cmd = "export_hysteria2_link";
          name = a.dataset.hy2;
        } else {
          cmd = "export_vless_link";
          name = a.dataset.vless;
        }
        try {
          const link = await invoke(cmd, { name });
          await copyText(link);
          a.textContent = "✓";
          setTimeout(() => (a.textContent = "⧉"), 1000);
        } catch (_) {
          a.textContent = "✗";
          setTimeout(() => (a.textContent = "⧉"), 1000);
        }
        return;
      }
      if ((a = t.closest(".node-act[data-export]"))) {
        e.stopPropagation();
        if (window.exportNode) window.exportNode(a.dataset.export);
        return;
      }
      if ((a = t.closest(".node-act[data-del]"))) {
        e.stopPropagation();
        if (window.removeNode) await window.removeNode(a.dataset.del);
        return;
      }
      if ((a = t.closest(".sub-icon[data-copysub]"))) {
        e.stopPropagation();
        const url = (window.SUB_URLS || {})[a.dataset.copysub];
        if (url) {
          try {
            await copyText(url);
            a.textContent = "✓";
          } catch (_) {
            a.textContent = "✗";
          }
          setTimeout(() => (a.textContent = "⧉"), 1000);
        }
        return;
      }
      if ((a = t.closest(".sub-icon[data-refresh]"))) {
        e.stopPropagation();
        if (!invoke) return;
        const url = (window.SUB_URLS || {})[a.dataset.refresh];
        if (url) {
          a.textContent = "…";
          try { await invoke("update_one_subscription", { url }); } catch (_) {}
          if (window.refreshNodes) await window.refreshNodes();
        }
        return;
      }
      if ((a = t.closest(".sub-icon[data-delsub]"))) {
        e.stopPropagation();
        const g = a.dataset.delsub;
        const url = (window.SUB_URLS || {})[g];
        if (url && invoke) {
          const ok = window.customConfirm ? await window.customConfirm(`Удалить подписку «${g}» и её узлы?`) : true;
          if (!ok) return;
          try { await invoke("remove_subscription", { url }); } catch (_) {}
          if (window.refreshNodes) await window.refreshNodes();
        }
        return;
      }
      if ((a = t.closest(".sub-head[data-sub]"))) {
        const g = a.dataset.sub;
        if (expanded.has(g)) expanded.delete(g); else expanded.add(g);
        renderNodes();
        return;
      }
      if ((a = t.closest(".node-row[data-pick]"))) {
        selectByValue(a.dataset.pick);
        return;
      }
    });

    // «Тест задержек» в шапке панели → реальный скрытый #btn-test (main.js).
    const testAll = $("btn-test-all");
    const testReal = $("btn-test");
    if (testAll && testReal) {
      testAll.addEventListener("click", () => { if (!testReal.disabled) testReal.click(); });
      const mirror = () => {
        testAll.disabled = testReal.disabled;
        testAll.textContent = testReal.disabled ? "Тестирую…" : "Тест задержек";
      };
      new MutationObserver(mirror).observe(testReal, { attributes: true, childList: true, characterData: true, subtree: true });
      mirror();
    }
  }

  // --- Пины на карте ---
  function buildPins() {
    const layer = $("pinLayer");
    if (!layer) return;
    const all = rows();
    layer.innerHTML = "";
    for (const r of all) {
      const g = nodeGeo(r.addr || r.name);
      const p = proj(g.lon, g.lat);
      const b = document.createElement("button");
      b.className = "pin";
      b.style.left = (p.x * 100).toFixed(2) + "%";
      b.style.top = (p.y * 100).toFixed(2) + "%";
      b.dataset.value = r.value;
      b.innerHTML = `<span class="pdot"></span><span class="plabel">${esc(r.name)}</span>`;
      b.addEventListener("click", () => selectByValue(r.value));
      layer.appendChild(b);
    }
    markPins();
    markMapDirty();
  }
  function markPins() {
    const val = ($("server") || {}).value || "";
    const layer = $("pinLayer");
    if (layer) layer.querySelectorAll(".pin").forEach((p) => p.classList.toggle("sel", p.dataset.value === val));
  }
  function selNodePos() {
    const r = curRow();
    return r ? nodeGeo(r.addr || r.name) : null;
  }

  // --- Выбранный узел во все варианты ---
  function applySel() {
    const r = curRow();
    const city = r ? r.name : "Авто";
    const cc = r ? ccFromName(r.name) : "AUTO";
    const ep = r ? r.addr : "по правилам конфига";
    const pingNum = r && r.lat && r.lat !== "—" ? r.lat.replace(/\s*ms$/i, "") : "—";
    const meta = r ? ep : "по правилам конфига";
    document.querySelectorAll("[data-selcity]").forEach((e) => (e.textContent = city));
    document.querySelectorAll("[data-selcc]").forEach((e) => (e.textContent = cc));
    document.querySelectorAll("[data-selep]").forEach((e) => (e.textContent = ep));
    document.querySelectorAll("[data-selping]").forEach((e) => (e.textContent = pingNum));
    document.querySelectorAll("[data-selload]").forEach((e) => (e.textContent = "—"));
    document.querySelectorAll("[data-selmeta]").forEach((e) => (e.textContent = meta));
    document.querySelectorAll("[data-metarow]").forEach((e) => (e.style.opacity = r ? "1" : ".5"));
    markPins();
    markMapDirty(); // выбранный узел сменился — обновить дугу/подсветку на карте
  }

  function refreshNodeUI() {
    renderNodes();
    buildPins();
    applySel();
    maybeGeolocate();
  }

  // ----------------------------------------------------------------
  // Переключатели: визуальный .toggle ↔ скрытый <input type=checkbox>,
  // который читает/пишет main.js. syncToggles вызывает main.js после load*.
  // ----------------------------------------------------------------
  function setupToggles() {
    document.querySelectorAll("[data-tg-for]").forEach((btn) => {
      const cb = $(btn.dataset.tgFor);
      btn.addEventListener("click", () => {
        if (!cb) { btn.classList.toggle("on"); return; }
        cb.checked = !cb.checked;
        btn.classList.toggle("on", cb.checked);
        cb.dispatchEvent(new Event("change", { bubbles: true }));
      });
    });
    syncToggles();
  }
  function syncToggles() {
    document.querySelectorAll("[data-tg-for]").forEach((btn) => {
      const cb = $(btn.dataset.tgFor);
      if (cb) btn.classList.toggle("on", cb.checked);
    });
  }
  window.syncToggles = syncToggles;

  // ----------------------------------------------------------------
  // Статистика соединений (живой опрос бэкенда) + скорости + график.
  // ----------------------------------------------------------------
  let measured = { d: 0, u: 0 }; // байт/с
  let prevBytes = new Map();
  let prevT = Date.now();
  let paused = false;
  let sortKey = "proc";

  function fmtBytes(n) {
    if (!n) return "—";
    if (n < 1024) return Math.round(n) + " Б";
    if (n < 1048576) return (n / 1024).toFixed(1) + " КБ";
    return (n / 1048576).toFixed(1) + " МБ";
  }
  function fmtSpeed(bps) {
    if (bps < 1) return "0 Б/с";
    if (bps < 1024) return Math.round(bps) + " Б/с";
    if (bps < 1048576) return (bps / 1024).toFixed(1) + " КБ/с";
    return (bps / 1048576).toFixed(2) + " МБ/с";
  }

  function updateSpeeds(list) {
    const now = Date.now();
    const dt = Math.max(0.2, (now - prevT) / 1000);
    let dUp = 0, dDown = 0;
    const cur = new Map();
    for (const c of list) {
      cur.set(c.id, { up: c.up, down: c.down });
      const p = prevBytes.get(c.id);
      if (p) { dUp += Math.max(0, c.up - p.up); dDown += Math.max(0, c.down - p.down); }
      else { dUp += c.up; dDown += c.down; }
    }
    prevBytes = cur;
    prevT = now;
    measured = { d: dDown / dt, u: dUp / dt };
  }

  function connRow(c) {
    const via = c.via === "direct" ? "direct" : c.via === "block" ? "block" : "proxy";
    const viaLabel = via === "direct" ? "напрямую" : via === "block" ? "заблок." : "прокси";
    return `<div class="conn-row">
      <span class="conn-proc"><span class="conn-dot ${via}"></span><span>—</span></span>
      <span class="conn-dest">${esc(c.target)}</span>
      <span class="conn-via">${viaLabel}</span>
      <span class="conn-up">${fmtBytes(c.up)}</span>
      <span class="conn-down">${fmtBytes(c.down)}</span>
      <span class="conn-kill"><button data-kill="${c.id}" title="Закрыть соединение">✕</button></span></div>`;
  }
  function renderConns(list) {
    const box = $("conns");
    if (!box) return;
    list.sort((a, b) => {
      if (sortKey === "ip") return b.up - a.up;
      if (sortKey === "proc" || sortKey === "dest") return String(a.target).localeCompare(String(b.target));
      return b.down - a.down;
    });
    box.innerHTML = list.length ? list.map(connRow).join("") : '<div class="empty">Нет активных соединений.</div>';
    const cc = document.querySelector("[data-conncount]");
    if (cc) cc.textContent = list.length;
  }

  async function poll() {
    if (!invoke || document.hidden) return; // в фоне не дёргаем бэкенд и UI
    try {
      const list = await invoke("list_connections");
      updateSpeeds(list);
      if (!paused) renderConns(list);
      if (measured.d || measured.u) wake(); // есть трафик — оживить индикаторы скорости
    } catch (_) {
      measured = { d: 0, u: 0 };
    }
  }

  function setupStats() {
    const box = $("conns");
    if (box) {
      box.addEventListener("click", (e) => {
        const b = e.target.closest("button[data-kill]");
        if (b && invoke) invoke("drop_connection", { id: parseInt(b.dataset.kill, 10) }).then(poll);
      });
    }
    const seg = $("st-sort");
    if (seg) {
      seg.addEventListener("click", (e) => {
        const b = e.target.closest(".seg-btn");
        if (!b) return;
        sortKey = b.dataset.sort;
        seg.querySelectorAll(".seg-btn").forEach((x) => x.classList.toggle("active", x === b));
        poll();
      });
    }
    const pause = $("st-pause");
    if (pause) {
      pause.addEventListener("click", () => {
        paused = !paused;
        pause.classList.toggle("paused", paused);
        pause.textContent = paused ? "▶ Продолжить" : "❚❚ Пауза";
      });
    }
    if (!invoke && box) box.innerHTML = '<div class="empty">Нет данных (бэкенд недоступен).</div>';
    poll();
    setInterval(poll, 1500);
  }

  // ----------------------------------------------------------------
  // Анимация: карта, график, скорости, параллакс (rAF-цикл).
  // Цикл экономный: ~30 fps, останавливается в простое и при сворачивании
  // окна (иначе webview жёг бы CPU постоянно, даже в фоне).
  // ----------------------------------------------------------------
  const DREF = 3 * 1048576, UREF = 512 * 1024; // шкала индикаторов скорости
  const FRAME_MS = 1000 / 30;
  const spd = { d: 0, u: 0 };
  const hist = new Array(140).fill(0);
  let t = 0, lastHist = 0, prevFrame = performance.now();
  const par = { x: 0, y: 0 }, parT = { x: 0, y: 0 };

  let timer = null, running = true;
  let mapDirty = true, graphDirty = true;
  let lastSpdD = "", lastSpdU = "", lastUptime = "";
  // Кеш DOM-элементов (не меняются после старта) — чтобы не сканировать документ каждый кадр.
  let elSpdD = [], elSpdU = [], elBarD = [], elBarU = [], elUptime = [], elBg = null, elMi = null;
  function cacheEls() {
    elSpdD = [...document.querySelectorAll('[data-spd="d"]')];
    elSpdU = [...document.querySelectorAll('[data-spd="u"]')];
    elBarD = [...document.querySelectorAll('[data-bar="d"]')];
    elBarU = [...document.querySelectorAll('[data-bar="u"]')];
    elUptime = [...document.querySelectorAll("[data-uptime]")];
    elBg = $("bgLayer"); elMi = $("mapInner");
  }

  function markMapDirty() { mapDirty = true; wake(); }
  function markDirty() { mapDirty = true; graphDirty = true; wake(); }
  // Планировщик на setTimeout (~30 fps) — меньше пробуждений, чем rAF на 60–144 Гц.
  function wake() { if (running && timer == null) timer = setTimeout(frame, 0); }
  function setRunning(v) {
    if (v === running) return;
    running = v;
    if (running) { prevFrame = performance.now(); markDirty(); }
    else if (timer != null) { clearTimeout(timer); timer = null; }
  }

  function setupParallax() {
    app.addEventListener("mousemove", (e) => {
      const r = app.getBoundingClientRect();
      parT.x = ((e.clientX - r.left) / r.width - 0.5) * 2;
      parT.y = ((e.clientY - r.top) / r.height - 0.5) * 2;
      wake();
    });
  }

  let dots = null, twinkle = [];
  fetch("world-dots.json")
    .then((r) => r.json())
    .then((j) => { dots = j.dots; for (let i = 0; i < 70; i++) twinkle.push(Math.floor(Math.random() * dots.length)); markMapDirty(); })
    .catch(() => { dots = []; });

  function qb(a, b, c, tt) { const m = 1 - tt; return m * m * a + 2 * m * tt * b + tt * tt * c; }

  // Статичные точки карты — один раз в offscreen-слой; каждый кадр только blit.
  let dotsLayer = null, dotsLW = 0, dotsLH = 0;
  function buildDotsLayer(w, h, dpr) {
    dotsLayer = document.createElement("canvas");
    dotsLayer.width = Math.round(w * dpr);
    dotsLayer.height = Math.round(h * dpr);
    const d = dotsLayer.getContext("2d");
    d.setTransform(dpr, 0, 0, dpr, 0, 0);
    const ds = Math.max(1.3, w / 640);
    d.fillStyle = "rgba(118,162,205,0.18)";
    for (let i = 0; i < dots.length; i++) d.fillRect(dots[i][0] * w, dots[i][1] * h, ds, ds);
    dotsLW = w; dotsLH = h;
  }

  function drawMap(on, isConnecting) {
    const active = on || isConnecting;
    const c = $("mapCanvas");
    if (!c) return;
    const w = c.clientWidth, h = c.clientHeight;
    if (!w || !h) return;
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    if (c.width !== Math.round(w * dpr)) { c.width = Math.round(w * dpr); c.height = Math.round(h * dpr); }
    const ctx = c.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    if (dots && dots.length) {
      if (!dotsLayer || dotsLW !== w || dotsLH !== h) buildDotsLayer(w, h, dpr);
      ctx.drawImage(dotsLayer, 0, 0, w, h);
      if (active) { // мерцание — только в активном состоянии (иначе карта статична)
        const ds = Math.max(1.3, w / 640);
        ctx.fillStyle = "rgba(170,225,255,0.95)";
        for (let j = 0; j < twinkle.length; j++) {
          const d = dots[twinkle[j]];
          if (!d) continue;
          ctx.globalAlpha = 0.25 + 0.55 * (0.5 + 0.5 * Math.sin(t * 1.7 + twinkle[j]));
          ctx.fillRect(d[0] * w - 0.4, d[1] * h - 0.4, ds + 1, ds + 1);
        }
        ctx.globalAlpha = 1;
      }
    }
    const u = proj(USER.lon, USER.lat);
    const ux = u.x * w, uy = u.y * h;
    const np = selNodePos();
    if (np) {
      const s = proj(np.lon, np.lat);
      const sx = s.x * w, sy = s.y * h;
      if (on) {
        const g = ctx.createRadialGradient(sx, sy, 0, sx, sy, 95);
        g.addColorStop(0, "rgba(34,211,238,0.26)");
        g.addColorStop(1, "rgba(34,211,238,0)");
        ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(sx, sy, 95, 0, 7); ctx.fill();
      }
      if (on || isConnecting) {
        const mx = (ux + sx) / 2, my = (uy + sy) / 2 - Math.hypot(sx - ux, sy - uy) * 0.3;
        const col = isConnecting ? "rgba(250,204,21,0.85)" : "rgba(34,211,238,0.9)";
        ctx.lineWidth = 1.6; ctx.strokeStyle = col; ctx.shadowColor = col; ctx.shadowBlur = 11;
        ctx.setLineDash([2, 7]); ctx.lineDashOffset = -t * 24;
        ctx.beginPath(); ctx.moveTo(ux, uy); ctx.quadraticCurveTo(mx, my, sx, sy); ctx.stroke();
        ctx.setLineDash([]); ctx.shadowBlur = 0;
        if (on) {
          const tt = (t * 0.33) % 1, bx = qb(ux, mx, sx, tt), by = qb(uy, my, sy, tt);
          ctx.fillStyle = "#eaffff"; ctx.shadowColor = "#22d3ee"; ctx.shadowBlur = 13;
          ctx.beginPath(); ctx.arc(bx, by, 3, 0, 7); ctx.fill(); ctx.shadowBlur = 0;
        }
      }
    }
    ctx.lineWidth = 1.5; ctx.strokeStyle = "rgba(255,255,255,0.85)";
    ctx.beginPath(); ctx.arc(ux, uy, 4.2, 0, 7); ctx.stroke();
    ctx.fillStyle = "rgba(255,255,255,0.92)";
    ctx.beginPath(); ctx.arc(ux, uy, 1.7, 0, 7); ctx.fill();
  }

  function drawGraph(on) {
    const c = $("graphCanvas");
    if (!c) return;
    const w = c.clientWidth, h = c.clientHeight;
    if (!w || !h) return;
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    if (c.width !== Math.round(w * dpr)) { c.width = Math.round(w * dpr); c.height = Math.round(h * dpr); }
    const ctx = c.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    let max = 1;
    for (const v of hist) if (v > max) max = v;
    const n = hist.length, step = w / (n - 1);
    let i, x, y;
    ctx.beginPath();
    for (i = 0; i < n; i++) { x = i * step; y = h - Math.min(1, hist[i] / max) * (h - 6) - 3; i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); }
    ctx.lineTo(w, h); ctx.lineTo(0, h); ctx.closePath();
    const g = ctx.createLinearGradient(0, 0, 0, h);
    g.addColorStop(0, "rgba(34,211,238,0.35)");
    g.addColorStop(1, "rgba(34,211,238,0)");
    ctx.fillStyle = g; ctx.fill();
    ctx.beginPath();
    for (i = 0; i < n; i++) { x = i * step; y = h - Math.min(1, hist[i] / max) * (h - 6) - 3; i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); }
    ctx.strokeStyle = on ? "rgba(34,211,238,0.95)" : "rgba(120,150,180,0.5)";
    ctx.lineWidth = 1.6; ctx.stroke();
  }

  function parSettled() {
    return Math.abs(parT.x - par.x) <= 0.002 && Math.abs(parT.y - par.y) <= 0.002;
  }
  // Простой = ничего не анимируется → можно остановить rAF (нулевой CPU).
  function isSettled() {
    const active = statusOn() || connecting;
    return !active && !mapDirty && !graphDirty && parSettled() && spd.d === 0 && spd.u === 0;
  }

  function step(dt) {
    t += dt;
    const on = statusOn(), isConnecting = connecting, active = on || isConnecting;

    // Скорости плавно тянутся к измеренным (или к нулю, если выключено).
    const tgt = active ? measured : { d: 0, u: 0 };
    spd.d += (tgt.d - spd.d) * 0.2;
    spd.u += (tgt.u - spd.u) * 0.2;
    if (Math.abs(spd.d - tgt.d) < 1) spd.d = tgt.d;
    if (Math.abs(spd.u - tgt.u) < 1) spd.u = tgt.u;

    const sD = fmtSpeed(spd.d), sU = fmtSpeed(spd.u);
    if (sD !== lastSpdD) {
      lastSpdD = sD;
      for (const e of elSpdD) e.textContent = sD;
      const wd = Math.min(100, (spd.d / DREF) * 100) + "%";
      for (const e of elBarD) e.style.width = wd;
    }
    if (sU !== lastSpdU) {
      lastSpdU = sU;
      for (const e of elSpdU) e.textContent = sU;
      const wu = Math.min(100, (spd.u / UREF) * 100) + "%";
      for (const e of elBarU) e.style.width = wu;
    }

    if (active && t - lastHist > 0.18) { lastHist = t; hist.push(spd.d); hist.shift(); graphDirty = true; }

    const upStr = connectedSince ? hms(Date.now() - connectedSince) : "—";
    if (upStr !== lastUptime) { lastUptime = upStr; for (const e of elUptime) e.textContent = upStr; }

    if (!parSettled()) {
      par.x += (parT.x - par.x) * 0.08;
      par.y += (parT.y - par.y) * 0.08;
      if (elBg) elBg.style.transform = "scale(1.08) translate(" + par.x * -16 + "px," + par.y * -16 + "px)";
      if (elMi) elMi.style.transform = "translate(" + par.x * 9 + "px," + par.y * 9 + "px)";
      mapDirty = true;
    }

    // Рисуем только видимый холст; флаг «dirty» невидимого — сразу снимаем,
    // иначе он навсегда держал бы цикл «не в простое».
    const tab = app.dataset.tab;
    if (tab === "home") { if (active || mapDirty) drawMap(on, isConnecting); }
    mapDirty = false;
    if (tab === "stats") { if (active || graphDirty) drawGraph(on); }
    graphDirty = false;
  }

  function frame() {
    timer = null;
    if (!running) return;
    const now = performance.now();
    const dt = Math.min(0.05, (now - prevFrame) / 1000);
    prevFrame = now;
    step(dt);
    if (!isSettled()) timer = setTimeout(frame, FRAME_MS); // в простое — останавливаемся
  }
  function hms(ms) {
    const s = Math.floor(ms / 1000);
    const p = (x) => String(x).padStart(2, "0");
    return p(Math.floor(s / 3600)) + ":" + p(Math.floor((s % 3600) / 60)) + ":" + p(s % 60);
  }

  // ----------------------------------------------------------------
  // Навигация, варианты, версия.
  // ----------------------------------------------------------------
  function setupNav() {
    document.querySelectorAll("[data-nav]").forEach((b) => {
      b.addEventListener("click", () => {
        app.dataset.tab = b.dataset.nav;
        document.querySelectorAll("[data-nav]").forEach((x) => x.classList.toggle("active", x === b));
        if (b.dataset.nav === "logs" && window.loadLog) window.loadLog();
        markDirty(); // показалась карта/график — перерисовать
      });
    });
  }
  function setupVariants() {
    let variant = "C";
    try { variant = localStorage.getItem("jamm_variant") || "C"; } catch (e) {}
    app.dataset.variant = variant;
    document.querySelectorAll("[data-var]").forEach((b) => {
      b.classList.toggle("active", b.dataset.var === variant);
      b.addEventListener("click", () => {
        variant = b.dataset.var;
        try { localStorage.setItem("jamm_variant", variant); } catch (e) {}
        app.dataset.variant = variant;
        document.querySelectorAll("[data-var]").forEach((x) => x.classList.toggle("active", x === b));
      });
    });
  }
  function setupServerPanel() {
    document.querySelectorAll("[data-openservers]").forEach((b) => b.addEventListener("click", () => app.classList.add("sp-open")));
    document.querySelectorAll("[data-closeservers]").forEach((b) => b.addEventListener("click", () => app.classList.remove("sp-open")));
  }
  function setupConnect() {
    document.querySelectorAll("[data-connect]").forEach((b) => b.addEventListener("click", onConnect));
  }
  function setupVersion() {
    const btn = $("ver-btn");
    // Открываем страницу проекта в браузере по умолчанию через бэкенд
    // (window.open в Tauri-webview не открывает внешний браузер).
    if (btn)
      btn.addEventListener("click", () => {
        if (invoke) invoke("open_url", { url: "https://github.com/Jammeren2/JammVpn" }).catch(() => {});
      });
    if (invoke) {
      invoke("app_version")
        .then((v) => {
          if (!v) return;
          if (btn && btn.firstChild) btn.firstChild.nodeValue = "v" + v + " ";
          const sub = $("acct-sub");
          if (sub) sub.textContent = "v" + v;
        })
        .catch(() => {});
    }
  }

  // ----------------------------------------------------------------
  ready(function () {
    setupNav();
    setupVariants();
    setupServerPanel();
    setupConnect();
    setupVersion();
    buildModes();
    syncModes();
    setupNodeList();
    setupToggles();
    setupStats();
    setupParallax();

    // Перерисовка узлов/пинов при изменениях, которые делает main.js.
    const sel = $("server");
    const body = $("nodes-body");
    if (sel) {
      new MutationObserver(refreshNodeUI).observe(sel, { childList: true });
      sel.addEventListener("change", () => { renderNodes(); applySel(); });
    }
    if (body) new MutationObserver(refreshNodeUI).observe(body, { childList: true, subtree: true, characterData: true });

    // Зеркало статуса: следим за скрытым #status (его пишет main.js).
    const status = $("status");
    if (status) {
      new MutationObserver(applyStatus).observe(status, { attributes: true, childList: true, characterData: true, subtree: true });
    }

    // Док подсказки запуска прокси показываем только когда в #proxy-hint есть текст.
    const ph = $("proxy-hint");
    const dock = ph && ph.closest(".hint-dock");
    if (ph && dock) {
      const syncDock = () => dock.classList.toggle("show", ph.textContent.trim() !== "");
      new MutationObserver(syncDock).observe(ph, { childList: true, characterData: true, subtree: true });
      syncDock();
    }

    // Пауза анимации, когда окно скрыто/свёрнуто в трей — иначе webview
    // продолжает жечь CPU в фоне. Возобновляем при возврате.
    document.addEventListener("visibilitychange", () => setRunning(!document.hidden));
    window.addEventListener("focus", () => setRunning(!document.hidden));
    window.addEventListener("blur", () => { if (document.hidden) setRunning(false); });
    window.addEventListener("resize", markDirty);

    cacheEls();
    refreshNodeUI();
    applyStatus();
    running = !document.hidden;
    markDirty();
    wake();
  });
})();
