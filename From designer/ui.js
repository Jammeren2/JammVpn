// JammVPN — UI-слой поверх логики: вкладки, зеркало статуса, монитор статистики.
// Аддитивный файл: НЕ трогает main.js и его id/классы-крючки.
(function () {
  function ready(fn) {
    if (document.readyState !== "loading") fn();
    else document.addEventListener("DOMContentLoaded", fn);
  }

  ready(function () {
    setupTabs();
    setupStatusMirror();
    setupStats();
  });

  // --- Вкладки ---
  function setupTabs() {
    const tabs = [...document.querySelectorAll(".tab")];
    const panels = [...document.querySelectorAll(".tabpanel")];
    function activate(name) {
      tabs.forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
      panels.forEach((p) =>
        p.classList.toggle("active", p.dataset.tabPanel === name)
      );
    }
    tabs.forEach((t) => t.addEventListener("click", () => activate(t.dataset.tab)));
  }

  // --- Зеркало статуса в app-bar + состояние кольца на «Главной» ---
  function setupStatusMirror() {
    const status = document.getElementById("status");
    const mirror = document.getElementById("appbar-status");
    const hero = document.querySelector(".hero");
    if (!status) return;
    function sync() {
      const on = status.classList.contains("on");
      if (mirror) {
        mirror.textContent = status.textContent || "—";
        mirror.className = "appbar-status " + (on ? "on" : "off");
      }
      if (hero) hero.classList.toggle("is-on", on);
    }
    new MutationObserver(sync).observe(status, {
      attributes: true,
      childList: true,
      characterData: true,
      subtree: true,
    });
    sync();
  }

  // --- Статистика соединений (демо-монитор; данные подключаются к бэкенду) ---
  function setupStats() {
    const body = document.getElementById("st-body");
    if (!body) return;

    // Пример живых соединений. В реальном приложении заполняется командой
    // бэкенда (напр. invoke("list_connections")) с теми же полями.
    const conns = [
      { proc: "chrome.exe", dest: "youtube.com", ip: "142.250.74.46", node: "🇯🇵 Tokyo — TUIC", via: "proxy", up: 180, down: 4200 },
      { proc: "Telegram.exe", dest: "telegram.org", ip: "149.154.167.51", node: "🇳🇱 Amsterdam", via: "proxy", up: 95, down: 360 },
      { proc: "Spotify.exe", dest: "spotify.com", ip: "104.199.65.124", node: "напрямую", via: "direct", up: 18, down: 280 },
      { proc: "steam.exe", dest: "steamcontent.com", ip: "23.62.99.18", node: "🇩🇪 Frankfurt", via: "proxy", up: 60, down: 8800 },
      { proc: "Discord.exe", dest: "discord.com", ip: "162.159.135.232", node: "🇫🇮 Helsinki", via: "proxy", up: 140, down: 220 },
      { proc: "Code.exe", dest: "github.com", ip: "140.82.121.4", node: "напрямую", via: "direct", up: 32, down: 110 },
      { proc: "chrome.exe", dest: "ads.example", ip: "8.8.8.8", node: "заблокировано", via: "block", up: 0, down: 0 },
      { proc: "firefox.exe", dest: "wikipedia.org", ip: "208.80.154.224", node: "🇳🇱 Amsterdam", via: "proxy", up: 24, down: 540 },
    ];

    let sortKey = "proc";
    let paused = false;

    function fmt(kbps) {
      if (kbps <= 0) return "—";
      if (kbps < 1000) return kbps.toFixed(0) + " КБ/с";
      return (kbps / 1000).toFixed(1) + " МБ/с";
    }

    function render() {
      const sorted = [...conns].sort((a, b) => {
        const x = String(a[sortKey]).toLowerCase();
        const y = String(b[sortKey]).toLowerCase();
        return x < y ? -1 : x > y ? 1 : 0;
      });
      body.innerHTML = sorted
        .map(
          (c) => `<div class="conn">
            <div class="conn-proc"><span class="conn-dot ${c.via}"></span>${esc(c.proc)}</div>
            <div class="conn-dest">${esc(c.dest)}<small>${esc(c.ip)}</small></div>
            <div class="conn-node">${esc(c.node)}</div>
            <div class="conn-up num">${fmt(c.up)}</div>
            <div class="conn-down num">${fmt(c.down)}</div>
          </div>`
        )
        .join("");

      const active = conns.filter((c) => c.via !== "block").length;
      const totalUp = conns.reduce((s, c) => s + c.up, 0);
      const totalDown = conns.reduce((s, c) => s + c.down, 0);
      setText("st-active", active);
      setText("st-up", fmt(totalUp));
      setText("st-down", fmt(totalDown));
    }

    // Лёгкое «дыхание» цифр, чтобы монитор выглядел живым; пауза замораживает.
    function tick() {
      if (paused) return;
      for (const c of conns) {
        if (c.via === "block") continue;
        const j = (base) => Math.max(0, Math.round(base * (0.82 + Math.random() * 0.36)));
        c.up = j(c.up || 20);
        c.down = j(c.down || 40);
      }
      render();
    }

    // Сортировка
    document.getElementById("st-sort").addEventListener("click", (e) => {
      const btn = e.target.closest(".seg-btn");
      if (!btn) return;
      sortKey = btn.dataset.sort;
      document
        .querySelectorAll("#st-sort .seg-btn")
        .forEach((b) => b.classList.toggle("active", b === btn));
      render();
    });

    // Пауза
    const pauseBtn = document.getElementById("st-pause");
    pauseBtn.addEventListener("click", () => {
      paused = !paused;
      pauseBtn.classList.toggle("paused", paused);
      pauseBtn.textContent = paused ? "▶ Продолжить" : "❚❚ Пауза";
    });

    render();
    setInterval(tick, 1300);
  }

  function setText(id, v) {
    const el = document.getElementById(id);
    if (el) el.textContent = v;
  }
  function esc(s) {
    return String(s).replace(/[&<>"]/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])
    );
  }
})();
