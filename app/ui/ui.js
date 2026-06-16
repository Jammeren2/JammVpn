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
    setupNodePicker();
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

  // --- Список узлов на Главной (зеркало скрытого #server, который ведёт main.js) ---
  function setupNodePicker() {
    const picker = document.getElementById("node-picker");
    const sel = document.getElementById("server");
    const nodesBody = document.getElementById("nodes-body");
    const heroLabel = document.getElementById("hero-node-label");
    if (!picker || !sel) return;

    // Данные берём из таблицы узлов (имя / протокол / адрес / задержка) —
    // она богаче опций select. Если таблицы нет — падаем на опции select.
    function rows() {
      const trs = nodesBody ? [...nodesBody.querySelectorAll("tr")] : [];
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
              ? lat.classList.contains("ok")
                ? "ok"
                : lat.classList.contains("err")
                  ? "err"
                  : ""
              : "",
          };
        });
      }
      return [...sel.options]
        .filter((o) => o.value !== "")
        .map((o) => ({ value: o.value, name: o.textContent, proto: "", addr: "", lat: "", latClass: "" }));
    }

    function item(r, selected, auto) {
      const sub = auto
        ? "по правилам конфига"
        : [r.proto, r.addr].filter(Boolean).join(" · ");
      const latBadge =
        !auto && r.lat && r.lat !== "—"
          ? `<span class="np-lat ${r.latClass}">${esc(r.lat)}</span>`
          : "";
      return `<button type="button" class="np-item${auto ? " np-auto" : ""}${
        selected ? " selected" : ""
      }" data-value="${esc(r.value)}">
        <span class="np-radio"></span>
        <span class="np-main"><span class="np-name">${esc(
          auto ? "Авто" : r.name
        )}</span><span class="np-sub">${esc(sub)}</span></span>
        ${latBadge}
      </button>`;
    }

    function render() {
      const val = sel.value || "";
      const list = rows();
      let html = item({ value: "" }, val === "", true);
      for (const r of list) html += item(r, val === r.value, false);
      if (!list.length)
        html += `<p class="np-empty">Узлов нет — добавьте их на вкладке «Узлы».</p>`;
      picker.innerHTML = html;

      if (heroLabel) {
        const cur = list.find((r) => r.value === val);
        heroLabel.innerHTML = val
          ? "Через <b>" + esc(cur ? cur.name : val) + "</b>"
          : "Авто — по правилам конфига";
      }
    }

    picker.addEventListener("click", (e) => {
      const btn = e.target.closest(".np-item");
      if (!btn) return;
      sel.value = btn.dataset.value;
      sel.dispatchEvent(new Event("change", { bubbles: true }));
      render();
    });

    // Кнопка-дублёр «Тест задержек» на Главной: запускает реальный #btn-test
    // (его слушает main.js) и зеркалит его состояние (disabled / «Тестирую…»).
    const testReal = document.getElementById("btn-test");
    const testHome = document.getElementById("btn-test-home");
    if (testReal && testHome) {
      testHome.addEventListener("click", () => {
        if (!testReal.disabled) testReal.click();
      });
      const mirror = () => {
        testHome.disabled = testReal.disabled;
        testHome.textContent = testReal.disabled ? "Тестирую…" : "Тест задержек";
      };
      new MutationObserver(mirror).observe(testReal, {
        attributes: true,
        childList: true,
        characterData: true,
        subtree: true,
      });
      mirror();
    }

    // main.js перестраивает #server (childList) и обновляет задержки в #nodes-body.
    new MutationObserver(render).observe(sel, { childList: true });
    // Восстановление выбора из настроек (main.js шлёт change) — перерисовать.
    sel.addEventListener("change", render);
    if (nodesBody)
      new MutationObserver(render).observe(nodesBody, {
        childList: true,
        subtree: true,
        characterData: true,
      });

    render();
  }

  // --- Статистика соединений (живой опрос бэкенда) ---
  // Реальные данные из движка: invoke("list_connections") → [{target, via, up, down}].
  function setupStats() {
    const body = document.getElementById("st-body");
    if (!body) return;
    const invoke =
      window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke;

    let sortKey = "down"; // proc|dest|down — сортировка
    let paused = false;

    function fmtBytes(n) {
      if (!n) return "—";
      if (n < 1024) return n + " Б";
      if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " КБ";
      return (n / 1024 / 1024).toFixed(1) + " МБ";
    }

    function row(c) {
      const node = c.via === "direct" ? "напрямую" : "прокси";
      return `<div class="conn">
        <div class="conn-proc"><span class="conn-dot ${esc(c.via)}"></span>—</div>
        <div class="conn-dest">${esc(c.target)}</div>
        <div class="conn-node">${esc(node)}</div>
        <div class="conn-up num">${fmtBytes(c.up)}</div>
        <div class="conn-down num">${fmtBytes(c.down)}</div>
        <div class="conn-kill"><button class="x" data-kill="${c.id}" title="Закрыть соединение">✕</button></div>
      </div>`;
    }

    // Делегированный клик: «дропнуть» соединение по id.
    body.addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-kill]");
      if (!btn) return;
      invoke("drop_connection", { id: parseInt(btn.dataset.kill, 10) }).then(poll);
    });

    function render(list) {
      list.sort((a, b) => {
        if (sortKey === "down") return b.down - a.down;
        if (sortKey === "ip") return b.up - a.up; // «IP» → по отдаче
        return String(a.target).localeCompare(String(b.target)); // proc/dest → по цели
      });
      body.innerHTML = list.length
        ? list.map(row).join("")
        : '<p class="np-empty">Нет активных соединений.</p>';
      setText("st-active", list.length);
      setText("st-up", fmtBytes(list.reduce((s, c) => s + c.up, 0)));
      setText("st-down", fmtBytes(list.reduce((s, c) => s + c.down, 0)));
    }

    async function poll() {
      if (paused || !invoke) return;
      try {
        render(await invoke("list_connections"));
      } catch (_) {
        /* прокси не запущен / нет данных */
      }
    }

    if (!invoke) {
      // Предпросмотр в браузере без бэкенда.
      body.innerHTML = '<p class="np-empty">Нет данных (бэкенд недоступен).</p>';
      return;
    }

    // Сортировка.
    const seg = document.getElementById("st-sort");
    if (seg)
      seg.addEventListener("click", (e) => {
        const btn = e.target.closest(".seg-btn");
        if (!btn) return;
        sortKey = btn.dataset.sort;
        seg.querySelectorAll(".seg-btn").forEach((b) => b.classList.toggle("active", b === btn));
        poll();
      });
    // Пауза.
    const pauseBtn = document.getElementById("st-pause");
    if (pauseBtn)
      pauseBtn.addEventListener("click", () => {
        paused = !paused;
        pauseBtn.classList.toggle("paused", paused);
        pauseBtn.textContent = paused ? "▶ Продолжить" : "❚❚ Пауза";
      });

    poll();
    setInterval(poll, 1500);
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
