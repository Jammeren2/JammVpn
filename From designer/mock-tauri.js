// Заглушка Tauri-API ТОЛЬКО для предпросмотра дизайна в браузере.
// В реальном приложении эти данные приходят из Rust-бэкенда (window.__TAURI__).
// Дизайнеру трогать этот файл не нужно — он лишь наполняет интерфейс примерами.
(function () {
  const nodes = [
    { name: "🇳🇱 Amsterdam — VLESS", protocol: "vless", address: "nl.example.com", port: 443 },
    { name: "🇩🇪 Frankfurt — Trojan", protocol: "trojan", address: "de.example.com", port: 443 },
    { name: "🇫🇮 Helsinki — Shadowsocks", protocol: "shadowsocks", address: "fi.example.com", port: 8388 },
    { name: "🇯🇵 Tokyo — TUIC", protocol: "tuic", address: "jp.example.com", port: 443 },
  ];
  const subscriptions = [
    { url: "https://sub.example.com/link", tag: "main", update_interval_hours: 12 },
    { url: "https://other.example.net/feed", tag: null, update_interval_hours: 24 },
  ];
  const rules = [
    { domains: ["suffix:youtube.com", "keyword:googlevideo"], ip_cidrs: [], processes: [], ports: [], geosite: [], geoip: [], action: "proxy", proxy_tag: "🇯🇵 Tokyo — TUIC" },
    { domains: [], ip_cidrs: [], processes: [], ports: [], geosite: ["category-ru"], geoip: ["ru"], action: "direct", proxy_tag: null },
    { domains: ["suffix:ads.example"], ip_cidrs: [], processes: [], ports: [], geosite: ["category-ads"], geoip: [], action: "block", proxy_tag: null },
  ];
  const split = {
    mode: "inclusive",
    apps: ["name:chrome.exe", "exe:C:\\Games\\game.exe"],
    inherit_children: true,
    kill_switch: true,
    force_direct: ["192.168.0.0/16"],
    force_tunnel: ["10.0.0.0/8"],
    endpoints: ["nl.example.com:443"],
  };

  const wait = (v, ms = 250) => new Promise((r) => setTimeout(() => r(v), ms));

  async function invoke(cmd, args) {
    switch (cmd) {
      case "config_path":
        return "C:\\Users\\you\\AppData\\Roaming\\jammvpn\\config.json";
      case "list_nodes":
        return nodes;
      case "proxy_status":
        return null; // или "127.0.0.1:1080" для состояния «запущен»
      case "proxy_start":
        return "127.0.0.1:1080";
      case "proxy_stop":
        return null;
      case "test_latencies":
        return wait(nodes.map((n, i) => ({ name: n.name, latency_ms: i === 2 ? null : 40 + i * 35, error: i === 2 ? "timeout" : null })), 900);
      case "list_subscriptions":
        return subscriptions;
      case "update_subscriptions":
        return wait(subscriptions.map((s) => ({ url: s.url, count: 7, error: null })), 900);
      case "geo_status":
        return { geosite_path: "C:\\jammvpn\\geosite.dat", geosite_exists: true, geoip_path: "C:\\jammvpn\\geoip.dat", geoip_exists: false };
      case "get_settings":
        return { default_to_proxy: true, default_proxy: "🇳🇱 Amsterdam — VLESS" };
      case "list_rules":
        return rules;
      case "autostart_status":
        return false;
      case "get_split":
        return split;
      case "split_status":
        return false;
      case "import":
        return "импортирован узел: пример [vless]";
      // Команды записи — просто подтверждаем (для предпросмотра ничего не меняем).
      case "add_subscription":
      case "remove_subscription":
      case "remove_node":
      case "set_settings":
      case "set_geo_paths":
      case "add_rule":
      case "update_rule":
      case "remove_rule":
      case "move_rule":
      case "set_autostart":
      case "set_split":
      case "split_apply":
      case "split_clear":
        return wait(true, 150);
      default:
        console.warn("[mock] неизвестная команда:", cmd, args);
        return null;
    }
  }

  window.__TAURI__ = { core: { invoke } };
  // confirm() в браузере работает; в реальном приложении — тоже.
})();
