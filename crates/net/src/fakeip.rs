//! FakeIP: синтетические IPv4 для доменов (ТЗ, раздел 5 — DNS/маршрутизация).
//!
//! Назначение: маршрутизировать по домену там, где приложение само резолвит и
//! подключается по IP (будущий TUN-режим). DNS-сервер выдаёт поддельный адрес из
//! заданного диапазона ([`FakeIp::allocate`]), движок при подключении к нему
//! восстанавливает домен ([`FakeIp::domain_of`]) и идёт по домену — реальный
//! резолв делает исходящий (remote DNS, без утечки и без раскрытия гео).
//!
//! Диапазон по умолчанию — `198.18.0.0/15` (RFC 2544, benchmarking; не
//! маршрутизируется в интернете, безопасен как «фейковое» пространство).

use jammvpn_core::split::IpCidr;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

/// Двунаправленное соответствие домен↔поддельный IP с round-robin-выделением и
/// вытеснением старейших привязок при исчерпании диапазона.
#[derive(Debug)]
pub struct FakeIp {
    /// Базовый (сетевой) адрес диапазона как `u32`.
    base: u32,
    /// Размер диапазона (число адресов).
    count: u32,
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    /// Следующий выделяемый сдвиг (1..count; 0 пропускаем — сетевой адрес).
    cursor: u32,
    dom_to_ip: HashMap<String, Ipv4Addr>,
    ip_to_dom: HashMap<Ipv4Addr, String>,
}

impl FakeIp {
    /// Строит аллокатор из IPv4 CIDR (например, `"198.18.0.0/15"`).
    ///
    /// Ошибка — если диапазон не IPv4 либо содержит меньше двух адресов.
    pub fn new(cidr: &str) -> Result<Self, String> {
        let c = IpCidr::parse(cidr).map_err(|e| e.to_string())?;
        let base_ip = match c.base() {
            IpAddr::V4(v) => u32::from(v),
            IpAddr::V6(_) => return Err("fakeip: нужен IPv4-диапазон".to_string()),
        };
        let prefix = c.prefix();
        let count = if prefix == 0 {
            // /0 нам не нужен и переполнил бы сдвиг; считаем некорректным.
            return Err("fakeip: слишком широкий диапазон".to_string());
        } else if prefix >= 32 {
            1
        } else {
            1u32 << (32 - prefix)
        };
        // Сдвиг 0 (сетевой адрес) не выдаётся, поэтому пригодных адресов = count-1.
        // Нужно ≥2 пригодных, иначе все домены коллапсируют в один IP (напр. /31).
        if count < 3 {
            return Err("fakeip: диапазон слишком мал (нужно ≥2 пригодных адресов)".to_string());
        }
        // Нормализуем базу к сетевому адресу (на случай host-бит в CIDR).
        let mask = u32::MAX << (32 - prefix);
        let base = base_ip & mask;
        Ok(Self {
            base,
            count,
            inner: Mutex::new(Inner {
                cursor: 1,
                ..Inner::default()
            }),
        })
    }

    /// Возвращает поддельный IP для домена, выделяя новый при первом обращении
    /// (повторные вызовы для того же домена возвращают тот же адрес).
    pub fn allocate(&self, domain: &str) -> Ipv4Addr {
        let mut g = self.inner.lock().unwrap();
        if let Some(ip) = g.dom_to_ip.get(domain) {
            return *ip;
        }
        let offset = g.cursor;
        g.cursor += 1;
        if g.cursor >= self.count {
            g.cursor = 1; // оборачиваемся, пропуская сдвиг 0
        }
        let ip = Ipv4Addr::from(self.base + offset);
        // Вытесняем прежнюю привязку этого адреса (при обороте диапазона).
        if let Some(old) = g.ip_to_dom.insert(ip, domain.to_string()) {
            if old != domain {
                g.dom_to_ip.remove(&old);
            }
        }
        g.dom_to_ip.insert(domain.to_string(), ip);
        ip
    }

    /// Восстанавливает домен по ранее выделенному поддельному IP.
    pub fn domain_of(&self, ip: IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(v) => self.inner.lock().unwrap().ip_to_dom.get(&v).cloned(),
            IpAddr::V6(_) => None,
        }
    }

    /// Принадлежит ли адрес диапазону FakeIP (overflow-безопасно).
    pub fn range_contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v) => u32::from(v).wrapping_sub(self.base) < self.count,
            IpAddr::V6(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_is_stable_and_reversible() {
        let fi = FakeIp::new("198.18.0.0/15").unwrap();
        let a1 = fi.allocate("example.com");
        let a2 = fi.allocate("example.com");
        assert_eq!(a1, a2, "тот же домен — тот же IP");
        let b = fi.allocate("other.org");
        assert_ne!(a1, b, "разные домены — разные IP");

        assert_eq!(fi.domain_of(IpAddr::V4(a1)).as_deref(), Some("example.com"));
        assert_eq!(fi.domain_of(IpAddr::V4(b)).as_deref(), Some("other.org"));
        assert!(fi.range_contains(IpAddr::V4(a1)));
        assert!(fi.range_contains(IpAddr::V4(b)));
    }

    #[test]
    fn allocated_ips_are_inside_range() {
        let fi = FakeIp::new("198.18.0.0/15").unwrap();
        for i in 0..1000 {
            let ip = fi.allocate(&format!("host{i}.test"));
            assert!(fi.range_contains(IpAddr::V4(ip)), "{ip} вне диапазона");
            // 198.18.0.0/15 → 198.18.0.0 .. 198.19.255.255
            let n = u32::from(ip);
            assert!((0xC612_0000..=0xC613_FFFF).contains(&n));
        }
    }

    #[test]
    fn unknown_ip_has_no_domain() {
        let fi = FakeIp::new("198.18.0.0/15").unwrap();
        assert_eq!(fi.domain_of("1.2.3.4".parse().unwrap()), None);
        assert!(!fi.range_contains("1.2.3.4".parse().unwrap()));
        // вне диапазона
        assert!(!fi.range_contains("198.20.0.1".parse().unwrap()));
    }

    #[test]
    fn recycles_and_evicts_on_wrap() {
        // Маленький диапазон /30 = 4 адреса (сдвиги 1..3 → 3 уникальных).
        let fi = FakeIp::new("10.0.0.0/30").unwrap();
        let first = fi.allocate("a.com");
        // Заполняем оборот, чтобы вернуться к адресу первого домена.
        let mut last_for_first_ip = "a.com".to_string();
        for i in 0..10 {
            let dom = format!("d{i}.com");
            let ip = fi.allocate(&dom);
            if ip == first {
                last_for_first_ip = dom;
            }
        }
        // После оборота адрес `first` принадлежит вытеснившему домену, а старая
        // привязка a.com снята (реверс не указывает на a.com).
        assert_eq!(
            fi.domain_of(IpAddr::V4(first)).as_deref(),
            Some(last_for_first_ip.as_str())
        );
        assert_ne!(
            fi.allocate("a.com"),
            first,
            "a.com переселён после вытеснения"
        );
    }

    #[test]
    fn rejects_bad_ranges() {
        assert!(FakeIp::new("::1/64").is_err()); // IPv6
        assert!(FakeIp::new("10.0.0.1/32").is_err()); // 1 адрес
        assert!(FakeIp::new("10.0.0.0/31").is_err()); // 2 адреса → 1 пригодный (коллапс)
        assert!(FakeIp::new("0.0.0.0/0").is_err()); // слишком широкий
        assert!(FakeIp::new("notacidr").is_err());
        // /30 (4 адреса → 3 пригодных) — допустим.
        assert!(FakeIp::new("10.0.0.0/30").is_ok());
    }
}
