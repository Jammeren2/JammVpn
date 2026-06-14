//! Разбор и сопоставление CIDR/IP без внешних зависимостей.

use crate::error::ParseError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IP-подсеть (IPv4/IPv6) с длиной префикса.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpCidr {
    base: IpAddr,
    prefix: u8,
}

impl IpCidr {
    /// Разбирает `"10.0.0.0/8"`, `"::1/128"` или одиночный IP (как `/32`/`/128`).
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        let (ip_str, prefix_opt) = match s.split_once('/') {
            Some((ip, p)) => {
                let pfx = p
                    .parse::<u8>()
                    .map_err(|_| ParseError::InvalidCidr(s.to_string()))?;
                (ip, Some(pfx))
            }
            None => (s, None),
        };
        let base: IpAddr = ip_str
            .parse()
            .map_err(|_| ParseError::InvalidCidr(s.to_string()))?;
        let max = if base.is_ipv4() { 32 } else { 128 };
        let prefix = prefix_opt.unwrap_or(max);
        if prefix > max {
            return Err(ParseError::InvalidCidr(s.to_string()));
        }
        Ok(IpCidr { base, prefix })
    }

    /// Конструирует подсеть из адреса и длины префикса.
    pub fn new(base: IpAddr, prefix: u8) -> Result<Self, ParseError> {
        let max = if base.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(ParseError::InvalidCidr(format!("{base}/{prefix}")));
        }
        Ok(IpCidr { base, prefix })
    }

    /// Базовый адрес подсети.
    pub fn base(&self) -> IpAddr {
        self.base
    }

    /// Длина префикса.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Входит ли адрес в подсеть (разные семейства → `false`).
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.base, ip) {
            (IpAddr::V4(base), IpAddr::V4(addr)) => v4_match(base, addr, self.prefix),
            (IpAddr::V6(base), IpAddr::V6(addr)) => v6_match(base, addr, self.prefix),
            _ => false,
        }
    }
}

fn v4_match(base: Ipv4Addr, addr: Ipv4Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(base) & mask) == (u32::from(addr) & mask)
}

fn v6_match(base: Ipv6Addr, addr: Ipv6Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else if prefix >= 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from(base) & mask) == (u128::from(addr) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn v4_subnet() {
        let c = IpCidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(ip("10.5.6.7")));
        assert!(!c.contains(ip("11.0.0.1")));
    }

    #[test]
    fn v4_bare_is_host() {
        let c = IpCidr::parse("1.2.3.4").unwrap();
        assert!(c.contains(ip("1.2.3.4")));
        assert!(!c.contains(ip("1.2.3.5")));
    }

    #[test]
    fn v4_default_route() {
        assert!(IpCidr::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
    }

    #[test]
    fn v6_subnet() {
        assert!(IpCidr::parse("::1/128").unwrap().contains(ip("::1")));
        assert!(IpCidr::parse("fc00::/7").unwrap().contains(ip("fd12::1")));
        assert!(!IpCidr::parse("fc00::/7")
            .unwrap()
            .contains(ip("2001:db8::1")));
    }

    #[test]
    fn family_mismatch() {
        assert!(!IpCidr::parse("10.0.0.0/8").unwrap().contains(ip("::1")));
    }

    #[test]
    fn rejects_bad() {
        assert!(IpCidr::parse("notanip").is_err());
        assert!(IpCidr::parse("10.0.0.0/40").is_err());
    }

    #[test]
    fn new_and_accessors_roundtrip() {
        let c = IpCidr::new(ip("172.16.0.0"), 12).unwrap();
        assert_eq!(c.base(), ip("172.16.0.0"));
        assert_eq!(c.prefix(), 12);
        assert!(c.contains(ip("172.16.5.5")));
        assert!(IpCidr::new(ip("10.0.0.0"), 33).is_err());
    }
}
