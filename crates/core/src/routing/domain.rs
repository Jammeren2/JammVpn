//! Доменные правила маршрутизации (`RTE-*`).

/// Способ сопоставления домена.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainRule {
    /// Точное совпадение хоста.
    Full(String),
    /// Совпадение домена и всех его поддоменов (`example.com` ⊇ `a.example.com`).
    Suffix(String),
    /// Подстрока в имени хоста.
    Keyword(String),
}

impl DomainRule {
    /// Совпадает ли правило с хостом (регистр и завершающая точка игнорируются).
    pub fn matches(&self, host: &str) -> bool {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        match self {
            DomainRule::Full(d) => h == d.to_ascii_lowercase(),
            DomainRule::Suffix(d) => {
                let d = d.trim_start_matches('.').to_ascii_lowercase();
                h == d || h.ends_with(&format!(".{d}"))
            }
            DomainRule::Keyword(k) => h.contains(&k.to_ascii_lowercase()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_match() {
        let r = DomainRule::Full("example.com".into());
        assert!(r.matches("example.com"));
        assert!(r.matches("EXAMPLE.com."));
        assert!(!r.matches("a.example.com"));
    }

    #[test]
    fn suffix_match() {
        let r = DomainRule::Suffix("example.com".into());
        assert!(r.matches("example.com"));
        assert!(r.matches("a.b.example.com"));
        assert!(!r.matches("notexample.com"));
        assert!(!r.matches("example.com.evil.net"));
    }

    #[test]
    fn keyword_match() {
        let r = DomainRule::Keyword("google".into());
        assert!(r.matches("www.google.com"));
        assert!(r.matches("googlevideo.com"));
        assert!(!r.matches("example.com"));
    }
}
