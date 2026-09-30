/// Hostname syntax check (no DNS lookup; Phase 1 sends no traffic).
pub fn is_valid_hostname_syntax(name: &str) -> bool {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.is_empty() || trimmed.len() > 253 {
        return false;
    }
    // Reject anything that parses as an IP literal; those go through the IP path.
    if trimmed.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    trimmed.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_names() {
        assert!(is_valid_hostname_syntax("example.com"));
        assert!(is_valid_hostname_syntax("localhost"));
        assert!(is_valid_hostname_syntax("host-1.lan."));
    }

    #[test]
    fn rejects_bad_names() {
        assert!(!is_valid_hostname_syntax(""));
        assert!(!is_valid_hostname_syntax("-bad.example"));
        assert!(!is_valid_hostname_syntax("bad_.example"));
        assert!(!is_valid_hostname_syntax("has space.example"));
        // IP literals are not hostnames here.
        assert!(!is_valid_hostname_syntax("192.168.1.1"));
    }
}
