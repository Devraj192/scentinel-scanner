use crate::detection::service::sniff_version;
use crate::results::model::sanitize;

/// One distro or vendor signal found in service text.
pub struct OsHint {
    pub family: &'static str,
    pub version: Option<String>,
    pub confidence: f32,
    pub snippet: String,
}

/// Quote at most 96 chars of banner text as evidence.
fn snippet(text: &str) -> String {
    sanitize(text).chars().take(96).collect()
}

/// Check service and banner text for explicit operating-system tokens.
/// Returns at most one hint per text: the first listed match wins, so more
/// specific vendors come before generic platform words.
pub fn distro_hint(service: Option<&str>, version: Option<&str>, banner: &str) -> Option<OsHint> {
    let haystacks = [service.unwrap_or(""), version.unwrap_or(""), banner];
    // (token, family, confidence)
    const SIGNALS: &[(&str, &str, f32)] = &[
        ("Microsoft", "Windows", 0.6),
        ("Windows", "Windows", 0.6),
        ("IIS", "Windows", 0.6),
        ("Exchange", "Windows", 0.55),
        ("Ubuntu", "Linux", 0.6),
        ("Debian", "Linux", 0.6),
        ("CentOS", "Linux", 0.6),
        ("Red Hat", "Linux", 0.6),
        ("Fedora", "Linux", 0.6),
        ("Alpine", "Linux", 0.6),
        ("OpenWrt", "Linux", 0.6),
        ("FreeBSD", "BSD", 0.6),
        ("OpenBSD", "BSD", 0.6),
        ("NetBSD", "BSD", 0.6),
        ("macOS", "macOS", 0.55),
        ("Darwin", "macOS", 0.55),
        ("Linux", "Linux", 0.5),
    ];
    for text in haystacks {
        for (token, family, confidence) in SIGNALS {
            if text.contains(token) {
                return Some(OsHint {
                    family,
                    version: sniff_version(text),
                    confidence: *confidence,
                    snippet: snippet(text),
                });
            }
        }
    }
    None
}

/// Implementation banners prove software, not the OS underneath: OpenSSH
/// ships on Linux, the BSDs, macOS, and Windows alike.
pub fn software_only_hint(service: Option<&str>) -> Option<OsHint> {
    match service {
        Some(name) if name.eq_ignore_ascii_case("ssh") => Some(OsHint {
            family: "Unix-like",
            version: None,
            confidence: 0.35,
            snippet: "SSH service banner".to_owned(),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_ubuntu() {
        let hint =
            distro_hint(None, None, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1").expect("hint");
        assert_eq!(hint.family, "Linux");
        assert!(hint.version.is_some());
    }

    #[test]
    fn finds_windows() {
        let hint = distro_hint(Some("http"), Some("Microsoft-IIS/10.0"), "").expect("hint");
        assert_eq!(hint.family, "Windows");
    }

    #[test]
    fn ignores_plain_openssh() {
        assert!(distro_hint(Some("ssh"), Some("OpenSSH_9.3"), "").is_none());
    }

    #[test]
    fn ssh_alone_is_weak_unix_like() {
        let hint = software_only_hint(Some("ssh")).expect("hint");
        assert_eq!(hint.family, "Unix-like");
        assert_eq!(hint.version, None);
    }
}
