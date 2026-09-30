use serde::{Deserialize, Serialize};

use super::evidence::{distro_hint, software_only_hint};
use crate::detection::service::Evidence;
use crate::results::model::PortResult;

/// An operating-system estimate. Banner hints are weak by nature, so
/// confidence never exceeds 0.65 and a precise version appears only beside
/// an explicit distro token. Anything else is `Unknown`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OsGuess {
    pub family: String,
    pub version: Option<String>,
    pub confidence: f32,
    pub evidence: Vec<Evidence>,
}

impl OsGuess {
    /// Admit ignorance. Valid whenever the signals are thin.
    pub fn unknown() -> Self {
        Self {
            family: "Unknown".to_owned(),
            version: None,
            confidence: 0.0,
            evidence: vec![Evidence::observation("no OS-identifying tokens in banners")],
        }
    }
}

/// Estimate the OS from already-detected services and their banners only.
/// Sends no traffic and opens no sockets; raw-packet techniques are
/// deliberately absent (see DECISION.md).
pub fn fingerprint(ports: &[PortResult]) -> OsGuess {
    let mut best: Option<OsGuess> = None;
    for port in ports {
        if port.state != crate::results::model::PortState::Open {
            continue;
        }
        let banner = port
            .banner
            .as_ref()
            .map(|banner| banner.text.as_str())
            .unwrap_or("");
        let hint = distro_hint(port.service.as_deref(), port.version.as_deref(), banner)
            .or_else(|| software_only_hint(port.service.as_deref()));
        let Some(hint) = hint else {
            continue;
        };
        let confidence = hint.confidence.clamp(0.0, 0.65);
        let better = best
            .as_ref()
            .is_none_or(|current: &OsGuess| confidence > current.confidence);
        if better {
            best = Some(OsGuess {
                family: hint.family.to_owned(),
                version: hint.version,
                confidence,
                evidence: vec![
                    Evidence::observation(&format!("port {}: {}", port.port, hint.snippet)),
                    Evidence::inference(&format!(
                        "OS token suggests {} (banner hints are weak)",
                        hint.family
                    )),
                ],
            });
        }
    }
    best.unwrap_or_else(OsGuess::unknown)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::results::model::{Banner, PortState};

    fn open_port(service: &str, version: Option<&str>, banner: &str) -> PortResult {
        PortResult {
            port: 22,
            protocol: "tcp".to_owned(),
            state: PortState::Open,
            reason: "handshake".to_owned(),
            latency_ms: 1,
            service: Some(service.to_owned()),
            version: version.map(str::to_owned),
            confidence: Some(0.9),
            evidence: Vec::new(),
            banner: Some(Banner {
                text: banner.to_owned(),
                encoding: "utf8".to_owned(),
                truncated: false,
                raw: Vec::new(),
            }),
        }
    }

    #[test]
    fn ubuntu_banner_suggests_linux() {
        let guess = fingerprint(&[open_port(
            "ssh",
            Some("OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"),
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
        )]);
        assert_eq!(guess.family, "Linux");
        assert!(guess.version.is_some());
        assert!(guess.confidence <= 0.65);
    }

    #[test]
    fn plain_ssh_is_weak_and_versionless() {
        let guess = fingerprint(&[open_port("ssh", Some("OpenSSH_9.3"), "SSH-2.0-OpenSSH_9.3")]);
        assert_eq!(guess.family, "Unix-like");
        assert_eq!(guess.version, None);
        assert!(guess.confidence < 0.5);
    }

    #[test]
    fn silence_is_unknown() {
        assert_eq!(fingerprint(&[]), OsGuess::unknown());
    }

    #[test]
    fn closed_ports_contribute_nothing() {
        let mut port = open_port("http", Some("Microsoft-IIS/10.0"), "");
        port.state = PortState::Closed;
        assert_eq!(fingerprint(&[port]), OsGuess::unknown());
    }

    #[test]
    fn hostile_bytes_never_panic() {
        let guess = fingerprint(&[open_port("unknown", None, "\0\u{7}\u{1b}[2Jevil")]);
        assert_eq!(guess.family, "Unknown");
    }
}
