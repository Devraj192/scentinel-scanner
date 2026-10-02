use crate::detection::service::{Detection, Evidence, ServiceDetector};

/// SSH servers greet with `SSH-2.0-software` on connect (RFC 4253), so a
/// passive banner match is decisive. No probe is ever sent.
pub struct SshDetector;

impl ServiceDetector for SshDetector {
    fn name(&self) -> &'static str {
        "ssh"
    }

    fn match_banner(&self, banner: &[u8], _port: u16) -> Option<Detection> {
        let line = std::str::from_utf8(banner).ok()?.lines().next()?;
        let rest = line.strip_prefix("SSH-")?;
        let (version, software) = rest.split_once('-')?;
        if version != "2.0" && version != "1.99" {
            return None;
        }
        let software = software.trim();
        if software.is_empty() {
            return None;
        }
        Some(Detection::new(
            "ssh",
            Some(software.to_owned()),
            0.95,
            vec![
                Evidence::observation(&format!("banner: {line}")),
                Evidence::inference("banner follows the SSH identification format"),
            ],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_openssh_banner() {
        let detection = SshDetector
            .match_banner(b"SSH-2.0-OpenSSH_9.3p1 Debian\r\n", 22)
            .expect("match");
        assert_eq!(detection.service, "ssh");
        assert_eq!(detection.version.as_deref(), Some("OpenSSH_9.3p1 Debian"));
        assert!(detection.confidence >= 0.9);
    }

    #[test]
    fn rejects_non_ssh() {
        assert!(SshDetector.match_banner(b"220 ftp\r\n", 22).is_none());
        assert!(SshDetector.match_banner(b"SSH-9.9-x\r\n", 22).is_none());
        assert!(SshDetector.match_banner(b"\x00\xff binary", 22).is_none());
    }
}
