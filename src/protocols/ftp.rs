use crate::detection::service::{sniff_version, Detection, Evidence, ServiceDetector};

/// FTP servers greet with `220` on connect. Passive only: no USER/PASS or any
/// other command is ever sent.
pub struct FtpDetector;

impl ServiceDetector for FtpDetector {
    fn name(&self) -> &'static str {
        "ftp"
    }

    fn match_banner(&self, banner: &[u8], _port: u16) -> Option<Detection> {
        let text = std::str::from_utf8(banner).ok()?;
        let line = text.lines().next()?;
        if !line.starts_with("220") {
            return None;
        }
        // FTP and SMTP share the 220 greeting code and FTP runs first, so
        // decline anything that reads as mail unless it names FTP.
        let has_ftp = line.contains("FTP") || line.contains("ftp");
        let has_mail = line.contains("SMTP") || line.contains("ESMTP") || line.contains("mail");
        if has_mail && !has_ftp {
            return None;
        }
        Some(Detection::new(
            "ftp",
            sniff_version(line),
            0.85,
            vec![
                Evidence::observation(&format!("banner: {line}")),
                Evidence::inference("220 greeting without mail tokens reads as FTP"),
            ],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_vsftpd() {
        let detection = FtpDetector
            .match_banner(b"220 (vsFTPd 3.0.3)\r\n", 21)
            .expect("match");
        assert_eq!(detection.service, "ftp");
        assert_eq!(detection.version.as_deref(), Some("vsFTPd 3.0.3"));
    }

    #[test]
    fn declines_smtp_greetings() {
        assert!(FtpDetector
            .match_banner(b"220 mail ESMTP Postfix\r\n", 21)
            .is_none());
        assert!(FtpDetector
            .match_banner(b"220 mail ready\r\n", 21)
            .is_none());
    }

    #[test]
    fn rejects_non_ftp() {
        assert!(FtpDetector.match_banner(b"SSH-2.0-x\r\n", 21).is_none());
    }
}
