use crate::detection::service::{sniff_version, Detection, Evidence, ServiceDetector};

/// SMTP servers greet with `220` plus mail tokens on connect. Passive only:
/// no EHLO, no mail commands, nothing that starts a session.
pub struct SmtpDetector;

impl ServiceDetector for SmtpDetector {
    fn name(&self) -> &'static str {
        "smtp"
    }

    fn match_banner(&self, banner: &[u8], _port: u16) -> Option<Detection> {
        let text = std::str::from_utf8(banner).ok()?;
        let line = text.lines().next()?;
        if !line.starts_with("220") {
            return None;
        }
        if !(line.contains("SMTP") || line.contains("ESMTP") || line.contains("mail")) {
            return None;
        }
        Some(Detection::new(
            "smtp",
            sniff_version(line),
            0.85,
            vec![
                Evidence::observation(&format!("banner: {line}")),
                Evidence::inference("220 greeting with mail tokens reads as SMTP"),
            ],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_postfix() {
        let detection = SmtpDetector
            .match_banner(b"220 mail.example.com ESMTP Postfix\r\n", 25)
            .expect("match");
        assert_eq!(detection.service, "smtp");
        assert_eq!(detection.version, None);
    }

    #[test]
    fn matches_exim_with_version() {
        let detection = SmtpDetector
            .match_banner(b"220-mail ESMTP Exim 4.96\r\n", 25)
            .expect("match");
        assert_eq!(detection.version.as_deref(), Some("Exim 4.96"));
    }
}
