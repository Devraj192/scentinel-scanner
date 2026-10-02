use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};

use super::ActiveCtx;
use crate::results::model::sanitize;

/// What was seen (bytes on the wire) versus what was concluded from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceKind {
    Observation,
    Inference,
}

/// One fact behind a detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub detail: String,
}

impl Evidence {
    /// Network-derived text is sanitized at construction.
    pub fn observation(detail: &str) -> Self {
        Self {
            kind: EvidenceKind::Observation,
            detail: sanitize(detail),
        }
    }

    pub fn inference(detail: &str) -> Self {
        Self {
            kind: EvidenceKind::Inference,
            detail: detail.to_owned(),
        }
    }
}

/// A service identification. Confidence is the detector's own score on
/// 0.0-1.0, not an externally verified probability.
#[derive(Debug, Clone)]
pub struct Detection {
    pub service: String,
    pub version: Option<String>,
    pub confidence: f32,
    pub evidence: Vec<Evidence>,
}

impl Detection {
    /// Confidence is clamped to 0.0-1.0; details from the wire are sanitized.
    /// An empty service name is meaningless, so it becomes `unknown` at zero
    /// confidence rather than propagating a blank claim.
    pub fn new(
        service: &str,
        version: Option<String>,
        confidence: f32,
        evidence: Vec<Evidence>,
    ) -> Self {
        let (service, confidence) = if service.is_empty() {
            ("unknown".to_owned(), 0.0)
        } else {
            (service.to_owned(), confidence.clamp(0.0, 1.0))
        };
        Self {
            service,
            version: version.map(|version| sanitize(&version)),
            confidence,
            evidence,
        }
    }

    /// Fallback when nothing matched. `unknown` is a valid answer.
    pub fn unknown(detail: &str) -> Self {
        Self::new("unknown", None, 0.0, vec![Evidence::observation(detail)])
    }
}

/// One pluggable service detector. Passive matching reads already-grabbed
/// bytes and sends nothing; `probe` may open at most one short connection via
/// the context handles. Either method returns `None` to pass to the next
/// detector.
pub trait ServiceDetector: Send + Sync {
    fn name(&self) -> &'static str;

    /// Match against passively grabbed bytes. No I/O.
    fn match_banner(&self, banner: &[u8], port: u16) -> Option<Detection>;

    /// Active probe. The default sends nothing.
    fn probe<'a>(
        &'a self,
        ctx: &'a ActiveCtx,
    ) -> Pin<Box<dyn Future<Output = Option<Detection>> + Send + 'a>> {
        let _ = ctx;
        Box::pin(async move { None })
    }
}

/// Best-effort `Name x.y` extraction from greeting banners such as
/// `220 (vsFTPd 3.0.3)` or `220 mail ESMTP Exim 4.96`. Returns `None` rather
/// than guessing when nothing version-like is present.
pub fn sniff_version(banner: &str) -> Option<String> {
    let tokens: Vec<&str> = banner.split_whitespace().collect();
    for (index, token) in tokens.iter().enumerate() {
        let digits = token.bytes().filter(u8::is_ascii_digit).count();
        let dots = token.bytes().filter(|&b| b == b'.').count();
        if digits >= 2 && dots >= 1 {
            let number: String = token
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '_' || *c == '-')
                .collect();
            if index > 0 && tokens[index - 1].chars().any(|c| c.is_alphabetic()) {
                let name: String = tokens[index - 1]
                    .chars()
                    .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                    .collect();
                if !name.is_empty() && !number.is_empty() {
                    return Some(format!("{name} {number}"));
                }
            }
            if !number.is_empty() {
                return Some(number);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_name_and_number() {
        assert_eq!(
            sniff_version("220 (vsFTPd 3.0.3)").as_deref(),
            Some("vsFTPd 3.0.3")
        );
        assert_eq!(
            sniff_version("220 mail ESMTP Exim 4.96").as_deref(),
            Some("Exim 4.96")
        );
    }

    #[test]
    fn returns_none_without_version() {
        assert_eq!(sniff_version("220 Welcome"), None);
        assert_eq!(sniff_version(""), None);
    }

    #[test]
    fn clamps_confidence() {
        assert_eq!(Detection::new("ssh", None, 9.9, vec![]).confidence, 1.0);
    }

    #[test]
    fn blank_service_becomes_unknown() {
        let detection = Detection::new("", Some("1.0".to_owned()), 0.9, vec![]);
        assert_eq!(detection.service, "unknown");
        assert_eq!(detection.confidence, 0.0);
    }
}
