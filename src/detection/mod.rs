pub mod banner;
pub mod service;

use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::config::Limits;
use crate::results::model::{Banner, PortResult};
use crate::safety::scope::ScopeGuard;
use crate::scanner::rate_limit::RateLimiter;
use service::{Detection, ServiceDetector};

/// All detectors, passive matchers first so active probes only fire when the
/// banner was inconclusive. Adding a detector means adding a file under
/// `protocols/` plus one line here; the engine below never changes.
pub fn all() -> Vec<Box<dyn ServiceDetector>> {
    vec![
        Box::new(crate::protocols::ssh::SshDetector),
        Box::new(crate::protocols::ftp::FtpDetector),
        Box::new(crate::protocols::smtp::SmtpDetector),
        Box::new(crate::protocols::http::HttpDetector),
        Box::new(crate::protocols::http::HttpsDetector),
        Box::new(crate::protocols::dns::DnsDetector),
        Box::new(crate::protocols::generic::GenericDetector),
    ]
}

/// Handles an active detector may use. Everything is owned so probes can move
/// into spawned tasks; every connection still passes the scope guard and the
/// shared concurrency/rate caps.
pub struct ActiveCtx {
    pub ip: IpAddr,
    pub port: u16,
    pub banner: Vec<u8>,
    pub limits: Limits,
    pub guard: ScopeGuard,
    pub semaphore: Arc<Semaphore>,
    pub rate: Arc<RateLimiter>,
}

/// Identify the service on one open port: passive banner match first, then at
/// most one active probe per detector, first confident match wins, Generic
/// always matches last. Never fails: the worst outcome is `unknown`.
///
/// Traffic budget per open port, on top of the one handshake the port scan
/// already made: one passive banner connection, then at most one HTTP `GET`
/// and one DNS query, each only while no earlier detector matched. Closed,
/// filtered, and unknown ports cost nothing here.
pub async fn identify(
    ip: IpAddr,
    port: u16,
    limits: &Limits,
    guard: &ScopeGuard,
    semaphore: &Arc<Semaphore>,
    rate: &Arc<RateLimiter>,
) -> PortResult {
    identify_with(&all(), ip, port, limits, guard, semaphore, rate).await
}

/// Same as [`identify`] with an explicit registry, so tests can plug in a new
/// detector without touching the engine.
pub async fn identify_with(
    detectors: &[Box<dyn ServiceDetector>],
    ip: IpAddr,
    port: u16,
    limits: &Limits,
    guard: &ScopeGuard,
    semaphore: &Arc<Semaphore>,
    rate: &Arc<RateLimiter>,
) -> PortResult {
    let banner = banner::grab(ip, port, limits, guard, semaphore, rate).await;
    let raw = banner
        .as_ref()
        .map(|banner| banner.raw.clone())
        .unwrap_or_default();

    for detector in detectors {
        if let Some(detection) = detector.match_banner(&raw, port) {
            tracing::info!(%ip, port, service = %detection.service, event = "service_detected");
            return finish(port, detection, banner);
        }
    }
    let ctx = ActiveCtx {
        ip,
        port,
        banner: raw,
        limits: limits.clone(),
        guard: guard.clone(),
        semaphore: Arc::clone(semaphore),
        rate: Arc::clone(rate),
    };
    for detector in detectors {
        if let Some(detection) = detector.probe(&ctx).await {
            tracing::info!(%ip, port, service = %detection.service, event = "service_detected");
            return finish(port, detection, banner);
        }
    }
    // Generic always matches, so this is unreachable in practice; keep the
    // fallback so a custom registry without Generic still yields `unknown`.
    finish(port, Detection::unknown("no detector matched"), banner)
}

fn finish(port: u16, detection: Detection, banner: Option<Banner>) -> PortResult {
    let stored = banner.unwrap_or(Banner {
        text: String::new(),
        encoding: "utf8".to_owned(),
        truncated: false,
        raw: Vec::new(),
    });
    PortResult {
        port,
        protocol: "tcp".to_owned(),
        state: crate::results::model::PortState::Open,
        reason: "handshake".to_owned(),
        latency_ms: 0,
        service: Some(detection.service),
        version: detection.version,
        confidence: Some(detection.confidence),
        evidence: detection.evidence,
        banner: Some(stored),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Limits;
    use crate::detection::service::{Detection, Evidence, ServiceDetector};
    use crate::safety::scope::{ParsedTarget, ScopeGuard};

    /// A detector the engine never knew about.
    struct HelloDetector;

    impl ServiceDetector for HelloDetector {
        fn name(&self) -> &'static str {
            "hello-test"
        }

        fn match_banner(&self, banner: &[u8], _port: u16) -> Option<Detection> {
            if banner.starts_with(b"HELLO-TEST") {
                Some(Detection::new(
                    "testproto",
                    Some("1.0".to_owned()),
                    0.5,
                    vec![Evidence::observation("hello greeting")],
                ))
            } else {
                None
            }
        }
    }

    #[tokio::test]
    async fn custom_detector_plugs_in_without_engine_changes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fixture");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                use tokio::io::AsyncWriteExt as _;
                let _ = socket.write_all(b"HELLO-TEST\r\n").await;
            }
        });
        let ip: IpAddr = "127.0.0.1".parse().expect("ip");
        let guard = ScopeGuard::from_targets(&[ParsedTarget::Ip(ip)]);
        let semaphore = Arc::new(Semaphore::new(4));
        let rate = Arc::new(RateLimiter::new(100));
        let registry: Vec<Box<dyn ServiceDetector>> = vec![
            Box::new(HelloDetector),
            Box::new(crate::protocols::generic::GenericDetector),
        ];
        let result = identify_with(
            &registry,
            ip,
            port,
            &Limits::default(),
            &guard,
            &semaphore,
            &rate,
        )
        .await;
        assert_eq!(result.service.as_deref(), Some("testproto"));
        assert_eq!(result.version.as_deref(), Some("1.0"));
    }
}
