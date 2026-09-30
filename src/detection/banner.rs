use std::net::IpAddr;
use std::sync::Arc;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::config::Limits;
use crate::results::model::{sanitize, Banner};
use crate::safety::scope::ScopeGuard;
use crate::scanner::rate_limit::RateLimiter;
use crate::scanner::timeout;

/// Open one bounded connection through the scope guard and shared caps.
/// Returns `None` when the connection itself fails.
pub async fn dial(
    ip: IpAddr,
    port: u16,
    limits: &Limits,
    guard: &ScopeGuard,
    semaphore: &Arc<Semaphore>,
    rate: &Arc<RateLimiter>,
) -> Option<TcpStream> {
    if guard.check_ip(&ip).is_err() {
        return None;
    }
    rate.acquire().await;
    let _permit = semaphore.acquire().await.ok()?;
    timeout::run(limits.connect_timeout_ms, TcpStream::connect((ip, port)))
        .await?
        .ok()
}

/// Read one passive banner: bytes the service volunteers on connect, up to
/// `max_banner_size`, within `probe_timeout_ms`. No writes, no auth, no
/// protocol commands. Returns `None` only when the connection failed.
pub async fn grab(
    ip: IpAddr,
    port: u16,
    limits: &Limits,
    guard: &ScopeGuard,
    semaphore: &Arc<Semaphore>,
    rate: &Arc<RateLimiter>,
) -> Option<Banner> {
    let mut stream = dial(ip, port, limits, guard, semaphore, rate).await?;
    let cap = limits.max_banner_size.max(1);
    let mut raw = Vec::new();
    let read_all = async {
        let mut chunk = vec![0u8; 4096];
        loop {
            if raw.len() > cap {
                break;
            }
            match stream.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => raw.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
    };
    if timeout::run(limits.probe_timeout_ms, read_all)
        .await
        .is_none()
    {
        tracing::debug!(%ip, port, event = "timeout");
    }
    let truncated = raw.len() > cap;
    raw.truncate(cap);
    let (text, encoding) = match std::str::from_utf8(&raw) {
        Ok(valid) => (sanitize(valid), "utf8".to_owned()),
        Err(_) => (
            sanitize(&String::from_utf8_lossy(&raw)),
            "utf8-lossy".to_owned(),
        ),
    };
    Some(Banner {
        text,
        encoding,
        truncated,
        raw,
    })
}
