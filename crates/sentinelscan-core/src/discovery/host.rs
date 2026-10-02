use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::config::Limits;
use crate::results::model::{HostResult, HostStatus, PortState};
use crate::safety::scope::ScopeGuard;
use crate::scanner::rate_limit::RateLimiter;
use crate::scanner::tcp::connect_one;
use crate::scanner::timeout;

/// Probe one host with TCP connects to a few ports. Any completed handshake or
/// refusal proves the host is up; silence on every probe means down; local-only
/// errors mean unknown. Each probe holds a semaphore permit across its connect.
pub async fn discover_one(
    ip: IpAddr,
    probe_ports: Vec<u16>,
    limits: Limits,
    guard: ScopeGuard,
    semaphore: Arc<Semaphore>,
    rate: Arc<RateLimiter>,
) -> HostResult {
    let start = Instant::now();
    let latency_ms = || start.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
    let mut set = JoinSet::new();
    for port in probe_ports.into_iter().take(4) {
        rate.acquire().await;
        let semaphore = Arc::clone(&semaphore);
        let guard = guard.clone();
        let timeout_ms = limits.probe_timeout_ms;
        set.spawn(async move {
            let permit = semaphore.acquire_owned().await;
            if permit.is_err() {
                return (PortState::Unknown, 0u64);
            }
            let outcome = connect_one(ip, port, timeout_ms, &guard).await;
            (outcome.state, outcome.latency_ms)
        });
    }
    let mut saw_answer = false;
    let mut saw_local_error = false;
    let mut best_latency = u64::MAX;
    while let Some(finished) = set.join_next().await {
        let Ok((state, latency)) = finished else {
            saw_local_error = true;
            continue;
        };
        match state {
            PortState::Open | PortState::Closed => {
                saw_answer = true;
                best_latency = best_latency.min(latency);
            }
            PortState::Filtered => {}
            PortState::Unknown => saw_local_error = true,
        }
    }
    let status = if saw_answer {
        HostStatus::Up
    } else if saw_local_error {
        HostStatus::Unknown
    } else {
        HostStatus::Down
    };
    tracing::info!(%ip, %status, event = "host_discovered");
    HostResult {
        address: ip.to_string(),
        status,
        latency_ms: if saw_answer {
            best_latency
        } else {
            latency_ms()
        },
        ports: Vec::new(),
        os: None,
    }
}

/// Discover all hosts with bounded concurrency. Cancel-aware: Ctrl-C returns
/// the hosts finished so far plus `cancelled`.
pub async fn discover_all(
    ips: &[IpAddr],
    probe_ports: &[u16],
    limits: &Limits,
    guard: &ScopeGuard,
    semaphore: Arc<Semaphore>,
    rate: Arc<RateLimiter>,
) -> (Vec<HostResult>, bool) {
    let mut set = JoinSet::new();
    for &ip in ips {
        let semaphore = Arc::clone(&semaphore);
        let guard = guard.clone();
        let probe_ports = probe_ports.to_vec();
        let limits = limits.clone();
        let rate = Arc::clone(&rate);
        set.spawn(
            async move { discover_one(ip, probe_ports, limits, guard, semaphore, rate).await },
        );
    }
    let (mut hosts, _join_errors, cancelled) = timeout::join_cancellable(&mut set).await;
    hosts.sort_by_key(|host| host.address.clone());
    (hosts, cancelled)
}
