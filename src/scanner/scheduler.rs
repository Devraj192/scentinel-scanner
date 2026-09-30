use std::net::IpAddr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::rate_limit::RateLimiter;
use super::tcp::{connect_one, PortOutcome};
use super::timeout;
use crate::config::Limits;
use crate::safety::scope::ScopeGuard;

/// One finished probe, with its identity attached (tasks complete out of order).
pub struct FinishedProbe {
    pub ip: IpAddr,
    pub port: u16,
    pub outcome: PortOutcome,
}

/// Scan outcome: probes in (ip, port) order, plus whether the run stopped early.
pub struct PortScan {
    pub probes: Vec<FinishedProbe>,
    pub cancelled: bool,
    pub join_errors: usize,
    /// Highest simultaneously active probe count observed.
    pub peak_active: usize,
}

/// Bounded port scan: the semaphore caps *active* probes, the rate limiter caps
/// *starts* per second. One failed probe never affects the others.
pub async fn scan_ports(
    ips: &[IpAddr],
    ports: &[u16],
    limits: &Limits,
    guard: &ScopeGuard,
    rate: Arc<RateLimiter>,
) -> PortScan {
    let semaphore = Arc::new(Semaphore::new(limits.max_concurrency.max(1)));
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let mut set = JoinSet::new();
    let stop = tokio::signal::ctrl_c();
    tokio::pin!(stop);
    let mut spawn_cancelled = false;
    'spawn: for &ip in ips {
        for &port in ports {
            tokio::select! {
                biased;
                _ = &mut stop => { spawn_cancelled = true; break 'spawn; }
                () = rate.acquire() => {}
            }
            let permit_slot = Arc::clone(&semaphore);
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            let guard = guard.clone();
            let timeout_ms = limits.connect_timeout_ms;
            set.spawn(async move {
                let _permit = permit_slot.acquire_owned().await;
                let Ok(_permit) = _permit else {
                    return FinishedProbe {
                        ip,
                        port,
                        outcome: PortOutcome {
                            state: crate::results::model::PortState::Unknown,
                            reason: "local_error",
                            latency_ms: 0,
                        },
                    };
                };
                let in_flight = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(in_flight, Ordering::SeqCst);
                let outcome = connect_one(ip, port, timeout_ms, &guard).await;
                if outcome.state == crate::results::model::PortState::Open {
                    tracing::info!(%ip, port, event = "port_open");
                }
                active.fetch_sub(1, Ordering::SeqCst);
                FinishedProbe { ip, port, outcome }
            });
        }
    }
    let (mut probes, join_errors, join_cancelled) = timeout::join_cancellable(&mut set).await;
    probes.sort_by_key(|probe| (probe.ip, probe.port));
    PortScan {
        probes,
        cancelled: spawn_cancelled || join_cancelled,
        join_errors,
        peak_active: peak.load(Ordering::SeqCst),
    }
}
