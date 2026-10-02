use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::anyhow;
use tokio::sync::{mpsc::Sender, Semaphore};
use tokio::task::JoinSet;

use crate::config::Limits;
use crate::detection::identify;
use crate::discovery::host::discover_all;
use crate::events::{ScanEvent, CHANNEL_CAPACITY};
use crate::os::fingerprint;
use crate::results::model::{self, HostResult, HostStatus, PortResult, Scan};
use crate::safety::scope::{ParsedTarget, ScopeGuard};
use crate::scanner::rate_limit::RateLimiter;
use crate::scanner::resolve::{authorize_resolved, resolve_targets, ResolvedHost};
use crate::scanner::scheduler::scan_ports;
use crate::scanner::timeout;
use crate::storage::{Storage, StoredScan};

/// Everything the engine needs. Scope parsing and user confirmation already
/// happened; the balancing half (`PreparedScan` in the binary) converts into
/// this before spawning the run.
pub struct ScanPlan {
    pub scan_id: String,
    pub targets: Vec<ParsedTarget>,
    pub ports: Vec<u16>,
    pub limits: Limits,
    pub guard: ScopeGuard,
    pub skip_discovery: bool,
    pub detect: bool,
    pub os_enabled: bool,
    pub storage: Storage,
}

/// Best-effort send: a gone receiver means nobody is listening, and the scan
/// continues so persistence and resume still work.
async fn emit(tx: &Sender<ScanEvent>, event: ScanEvent) {
    let _ = tx.send(event).await;
}

/// Run the full pipeline, emitting each stage. The two [`Scan`] assemblies —
/// the persisted one here and the consumer's from the stream — carry the same
/// rows; the parity test proves it on the lab.
pub async fn execute(
    plan: &ScanPlan,
    resume: Option<&StoredScan>,
    tx: &Sender<ScanEvent>,
) -> anyhow::Result<Scan> {
    match execute_inner(plan, resume, tx).await {
        Ok(scan) => Ok(scan),
        Err(error) => {
            emit(
                tx,
                ScanEvent::Error {
                    message: error.to_string(),
                },
            )
            .await;
            Err(error)
        }
    }
}

async fn execute_inner(
    plan: &ScanPlan,
    resume: Option<&StoredScan>,
    tx: &Sender<ScanEvent>,
) -> anyhow::Result<Scan> {
    let _ = CHANNEL_CAPACITY;
    let scan_id = resume.map_or(plan.scan_id.clone(), |stored| stored.scan_id.clone());
    let ports = resume.map_or(plan.ports.clone(), |stored| stored.ports.clone());
    let target_names: Vec<String> = resume.map_or_else(
        || plan.targets.iter().map(ToString::to_string).collect(),
        |stored| stored.targets.clone(),
    );
    emit(
        tx,
        ScanEvent::Started {
            scan_id: scan_id.clone(),
            targets: target_names.clone(),
            ports: ports.clone(),
        },
    )
    .await;
    let mut scan = Scan::start(scan_id.clone(), target_names);
    // The guard gains every resolved address before any connect, so hostname
    // targets pass the same `check_ip` as literal ones.
    let mut guard = plan.guard.clone();
    let resolved: Vec<ResolvedHost> = match resume {
        Some(stored) => {
            authorize_resolved(&mut guard, &stored.resolved);
            stored.resolved.clone()
        }
        None => resolve_targets(&plan.targets, &mut guard, plan.limits.max_hosts)
            .await
            .map_err(|e| anyhow!("{e}"))?,
    };
    if resume.is_none() {
        plan.storage
            .begin_scan(&scan_id, &scan.targets, &ports, &resolved)
            .map_err(|e| anyhow!("{e}"))?;
    }
    let mut completed: HashMap<(String, u16), PortResult> = HashMap::new();
    if resume.is_some() {
        for saved in plan
            .storage
            .port_rows(&scan_id)
            .map_err(|e| anyhow!("{e}"))?
        {
            completed.insert((saved.address.clone(), saved.port.port), saved.port);
        }
    }
    // Pairs an interrupted run already saved are never probed again.
    let skip: HashSet<(IpAddr, u16)> = completed
        .keys()
        .filter_map(|(address, port)| address.parse().ok().map(|ip| (ip, *port)))
        .collect();

    let semaphore = Arc::new(Semaphore::new(plan.limits.max_concurrency.max(1)));
    let rate = Arc::new(RateLimiter::new(plan.limits.max_rate.max(1)));

    let mut hosts: Vec<HostResult> = Vec::new();
    let mut scannable: Vec<IpAddr> = Vec::new();
    if plan.skip_discovery {
        for host in &resolved {
            match host.addr {
                Some(ip) => {
                    hosts.push(HostResult {
                        address: ip.to_string(),
                        status: HostStatus::Unknown,
                        latency_ms: 0,
                        ports: Vec::new(),
                        os: None,
                    });
                    scannable.push(ip);
                }
                None => hosts.push(HostResult {
                    address: model::sanitize(&host.display),
                    status: HostStatus::Unknown,
                    latency_ms: 0,
                    ports: Vec::new(),
                    os: None,
                }),
            }
        }
    } else {
        let mut pending: Vec<IpAddr> = Vec::new();
        let mut index_of: Vec<usize> = Vec::new();
        for (index, host) in resolved.iter().enumerate() {
            match host.addr {
                Some(ip) => {
                    pending.push(ip);
                    index_of.push(index);
                }
                None => hosts.push(HostResult {
                    address: model::sanitize(&host.display),
                    status: HostStatus::Unknown,
                    latency_ms: 0,
                    ports: Vec::new(),
                    os: None,
                }),
            }
        }
        let (mut discovered, discovery_cancelled) = discover_all(
            &pending,
            &ports,
            &plan.limits,
            &guard,
            Arc::clone(&semaphore),
            Arc::clone(&rate),
        )
        .await;
        if discovery_cancelled {
            scan.meta.truncated = true;
            emit(
                tx,
                ScanEvent::Warning {
                    message: "host discovery interrupted; results are partial".to_owned(),
                },
            )
            .await;
        }
        // Keep resolution order for hosts the discovery set may have cut short.
        discovered.sort_by_key(|host| {
            index_of
                .iter()
                .zip(pending.iter())
                .find(|(_, ip)| ip.to_string() == host.address)
                .map(|(index, _)| *index)
                .unwrap_or(usize::MAX)
        });
        for host in discovered {
            if host.status != HostStatus::Down {
                if let Ok(ip) = host.address.parse() {
                    scannable.push(ip);
                }
            }
            hosts.push(host);
        }
    }
    for host in &hosts {
        emit(
            tx,
            ScanEvent::HostDiscovered {
                address: host.address.clone(),
                status: host.status,
                latency_ms: host.latency_ms,
            },
        )
        .await;
    }
    let total = scannable
        .iter()
        .flat_map(|ip| ports.iter().filter(|port| !skip.contains(&(*ip, **port))))
        .count();
    let port_scan = scan_ports(
        &scannable,
        &ports,
        &plan.limits,
        &guard,
        Arc::clone(&rate),
        &skip,
    )
    .await;
    if port_scan.cancelled || port_scan.join_errors > 0 {
        scan.meta.truncated = true;
        emit(
            tx,
            ScanEvent::Warning {
                message: "port scan interrupted; results are partial".to_owned(),
            },
        )
        .await;
    }
    scan.meta.peak_active_probes = port_scan.peak_active;
    for (index, probe) in port_scan.probes.into_iter().enumerate() {
        let address = probe.ip.to_string();
        if let Some(host) = hosts.iter_mut().find(|host| host.address == address) {
            host.ports.push(PortResult {
                port: probe.port,
                protocol: "tcp".to_owned(),
                state: probe.outcome.state,
                reason: probe.outcome.reason.to_owned(),
                latency_ms: probe.outcome.latency_ms,
                service: None,
                version: None,
                confidence: None,
                evidence: Vec::new(),
                banner: None,
            });
            let port = host.ports.last().expect("just pushed");
            emit(
                tx,
                ScanEvent::PortProbed {
                    address: address.clone(),
                    port: port.clone(),
                },
            )
            .await;
        }
        emit(
            tx,
            ScanEvent::Progress {
                done: index + 1,
                total,
            },
        )
        .await;
    }
    // Reattach previously saved probes (resume path).
    for ((address, _), saved) in &completed {
        match hosts.iter_mut().find(|host| &host.address == address) {
            Some(host) => {
                if !host.ports.iter().any(|port| port.port == saved.port) {
                    host.ports.push(saved.clone());
                    let port = host.ports.last().expect("just pushed");
                    emit(
                        tx,
                        ScanEvent::PortProbed {
                            address: address.clone(),
                            port: port.clone(),
                        },
                    )
                    .await;
                }
            }
            None => hosts.push(HostResult {
                address: address.clone(),
                status: HostStatus::Unknown,
                latency_ms: 0,
                ports: vec![saved.clone()],
                os: None,
            }),
        }
    }
    for host in &mut hosts {
        host.ports.sort_by_key(|port| port.port);
    }
    // One transaction for the whole pass instead of one connection per row.
    plan.storage
        .save_progress(&scan_id, &hosts)
        .map_err(|e| anyhow!("{e}"))?;
    scan.hosts = hosts;
    if plan.detect {
        identify_services(&mut scan, &plan.limits, &guard, &semaphore, &rate, tx).await;
    }
    // OS estimates need detected services; without them every guess would be
    // Unknown noise, so skip the stage entirely.
    if plan.os_enabled && plan.detect {
        for host in &mut scan.hosts {
            let os = fingerprint(&host.ports);
            emit(
                tx,
                ScanEvent::OsEstimated {
                    address: host.address.clone(),
                    os: Some(os.clone()),
                },
            )
            .await;
            host.os = Some(os);
        }
    }
    // Hosts (with OS estimates) plus detection columns, one transaction.
    plan.storage
        .save_detections(&scan_id, &scan.hosts)
        .map_err(|e| anyhow!("{e}"))?;
    scan.finish();
    tracing::info!(scan_id = %scan.meta.scan_id, event = "scan_completed");
    emit(tx, ScanEvent::Completed { scan: scan.clone() }).await;
    Ok(scan)
}

/// Run service detection on open ports lacking service data. Probe latency and
/// state stay as the port scan measured them; detection fills service fields
/// and banners. The caller persists the batch with one transaction.
async fn identify_services(
    scan: &mut Scan,
    limits: &Limits,
    guard: &ScopeGuard,
    semaphore: &Arc<Semaphore>,
    rate: &Arc<RateLimiter>,
    tx: &Sender<ScanEvent>,
) {
    let mut set = JoinSet::new();
    for (host_index, host) in scan.hosts.iter().enumerate() {
        let Ok(ip) = host.address.parse::<IpAddr>() else {
            continue;
        };
        for (port_index, port) in host.ports.iter().enumerate() {
            if port.state != crate::results::model::PortState::Open || port.service.is_some() {
                continue;
            }
            let semaphore = Arc::clone(semaphore);
            let rate = Arc::clone(rate);
            let limits = limits.clone();
            let guard = guard.clone();
            let port_number = port.port;
            set.spawn(async move {
                let detected = identify(ip, port_number, &limits, &guard, &semaphore, &rate).await;
                (host_index, port_index, detected)
            });
        }
    }
    let (done, join_errors, cancelled) = timeout::join_cancellable(&mut set).await;
    if cancelled || join_errors > 0 {
        scan.meta.truncated = true;
        emit(
            tx,
            ScanEvent::Warning {
                message: "service detection interrupted; results are partial".to_owned(),
            },
        )
        .await;
    }
    for (host_index, port_index, detected) in done {
        let Some(address) = scan.hosts.get(host_index).map(|host| host.address.clone()) else {
            continue;
        };
        let Some(port) = scan
            .hosts
            .get_mut(host_index)
            .and_then(|host| host.ports.get_mut(port_index))
        else {
            continue;
        };
        port.service = detected.service;
        port.version = detected.version;
        port.confidence = detected.confidence;
        port.evidence = detected.evidence;
        port.banner = detected.banner;
        emit(
            tx,
            ScanEvent::ServiceDetected {
                address,
                port: port.port,
                service: port.service.clone(),
                version: port.version.clone(),
                confidence: port.confidence,
                evidence: port.evidence.clone(),
                banner: port.banner.clone(),
            },
        )
        .await;
    }
}
