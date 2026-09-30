use std::io::{self, BufRead, Write};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use tokio::sync::Semaphore;

use super::args::{Command, ScanArgs, TargetArg};
use crate::config::{Config, Limits};
use crate::discovery::host::discover_all;
use crate::errors::Error;
use crate::results::model::{self, HostResult, HostStatus, PortResult, Scan};
use crate::safety::limits::enforce_host_count;
use crate::safety::ports::parse_ports;
use crate::safety::scope::{host_count, parse_targets, ParsedTarget, ScopeGuard};
use crate::scanner::rate_limit::RateLimiter;
use crate::scanner::scheduler::scan_ports;

/// Print the pre-scan scope summary and require `y` unless `--yes` was given.
/// In json mode the summary and prompt go to stderr so stdout stays pure JSON.
fn confirm_scope(summary: &str, yes: bool, use_stderr: bool) -> anyhow::Result<bool> {
    if use_stderr {
        eprintln!("{summary}");
    } else {
        println!("{summary}");
    }
    if yes {
        return Ok(true);
    }
    if use_stderr {
        eprint!("Continue? [y/N] ");
    } else {
        print!("Continue? [y/N] ");
    }
    io::stdout().flush().context("flush prompt")?;
    let stdin = io::stdin();
    let line = stdin
        .lock()
        .lines()
        .next()
        .transpose()
        .context("read confirmation")?
        .unwrap_or_default();
    Ok(matches!(line.trim().to_lowercase().as_str(), "y" | "yes"))
}

fn validate_output_format(output: &str) -> Result<(), Error> {
    match output {
        "terminal" | "json" => Ok(()),
        "csv" => Err(Error::Config(
            "csv output arrives in Phase 3; use terminal or json".to_owned(),
        )),
        other => Err(Error::Config(format!(
            "unknown output '{other}' (terminal|json|csv)"
        ))),
    }
}

/// One resolved scan target. `addr` is `None` when hostname resolution failed;
/// the host is still reported (as `unknown`) so one bad target never aborts
/// the scan.
struct ResolvedHost {
    display: String,
    addr: Option<IpAddr>,
}

/// Expand parsed targets to addresses. Hostname resolution happens here, after
/// confirmation: it is the first network I/O in the program.
async fn resolve_targets(
    targets: &[ParsedTarget],
    guard: &ScopeGuard,
    max_hosts: usize,
) -> Result<Vec<ResolvedHost>, Error> {
    let mut out = Vec::new();
    for target in targets {
        match target {
            ParsedTarget::Ip(ip) => out.push(ResolvedHost {
                display: ip.to_string(),
                addr: Some(*ip),
            }),
            ParsedTarget::Cidr(net) => {
                for ip in net.hosts().take(max_hosts.saturating_add(1)) {
                    out.push(ResolvedHost {
                        display: ip.to_string(),
                        addr: Some(ip),
                    });
                }
            }
            ParsedTarget::Hostname(name) => {
                guard.check_hostname(name)?;
                match tokio::net::lookup_host((name.as_str(), 0)).await {
                    Ok(addrs) => {
                        for addr in addrs {
                            out.push(ResolvedHost {
                                display: name.clone(),
                                addr: Some(addr.ip()),
                            });
                        }
                    }
                    Err(_) => out.push(ResolvedHost {
                        display: name.clone(),
                        addr: None,
                    }),
                }
            }
        }
        enforce_host_count(out.len(), max_hosts)?;
    }
    Ok(out)
}

struct PreparedScan {
    scan_id: String,
    config: Config,
    ports: Vec<u16>,
    targets: Vec<ParsedTarget>,
    guard: ScopeGuard,
}

/// Inputs for scope preparation; grouped so the parameter list stays small.
struct PrepareRequest {
    raw_targets: Vec<String>,
    allow_hostnames: bool,
    port_spec: Option<String>,
    profile_default_ports: String,
    output: String,
    concurrency: Option<usize>,
    rate: Option<u64>,
    config_path: Option<String>,
    yes: bool,
}

/// Parse, validate, and confirm scope. No socket opens before this returns.
fn prepare(request: &PrepareRequest) -> anyhow::Result<Option<PreparedScan>> {
    let scan_id = ulid::Ulid::new().to_string();
    tracing::info!(scan_id = %scan_id, event = "scan_started");

    validate_output_format(&request.output).map_err(|e| anyhow!("{e}"))?;
    let mut config = Config::load(request.config_path.as_deref()).map_err(|e| anyhow!("{e}"))?;
    apply_overrides(&mut config.limits, request.concurrency, request.rate)?;

    let port_spec = request
        .port_spec
        .clone()
        .unwrap_or_else(|| request.profile_default_ports.clone());
    let ports = parse_ports(&port_spec, config.limits.max_ports).map_err(|e| anyhow!("{e}"))?;
    let targets = parse_targets(
        &request.raw_targets,
        request.allow_hostnames,
        config.limits.max_hosts,
    )
    .map_err(|e| anyhow!("{e}"))?;
    let guard = ScopeGuard::from_targets(&targets);

    let summary = format!(
        "Authorized use only: scan only systems you own or have written permission to test.\n\
         scan_id: {scan_id}\n\
         targets: {}\n\
         hosts: {}\n\
         ports: {} ({} selected)\n\
         concurrency: {}\n\
         rate: {}/s\n\
         output: {}",
        model::sanitize(
            &targets
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ")
        ),
        host_count(&targets),
        model::sanitize(&port_spec),
        ports.len(),
        config.limits.max_concurrency,
        config.limits.max_rate,
        model::sanitize(&request.output),
    );
    if !confirm_scope(&summary, request.yes, request.output == "json")? {
        println!("Aborted. No traffic sent.");
        return Ok(None);
    }
    Ok(Some(PreparedScan {
        scan_id,
        config,
        ports,
        targets,
        guard,
    }))
}

fn apply_overrides(
    limits: &mut Limits,
    concurrency: Option<usize>,
    rate: Option<u64>,
) -> anyhow::Result<()> {
    if let Some(concurrency) = concurrency {
        if concurrency == 0 || concurrency > 5000 {
            return Err(anyhow!("--concurrency must be 1-5000, got {concurrency}"));
        }
        limits.max_concurrency = concurrency;
    }
    if let Some(rate) = rate {
        if rate == 0 || rate > 100_000 {
            return Err(anyhow!("--rate must be 1-100000, got {rate}"));
        }
        limits.max_rate = rate;
    }
    Ok(())
}

/// Discover hosts then scan ports on everything not `down`.
async fn run_phases(prepared: &PreparedScan, skip_discovery: bool) -> anyhow::Result<Scan> {
    let target_names: Vec<String> = prepared.targets.iter().map(ToString::to_string).collect();
    let mut scan = Scan::start(prepared.scan_id.clone(), target_names);
    let resolved = resolve_targets(
        &prepared.targets,
        &prepared.guard,
        prepared.config.limits.max_hosts,
    )
    .await
    .map_err(|e| anyhow!("{e}"))?;

    let semaphore = Arc::new(Semaphore::new(
        prepared.config.limits.max_concurrency.max(1),
    ));
    let rate = Arc::new(RateLimiter::new(prepared.config.limits.max_rate.max(1)));

    let mut hosts: Vec<HostResult> = Vec::new();
    let mut scannable: Vec<IpAddr> = Vec::new();
    if skip_discovery {
        for host in &resolved {
            match host.addr {
                Some(ip) => {
                    hosts.push(HostResult {
                        address: ip.to_string(),
                        status: HostStatus::Unknown,
                        latency_ms: 0,
                        ports: Vec::new(),
                    });
                    scannable.push(ip);
                }
                None => hosts.push(HostResult {
                    address: model::sanitize(&host.display),
                    status: HostStatus::Unknown,
                    latency_ms: 0,
                    ports: Vec::new(),
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
                }),
            }
        }
        let (mut discovered, discovery_cancelled) = discover_all(
            &pending,
            &prepared.ports,
            &prepared.config.limits,
            &prepared.guard,
            Arc::clone(&semaphore),
            Arc::clone(&rate),
        )
        .await;
        if discovery_cancelled {
            scan.meta.truncated = true;
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

    let port_scan = scan_ports(
        &scannable,
        &prepared.ports,
        &prepared.config.limits,
        &prepared.guard,
        Arc::clone(&rate),
    )
    .await;
    if port_scan.cancelled || port_scan.join_errors > 0 {
        scan.meta.truncated = true;
    }
    scan.meta.peak_active_probes = port_scan.peak_active;
    for probe in port_scan.probes {
        let address = probe.ip.to_string();
        if let Some(host) = hosts.iter_mut().find(|host| host.address == address) {
            host.ports.push(PortResult {
                port: probe.port,
                protocol: "tcp".to_owned(),
                state: probe.outcome.state,
                reason: probe.outcome.reason.to_owned(),
                latency_ms: probe.outcome.latency_ms,
                service: None,
            });
        }
    }
    scan.hosts = hosts;
    scan.finish();
    tracing::info!(scan_id = %scan.meta.scan_id, event = "scan_completed");
    Ok(scan)
}

/// Bound the whole scan (discovery plus ports) by `max_scan_duration_secs`.
async fn run_bounded(prepared: &PreparedScan, skip_discovery: bool) -> anyhow::Result<Scan> {
    let duration = Duration::from_secs(prepared.config.limits.max_scan_duration_secs.max(1));
    match tokio::time::timeout(duration, run_phases(prepared, skip_discovery)).await {
        Ok(scan) => scan,
        Err(_) => Err(anyhow!("scan duration exceeded max_scan_duration_secs")),
    }
}

fn emit(scan: &Scan, output: &str) {
    match output {
        "json" => println!("{}", model::to_json(scan)),
        _ => {
            print!("{}", model::terminal_table(scan));
            if scan.meta.truncated {
                println!("Note: scan stopped early; results are partial.");
            }
        }
    }
}

/// Run the `scan` subcommand end to end.
pub async fn run_scan(args: &ScanArgs) -> anyhow::Result<()> {
    for (flag, phase) in [
        (args.service_detection, "3"),
        (args.banner, "3"),
        (args.os_detection, "5"),
    ] {
        if flag {
            eprintln!("Note: detection flags arrive in Phase {phase}; continuing without them.");
            break;
        }
    }
    let Some(prepared) = prepare(&PrepareRequest {
        raw_targets: args.targets.clone(),
        allow_hostnames: args.allow_hostnames,
        port_spec: args.ports.clone(),
        profile_default_ports: args.profile.default_ports().to_owned(),
        output: args.output.clone(),
        concurrency: args.concurrency,
        rate: args.rate,
        config_path: args.config.clone(),
        yes: args.yes,
    })?
    else {
        return Ok(());
    };
    let scan = run_bounded(&prepared, args.skip_host_discovery).await?;
    emit(&scan, &args.output);
    Ok(())
}

async fn run_target_command(
    arg: &TargetArg,
    ports: Option<String>,
    discover_only: bool,
) -> anyhow::Result<()> {
    let Some(prepared) = prepare(&PrepareRequest {
        raw_targets: std::slice::from_ref(&arg.target).to_vec(),
        allow_hostnames: arg.allow_hostnames,
        port_spec: ports,
        profile_default_ports: "standard".to_owned(),
        output: "terminal".to_owned(),
        concurrency: None,
        rate: None,
        config_path: None,
        yes: arg.yes,
    })?
    else {
        return Ok(());
    };
    if discover_only {
        let resolved = resolve_targets(
            &prepared.targets,
            &prepared.guard,
            prepared.config.limits.max_hosts,
        )
        .await
        .map_err(|e| anyhow!("{e}"))?;
        let ips: Vec<IpAddr> = resolved.iter().filter_map(|host| host.addr).collect();
        let semaphore = Arc::new(Semaphore::new(
            prepared.config.limits.max_concurrency.max(1),
        ));
        let rate = Arc::new(RateLimiter::new(prepared.config.limits.max_rate.max(1)));
        let (hosts, _) = discover_all(
            &ips,
            &prepared.ports,
            &prepared.config.limits,
            &prepared.guard,
            semaphore,
            rate,
        )
        .await;
        print!("{}", model::host_table(&hosts));
        return Ok(());
    }
    let scan = run_bounded(&prepared, false).await?;
    emit(&scan, "terminal");
    Ok(())
}

/// Dispatch any subcommand; `services` arrives in Phase 3, history/compare in Phase 4.
pub async fn run(command: &Command) -> anyhow::Result<()> {
    match command {
        Command::Scan(args) => run_scan(args).await,
        Command::Config(args) => {
            let config = Config::load(args.config.as_deref()).map_err(|e| anyhow!("{e}"))?;
            println!("{}", toml::to_string(&config.limits).unwrap_or_default());
            Ok(())
        }
        Command::Hosts(arg) => run_target_command(arg, None, true).await,
        Command::Ports(arg) => run_target_command(arg, None, false).await,
        Command::Services(_) => {
            println!("'services' arrives in Phase 3; Phase 2 scans ports only.");
            Ok(())
        }
        Command::History => {
            println!("'history' arrives in Phase 4; Phase 2 prints to the terminal.");
            Ok(())
        }
        Command::Compare(_) => {
            println!("'compare' arrives in Phase 4; Phase 2 prints to the terminal.");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_args(targets: &[&str], ports: &str) -> ScanArgs {
        ScanArgs {
            targets: targets.iter().map(ToString::to_string).collect(),
            ports: Some(ports.to_owned()),
            profile: crate::config::profiles::Profile::Standard,
            concurrency: None,
            rate: None,
            service_detection: false,
            banner: false,
            os_detection: false,
            output: "terminal".to_owned(),
            skip_host_discovery: false,
            allow_hostnames: false,
            config: None,
            yes: true,
        }
    }

    #[tokio::test]
    async fn rejects_bad_output_format() {
        let mut args = scan_args(&["127.0.0.1"], "80");
        args.output = "xml".to_owned();
        assert!(run_scan(&args).await.is_err());
    }

    #[tokio::test]
    async fn rejects_malformed_target_without_traffic() {
        let args = scan_args(&["999.999.0.1"], "80");
        assert!(run_scan(&args).await.is_err());
    }

    #[tokio::test]
    async fn rejects_malformed_ports_without_traffic() {
        let args = scan_args(&["127.0.0.1"], "0");
        assert!(run_scan(&args).await.is_err());
    }

    #[tokio::test]
    async fn resolves_cidr() {
        let targets = parse_targets(&["127.0.0.0/30".to_owned()], false, 256).expect("parse");
        let guard = ScopeGuard::from_targets(&targets);
        let resolved = resolve_targets(&targets, &guard, 256)
            .await
            .expect("resolve");
        assert_eq!(resolved.len(), 2);
    }
}
