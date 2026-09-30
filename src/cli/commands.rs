use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, Write};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::args::{Command, HistoryArgs, ScanArgs, TargetArg};
use crate::config::profiles::Profile;
use crate::config::{Config, Limits};
use crate::detection::identify;
use crate::discovery::host::discover_all;
use crate::errors::Error;
use crate::results::model::{self, HostResult, HostStatus, PortResult, Scan};
use crate::safety::ports::parse_ports;
use crate::safety::scope::{host_count, parse_targets, ParsedTarget, ScopeGuard};
use crate::scanner::rate_limit::RateLimiter;
use crate::scanner::resolve::{resolve_targets, ResolvedHost};
use crate::scanner::scheduler::scan_ports;
use crate::scanner::timeout;
use crate::storage::{compare, comparison_table, default_db_path, Comparison, Storage, StoredScan};

/// Print the pre-scan scope summary and require `y` unless `--yes` was given.
/// Machine-readable modes keep stdout pure, so the summary goes to stderr.
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
        "terminal" | "json" | "csv" => Ok(()),
        other => Err(Error::Config(format!(
            "unknown output '{other}' (terminal|json|csv)"
        ))),
    }
}

fn validate_machine_output(output: &str) -> Result<(), Error> {
    match output {
        "terminal" | "json" => Ok(()),
        other => Err(Error::Config(format!(
            "unknown output '{other}' (terminal|json)"
        ))),
    }
}

struct PreparedScan {
    scan_id: String,
    config: Config,
    ports: Vec<u16>,
    targets: Vec<ParsedTarget>,
    guard: ScopeGuard,
    skip_discovery: bool,
    detect: bool,
    os_enabled: bool,
    storage: Storage,
}

/// Inputs for scope preparation; grouped so the parameter list stays small.
struct PrepareRequest {
    raw_targets: Vec<String>,
    allow_hostnames: bool,
    port_spec: Option<String>,
    profile: Profile,
    service_detection: bool,
    banner: bool,
    os_detection: bool,
    skip_discovery: bool,
    output: String,
    concurrency: Option<usize>,
    rate: Option<u64>,
    config_path: Option<String>,
    db_path: Option<String>,
    yes: bool,
}

/// Effective behavior after layering explicit flags over config-file profile
/// tables over built-in profile defaults.
struct EffectiveSettings {
    port_spec: String,
    detect: bool,
    skip_discovery: bool,
}

fn effective_settings(
    profile: Profile,
    config: &Config,
    port_spec: Option<String>,
    service_detection: bool,
    banner: bool,
    skip_discovery: bool,
) -> EffectiveSettings {
    let table = config.profiles.get(profile.section());
    let builtin_detect = profile == Profile::Standard;
    EffectiveSettings {
        port_spec: port_spec
            .or_else(|| table.and_then(|table| table.ports.clone()))
            .unwrap_or_else(|| profile.default_ports().to_owned()),
        detect: service_detection
            || banner
            || table
                .and_then(|table| table.service_detection.or(table.banner))
                .unwrap_or(builtin_detect),
        skip_discovery: skip_discovery
            || table
                .and_then(|table| table.skip_host_discovery)
                .unwrap_or(false),
    }
}

/// Parse, validate, and confirm scope. No socket opens before this returns.
fn prepare(request: &PrepareRequest) -> anyhow::Result<Option<PreparedScan>> {
    let scan_id = ulid::Ulid::new().to_string();
    tracing::info!(scan_id = %scan_id, event = "scan_started");

    validate_output_format(&request.output).map_err(|e| anyhow!("{e}"))?;
    let mut config = Config::load(request.config_path.as_deref()).map_err(|e| anyhow!("{e}"))?;
    apply_overrides(&mut config.limits, request.concurrency, request.rate)?;
    let settings = effective_settings(
        request.profile,
        &config,
        request.port_spec.clone(),
        request.service_detection,
        request.banner,
        request.skip_discovery,
    );

    let ports =
        parse_ports(&settings.port_spec, config.limits.max_ports).map_err(|e| anyhow!("{e}"))?;
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
        model::sanitize(&settings.port_spec),
        ports.len(),
        config.limits.max_concurrency,
        config.limits.max_rate,
        model::sanitize(&request.output),
    );
    if !confirm_scope(&summary, request.yes, request.output != "terminal")? {
        println!("Aborted. No traffic sent.");
        return Ok(None);
    }
    let db_path = request
        .db_path
        .clone()
        .map_or_else(default_db_path, std::path::PathBuf::from);
    let storage = Storage::open(&db_path).map_err(|e| anyhow!("{e}"))?;
    // OS estimates ride on detected services: Standard wires them up, Quick
    // leaves them off unless explicitly requested. Requesting OS detection
    // implies service detection, which supplies the signals.
    let os_enabled = request.os_detection || request.profile == Profile::Standard;
    let detect = settings.detect || request.os_detection;
    Ok(Some(PreparedScan {
        scan_id,
        config,
        ports,
        targets,
        guard,
        skip_discovery: settings.skip_discovery,
        detect,
        os_enabled,
        storage,
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

/// Discover hosts, scan ports on everything not `down`, and persist progress
/// after every stage so an interrupted scan stays resumable. When `resume` is
/// set, already-saved probes are reused, never rescanned.
async fn run_phases(prepared: &PreparedScan, resume: Option<&StoredScan>) -> anyhow::Result<Scan> {
    let scan_id = resume.map_or(prepared.scan_id.clone(), |stored| stored.scan_id.clone());
    let ports = resume.map_or(prepared.ports.clone(), |stored| stored.ports.clone());
    let target_names: Vec<String> = resume.map_or_else(
        || prepared.targets.iter().map(ToString::to_string).collect(),
        |stored| stored.targets.clone(),
    );
    let mut scan = Scan::start(scan_id.clone(), target_names);
    let resolved: Vec<ResolvedHost> = match resume {
        Some(stored) => stored.resolved.clone(),
        None => resolve_targets(
            &prepared.targets,
            &prepared.guard,
            prepared.config.limits.max_hosts,
        )
        .await
        .map_err(|e| anyhow!("{e}"))?,
    };
    if resume.is_none() {
        prepared
            .storage
            .begin_scan(&scan_id, &scan.targets, &ports, &resolved)
            .map_err(|e| anyhow!("{e}"))?;
    }
    let mut completed: HashMap<(String, u16), PortResult> = HashMap::new();
    if resume.is_some() {
        for saved in prepared
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

    let semaphore = Arc::new(Semaphore::new(
        prepared.config.limits.max_concurrency.max(1),
    ));
    let rate = Arc::new(RateLimiter::new(prepared.config.limits.max_rate.max(1)));

    let mut hosts: Vec<HostResult> = Vec::new();
    let mut scannable: Vec<IpAddr> = Vec::new();
    if prepared.skip_discovery {
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
        &ports,
        &prepared.config.limits,
        &prepared.guard,
        Arc::clone(&rate),
        &skip,
    )
    .await;
    if port_scan.cancelled || port_scan.join_errors > 0 {
        scan.meta.truncated = true;
    }
    scan.meta.peak_active_probes = port_scan.peak_active;
    for probe in port_scan.probes {
        let address = probe.ip.to_string();
        prepared
            .storage
            .save_probe(
                &scan_id,
                &address,
                probe.port,
                probe.outcome.state,
                probe.outcome.reason,
                probe.outcome.latency_ms,
            )
            .map_err(|e| anyhow!("{e}"))?;
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
        }
    }
    // Reattach previously saved probes (resume path).
    for ((address, _), saved) in &completed {
        match hosts.iter_mut().find(|host| &host.address == address) {
            Some(host) => {
                if !host.ports.iter().any(|port| port.port == saved.port) {
                    host.ports.push(saved.clone());
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
    scan.hosts = hosts;
    if prepared.detect {
        identify_services(&mut scan, prepared, &scan_id, &semaphore, &rate).await;
    }
    // OS estimates need detected services; without them every guess would be
    // Unknown noise, so skip the stage entirely.
    if prepared.os_enabled && prepared.detect {
        for host in &mut scan.hosts {
            host.os = Some(crate::os::fingerprint(&host.ports));
        }
    }
    for host in &scan.hosts {
        prepared
            .storage
            .save_host(
                &scan_id,
                &host.address,
                host.status,
                host.latency_ms,
                host.os.as_ref(),
            )
            .map_err(|e| anyhow!("{e}"))?;
    }
    scan.finish();
    tracing::info!(scan_id = %scan.meta.scan_id, event = "scan_completed");
    Ok(scan)
}

/// Run service detection on open ports lacking service data. Probe latency and
/// state stay as the port scan measured them; detection fills service fields
/// and banners, persisting each result as it completes.
async fn identify_services(
    scan: &mut Scan,
    prepared: &PreparedScan,
    scan_id: &str,
    semaphore: &Arc<Semaphore>,
    rate: &Arc<RateLimiter>,
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
            let limits = prepared.config.limits.clone();
            let guard = prepared.guard.clone();
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
        if let Err(e) = prepared.storage.update_detection(scan_id, &address, port) {
            tracing::warn!(%e, "detection result not persisted");
        }
    }
}
use std::path::PathBuf;

/// Bound the whole scan (discovery plus ports) by `max_scan_duration_secs`.
async fn run_bounded(prepared: &PreparedScan, resume: Option<&StoredScan>) -> anyhow::Result<Scan> {
    let duration = Duration::from_secs(prepared.config.limits.max_scan_duration_secs.max(1));
    match tokio::time::timeout(duration, run_phases(prepared, resume)).await {
        Ok(scan) => scan,
        Err(_) => Err(anyhow!("scan duration exceeded max_scan_duration_secs")),
    }
}

fn emit(scan: &Scan, output: &str) {
    match output {
        "json" => println!("{}", model::to_json(scan)),
        "csv" => print!("{}", model::to_csv(scan)),
        _ => {
            print!("{}", model::terminal_table(scan));
            print!("{}", model::os_lines(scan));
            if scan.meta.truncated {
                println!("Note: scan stopped early; results are partial.");
            }
        }
    }
}

/// Persist a cleanly finished scan. Interrupted scans stay `running` so
/// `--resume` can pick them up.
fn maybe_finish(prepared: &PreparedScan, scan: &Scan) -> anyhow::Result<()> {
    if scan.meta.truncated {
        eprintln!(
            "Scan {} stopped early; resume it with: sentinelscan scan --resume {} --yes",
            scan.meta.scan_id, scan.meta.scan_id
        );
        return Ok(());
    }
    prepared
        .storage
        .finish_scan(&scan.meta.scan_id, false, scan.meta.peak_active_probes)
        .map_err(|e| anyhow!("{e}"))
}

/// Run the `scan` subcommand end to end.
pub async fn run_scan(args: &ScanArgs) -> anyhow::Result<()> {
    if let Some(resume_id) = &args.resume {
        return run_resume(args, resume_id).await;
    }
    if args.targets.is_empty() {
        return Err(anyhow!("no targets given"));
    }
    let Some(prepared) = prepare(&PrepareRequest {
        raw_targets: args.targets.clone(),
        allow_hostnames: args.allow_hostnames,
        port_spec: args.ports.clone(),
        profile: args.profile,
        service_detection: args.service_detection,
        banner: args.banner,
        os_detection: args.os_detection,
        skip_discovery: args.skip_host_discovery,
        output: args.output.clone(),
        concurrency: args.concurrency,
        rate: args.rate,
        config_path: args.config.clone(),
        db_path: args.db.clone(),
        yes: args.yes,
    })?
    else {
        return Ok(());
    };
    let scan = run_bounded(&prepared, None).await?;
    maybe_finish(&prepared, &scan)?;
    emit(&scan, &args.output);
    Ok(())
}

/// Resume an interrupted scan: reuse its stored scope and saved probes, probe
/// only what is missing. Targets and ports cannot be combined with `--resume`.
async fn run_resume(args: &ScanArgs, resume_id: &str) -> anyhow::Result<()> {
    if !args.targets.is_empty() || args.ports.is_some() {
        return Err(anyhow!(
            "--resume cannot be combined with targets or --ports"
        ));
    }
    validate_output_format(&args.output).map_err(|e| anyhow!("{e}"))?;
    let db_path = args.db.clone().map_or_else(default_db_path, PathBuf::from);
    let storage = Storage::open(&db_path).map_err(|e| anyhow!("{e}"))?;
    let stored = storage.load_scan(resume_id).map_err(|e| anyhow!("{e}"))?;
    if stored.status != "running" {
        return Err(anyhow!(
            "scan {resume_id} is '{}'; only interrupted scans can resume",
            stored.status
        ));
    }
    let mut config = Config::load(args.config.as_deref()).map_err(|e| anyhow!("{e}"))?;
    apply_overrides(&mut config.limits, args.concurrency, args.rate)?;
    let settings = effective_settings(
        args.profile,
        &config,
        None,
        args.service_detection,
        args.banner,
        args.skip_host_discovery,
    );
    // The scope was confirmed when the scan first ran; rebuild the guard from
    // the same declared targets. Hostnames parse leniently here because the
    // stored resolution is reused, not re-resolved.
    let targets = parse_targets(&stored.targets, true, config.limits.max_hosts)
        .map_err(|e| anyhow!("{e}"))?;
    let guard = ScopeGuard::from_targets(&targets);
    let summary = format!(
        "Authorized use only: scan only systems you own or have written permission to test.\n\
         resuming scan: {resume_id}\n\
         targets: {}\n\
         ports: {} outstanding",
        model::sanitize(&stored.targets.join(" ")),
        stored.ports.len(),
    );
    if !confirm_scope(&summary, args.yes, args.output != "terminal")? {
        println!("Aborted. No traffic sent.");
        return Ok(());
    }
    let prepared = PreparedScan {
        scan_id: stored.scan_id.clone(),
        config,
        ports: stored.ports.clone(),
        targets,
        guard,
        skip_discovery: settings.skip_discovery,
        detect: settings.detect || args.os_detection,
        os_enabled: args.os_detection || args.profile == Profile::Standard,
        storage,
    };
    let scan = run_bounded(&prepared, Some(&stored)).await?;
    maybe_finish(&prepared, &scan)?;
    emit(&scan, &args.output);
    Ok(())
}

/// What a single-target subcommand does after scope confirmation.
enum TargetMode {
    /// Discovery only.
    Hosts,
    /// Discovery plus port scan.
    Ports,
    /// Discovery plus port scan plus service detection, service view.
    Services,
}

async fn run_target_command(arg: &TargetArg, mode: TargetMode) -> anyhow::Result<()> {
    let Some(prepared) = prepare(&PrepareRequest {
        raw_targets: std::slice::from_ref(&arg.target).to_vec(),
        allow_hostnames: arg.allow_hostnames,
        port_spec: None,
        profile: Profile::Standard,
        service_detection: matches!(mode, TargetMode::Services),
        banner: false,
        os_detection: false,
        skip_discovery: false,
        output: "terminal".to_owned(),
        concurrency: None,
        rate: None,
        config_path: None,
        db_path: None,
        yes: arg.yes,
    })?
    else {
        return Ok(());
    };
    if matches!(mode, TargetMode::Hosts) {
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
    let scan = run_bounded(&prepared, None).await?;
    maybe_finish(&prepared, &scan)?;
    if matches!(mode, TargetMode::Services) {
        print!("{}", model::service_table(&scan));
        print!("{}", model::os_lines(&scan));
    } else {
        emit(&scan, "terminal");
    }
    Ok(())
}

async fn run_history(args: &HistoryArgs) -> anyhow::Result<()> {
    validate_machine_output(&args.output).map_err(|e| anyhow!("{e}"))?;
    let db_path = args.db.clone().map_or_else(default_db_path, PathBuf::from);
    let storage = Storage::open(&db_path).map_err(|e| anyhow!("{e}"))?;
    let scans = storage.list_scans().map_err(|e| anyhow!("{e}"))?;
    if args.output == "json" {
        println!(
            "{}",
            serde_json::to_string_pretty(&scans).unwrap_or_else(|_| "[]".to_owned())
        );
        return Ok(());
    }
    println!("SCAN_ID\tSTATUS\tSTARTED\tTARGETS\tHOSTS\tOPEN");
    for scan in scans {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            scan.scan_id,
            scan.status,
            scan.started_unix_secs,
            model::sanitize(&scan.targets.join(" ")),
            scan.host_count,
            scan.open_port_count
        );
    }
    Ok(())
}

fn emit_comparison(comparison: &Comparison, output: &str) {
    if output == "json" {
        println!(
            "{}",
            serde_json::to_string_pretty(comparison).unwrap_or_else(|_| "{}".to_owned())
        );
    } else {
        print!("{}", comparison_table(comparison));
    }
}

async fn run_compare(
    scan_a: &str,
    scan_b: &str,
    db: &Option<String>,
    output: &str,
) -> anyhow::Result<()> {
    validate_machine_output(output).map_err(|e| anyhow!("{e}"))?;
    let db_path = db.clone().map_or_else(default_db_path, PathBuf::from);
    let storage = Storage::open(&db_path).map_err(|e| anyhow!("{e}"))?;
    let older = storage.load_full_scan(scan_a).map_err(|e| anyhow!("{e}"))?;
    let newer = storage.load_full_scan(scan_b).map_err(|e| anyhow!("{e}"))?;
    emit_comparison(&compare(&older, &newer), output);
    Ok(())
}

/// Dispatch any subcommand; OS detection arrives in Phase 5.
pub async fn run(command: &Command) -> anyhow::Result<()> {
    match command {
        Command::Scan(args) => run_scan(args).await,
        Command::Config(args) => {
            let config = Config::load(args.config.as_deref()).map_err(|e| anyhow!("{e}"))?;
            println!("{}", toml::to_string(&config).unwrap_or_default());
            Ok(())
        }
        Command::Hosts(arg) => run_target_command(arg, TargetMode::Hosts).await,
        Command::Ports(arg) => run_target_command(arg, TargetMode::Ports).await,
        Command::Services(arg) => run_target_command(arg, TargetMode::Services).await,
        Command::History(args) => run_history(args).await,
        Command::Compare(args) => {
            run_compare(&args.scan_a, &args.scan_b, &args.db, &args.output).await
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
            db: None,
            resume: None,
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
    async fn rejects_empty_targets_without_resume() {
        let args = scan_args(&[], "80");
        assert!(run_scan(&args).await.is_err());
    }

    #[tokio::test]
    async fn rejects_resume_with_targets() {
        let mut args = scan_args(&["127.0.0.1"], "80");
        args.resume = Some("01NEVER".to_owned());
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
