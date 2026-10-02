use std::io::{self, BufRead, Write};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use tokio::sync::{mpsc, Semaphore};

use super::args::{Command, HistoryArgs, ScanArgs, TargetArg};
use sentinelscan_core::config::profiles::Profile;
use sentinelscan_core::config::{Config, Limits};
use sentinelscan_core::discovery::host::discover_all;
use sentinelscan_core::errors::Error;
use sentinelscan_core::events::{ScanEvent, CHANNEL_CAPACITY};
use sentinelscan_core::pipeline::{execute, ScanPlan};
use sentinelscan_core::results::model::{self, Scan};
use sentinelscan_core::safety::ports::parse_ports;
use sentinelscan_core::safety::scope::{host_count, parse_targets, ParsedTarget, ScopeGuard};
use sentinelscan_core::scanner::rate_limit::RateLimiter;
use sentinelscan_core::scanner::resolve::resolve_targets;
use sentinelscan_core::storage::{compare, comparison_table, Comparison, Storage, StoredScan};

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

/// Open history: explicit `--db` as-is, otherwise the XDG default (which
/// relocates a v1 file with a backup on first run).
fn open_storage(db: &Option<String>) -> anyhow::Result<Storage> {
    match db {
        Some(path) => Storage::open(Path::new(path)),
        None => Storage::open_default(),
    }
    .map_err(|e| anyhow!("{e}"))
}

/// Config source: explicit `--config`, else the XDG file when it exists,
/// else built-in defaults.
fn config_source(explicit: &Option<String>) -> Option<String> {
    explicit
        .clone()
        .or_else(|| Config::default_path().map(|path| path.to_string_lossy().into_owned()))
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
    let mut config =
        Config::load(config_source(&request.config_path).as_deref()).map_err(|e| anyhow!("{e}"))?;
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
    let storage = open_storage(&request.db_path)?;
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

impl PreparedScan {
    /// Convert the confirmed scope into the engine's run plan.
    fn plan(&self) -> ScanPlan {
        ScanPlan {
            scan_id: self.scan_id.clone(),
            targets: self.targets.clone(),
            ports: self.ports.clone(),
            limits: self.config.limits.clone(),
            guard: self.guard.clone(),
            skip_discovery: self.skip_discovery,
            detect: self.detect,
            os_enabled: self.os_enabled,
            storage: self.storage.clone(),
        }
    }
}

/// Run the engine and take the finished model from its event stream. The
/// `Completed` event is the single source of truth both UIs share — the CLI
/// assembles nothing in parallel that could drift from it.
async fn run_plan(prepared: PreparedScan, resume: Option<StoredScan>) -> anyhow::Result<Scan> {
    let (tx, mut rx) = mpsc::channel(CHANNEL_CAPACITY);
    let plan = prepared.plan();
    let handle = tokio::spawn(async move { execute(&plan, resume.as_ref(), &tx).await });
    let mut completed: Option<Scan> = None;
    while let Some(event) = rx.recv().await {
        match event {
            ScanEvent::Warning { message } => tracing::warn!("{message}"),
            ScanEvent::Progress { done, total } => {
                tracing::debug!(done, total, event = "progress");
            }
            ScanEvent::Completed { scan } => completed = Some(scan),
            ScanEvent::Error { message } => tracing::warn!(event = "scan_error", "{message}"),
            _ => {}
        }
    }
    let direct = handle
        .await
        .map_err(|e| anyhow!("scan task failed: {e}"))??;
    Ok(completed.unwrap_or(direct))
}

/// Bound the whole scan by `max_scan_duration_secs`. Expiry aborts the run;
/// whatever was persisted stays resumable.
async fn run_bounded(prepared: PreparedScan, resume: Option<StoredScan>) -> anyhow::Result<Scan> {
    let duration = Duration::from_secs(prepared.config.limits.max_scan_duration_secs.max(1));
    let task = tokio::spawn(run_plan(prepared, resume));
    match tokio::time::timeout(duration, task).await {
        Ok(join) => join.map_err(|e| anyhow!("scan task failed: {e}"))?,
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
fn maybe_finish(storage: &Storage, scan: &Scan) -> anyhow::Result<()> {
    if scan.meta.truncated {
        eprintln!(
            "Scan {} stopped early; resume it with: sentinelscan scan --resume {} --yes",
            scan.meta.scan_id, scan.meta.scan_id
        );
        return Ok(());
    }
    storage
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
    let storage = prepared.storage.clone();
    let scan = run_bounded(prepared, None).await?;
    maybe_finish(&storage, &scan)?;
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
    let storage = open_storage(&args.db)?;
    let stored = storage.load_scan(resume_id).map_err(|e| anyhow!("{e}"))?;
    if stored.status != "running" {
        return Err(anyhow!(
            "scan {resume_id} is '{}'; only interrupted scans can resume",
            stored.status
        ));
    }
    let mut config =
        Config::load(config_source(&args.config).as_deref()).map_err(|e| anyhow!("{e}"))?;
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
    let storage = prepared.storage.clone();
    let scan = run_bounded(prepared, Some(stored)).await?;
    maybe_finish(&storage, &scan)?;
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
        let mut guard = prepared.guard.clone();
        let resolved = resolve_targets(
            &prepared.targets,
            &mut guard,
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
            &guard,
            semaphore,
            rate,
        )
        .await;
        print!("{}", model::host_table(&hosts));
        return Ok(());
    }
    let storage = prepared.storage.clone();
    let scan = run_bounded(prepared, None).await?;
    maybe_finish(&storage, &scan)?;
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
    let storage = open_storage(&args.db)?;
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
    let storage = open_storage(db)?;
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
            let config =
                Config::load(config_source(&args.config).as_deref()).map_err(|e| anyhow!("{e}"))?;
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
            profile: sentinelscan_core::config::profiles::Profile::Standard,
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
        let mut guard = ScopeGuard::from_targets(&targets);
        let resolved = resolve_targets(&targets, &mut guard, 256)
            .await
            .expect("resolve");
        assert_eq!(resolved.len(), 2);
    }
}
