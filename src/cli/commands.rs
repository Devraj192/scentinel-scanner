use std::io::{self, BufRead, Write};

use anyhow::{anyhow, Context};

use super::args::{Command, ScanArgs};
use crate::config::Config;
use crate::errors::Error;
use crate::safety::ports::parse_ports;
use crate::safety::scope::{host_count, parse_targets, ScopeGuard};

/// Strip control characters before echoing user input to the terminal.
fn sanitize(output: &str) -> String {
    output
        .chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                '�'
            } else {
                c
            }
        })
        .collect()
}

/// Print the pre-scan scope summary and require `y` unless `--yes` was given.
fn confirm_scope(summary: &str, yes: bool) -> anyhow::Result<bool> {
    println!("{summary}");
    if yes {
        return Ok(true);
    }
    print!("Continue? [y/N] ");
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

/// Run the `scan` subcommand. Phase 1 validates and confirms scope, then exits
/// without opening any socket.
pub fn run_scan(args: &ScanArgs) -> anyhow::Result<()> {
    let scan_id = ulid::Ulid::new().to_string();
    tracing::info!(scan_id = %scan_id, event = "scan_started");

    validate_output_format(&args.output).map_err(|e| anyhow!("{e}"))?;
    let mut config = Config::load(args.config.as_deref()).map_err(|e| anyhow!("{e}"))?;
    if let Some(concurrency) = args.concurrency {
        if concurrency == 0 || concurrency > 5000 {
            return Err(anyhow!("--concurrency must be 1-5000, got {concurrency}"));
        }
        config.limits.max_concurrency = concurrency;
    }
    if let Some(rate) = args.rate {
        if rate == 0 || rate > 100_000 {
            return Err(anyhow!("--rate must be 1-100000, got {rate}"));
        }
        config.limits.max_rate = rate;
    }

    let port_spec = args
        .ports
        .clone()
        .unwrap_or_else(|| args.profile.default_ports().to_owned());
    let ports = parse_ports(&port_spec, config.limits.max_ports).map_err(|e| anyhow!("{e}"))?;
    let targets = parse_targets(&args.targets, args.allow_hostnames, config.limits.max_hosts)
        .map_err(|e| anyhow!("{e}"))?;
    let _guard = ScopeGuard::from_targets(&targets);

    let summary = format!(
        "Authorized use only: scan only systems you own or have written permission to test.\n\
         scan_id: {scan_id}\n\
         targets: {}\n\
         hosts: {}\n\
         ports: {} ({} selected)\n\
         profile: {:?}\n\
         concurrency: {}\n\
         rate: {}/s\n\
         output: {}",
        sanitize(
            &targets
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ")
        ),
        host_count(&targets),
        sanitize(&port_spec),
        ports.len(),
        args.profile,
        config.limits.max_concurrency,
        config.limits.max_rate,
        sanitize(&args.output),
    );
    if !confirm_scope(&summary, args.yes)? {
        println!("Aborted. No traffic sent.");
        return Ok(());
    }
    tracing::info!(scan_id = %scan_id, event = "scan_completed");
    println!("Scope confirmed. Phase 1 sends no traffic; exiting.");
    Ok(())
}

/// Dispatch any subcommand; only `scan` and `config` do real work in Phase 1.
pub fn run(command: &Command) -> anyhow::Result<()> {
    match command {
        Command::Scan(args) => run_scan(args),
        Command::Config(args) => {
            let config = Config::load(args.config.as_deref()).map_err(|e| anyhow!("{e}"))?;
            println!("{}", toml::to_string(&config.limits).unwrap_or_default());
            Ok(())
        }
        Command::Hosts(_) => {
            println!("'hosts' arrives in Phase 2; Phase 1 validates scope only.");
            Ok(())
        }
        Command::Ports(_) => {
            println!("'ports' arrives in Phase 2; Phase 1 validates scope only.");
            Ok(())
        }
        Command::Services(_) => {
            println!("'services' arrives in Phase 3; Phase 1 validates scope only.");
            Ok(())
        }
        Command::History => {
            println!("'history' arrives in Phase 4; Phase 1 validates scope only.");
            Ok(())
        }
        Command::Compare(_) => {
            println!("'compare' arrives in Phase 4; Phase 1 validates scope only.");
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

    #[test]
    fn rejects_bad_output_format() {
        let mut args = scan_args(&["127.0.0.1"], "80");
        args.output = "xml".to_owned();
        assert!(run_scan(&args).is_err());
    }

    #[test]
    fn rejects_malformed_target_without_traffic() {
        let args = scan_args(&["999.999.0.1"], "80");
        assert!(run_scan(&args).is_err());
    }

    #[test]
    fn rejects_malformed_ports_without_traffic() {
        let args = scan_args(&["127.0.0.1"], "0");
        assert!(run_scan(&args).is_err());
    }

    #[test]
    fn sanitizes_control_characters() {
        assert_eq!(sanitize("a\x00b\x1bc"), "a�b�c");
    }
}
