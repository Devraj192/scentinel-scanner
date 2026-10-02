use clap::{Parser, Subcommand};

use sentinelscan_core::config::profiles::Profile;

const AUTH_WARNING: &str =
    "Authorized use only: scan only systems and networks you own or have written permission to test.";

/// Fast, safety-first network scanner for authorized networks.
#[derive(Debug, Parser)]
#[command(
    name = "sentinelscan",
    version = env!("SENTINELSCAN_BUILD"),
    about = AUTH_WARNING
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run a scan: confirm scope, discover hosts, probe ports, detect services.
    ///
    /// Examples:
    ///   sentinelscan scan 127.0.0.1 --ports 22,80,443 --yes
    ///   sentinelscan scan 192.168.1.0/24 --ports 1-1024 --output json --yes
    ///   sentinelscan scan --resume 01HEXAMPLE --yes
    Scan(ScanArgs),
    /// List live hosts.
    ///
    /// Examples:
    ///   sentinelscan hosts 127.0.0.1 --yes
    Hosts(TargetArg),
    /// Scan ports without service detection.
    ///
    /// Examples:
    ///   sentinelscan ports 127.0.0.1 --yes
    Ports(TargetArg),
    /// Scan ports and identify services.
    ///
    /// Examples:
    ///   sentinelscan services 127.0.0.1 --yes
    Services(TargetArg),
    /// Show scan history.
    ///
    /// Examples:
    ///   sentinelscan history
    ///   sentinelscan history --output json --db /tmp/lab.db
    History(HistoryArgs),
    /// Compare two scans: added, removed, and changed ports and services.
    ///
    /// Examples:
    ///   sentinelscan compare 01SCAN_A 01SCAN_B
    Compare(CompareArgs),
    /// Check the environment: limits, privileges, DNS, directories, install.
    ///
    /// Examples:
    ///   sentinelscan doctor
    Doctor(DoctorArgs),
    /// Explain a port state or confidence word in plain language.
    ///
    /// Examples:
    ///   sentinelscan explain filtered
    ///   sentinelscan explain confidence
    Explain(ExplainArgs),
    /// Write a commented default config file to the XDG config directory.
    ///
    /// Examples:
    ///   sentinelscan init
    Init(InitArgs),
    /// Print shell completions.
    ///
    /// Examples:
    ///   sentinelscan completions bash >> ~/.bash_completion
    Completions(CompletionsArgs),
    /// Print the man page (roff).
    ///
    /// Examples:
    ///   sentinelscan man | man -l -
    Man,
    /// Show effective configuration.
    ///
    /// Examples:
    ///   sentinelscan config
    ///   sentinelscan config --config mylimits.toml
    Config(ConfigArgs),
}

/// Full `scan` arguments.
#[derive(Debug, Clone, Parser)]
pub struct ScanArgs {
    /// Targets: IPv4, IPv6, CIDR, or hostname (hostnames need --allow-hostnames).
    /// Empty only with --resume, which reuses the stored scope.
    pub targets: Vec<String>,
    /// Ports: single, list, range, or named profile (quick, standard, full).
    #[arg(long)]
    pub ports: Option<String>,
    /// Scan profile.
    #[arg(long, default_value = "standard")]
    pub profile: Profile,
    /// Active-operation cap (overrides config).
    #[arg(long)]
    pub concurrency: Option<usize>,
    /// New operations per second (overrides config).
    #[arg(long)]
    pub rate: Option<u64>,
    /// Enable service detection.
    #[arg(long, default_value_t = false)]
    pub service_detection: bool,
    /// Enable banner grabbing.
    #[arg(long, default_value_t = false)]
    pub banner: bool,
    /// Enable OS detection.
    #[arg(long, default_value_t = false)]
    pub os_detection: bool,
    /// Output format.
    #[arg(long, default_value = "terminal")]
    pub output: String,
    /// Skip host discovery.
    #[arg(long, default_value_t = false)]
    pub skip_host_discovery: bool,
    /// Allow hostname targets (off by default).
    #[arg(long, default_value_t = false)]
    pub allow_hostnames: bool,
    /// Path to TOML config file.
    #[arg(long)]
    pub config: Option<String>,
    /// Path to SQLite history database.
    #[arg(long)]
    pub db: Option<String>,
    /// Resume an interrupted scan instead of starting a new one.
    #[arg(long)]
    pub resume: Option<String>,
    /// Skip the confirmation prompt (automation).
    #[arg(long, default_value_t = false)]
    pub yes: bool,
}

#[derive(Debug, Clone, Parser)]
pub struct TargetArg {
    /// Target to operate on.
    pub target: String,
    /// Allow hostname targets (off by default).
    #[arg(long, default_value_t = false)]
    pub allow_hostnames: bool,
    /// Skip the confirmation prompt (automation).
    #[arg(long, default_value_t = false)]
    pub yes: bool,
}

#[derive(Debug, Clone, Parser)]
pub struct CompareArgs {
    /// First scan id (baseline).
    pub scan_a: String,
    /// Second scan id.
    pub scan_b: String,
    /// Path to SQLite history database.
    #[arg(long)]
    pub db: Option<String>,
    /// Output format (terminal or json).
    #[arg(long, default_value = "terminal")]
    pub output: String,
}
#[derive(Debug, Clone, Parser)]
pub struct HistoryArgs {
    /// Path to SQLite history database.
    #[arg(long)]
    pub db: Option<String>,
    /// Output format (terminal or json).
    #[arg(long, default_value = "terminal")]
    pub output: String,
}

#[derive(Debug, Clone, Parser)]
pub struct DoctorArgs {
    /// Output format (terminal or json).
    #[arg(long, default_value = "terminal")]
    pub output: String,
}

#[derive(Debug, Clone, Parser)]
pub struct ExplainArgs {
    /// Topic: open, closed, filtered, unknown, or confidence.
    pub topic: String,
}

#[derive(Debug, Clone, Parser)]
pub struct InitArgs {
    /// Overwrite an existing config file.
    #[arg(long, default_value_t = false)]
    pub force: bool,
}

#[derive(Debug, Clone, Parser)]
pub struct CompletionsArgs {
    /// Shell: bash, zsh, or fish.
    pub shell: String,
}

#[derive(Debug, Clone, Parser)]
pub struct ConfigArgs {
    /// Path to TOML config file.
    #[arg(long)]
    pub config: Option<String>,
}
