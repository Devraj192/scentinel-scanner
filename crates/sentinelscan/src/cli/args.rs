use clap::{Parser, Subcommand};

use sentinelscan_core::config::profiles::Profile;

const AUTH_WARNING: &str =
    "Authorized use only: scan only systems and networks you own or have written permission to test.";

/// Fast, safety-first network scanner for authorized networks.
#[derive(Debug, Parser)]
#[command(name = "sentinelscan", version, about = AUTH_WARNING)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Validate scope and (in later phases) run a scan. Phase 1 stops after confirmation.
    Scan(ScanArgs),
    /// List live hosts (Phase 2).
    Hosts(TargetArg),
    /// Scan ports (Phase 2).
    Ports(TargetArg),
    /// Detect services (Phase 3).
    Services(TargetArg),
    /// Show scan history.
    History(HistoryArgs),
    /// Compare two scans.
    Compare(CompareArgs),
    /// Show effective configuration.
    Config(ConfigArgs),
}

/// Full `scan` arguments; every flag from PRD 3.10 parses in Phase 1.
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
    /// Enable service detection (Phase 3).
    #[arg(long, default_value_t = false)]
    pub service_detection: bool,
    /// Enable banner grabbing (Phase 3).
    #[arg(long, default_value_t = false)]
    pub banner: bool,
    /// Enable OS detection (Phase 5).
    #[arg(long, default_value_t = false)]
    pub os_detection: bool,
    /// Output format.
    #[arg(long, default_value = "terminal")]
    pub output: String,
    /// Skip host discovery (Phase 2).
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
pub struct ConfigArgs {
    /// Path to TOML config file.
    #[arg(long)]
    pub config: Option<String>,
}
