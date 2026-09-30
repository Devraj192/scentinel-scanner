//! SentinelScan: fast, safety-conscious network scanning for authorized networks.
//!
//! The binary in `src/main.rs` is a thin CLI over this library. Future front
//! ends (desktop app, dashboard, CI job) reuse the same pieces:
//! - [`config`]: limits, profiles, TOML loading.
//! - [`safety`]: target/port parsing plus [`safety::scope::ScopeGuard`], the
//!   only path to the network.
//! - [`scanner`] and [`discovery`]: bounded async TCP probing.
//! - [`detection`] and [`protocols`]: pluggable service identification.
//! - [`os`]: banner-only OS estimates with evidence.
//! - [`results`]: one canonical model with terminal, JSON, and CSV views.
//! - [`storage`]: SQLite history, comparison, and resumable scans.
//!
//! # Example
//!
//! ```no_run
//! use sentinelscan::config::Config;
//!
//! let config = Config::load(None).expect("defaults always validate");
//! assert_eq!(config.limits.max_hosts, 256);
//! ```

pub mod cli;
pub mod config;
pub mod detection;
pub mod discovery;
pub mod errors;
pub mod os;
pub mod protocols;
pub mod results;
pub mod safety;
pub mod scanner;
pub mod storage;

pub use config::Config;
pub use errors::Error;
pub use results::model::Scan;
pub use storage::Storage;
