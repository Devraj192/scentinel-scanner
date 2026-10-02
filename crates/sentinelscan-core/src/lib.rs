//! SentinelScan engine: fast, safety-conscious network scanning for authorized
//! networks, as a library.
//!
//! The `sentinelscan` binary is a thin CLI over this library, and the v2 TUI
//! is a second consumer of the same [`events`] stream. Reusable pieces:
//! - [`config`]: limits, profiles, TOML loading.
//! - [`safety`]: target/port parsing plus [`safety::scope::ScopeGuard`], the
//!   only path to the network.
//! - [`scanner`] and [`discovery`]: bounded async TCP probing.
//! - [`detection`] and [`protocols`]: pluggable service identification.
//! - [`os`]: banner-only OS estimates with evidence.
//! - [`pipeline`]: staged runs emitting [`events::ScanEvent`].
//! - [`results`]: one canonical model with terminal, JSON, and CSV views.
//! - [`storage`]: SQLite history, comparison, and resumable scans.
//!
//! # Example
//!
//! ```no_run
//! use sentinelscan_core::config::Config;
//!
//! let config = Config::load(None).expect("defaults always validate");
//! assert_eq!(config.limits.max_hosts, 256);
//! ```

pub mod config;
pub mod detection;
pub mod discovery;
pub mod errors;
pub mod events;
pub mod os;
pub mod paths;
pub mod pipeline;
pub mod protocols;
pub mod results;
pub mod safety;
pub mod scanner;
pub mod storage;

pub use config::Config;
pub use errors::Error;
pub use results::model::Scan;
pub use storage::Storage;
