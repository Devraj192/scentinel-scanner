use crate::os::OsGuess;
use crate::results::model::{HostStatus, PortResult, Scan};

/// Bounded channel capacity for the scan event stream. Large enough that
/// producers never block on a live consumer; small enough to bound memory.
pub const CHANNEL_CAPACITY: usize = 1024;

/// Typed events from a running scan. The CLI printer and (later) the TUI are
/// two consumers of this same stream; no scanning logic lives in UI code.
#[derive(Debug, Clone)]
pub enum ScanEvent {
    /// Scope confirmed, resolution about to start.
    Started {
        scan_id: String,
        targets: Vec<String>,
        ports: Vec<u16>,
    },
    /// One host classified by discovery (or `unknown` when skipped).
    HostDiscovered {
        address: String,
        status: HostStatus,
        latency_ms: u64,
    },
    /// One classified probe, before service detection.
    PortProbed { address: String, port: PortResult },
    /// Service identification finished for one open port.
    ServiceDetected {
        address: String,
        port: u16,
        service: Option<String>,
        version: Option<String>,
        confidence: Option<f32>,
        evidence: Vec<crate::detection::service::Evidence>,
        banner: Option<crate::results::model::Banner>,
    },
    /// OS estimate finished for one host (`None` means the stage was skipped).
    OsEstimated {
        address: String,
        os: Option<OsGuess>,
    },
    /// How many probe operations finished out of the planned total.
    Progress { done: usize, total: usize },
    /// Something degraded but the scan continues (cancel, join error).
    Warning { message: String },
    /// The finished canonical model, with final timestamps and flags.
    Completed { scan: Scan },
    /// The run failed; no usable model follows.
    Error { message: String },
}
