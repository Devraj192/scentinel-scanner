use serde::{Deserialize, Serialize};

/// Port state per PRD 3.3. A timeout is never `closed`; local errors are
/// `unknown`, never a guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unknown,
}

impl std::fmt::Display for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::Closed => write!(f, "closed"),
            Self::Filtered => write!(f, "filtered"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Host liveness from TCP probes. `Unknown` means not probed or inconclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostStatus {
    Up,
    Down,
    Unknown,
}

impl std::fmt::Display for HostStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Up => write!(f, "up"),
            Self::Down => write!(f, "down"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// One TCP port result. Service fields stay `None` until Phase 3 fills them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub protocol: String,
    pub state: PortState,
    pub reason: String,
    pub latency_ms: u64,
    pub service: Option<String>,
}

/// One host in the canonical result model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    pub address: String,
    pub status: HostStatus,
    pub latency_ms: u64,
    pub ports: Vec<PortResult>,
}

/// Scan metadata. Every scan carries a unique ULID `scan_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMeta {
    pub scan_id: String,
    pub version: String,
    pub started_unix_secs: u64,
    pub finished_unix_secs: u64,
    pub truncated: bool,
    /// Highest number of simultaneously active port probes observed. Lets
    /// operators (and tests) verify the concurrency cap held.
    pub peak_active_probes: usize,
}

/// Canonical scan result. Terminal, JSON, and (Phase 4) SQLite all derive from this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scan {
    pub meta: ScanMeta,
    pub targets: Vec<String>,
    pub hosts: Vec<HostResult>,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Scan {
    /// New scan with `finished` unset (0) and `truncated` false.
    pub fn start(scan_id: String, targets: Vec<String>) -> Self {
        Self {
            meta: ScanMeta {
                scan_id,
                version: env!("CARGO_PKG_VERSION").to_owned(),
                started_unix_secs: unix_now(),
                finished_unix_secs: 0,
                truncated: false,
                peak_active_probes: 0,
            },
            targets,
            hosts: Vec::new(),
        }
    }

    /// Stamp completion time.
    pub fn finish(&mut self) {
        self.meta.finished_unix_secs = unix_now();
    }
}

/// Strip control characters before printing or storing network-derived text.
pub fn sanitize(output: &str) -> String {
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

/// HOST / PORT / STATE / SERVICE table over every scanned port.
pub fn terminal_table(scan: &Scan) -> String {
    let mut out = String::from("HOST\tPORT\tSTATE\tSERVICE\n");
    for host in &scan.hosts {
        if host.ports.is_empty() {
            out.push_str(&format!(
                "{}\t-\t{}\t-\n",
                sanitize(&host.address),
                host.status
            ));
        }
        for port in &host.ports {
            out.push_str(&format!(
                "{}\t{}\t{}\t{}\n",
                sanitize(&host.address),
                port.port,
                port.state,
                sanitize(port.service.as_deref().unwrap_or("-")),
            ));
        }
    }
    out
}

/// HOST / STATUS / LATENCY table for discovery-only output.
pub fn host_table(hosts: &[HostResult]) -> String {
    let mut out = String::from("HOST\tSTATUS\tLATENCY_MS\n");
    for host in hosts {
        out.push_str(&format!(
            "{}\t{}\t{}\n",
            sanitize(&host.address),
            host.status,
            host.latency_ms
        ));
    }
    out
}

/// Canonical JSON encoding of the scan.
pub fn to_json(scan: &Scan) -> String {
    serde_json::to_string_pretty(scan).unwrap_or_else(|_| "{}".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trips() {
        let mut scan = Scan::start("01TEST".to_owned(), vec!["127.0.0.1".to_owned()]);
        scan.hosts.push(HostResult {
            address: "127.0.0.1".to_owned(),
            status: HostStatus::Up,
            latency_ms: 1,
            ports: vec![PortResult {
                port: 80,
                protocol: "tcp".to_owned(),
                state: PortState::Open,
                reason: "handshake".to_owned(),
                latency_ms: 1,
                service: None,
            }],
        });
        scan.finish();
        let text = to_json(&scan);
        let back: Scan = serde_json::from_str(&text).expect("round trip");
        assert_eq!(back.hosts.len(), 1);
        assert_eq!(back.hosts[0].ports[0].state, PortState::Open);
    }

    #[test]
    fn terminal_table_lists_down_hosts() {
        let mut scan = Scan::start("01TEST".to_owned(), vec![]);
        scan.hosts.push(HostResult {
            address: "127.0.0.2".to_owned(),
            status: HostStatus::Down,
            latency_ms: 5,
            ports: Vec::new(),
        });
        let table = terminal_table(&scan);
        assert!(table.contains("127.0.0.2"));
        assert!(table.contains("down"));
    }
}
