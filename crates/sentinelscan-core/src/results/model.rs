use serde::{Deserialize, Serialize};

use crate::detection::service::Evidence;
use crate::os::OsGuess;

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

/// One TCP port result. Service fields stay empty until Phase 3 fills them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub protocol: String,
    pub state: PortState,
    pub reason: String,
    pub latency_ms: u64,
    pub service: Option<String>,
    pub version: Option<String>,
    pub confidence: Option<f32>,
    pub evidence: Vec<Evidence>,
    pub banner: Option<Banner>,
}

/// A collected service banner. `raw` never serializes; JSON carries `text`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Banner {
    pub text: String,
    pub encoding: String,
    pub truncated: bool,
    #[serde(skip)]
    pub raw: Vec<u8>,
}

/// One host in the canonical result model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostResult {
    pub address: String,
    pub status: HostStatus,
    pub latency_ms: u64,
    pub ports: Vec<PortResult>,
    /// OS estimate, present only when OS detection ran.
    #[serde(default)]
    pub os: Option<OsGuess>,
}

/// Scan metadata. Every scan carries a unique ULID `scan_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanMeta {
    pub scan_id: String,
    pub version: String,
    /// JSON schema version. Additive only: version 1 payloads (without this
    /// field) still parse, defaulting to the current version.
    #[serde(default = "current_schema_version")]
    pub schema_version: u32,
    pub started_unix_secs: u64,
    pub finished_unix_secs: u64,
    pub truncated: bool,
    /// Highest number of simultaneously active port probes observed. Lets
    /// operators (and tests) verify the concurrency cap held.
    pub peak_active_probes: usize,
}

/// Canonical scan result. Terminal, JSON, CSV, and SQLite all derive from this.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// Current JSON schema version, used for new scans and as the default when
/// reading payloads that predate the field.
pub fn current_schema_version() -> u32 {
    2
}

impl Scan {
    /// New scan with `finished` unset (0) and `truncated` false.
    pub fn start(scan_id: String, targets: Vec<String>) -> Self {
        Self {
            meta: ScanMeta {
                scan_id,
                version: env!("CARGO_PKG_VERSION").to_owned(),
                schema_version: current_schema_version(),
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

/// HOST / PORT / SERVICE / VERSION / CONFIDENCE table over open ports.
pub fn service_table(scan: &Scan) -> String {
    let mut out = String::from("HOST\tPORT\tSERVICE\tVERSION\tCONFIDENCE\n");
    for host in &scan.hosts {
        for port in &host.ports {
            if port.state != PortState::Open {
                continue;
            }
            let confidence = port
                .confidence
                .map(|confidence| format!("{confidence:.2}"))
                .unwrap_or_else(|| "-".to_owned());
            out.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\n",
                sanitize(&host.address),
                port.port,
                sanitize(port.service.as_deref().unwrap_or("-")),
                sanitize(port.version.as_deref().unwrap_or("-")),
                confidence,
            ));
        }
    }
    out
}

fn csv_field(text: &str) -> String {
    if text.contains([',', '"', '\n']) {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text.to_owned()
    }
}

/// CSV encoding of the canonical model, one row per scanned port.
pub fn to_csv(scan: &Scan) -> String {
    let mut out =
        String::from("scan_id,host,port,protocol,state,reason,service,version,confidence\n");
    for host in &scan.hosts {
        for port in &host.ports {
            let confidence = port
                .confidence
                .map(|confidence| format!("{confidence:.2}"))
                .unwrap_or_default();
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{},{}\n",
                csv_field(&scan.meta.scan_id),
                csv_field(&host.address),
                port.port,
                csv_field(&port.protocol),
                port.state,
                csv_field(&port.reason),
                csv_field(port.service.as_deref().unwrap_or("")),
                csv_field(port.version.as_deref().unwrap_or("")),
                confidence,
            ));
        }
    }
    out
}
/// HOST / OS / VERSION / CONFIDENCE lines for hosts with a decided OS
/// estimate. Empty when OS detection did not run or admitted Unknown.
pub fn os_lines(scan: &Scan) -> String {
    let mut out = String::new();
    for host in &scan.hosts {
        let Some(os) = &host.os else {
            continue;
        };
        if os.family == "Unknown" {
            continue;
        }
        out.push_str(&format!(
            "os\t{}\t{}\t{}\t{:.2}\n",
            sanitize(&host.address),
            sanitize(&os.family),
            sanitize(os.version.as_deref().unwrap_or("-")),
            os.confidence,
        ));
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
                service: Some("http".to_owned()),
                version: Some("TestLab/1.0".to_owned()),
                confidence: Some(0.9),
                evidence: Vec::new(),
                banner: None,
            }],
            os: None,
        });
        scan.finish();
        let text = to_json(&scan);
        let back: Scan = serde_json::from_str(&text).expect("round trip");
        assert_eq!(back.hosts.len(), 1);
        assert_eq!(back.hosts[0].ports[0].state, PortState::Open);
    }

    #[test]
    fn csv_quotes_hostile_fields() {
        let mut scan = Scan::start("01TEST".to_owned(), vec![]);
        scan.hosts.push(HostResult {
            address: "a,b".to_owned(),
            status: HostStatus::Up,
            latency_ms: 1,
            ports: vec![PortResult {
                port: 80,
                protocol: "tcp".to_owned(),
                state: PortState::Open,
                reason: "handshake".to_owned(),
                latency_ms: 1,
                service: Some("x\"y".to_owned()),
                version: None,
                confidence: None,
                evidence: Vec::new(),
                banner: None,
            }],
            os: None,
        });
        let csv = to_csv(&scan);
        assert!(csv.contains("\"a,b\""));
        assert!(csv.contains("\"x\"\"y\""));
    }

    #[test]
    fn v1_payloads_parse_with_current_schema() {
        let v1 = r#"{"scan_id":"01V1","version":"1.0.1","started_unix_secs":1,
            "finished_unix_secs":2,"truncated":false,"peak_active_probes":0}"#;
        let meta: ScanMeta =
            serde_json::from_str(&v1.lines().collect::<String>()).expect("v1 parses");
        assert_eq!(meta.schema_version, current_schema_version());
    }

    #[test]
    fn terminal_table_lists_down_hosts() {
        let mut scan = Scan::start("01TEST".to_owned(), vec![]);
        scan.hosts.push(HostResult {
            address: "127.0.0.2".to_owned(),
            status: HostStatus::Down,
            latency_ms: 5,
            ports: Vec::new(),
            os: None,
        });
        let table = terminal_table(&scan);
        assert!(table.contains("127.0.0.2"));
        assert!(table.contains("down"));
    }
}
