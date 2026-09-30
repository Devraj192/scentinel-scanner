use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::detection::service::Evidence;
use crate::errors::Error;
use crate::results::model::{Banner, HostResult, HostStatus, PortResult, PortState, Scan};
use crate::scanner::resolve::ResolvedHost;

/// Default history location: a local directory the user owns.
pub fn default_db_path() -> PathBuf {
    PathBuf::from(".sentinelscan/history.db")
}

const SCHEMA_VERSION: i64 = 1;

const MIGRATION_V1: &str = "
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_unix_secs INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'running',
    started_unix_secs INTEGER NOT NULL,
    finished_unix_secs INTEGER NOT NULL DEFAULT 0,
    truncated INTEGER NOT NULL DEFAULT 0,
    peak_active_probes INTEGER NOT NULL DEFAULT 0,
    targets_json TEXT NOT NULL DEFAULT '[]',
    ports_json TEXT NOT NULL DEFAULT '[]',
    resolved_json TEXT NOT NULL DEFAULT '[]',
    version TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS hosts (
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    address TEXT NOT NULL,
    status TEXT NOT NULL,
    latency_ms INTEGER NOT NULL,
    PRIMARY KEY (scan_id, address)
);
CREATE TABLE IF NOT EXISTS ports (
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    address TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    state TEXT NOT NULL,
    reason TEXT NOT NULL,
    latency_ms INTEGER NOT NULL,
    service TEXT,
    version TEXT,
    confidence REAL,
    evidence_json TEXT NOT NULL DEFAULT '[]',
    banner_text TEXT,
    banner_encoding TEXT,
    banner_truncated INTEGER,
    PRIMARY KEY (scan_id, address, port)
);
";

/// Scan row plus the scope needed to resume it.
#[derive(Debug, Clone)]
pub struct StoredScan {
    pub scan_id: String,
    pub status: String,
    pub started_unix_secs: u64,
    pub targets: Vec<String>,
    pub ports: Vec<u16>,
    pub resolved: Vec<ResolvedHost>,
}

/// One row of `history` output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub scan_id: String,
    pub status: String,
    pub started_unix_secs: u64,
    pub targets: Vec<String>,
    pub host_count: usize,
    pub open_port_count: usize,
}

/// Local SQLite history. Each call opens its own connection, so no connection
/// is ever shared across threads; every write is a short local transaction.
pub struct Storage {
    path: PathBuf,
}

impl Storage {
    /// Open (creating parents) at `path`, migrate, and lock down permissions.
    pub fn open(path: &Path) -> Result<Self, Error> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    Error::Storage(format!("cannot create {}: {e}", parent.display()))
                })?;
            }
        }
        let storage = Self {
            path: path.to_owned(),
        };
        let conn = storage.connect()?;
        migrate(&conn)?;
        restrict_permissions(path)?;
        Ok(storage)
    }

    fn connect(&self) -> Result<Connection, Error> {
        Connection::open(&self.path)
            .map_err(|e| Error::Storage(format!("cannot open {}: {e}", self.path.display())))
    }

    /// Start a scan row in `running` state with its scope attached.
    pub fn begin_scan(
        &self,
        scan_id: &str,
        targets: &[String],
        ports: &[u16],
        resolved: &[ResolvedHost],
    ) -> Result<(), Error> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO scans (scan_id, status, started_unix_secs, targets_json, ports_json, resolved_json, version)
             VALUES (?1, 'running', ?2, ?3, ?4, ?5, ?6)",
            params![
                scan_id,
                unix_now() as i64,
                serde_json::to_string(targets).unwrap_or_else(|_| "[]".to_owned()),
                serde_json::to_string(ports).unwrap_or_else(|_| "[]".to_owned()),
                serde_json::to_string(resolved).unwrap_or_else(|_| "[]".to_owned()),
                env!("CARGO_PKG_VERSION"),
            ],
        )
        .map_err(|e| Error::Storage(format!("begin_scan: {e}")))?;
        Ok(())
    }

    /// Record one finished probe. Safe to call for the same key twice: the
    /// latest result wins, which is what resume relies on.
    pub fn save_probe(
        &self,
        scan_id: &str,
        address: &str,
        port: u16,
        state: PortState,
        reason: &str,
        latency_ms: u64,
    ) -> Result<(), Error> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO ports (scan_id, address, port, state, reason, latency_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (scan_id, address, port) DO UPDATE SET
               state = excluded.state, reason = excluded.reason, latency_ms = excluded.latency_ms",
            params![
                scan_id,
                address,
                port,
                state.to_string(),
                reason,
                latency_ms as i64
            ],
        )
        .map_err(|e| Error::Storage(format!("save_probe: {e}")))?;
        Ok(())
    }

    /// Attach detection output to an already-saved probe row.
    pub fn update_detection(
        &self,
        scan_id: &str,
        address: &str,
        port: &PortResult,
    ) -> Result<(), Error> {
        let conn = self.connect()?;
        let (text, encoding, truncated) = match &port.banner {
            Some(banner) => (
                Some(banner.text.clone()),
                Some(banner.encoding.clone()),
                Some(i64::from(banner.truncated)),
            ),
            None => (None, None, None),
        };
        conn.execute(
            "UPDATE ports SET service = ?4, version = ?5, confidence = ?6,
               evidence_json = ?7, banner_text = ?8, banner_encoding = ?9, banner_truncated = ?10
             WHERE scan_id = ?1 AND address = ?2 AND port = ?3",
            params![
                scan_id,
                address,
                port.port,
                port.service,
                port.version,
                port.confidence.map(f64::from),
                serde_json::to_string(&port.evidence).unwrap_or_else(|_| "[]".to_owned()),
                text,
                encoding,
                truncated,
            ],
        )
        .map_err(|e| Error::Storage(format!("update_detection: {e}")))?;
        Ok(())
    }

    /// Record host liveness for the scan.
    pub fn save_host(
        &self,
        scan_id: &str,
        address: &str,
        status: HostStatus,
        latency_ms: u64,
    ) -> Result<(), Error> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO hosts (scan_id, address, status, latency_ms)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (scan_id, address) DO UPDATE SET
               status = excluded.status, latency_ms = excluded.latency_ms",
            params![scan_id, address, status.to_string(), latency_ms as i64],
        )
        .map_err(|e| Error::Storage(format!("save_host: {e}")))?;
        Ok(())
    }

    /// Mark the scan row finished. Interrupted scans stay `running` so
    /// `--resume` can pick them up.
    pub fn finish_scan(
        &self,
        scan_id: &str,
        truncated: bool,
        peak_active_probes: usize,
    ) -> Result<(), Error> {
        let conn = self.connect()?;
        conn.execute(
            "UPDATE scans SET status = 'complete', finished_unix_secs = ?2,
               truncated = ?3, peak_active_probes = ?4 WHERE scan_id = ?1",
            params![
                scan_id,
                unix_now() as i64,
                i64::from(truncated),
                peak_active_probes as i64,
            ],
        )
        .map_err(|e| Error::Storage(format!("finish_scan: {e}")))?;
        Ok(())
    }

    /// Load a scan row with its resume scope.
    pub fn load_scan(&self, scan_id: &str) -> Result<StoredScan, Error> {
        let conn = self.connect()?;
        let (status, started, targets, ports, resolved): (String, i64, String, String, String) =
            conn.query_row(
                "SELECT status, started_unix_secs, targets_json, ports_json, resolved_json
                 FROM scans WHERE scan_id = ?1",
                [scan_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .map_err(|e| Error::Storage(format!("unknown scan id '{scan_id}': {e}")))?;
        Ok(StoredScan {
            scan_id: scan_id.to_owned(),
            status,
            started_unix_secs: started.max(0) as u64,
            targets: serde_json::from_str(&targets).unwrap_or_default(),
            ports: serde_json::from_str(&ports).unwrap_or_default(),
            resolved: serde_json::from_str(&resolved).unwrap_or_default(),
        })
    }

    /// All saved probe rows for a scan with detection attached, ordered by
    /// (address, port).
    pub fn port_rows(&self, scan_id: &str) -> Result<Vec<SavedProbe>, Error> {
        let conn = self.connect()?;
        let mut stmt = conn
            .prepare(
                "SELECT address, port, protocol, state, reason, latency_ms,
                   service, version, confidence, evidence_json,
                   banner_text, banner_encoding, banner_truncated
                 FROM ports WHERE scan_id = ?1 ORDER BY address, port",
            )
            .map_err(|e| Error::Storage(format!("port_rows: {e}")))?;
        let rows = stmt
            .query_map([scan_id], |row| {
                Ok(PortRow {
                    address: row.get(0)?,
                    port: row.get(1)?,
                    protocol: row.get(2)?,
                    state: row.get(3)?,
                    reason: row.get(4)?,
                    latency_ms: row.get::<_, i64>(5)? as u64,
                    service: row.get(6)?,
                    version: row.get(7)?,
                    confidence: row.get::<_, Option<f64>>(8)?,
                    evidence_json: row.get(9)?,
                    banner_text: row.get(10)?,
                    banner_encoding: row.get(11)?,
                    banner_truncated: row.get::<_, Option<i64>>(12)?,
                })
            })
            .map_err(|e| Error::Storage(format!("port_rows: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            let row = row.map_err(|e| Error::Storage(format!("port_rows: {e}")))?;
            out.push(SavedProbe {
                address: row.address.clone(),
                port: decode_port_row(&row)?,
            });
        }
        Ok(out)
    }

    /// Host liveness rows for a scan.
    pub fn host_rows(&self, scan_id: &str) -> Result<Vec<HostRow>, Error> {
        let conn = self.connect()?;
        let mut stmt = conn
            .prepare("SELECT address, status, latency_ms FROM hosts WHERE scan_id = ?1")
            .map_err(|e| Error::Storage(format!("host_rows: {e}")))?;
        let rows = stmt
            .query_map([scan_id], |row| {
                Ok(HostRow {
                    address: row.get(0)?,
                    status: row.get(1)?,
                    latency_ms: row.get::<_, i64>(2)? as u64,
                })
            })
            .map_err(|e| Error::Storage(format!("host_rows: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| Error::Storage(format!("host_rows: {e}")))?);
        }
        Ok(out)
    }

    /// Rebuild the canonical scan from its rows. Fails loudly on corrupt
    /// state text rather than inventing results.
    pub fn load_full_scan(&self, scan_id: &str) -> Result<Scan, Error> {
        let stored = self.load_scan(scan_id)?;
        let conn = self.connect()?;
        let (finished, truncated, peak): (i64, i64, i64) = conn
            .query_row(
                "SELECT finished_unix_secs, truncated, peak_active_probes FROM scans WHERE scan_id = ?1",
                [scan_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|e| Error::Storage(format!("load_full_scan: {e}")))?;
        let mut hosts: Vec<HostResult> = Vec::new();
        for host in self.host_rows(scan_id)? {
            hosts.push(HostResult {
                address: host.address,
                status: parse_status(&host.status)?,
                latency_ms: host.latency_ms,
                ports: Vec::new(),
            });
        }
        for saved in self.port_rows(scan_id)? {
            let address = saved.address;
            let port = saved.port;
            match hosts.iter_mut().find(|host| host.address == address) {
                Some(host) => host.ports.push(port),
                None => hosts.push(HostResult {
                    address,
                    status: HostStatus::Unknown,
                    latency_ms: 0,
                    ports: vec![port],
                }),
            }
        }
        hosts.sort_by(|a, b| a.address.cmp(&b.address));
        Ok(Scan {
            meta: crate::results::model::ScanMeta {
                scan_id: stored.scan_id,
                version: env!("CARGO_PKG_VERSION").to_owned(),
                started_unix_secs: stored.started_unix_secs,
                finished_unix_secs: finished.max(0) as u64,
                truncated: truncated != 0,
                peak_active_probes: peak.max(0) as usize,
            },
            targets: stored.targets,
            hosts,
        })
    }

    /// Every stored scan, newest first, with host and open-port counts.
    pub fn list_scans(&self) -> Result<Vec<ScanSummary>, Error> {
        let conn = self.connect()?;
        let mut stmt = conn
            .prepare(
                "SELECT scan_id, status, started_unix_secs, targets_json FROM scans
                 ORDER BY started_unix_secs DESC, scan_id DESC",
            )
            .map_err(|e| Error::Storage(format!("list_scans: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|e| Error::Storage(format!("list_scans: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            let (scan_id, status, started, targets) =
                row.map_err(|e| Error::Storage(format!("list_scans: {e}")))?;
            let host_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM hosts WHERE scan_id = ?1",
                    [&scan_id],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            let open_port_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM ports WHERE scan_id = ?1 AND state = 'open'",
                    [&scan_id],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            out.push(ScanSummary {
                scan_id,
                status,
                started_unix_secs: started.max(0) as u64,
                targets: serde_json::from_str(&targets).unwrap_or_default(),
                host_count: host_count.max(0) as usize,
                open_port_count: open_port_count.max(0) as usize,
            });
        }
        Ok(out)
    }
}

/// One saved probe row with its address attached, decoded into the canonical
/// port model.
#[derive(Debug, Clone)]
pub struct SavedProbe {
    pub address: String,
    pub port: PortResult,
}

/// One saved probe row, exactly as stored.
#[derive(Debug, Clone)]
pub struct PortRow {
    pub address: String,
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub reason: String,
    pub latency_ms: u64,
    pub service: Option<String>,
    pub version: Option<String>,
    pub confidence: Option<f64>,
    pub evidence_json: String,
    pub banner_text: Option<String>,
    pub banner_encoding: Option<String>,
    pub banner_truncated: Option<i64>,
}

/// One saved host row, exactly as stored.
#[derive(Debug, Clone)]
pub struct HostRow {
    pub address: String,
    pub status: String,
    pub latency_ms: u64,
}

fn parse_state(text: &str) -> Result<PortState, Error> {
    match text {
        "open" => Ok(PortState::Open),
        "closed" => Ok(PortState::Closed),
        "filtered" => Ok(PortState::Filtered),
        "unknown" => Ok(PortState::Unknown),
        other => Err(Error::Storage(format!("corrupt port state '{other}'"))),
    }
}

fn parse_status(text: &str) -> Result<HostStatus, Error> {
    match text {
        "up" => Ok(HostStatus::Up),
        "down" => Ok(HostStatus::Down),
        "unknown" => Ok(HostStatus::Unknown),
        other => Err(Error::Storage(format!("corrupt host status '{other}'"))),
    }
}

fn decode_port_row(row: &PortRow) -> Result<PortResult, Error> {
    let evidence: Vec<Evidence> = serde_json::from_str(&row.evidence_json).unwrap_or_default();
    let banner = row.banner_text.clone().map(|text| Banner {
        text,
        encoding: row.banner_encoding.clone().unwrap_or_default(),
        truncated: row.banner_truncated.unwrap_or(0) != 0,
        raw: Vec::new(),
    });
    Ok(PortResult {
        port: row.port,
        protocol: row.protocol.clone(),
        state: parse_state(&row.state)?,
        reason: row.reason.clone(),
        latency_ms: row.latency_ms,
        service: row.service.clone(),
        version: row.version.clone(),
        confidence: row.confidence.map(|confidence| confidence as f32),
        evidence,
        banner,
    })
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn migrate(conn: &Connection) -> Result<(), Error> {
    conn.execute_batch(MIGRATION_V1)
        .map_err(|e| Error::Storage(format!("migrate: {e}")))?;
    let applied: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = ?1",
            [SCHEMA_VERSION],
            |row| row.get(0),
        )
        .map_err(|e| Error::Storage(format!("migrate: {e}")))?;
    if applied == 0 {
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_unix_secs) VALUES (?1, ?2)",
            params![SCHEMA_VERSION, unix_now() as i64],
        )
        .map_err(|e| Error::Storage(format!("migrate: {e}")))?;
    }
    Ok(())
}

/// Scan history maps someone's network, so it must not be world-readable.
fn restrict_permissions(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_err(
                    |e| Error::Storage(format!("cannot lock down {}: {e}", parent.display())),
                )?;
            }
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::Storage(format!("cannot lock down {}: {e}", path.display())))?;
    }
    #[cfg(not(unix))]
    {
        // Windows has no POSIX mode bits; the file inherits the user's ACLs.
        let _ = path;
    }
    Ok(())
}

/// A port present in B but not A (`added`), in A but not B (`removed`), or in
/// both with a different state, service, or version (`changed`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortChange {
    pub host: String,
    pub port: u16,
    pub old_state: Option<String>,
    pub new_state: Option<String>,
    pub old_service: Option<String>,
    pub new_service: Option<String>,
}

/// The difference between two scans: `scan_a` is the baseline, `scan_b` the new scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comparison {
    pub scan_a: String,
    pub scan_b: String,
    pub added: Vec<PortChange>,
    pub removed: Vec<PortChange>,
    pub changed: Vec<PortChange>,
}

/// Pure diff of two canonical scans, keyed by (host, port).
pub fn compare(scan_a: &Scan, scan_b: &Scan) -> Comparison {
    use std::collections::BTreeMap;

    fn key(host: &str, port: u16) -> (String, u16) {
        (host.to_owned(), port)
    }
    fn index(scan: &Scan) -> BTreeMap<(String, u16), &PortResult> {
        let mut map = BTreeMap::new();
        for host in &scan.hosts {
            for port in &host.ports {
                map.insert(key(&host.address, port.port), port);
            }
        }
        map
    }

    let old = index(scan_a);
    let new = index(scan_b);
    let mut comparison = Comparison {
        scan_a: scan_a.meta.scan_id.clone(),
        scan_b: scan_b.meta.scan_id.clone(),
        added: Vec::new(),
        removed: Vec::new(),
        changed: Vec::new(),
    };
    for (key, port) in &new {
        match old.get(key) {
            None => comparison.added.push(PortChange {
                host: key.0.clone(),
                port: key.1,
                old_state: None,
                new_state: Some(port.state.to_string()),
                old_service: None,
                new_service: port.service.clone(),
            }),
            Some(previous)
                if previous.state != port.state
                    || previous.service != port.service
                    || previous.version != port.version =>
            {
                comparison.changed.push(PortChange {
                    host: key.0.clone(),
                    port: key.1,
                    old_state: Some(previous.state.to_string()),
                    new_state: Some(port.state.to_string()),
                    old_service: previous.service.clone(),
                    new_service: port.service.clone(),
                });
            }
            Some(_) => {}
        }
    }
    for (key, port) in &old {
        if !new.contains_key(key) {
            comparison.removed.push(PortChange {
                host: key.0.clone(),
                port: key.1,
                old_state: Some(port.state.to_string()),
                new_state: None,
                old_service: port.service.clone(),
                new_service: None,
            });
        }
    }
    comparison
}

/// Human-readable diff table.
pub fn comparison_table(comparison: &Comparison) -> String {
    let mut out = String::from("CHANGE\tHOST\tPORT\tOLD\tNEW\n");
    for change in &comparison.added {
        out.push_str(&format!(
            "added\t{}\t{}\t-\t{}\n",
            change.host,
            change.port,
            change.new_state.as_deref().unwrap_or("-")
        ));
    }
    for change in &comparison.removed {
        out.push_str(&format!(
            "removed\t{}\t{}\t{}\t-\n",
            change.host,
            change.port,
            change.old_state.as_deref().unwrap_or("-")
        ));
    }
    for change in &comparison.changed {
        out.push_str(&format!(
            "changed\t{}\t{}\t{} -> {}\t{} -> {}\n",
            change.host,
            change.port,
            change.old_state.as_deref().unwrap_or("-"),
            change.new_state.as_deref().unwrap_or("-"),
            change.old_service.as_deref().unwrap_or("-"),
            change.new_service.as_deref().unwrap_or("-"),
        ));
    }
    if comparison.added.is_empty() && comparison.removed.is_empty() && comparison.changed.is_empty()
    {
        out.push_str("no differences\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::results::model::ScanMeta;

    fn db() -> (TempFile, Storage) {
        let path = std::env::temp_dir().join(format!(
            "sentinelscan-ut-{}.db",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let storage = Storage::open(&path).expect("open");
        (TempFile { path }, storage)
    }

    struct TempFile {
        path: PathBuf,
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn scan_fixture(id: &str) -> Scan {
        Scan {
            meta: ScanMeta {
                scan_id: id.to_owned(),
                version: "0.0.0".to_owned(),
                started_unix_secs: 1,
                finished_unix_secs: 2,
                truncated: false,
                peak_active_probes: 3,
            },
            targets: vec!["127.0.0.1".to_owned()],
            hosts: vec![HostResult {
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
                    evidence: vec![Evidence::observation("status: HTTP/1.1 200 OK")],
                    banner: Some(Banner {
                        text: "HTTP/1.1 200 OK".to_owned(),
                        encoding: "utf8".to_owned(),
                        truncated: false,
                        raw: b"HTTP/1.1 200 OK".to_vec(),
                    }),
                }],
            }],
        }
    }

    #[test]
    fn stores_and_reloads_losslessly() {
        let (_file, storage) = db();
        let scan = scan_fixture("01LOSSLESS");
        storage
            .begin_scan(&scan.meta.scan_id, &scan.targets, &[80], &[])
            .expect("begin");
        for host in &scan.hosts {
            storage
                .save_host(
                    &scan.meta.scan_id,
                    &host.address,
                    host.status,
                    host.latency_ms,
                )
                .expect("host");
            for port in &host.ports {
                storage
                    .save_probe(
                        &scan.meta.scan_id,
                        &host.address,
                        port.port,
                        port.state,
                        &port.reason,
                        port.latency_ms,
                    )
                    .expect("probe");
                storage
                    .update_detection(&scan.meta.scan_id, &host.address, port)
                    .expect("detection");
            }
        }
        storage
            .finish_scan(&scan.meta.scan_id, false, 3)
            .expect("finish");
        let back = storage.load_full_scan(&scan.meta.scan_id).expect("load");
        // `raw` never persists; everything else must round-trip exactly.
        let mut expected = scan;
        for host in &mut expected.hosts {
            for port in &mut host.ports {
                if let Some(banner) = port.banner.as_mut() {
                    banner.raw.clear();
                }
            }
        }
        let mut back = back;
        back.meta.version = "0.0.0".to_owned();
        back.meta.started_unix_secs = 1;
        back.meta.finished_unix_secs = 2;
        assert_eq!(back, expected);
    }

    #[test]
    fn migrate_is_idempotent() {
        let (file, _) = db();
        Storage::open(&file.path).expect("reopen");
        let stored = Storage::open(&file.path)
            .expect("reopen")
            .list_scans()
            .expect("list");
        assert!(stored.is_empty());
    }

    #[test]
    fn compare_finds_added_removed_changed() {
        let mut older = scan_fixture("01OLD");
        let mut newer = scan_fixture("01NEW");
        newer.hosts[0].ports[0].state = PortState::Closed;
        newer.hosts[0].ports[0].reason = "refused".to_owned();
        newer.hosts[0].ports.push(PortResult {
            port: 443,
            protocol: "tcp".to_owned(),
            state: PortState::Open,
            reason: "handshake".to_owned(),
            latency_ms: 1,
            service: Some("https".to_owned()),
            version: None,
            confidence: Some(0.8),
            evidence: Vec::new(),
            banner: None,
        });
        older.hosts.push(HostResult {
            address: "127.0.0.2".to_owned(),
            status: HostStatus::Up,
            latency_ms: 1,
            ports: vec![PortResult {
                port: 22,
                protocol: "tcp".to_owned(),
                state: PortState::Open,
                reason: "handshake".to_owned(),
                latency_ms: 1,
                service: Some("ssh".to_owned()),
                version: None,
                confidence: Some(0.9),
                evidence: Vec::new(),
                banner: None,
            }],
        });
        let diff = compare(&older, &newer);
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].port, 443);
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.removed[0].port, 22);
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].port, 80);
    }
}
