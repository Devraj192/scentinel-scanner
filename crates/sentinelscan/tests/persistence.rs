use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use sentinelscan_core::results::model::{PortState, Scan};
use sentinelscan_core::scanner::resolve::ResolvedHost;
use sentinelscan_core::storage::{Comparison, ScanSummary, Storage};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

fn binary() -> String {
    env!("CARGO_BIN_EXE_sentinelscan").to_owned()
}

fn unique(suffix: &str) -> String {
    std::env::temp_dir()
        .join(format!(
            "sentinelscan-{suffix}-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
        .to_str()
        .expect("utf8")
        .to_owned()
}

fn fast_config() -> String {
    let path = unique("cfg");
    let config = format!("{path}.toml");
    std::fs::write(
        &config,
        "[limits]\nconnect_timeout_ms = 800\nprobe_timeout_ms = 800\nmax_scan_duration_secs = 120\n",
    )
    .expect("write config");
    config
}

async fn run(args: &[String]) -> (bool, String, String) {
    let output = tokio::process::Command::new(binary())
        .args(args)
        .output()
        .await
        .expect("run binary");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn scan_id_of(stdout: &str) -> String {
    serde_json::from_str::<Scan>(stdout)
        .expect("canonical json")
        .meta
        .scan_id
}

/// Listener that counts accepted connections.
async fn counting_listener(counter: Arc<AtomicUsize>) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind lab");
    let port = listener.local_addr().expect("addr").port();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let _ = socket.write_all(b"").await;
            });
        }
    });
    (port, handle)
}

#[tokio::test]
async fn history_lists_completed_scan() {
    let counter = Arc::new(AtomicUsize::new(0));
    let (port, _handle) = counting_listener(Arc::clone(&counter)).await;
    let db = unique("hist");
    let config = fast_config();
    let (ok, stdout, _) = run(&[
        "scan".to_owned(),
        "127.0.0.1".to_owned(),
        "--ports".to_owned(),
        port.to_string(),
        "--yes".to_owned(),
        "--skip-host-discovery".to_owned(),
        "--profile".to_owned(),
        "quick".to_owned(),
        "--output".to_owned(),
        "json".to_owned(),
        "--config".to_owned(),
        config,
        "--db".to_owned(),
        db.clone(),
    ])
    .await;
    assert!(ok, "{stdout}");
    let scan_id = scan_id_of(&stdout);

    let (ok, stdout, _) = run(&["history".to_owned(), "--db".to_owned(), db.clone()]).await;
    assert!(ok, "{stdout}");
    assert!(stdout.contains(&scan_id), "{stdout}");

    let (ok, stdout, _) = run(&[
        "history".to_owned(),
        "--db".to_owned(),
        db,
        "--output".to_owned(),
        "json".to_owned(),
    ])
    .await;
    assert!(ok, "{stdout}");
    let summaries: Vec<ScanSummary> = serde_json::from_str(&stdout).expect("history json");
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].scan_id, scan_id);
    assert_eq!(summaries[0].status, "complete");
    assert_eq!(summaries[0].open_port_count, 1);
}

#[tokio::test]
async fn compare_reports_changed_ports() {
    let counter = Arc::new(AtomicUsize::new(0));
    let (open_port, _handle) = counting_listener(Arc::clone(&counter)).await;
    let dead: u16 = {
        let free = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = free.local_addr().expect("addr").port();
        drop(free);
        port
    };
    // Avoid colliding with the lab listener above.
    assert_ne!(open_port, dead);
    let db = unique("cmp");
    let config = fast_config();
    let ports = format!("{open_port},{dead}");
    let scan_args = vec![
        "scan".to_owned(),
        "127.0.0.1".to_owned(),
        "--ports".to_owned(),
        ports.clone(),
        "--yes".to_owned(),
        "--skip-host-discovery".to_owned(),
        "--profile".to_owned(),
        "quick".to_owned(),
        "--output".to_owned(),
        "json".to_owned(),
        "--config".to_owned(),
        config.clone(),
        "--db".to_owned(),
        db.clone(),
    ];
    let (ok, stdout, _) = run(&scan_args).await;
    assert!(ok, "{stdout}");
    let id_a = scan_id_of(&stdout);
    // Abort the accept loop so the OS releases the port; the second scan
    // must see a different state. (Dropping a JoinHandle would not stop it.)
    _handle.abort();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (ok, stdout, _) = run(&scan_args).await;
    assert!(ok, "{stdout}");
    let id_b = scan_id_of(&stdout);
    assert_ne!(id_a, id_b);

    let (ok, stdout, _) = run(&[
        "compare".to_owned(),
        id_a.clone(),
        id_b.clone(),
        "--db".to_owned(),
        db.clone(),
    ])
    .await;
    assert!(ok, "{stdout}");
    assert!(stdout.contains("changed"), "{stdout}");
    assert!(stdout.contains(&open_port.to_string()), "{stdout}");

    let (ok, stdout, _) = run(&[
        "compare".to_owned(),
        id_a,
        id_b,
        "--db".to_owned(),
        db,
        "--output".to_owned(),
        "json".to_owned(),
    ])
    .await;
    assert!(ok, "{stdout}");
    let diff: Comparison = serde_json::from_str(&stdout).expect("compare json");
    assert_eq!(diff.changed.len(), 1);
    assert!(diff.added.is_empty() && diff.removed.is_empty());
}

#[tokio::test]
async fn resume_skips_completed_ports() {
    let counter = Arc::new(AtomicUsize::new(0));
    let (done_port, _handle) = counting_listener(Arc::clone(&counter)).await;
    let db = unique("resume");
    let scan_id = "01RESUME00000000000000000001";
    let storage = Storage::open(std::path::Path::new(&db)).expect("open db");
    let resolved = vec![ResolvedHost {
        display: "127.0.0.1".to_owned(),
        addr: Some("127.0.0.1".parse().expect("ip")),
    }];
    // Pretend an interrupted run already saved one open probe, with no traffic
    // at all: any new connection to it proves an unwanted rescan.
    let dead: u16 = {
        let free = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = free.local_addr().expect("addr").port();
        drop(free);
        port
    };
    storage
        .begin_scan(
            scan_id,
            &["127.0.0.1".to_owned()],
            &[done_port, dead],
            &resolved,
        )
        .expect("begin");
    storage
        .save_probe(
            scan_id,
            "127.0.0.1",
            done_port,
            PortState::Open,
            "handshake",
            1,
        )
        .expect("probe");
    drop(storage);

    let config = fast_config();
    let before = counter.load(Ordering::SeqCst);
    let (ok, stdout, _) = run(&[
        "scan".to_owned(),
        "--resume".to_owned(),
        scan_id.to_owned(),
        "--yes".to_owned(),
        "--skip-host-discovery".to_owned(),
        "--profile".to_owned(),
        "quick".to_owned(),
        "--output".to_owned(),
        "json".to_owned(),
        "--config".to_owned(),
        config,
        "--db".to_owned(),
        db.clone(),
    ])
    .await;
    assert!(ok, "{stdout}");
    assert_eq!(
        counter.load(Ordering::SeqCst),
        before,
        "completed port was rescanned"
    );
    let scan: Scan = serde_json::from_str(&stdout).expect("canonical json");
    assert_eq!(scan.hosts.len(), 1);
    assert_eq!(scan.hosts[0].ports.len(), 2);
    let storage = Storage::open(std::path::Path::new(&db)).expect("reopen");
    assert_eq!(storage.load_scan(scan_id).expect("load").status, "complete");
}

#[tokio::test]
async fn resume_rejects_completed_scan() {
    let counter = Arc::new(AtomicUsize::new(0));
    let (port, _handle) = counting_listener(Arc::clone(&counter)).await;
    let db = unique("resrej");
    let config = fast_config();
    let (ok, stdout, _) = run(&[
        "scan".to_owned(),
        "127.0.0.1".to_owned(),
        "--ports".to_owned(),
        port.to_string(),
        "--yes".to_owned(),
        "--skip-host-discovery".to_owned(),
        "--profile".to_owned(),
        "quick".to_owned(),
        "--output".to_owned(),
        "json".to_owned(),
        "--config".to_owned(),
        config.clone(),
        "--db".to_owned(),
        db.clone(),
    ])
    .await;
    assert!(ok, "{stdout}");
    let scan_id = scan_id_of(&stdout);
    let (ok, _, stderr) = run(&[
        "scan".to_owned(),
        "--resume".to_owned(),
        scan_id,
        "--yes".to_owned(),
        "--config".to_owned(),
        config,
        "--db".to_owned(),
        db,
    ])
    .await;
    assert!(!ok);
    assert!(
        stderr.contains("only interrupted scans can resume"),
        "{stderr}"
    );
}

#[tokio::test]
async fn profiles_change_behavior() {
    let config_path = unique("prof");
    std::fs::write(
        format!("{config_path}.toml"),
        "[limits]\nconnect_timeout_ms = 800\nprobe_timeout_ms = 800\n\
         [profiles.quick]\nports = \"22\"\n\
         [profiles.standard]\nservice_detection = false\n",
    )
    .expect("write config");
    let config = format!("{config_path}.toml");
    let counter = Arc::new(AtomicUsize::new(0));
    let (port, _handle) = counting_listener(Arc::clone(&counter)).await;

    // Config-file quick profile overrides the port set to 22 only.
    let db = unique("profq");
    let (ok, stdout, _) = run(&[
        "scan".to_owned(),
        "127.0.0.1".to_owned(),
        "--profile".to_owned(),
        "quick".to_owned(),
        "--yes".to_owned(),
        "--skip-host-discovery".to_owned(),
        "--output".to_owned(),
        "json".to_owned(),
        "--config".to_owned(),
        config.clone(),
        "--db".to_owned(),
        db,
    ])
    .await;
    assert!(ok, "{stdout}");
    let scan: Scan = serde_json::from_str(&stdout).expect("canonical json");
    assert_eq!(scan.hosts[0].ports.len(), 1);
    assert_eq!(scan.hosts[0].ports[0].port, 22);

    // Config-file standard profile disables detection: open ports stay
    // service-less even though the port is open.
    let db = unique("profs");
    let (ok, stdout, _) = run(&[
        "scan".to_owned(),
        "127.0.0.1".to_owned(),
        "--ports".to_owned(),
        port.to_string(),
        "--yes".to_owned(),
        "--skip-host-discovery".to_owned(),
        "--output".to_owned(),
        "json".to_owned(),
        "--config".to_owned(),
        config,
        "--db".to_owned(),
        db,
    ])
    .await;
    assert!(ok, "{stdout}");
    let scan: Scan = serde_json::from_str(&stdout).expect("canonical json");
    assert_eq!(scan.hosts[0].ports[0].state, PortState::Open);
    assert_eq!(scan.hosts[0].ports[0].service, None);
}
