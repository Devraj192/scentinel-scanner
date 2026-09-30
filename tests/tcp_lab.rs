use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use sentinelscan::results::model::{HostStatus, PortState, Scan};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

fn binary() -> String {
    env!("CARGO_BIN_EXE_sentinelscan").to_owned()
}

/// Short-timeout config so dead ports fail fast on any platform.
fn fast_config() -> String {
    let path = std::env::temp_dir().join(format!("sentinelscan-lab-{}.toml", std::process::id()));
    std::fs::write(
        &path,
        "[limits]\nconnect_timeout_ms = 800\nprobe_timeout_ms = 800\nmax_scan_duration_secs = 120\n",
    )
    .expect("write lab config");
    path.to_str().expect("utf8").to_owned()
}

struct LabListener {
    port: u16,
}

impl LabListener {
    /// Bound listener that accepts in the background. Tracks concurrent
    /// connections in `current`/`max` and accept times in `arrivals`.
    async fn start(
        current: Arc<AtomicUsize>,
        max: Arc<AtomicUsize>,
        arrivals: Arc<Mutex<Vec<Instant>>>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind lab");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                arrivals.lock().await.push(Instant::now());
                let now = current.fetch_add(1, Ordering::SeqCst) + 1;
                max.fetch_max(now, Ordering::SeqCst);
                let current = Arc::clone(&current);
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    drop(socket);
                    current.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        Self { port }
    }
}

fn lab_state() -> (Arc<AtomicUsize>, Arc<AtomicUsize>, Arc<Mutex<Vec<Instant>>>) {
    (
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(Mutex::new(Vec::new())),
    )
}

async fn run_scan(args: &[String]) -> (bool, String) {
    let db = std::env::temp_dir().join(format!(
        "sentinelscan-tcp-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let mut full: Vec<String> = args.to_vec();
    full.extend(["--db".to_owned(), db.to_str().expect("utf8").to_owned()]);
    let output = tokio::process::Command::new(binary())
        .args(&full)
        .output()
        .await
        .expect("run binary");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    (output.status.success(), stdout)
}

fn parse_scan(stdout: &str) -> Scan {
    serde_json::from_str(stdout).expect("stdout is canonical JSON")
}

#[tokio::test]
async fn open_port_is_open_and_host_is_up() {
    let (current, max, arrivals) = lab_state();
    let lab = LabListener::start(current, max, arrivals).await;
    let config = fast_config();
    let port = lab.port.to_string();
    let (ok, stdout) = run_scan(&[
        "scan".to_owned(),
        "127.0.0.1".to_owned(),
        "--ports".to_owned(),
        port.clone(),
        "--yes".to_owned(),
        "--output".to_owned(),
        "json".to_owned(),
        "--config".to_owned(),
        config,
    ])
    .await;
    assert!(ok, "{stdout}");
    let scan = parse_scan(&stdout);
    assert_eq!(scan.hosts.len(), 1);
    assert_eq!(scan.hosts[0].status, HostStatus::Up);
    assert_eq!(scan.hosts[0].ports.len(), 1);
    assert_eq!(scan.hosts[0].ports[0].state, PortState::Open);
    assert_eq!(scan.hosts[0].ports[0].reason, "handshake");
}

#[tokio::test]
async fn terminal_and_json_agree() {
    let (current, max, arrivals) = lab_state();
    let lab = LabListener::start(current, max, arrivals).await;
    let config = fast_config();
    let port = lab.port.to_string();
    let base = vec![
        "scan".to_owned(),
        "127.0.0.1".to_owned(),
        "--ports".to_owned(),
        port,
        "--yes".to_owned(),
        "--skip-host-discovery".to_owned(),
        "--config".to_owned(),
        config,
    ];
    let mut terminal_args = base.clone();
    terminal_args.extend(["--output".to_owned(), "terminal".to_owned()]);
    let (ok, terminal) = run_scan(&terminal_args).await;
    assert!(ok, "{terminal}");
    assert!(terminal.contains("open"), "{terminal}");
    let mut json_args = base;
    json_args.extend(["--output".to_owned(), "json".to_owned()]);
    let (ok, stdout) = run_scan(&json_args).await;
    assert!(ok, "{stdout}");
    let scan = parse_scan(&stdout);
    assert_eq!(scan.hosts[0].ports[0].state, PortState::Open);
}

#[tokio::test]
async fn dead_port_is_never_open_or_unknown() {
    // Bind-then-drop reserves a port nothing listens on.
    let free = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = free.local_addr().expect("addr").port().to_string();
    drop(free);
    let config = fast_config();
    let (ok, stdout) = run_scan(&[
        "scan".to_owned(),
        "127.0.0.1".to_owned(),
        "--ports".to_owned(),
        port,
        "--yes".to_owned(),
        "--skip-host-discovery".to_owned(),
        "--output".to_owned(),
        "json".to_owned(),
        "--config".to_owned(),
        config,
    ])
    .await;
    assert!(ok, "{stdout}");
    let scan = parse_scan(&stdout);
    let state = scan.hosts[0].ports[0].state;
    // Platform decides refused (closed) vs silence (filtered); both are honest.
    assert!(
        state == PortState::Closed || state == PortState::Filtered,
        "{state}"
    );
    assert!(!scan.hosts[0].ports[0].reason.is_empty());
}

#[tokio::test]
async fn concurrency_never_exceeds_cap() {
    let (current, max, arrivals) = lab_state();
    let mut ports = Vec::new();
    for _ in 0..12 {
        let lab = LabListener::start(
            Arc::clone(&current),
            Arc::clone(&max),
            Arc::clone(&arrivals),
        )
        .await;
        ports.push(lab.port.to_string());
    }
    let config = fast_config();
    let mut args = vec![
        "scan".to_owned(),
        "127.0.0.1".to_owned(),
        "--ports".to_owned(),
        ports.join(","),
        "--yes".to_owned(),
        "--skip-host-discovery".to_owned(),
        "--profile".to_owned(),
        "quick".to_owned(),
        "--concurrency".to_owned(),
        "4".to_owned(),
        "--rate".to_owned(),
        "1000".to_owned(),
        "--output".to_owned(),
        "json".to_owned(),
        "--config".to_owned(),
        config,
    ];
    let _ = &mut args;
    let (ok, stdout) = run_scan(&args).await;
    assert!(ok, "{stdout}");
    let scan = parse_scan(&stdout);
    assert_eq!(scan.hosts[0].ports.len(), 12);
    assert!(
        scan.hosts[0]
            .ports
            .iter()
            .all(|port| port.state == PortState::Open),
        "{stdout}"
    );
    // The scan reports its own peak; it must never exceed the cap.
    assert!(scan.meta.peak_active_probes > 0, "{stdout}");
    assert!(
        scan.meta.peak_active_probes <= 4,
        "peak {}",
        scan.meta.peak_active_probes
    );
}

#[tokio::test]
async fn rate_stays_within_limit() {
    let (current, max, arrivals) = lab_state();
    let mut ports = Vec::new();
    for _ in 0..8 {
        let lab = LabListener::start(
            Arc::clone(&current),
            Arc::clone(&max),
            Arc::clone(&arrivals),
        )
        .await;
        ports.push(lab.port.to_string());
    }
    let config = fast_config();
    let (ok, stdout) = run_scan(&[
        "scan".to_owned(),
        "127.0.0.1".to_owned(),
        "--ports".to_owned(),
        ports.join(","),
        "--yes".to_owned(),
        "--skip-host-discovery".to_owned(),
        "--profile".to_owned(),
        "quick".to_owned(),
        "--concurrency".to_owned(),
        "50".to_owned(),
        "--rate".to_owned(),
        "10".to_owned(),
        "--output".to_owned(),
        "json".to_owned(),
        "--config".to_owned(),
        config,
    ])
    .await;
    assert!(ok, "{stdout}");
    let times = arrivals.lock().await;
    assert_eq!(times.len(), 8);
    let span = times
        .last()
        .expect("times")
        .saturating_duration_since(*times.first().expect("times"));
    // 8 starts at 10/s need 0.7s; wide margin for loaded machines.
    assert!(span >= Duration::from_millis(400), "{span:?}");
}

#[tokio::test]
async fn one_failing_target_does_not_abort_scan() {
    let (current, max, arrivals) = lab_state();
    let lab = LabListener::start(current, max, arrivals).await;
    let config = fast_config();
    let (ok, stdout) = run_scan(&[
        "scan".to_owned(),
        "127.0.0.1".to_owned(),
        "nonexistent.invalid".to_owned(),
        "--allow-hostnames".to_owned(),
        "--ports".to_owned(),
        lab.port.to_string(),
        "--yes".to_owned(),
        "--output".to_owned(),
        "json".to_owned(),
        "--config".to_owned(),
        config,
    ])
    .await;
    assert!(ok, "{stdout}");
    let scan = parse_scan(&stdout);
    assert_eq!(scan.hosts.len(), 2);
    assert!(
        scan.hosts
            .iter()
            .any(|host| host.ports.iter().any(|port| port.state == PortState::Open)),
        "{stdout}"
    );
}
