use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use sentinelscan::results::model::Scan;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

fn binary() -> String {
    env!("CARGO_BIN_EXE_sentinelscan").to_owned()
}

fn fast_config() -> String {
    let path = std::env::temp_dir().join(format!("sentinelscan-os-{}.toml", std::process::id()));
    std::fs::write(
        &path,
        "[limits]\nconnect_timeout_ms = 800\nprobe_timeout_ms = 800\nmax_scan_duration_secs = 120\n",
    )
    .expect("write lab config");
    path.to_str().expect("utf8").to_owned()
}

type Responder =
    Arc<dyn Fn(TcpStream) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> + Send + Sync>;

async fn serve(responder: Responder) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let responder = Arc::clone(&responder);
            tokio::spawn(async move { responder(socket).await });
        }
    });
    port
}

async fn run_scan(args: &[String]) -> (bool, String) {
    let db = std::env::temp_dir().join(format!(
        "sentinelscan-os-db-{}-{}.db",
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
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

fn scan_args(port: u16, config: &str, output: &str) -> Vec<String> {
    vec![
        "scan".to_owned(),
        "127.0.0.1".to_owned(),
        "--ports".to_owned(),
        port.to_string(),
        "--yes".to_owned(),
        "--skip-host-discovery".to_owned(),
        "--output".to_owned(),
        output.to_owned(),
        "--config".to_owned(),
        config.to_owned(),
    ]
}

#[tokio::test]
async fn ubuntu_banner_suggests_linux_without_precise_claims() {
    let port = serve(Arc::new(|mut socket| {
        Box::pin(async move {
            let _ = socket
                .write_all(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
                .await;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }) as Pin<Box<dyn Future<Output = ()> + Send + 'static>>
    }))
    .await;
    let config = fast_config();
    let (ok, stdout) = run_scan(&scan_args(port, &config, "json")).await;
    assert!(ok, "{stdout}");
    let scan: Scan = serde_json::from_str(&stdout).expect("canonical json");
    let os = scan.hosts[0].os.as_ref().expect("os estimate stored");
    assert_eq!(os.family, "Linux");
    assert!(os.version.is_some(), "distro token present");
    assert!(os.confidence <= 0.65 && os.confidence > 0.0);
    assert!(!os.evidence.is_empty());

    let (ok, terminal) = run_scan(&scan_args(port, &config, "terminal")).await;
    assert!(ok, "{terminal}");
    assert!(terminal.contains("Linux"), "{terminal}");
}

#[tokio::test]
async fn thin_evidence_is_unknown() {
    let port = serve(Arc::new(|mut socket| {
        Box::pin(async move {
            let _ = socket.write_all(b"HELLO\r\n").await;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }) as Pin<Box<dyn Future<Output = ()> + Send + 'static>>
    }))
    .await;
    let config = fast_config();
    let (ok, stdout) = run_scan(&scan_args(port, &config, "json")).await;
    assert!(ok, "{stdout}");
    let scan: Scan = serde_json::from_str(&stdout).expect("canonical json");
    let os = scan.hosts[0].os.as_ref().expect("os estimate stored");
    assert_eq!(os.family, "Unknown");
    assert_eq!(os.version, None);
    assert_eq!(os.confidence, 0.0);
}

#[tokio::test]
async fn quick_profile_skips_os() {
    let port = serve(Arc::new(|mut socket| {
        Box::pin(async move {
            let _ = socket
                .write_all(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
                .await;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }) as Pin<Box<dyn Future<Output = ()> + Send + 'static>>
    }))
    .await;
    let config = fast_config();
    let mut args = scan_args(port, &config, "json");
    args.extend(["--profile".to_owned(), "quick".to_owned()]);
    let (ok, stdout) = run_scan(&args).await;
    assert!(ok, "{stdout}");
    let scan: Scan = serde_json::from_str(&stdout).expect("canonical json");
    assert_eq!(scan.hosts[0].os, None);
    assert_eq!(scan.hosts[0].ports[0].service, None);
}
