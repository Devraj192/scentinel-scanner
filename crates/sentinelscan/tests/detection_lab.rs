use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use sentinelscan_core::results::model::Scan;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn binary() -> String {
    env!("CARGO_BIN_EXE_sentinelscan").to_owned()
}

fn fast_config() -> String {
    let path = std::env::temp_dir().join(format!("sentinelscan-det-{}.toml", std::process::id()));
    std::fs::write(
        &path,
        "[limits]\nconnect_timeout_ms = 800\nprobe_timeout_ms = 800\nmax_scan_duration_secs = 120\n",
    )
    .expect("write lab config");
    path.to_str().expect("utf8").to_owned()
}

async fn run_scan(args: &[String]) -> (bool, String) {
    let db = std::env::temp_dir().join(format!(
        "sentinelscan-det-db-{}-{}.db",
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

type Responder =
    Arc<dyn Fn(TcpStream) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> + Send + Sync>;

/// Serve every connection with `responder` until the test ends.
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

fn scan_args(port: u16, config: &str, output: &str) -> Vec<String> {
    vec![
        "scan".to_owned(),
        "127.0.0.1".to_owned(),
        "--ports".to_owned(),
        port.to_string(),
        "--yes".to_owned(),
        "--skip-host-discovery".to_owned(),
        "--service-detection".to_owned(),
        "--output".to_owned(),
        output.to_owned(),
        "--config".to_owned(),
        config.to_owned(),
    ]
}

#[tokio::test]
async fn detects_ssh_with_version_and_evidence() {
    let port = serve(Arc::new(|mut socket| {
        Box::pin(async move {
            let _ = socket.write_all(b"SSH-2.0-OpenSSH_9.3p1 TestLab\r\n").await;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }) as Pin<Box<dyn Future<Output = ()> + Send + 'static>>
    }))
    .await;
    let config = fast_config();
    let (ok, stdout) = run_scan(&scan_args(port, &config, "json")).await;
    assert!(ok, "{stdout}");
    let scan: Scan = serde_json::from_str(&stdout).expect("canonical json");
    let service = &scan.hosts[0].ports[0];
    assert_eq!(service.service.as_deref(), Some("ssh"));
    assert_eq!(service.version.as_deref(), Some("OpenSSH_9.3p1 TestLab"));
    assert!(service.confidence.unwrap_or(0.0) >= 0.9);
    assert!(!service.evidence.is_empty());
}

#[tokio::test]
async fn detects_http_with_server_header() {
    let port = serve(Arc::new(|mut socket| {
        Box::pin(async move {
            let mut buf = vec![0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nServer: TestLab/1.2.3\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
        }) as Pin<Box<dyn Future<Output = ()> + Send + 'static>>
    }))
    .await;
    let config = fast_config();
    let (ok, stdout) = run_scan(&scan_args(port, &config, "json")).await;
    assert!(ok, "{stdout}");
    let scan: Scan = serde_json::from_str(&stdout).expect("canonical json");
    let service = &scan.hosts[0].ports[0];
    assert_eq!(service.service.as_deref(), Some("http"));
    assert_eq!(service.version.as_deref(), Some("TestLab/1.2.3"));
}

#[tokio::test]
async fn malformed_banner_is_unknown_and_terminal_safe() {
    let port = serve(Arc::new(|mut socket| {
        Box::pin(async move {
            let _ = socket
                .write_all(&[0x00, 0xff, 0x1b, 0x07, 0x08, 0x0d, b'x'])
                .await;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }) as Pin<Box<dyn Future<Output = ()> + Send + 'static>>
    }))
    .await;
    let config = fast_config();
    let (ok, stdout) = run_scan(&scan_args(port, &config, "json")).await;
    assert!(ok, "{stdout}");
    let scan: Scan = serde_json::from_str(&stdout).expect("canonical json");
    assert_eq!(scan.hosts[0].ports[0].service.as_deref(), Some("unknown"));

    let (ok, terminal) = run_scan(&scan_args(port, &config, "terminal")).await;
    assert!(ok, "{terminal}");
    assert!(
        terminal
            .chars()
            .all(|c| !c.is_control() || c == '\n' || c == '\t'),
        "{terminal:?}"
    );
}

#[tokio::test]
async fn oversized_banner_is_truncated() {
    let port = serve(Arc::new(|mut socket| {
        Box::pin(async move {
            let _ = socket.write_all(&vec![b'A'; 65536]).await;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }) as Pin<Box<dyn Future<Output = ()> + Send + 'static>>
    }))
    .await;
    let config = fast_config();
    let (ok, stdout) = run_scan(&scan_args(port, &config, "json")).await;
    assert!(ok, "{stdout}");
    let scan: Scan = serde_json::from_str(&stdout).expect("canonical json");
    let banner = scan.hosts[0].ports[0].banner.as_ref().expect("banner");
    assert!(banner.truncated);
    assert!(banner.text.len() <= 4096);
}

#[tokio::test]
async fn slow_responder_yields_unknown() {
    let port = serve(Arc::new(|_socket| {
        Box::pin(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }) as Pin<Box<dyn Future<Output = ()> + Send + 'static>>
    }))
    .await;
    let config = fast_config();
    let (ok, stdout) = run_scan(&scan_args(port, &config, "json")).await;
    assert!(ok, "{stdout}");
    let scan: Scan = serde_json::from_str(&stdout).expect("canonical json");
    assert_eq!(scan.hosts[0].ports[0].service.as_deref(), Some("unknown"));
}

#[tokio::test]
async fn detects_dns_version() {
    let port = serve(Arc::new(|mut socket| {
        Box::pin(async move {
            let mut len = [0u8; 2];
            if socket.read_exact(&mut len).await.is_err() {
                return;
            }
            let query_len = u16::from_be_bytes(len) as usize;
            let mut query = vec![0u8; query_len.min(512)];
            if socket.read_exact(&mut query).await.is_err() {
                return;
            }
            // Fixed version.bind TXT reply; id echoes the query id.
            let id = [query[0], query[1]];
            let mut message = vec![
                id[0], id[1], 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            ];
            message.extend_from_slice(&[0x07]);
            message.extend_from_slice(b"version");
            message.extend_from_slice(&[0x04]);
            message.extend_from_slice(b"bind");
            message.extend_from_slice(&[0x00, 0x00, 0x10, 0x00, 0x03]);
            message.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x10, 0x00, 0x03]);
            message.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0B]);
            message.extend_from_slice(b"TestDNS 9.9");
            let frame_len = message.len() as u16;
            let _ = socket.write_all(&frame_len.to_be_bytes()).await;
            let _ = socket.write_all(&message).await;
        }) as Pin<Box<dyn Future<Output = ()> + Send + 'static>>
    }))
    .await;
    let config = fast_config();
    let (ok, stdout) = run_scan(&scan_args(port, &config, "json")).await;
    assert!(ok, "{stdout}");
    let scan: Scan = serde_json::from_str(&stdout).expect("canonical json");
    let service = &scan.hosts[0].ports[0];
    assert_eq!(service.service.as_deref(), Some("dns"));
    assert_eq!(service.version.as_deref(), Some("TestDNS 9.9"));
}

#[tokio::test]
async fn csv_output_lists_services() {
    let port = serve(Arc::new(|mut socket| {
        Box::pin(async move {
            let _ = socket.write_all(b"SSH-2.0-OpenSSH_9.3p1 TestLab\r\n").await;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }) as Pin<Box<dyn Future<Output = ()> + Send + 'static>>
    }))
    .await;
    let config = fast_config();
    let (ok, stdout) = run_scan(&scan_args(port, &config, "csv")).await;
    assert!(ok, "{stdout}");
    assert!(stdout.starts_with("scan_id,host,port,"));
    assert!(stdout.contains(",ssh,"), "{stdout}");
}

#[tokio::test]
async fn services_subcommand_prints_service_table() {
    let output = tokio::process::Command::new(binary())
        .args(["services", "127.0.0.1", "--yes"])
        .output()
        .await
        .expect("run binary");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("SERVICE"), "{stdout}");
}
