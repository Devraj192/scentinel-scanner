use std::future::Future;
use std::pin::Pin;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::detection::banner::dial;
use crate::detection::service::{Detection, Evidence, ServiceDetector};
use crate::detection::ActiveCtx;
use crate::scanner::timeout;

/// Parse an HTTP response head. Returns (server_header, is_http).
fn parse_response(head: &[u8]) -> Option<(Option<String>, bool)> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.lines();
    let status = lines.next()?;
    if !status.starts_with("HTTP/") {
        return None;
    }
    let mut server = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(value) = line
            .strip_prefix("Server:")
            .or(line.strip_prefix("server:"))
        {
            let value = value.trim();
            if !value.is_empty() {
                server = Some(value.chars().take(128).collect::<String>());
            }
        }
    }
    Some((server, true))
}

fn http_detection(head: &[u8]) -> Option<Detection> {
    let (server, _) = parse_response(head)?;
    let status_line = std::str::from_utf8(head)
        .ok()?
        .lines()
        .next()
        .unwrap_or("")
        .to_owned();
    let mut evidence = vec![Evidence::observation(&format!("status: {status_line}"))];
    let (version, confidence) = match server {
        Some(server) => {
            evidence.push(Evidence::observation(&format!("server header: {server}")));
            (Some(server), 0.95)
        }
        None => (None, 0.85),
    };
    evidence.push(Evidence::inference(
        "status line follows the HTTP response format",
    ));
    Some(Detection::new("http", version, confidence, evidence))
}

/// Read a response head: up to 8KB or the end of headers, within the probe timeout.
async fn read_head(stream: &mut tokio::net::TcpStream, timeout_ms: u64) -> Option<Vec<u8>> {
    let body = async {
        let mut head = Vec::new();
        let mut chunk = vec![0u8; 4096];
        loop {
            if head.len() >= 8192 || head.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            match stream.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => head.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
        head
    };
    timeout::run(timeout_ms, body).await
}

/// Minimal non-destructive HTTP probe: one `GET /` with connection close.
/// Also recognizes TLS servers by their alert reply to plaintext HTTP.
pub struct HttpDetector;

impl ServiceDetector for HttpDetector {
    fn name(&self) -> &'static str {
        "http"
    }

    fn match_banner(&self, banner: &[u8], _port: u16) -> Option<Detection> {
        if banner.is_empty() {
            return None;
        }
        http_detection(banner)
    }

    fn probe<'a>(
        &'a self,
        ctx: &'a ActiveCtx,
    ) -> Pin<Box<dyn Future<Output = Option<Detection>> + Send + 'a>> {
        Box::pin(async move {
            let mut stream = dial(
                ctx.ip,
                ctx.port,
                &ctx.limits,
                &ctx.guard,
                &ctx.semaphore,
                &ctx.rate,
            )
            .await?;
            let request = format!(
                "GET / HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
                ctx.ip
            );
            let write = async { stream.write_all(request.as_bytes()).await.is_ok() };
            if timeout::run(ctx.limits.probe_timeout_ms, write).await != Some(true) {
                return None;
            }
            let head = read_head(&mut stream, ctx.limits.probe_timeout_ms).await?;
            if head.len() >= 3 && head[0] == 0x15 && head[1] == 0x03 {
                return Some(Detection::new(
                    "https",
                    None,
                    0.8,
                    vec![
                        Evidence::observation("server replied with a TLS alert record"),
                        Evidence::inference("TLS alert in reply to plaintext HTTP reads as HTTPS"),
                    ],
                ));
            }
            http_detection(&head)
        })
    }
}

/// Matches TLS alert bytes already present in a passive banner (some servers
/// blurt an alert on connect). Sends nothing itself.
pub struct HttpsDetector;

impl ServiceDetector for HttpsDetector {
    fn name(&self) -> &'static str {
        "https"
    }

    fn match_banner(&self, banner: &[u8], _port: u16) -> Option<Detection> {
        if banner.len() >= 3 && banner[0] == 0x15 && banner[1] == 0x03 {
            Some(Detection::new(
                "https",
                None,
                0.8,
                vec![
                    Evidence::observation("banner opens with a TLS alert record"),
                    Evidence::inference("TLS record framing reads as HTTPS"),
                ],
            ))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_response_with_server() {
        let head = b"HTTP/1.1 200 OK\r\nServer: TestLab/1.2.3\r\n\r\n";
        let detection = HttpDetector.match_banner(head, 80).expect("match");
        assert_eq!(detection.service, "http");
        assert_eq!(detection.version.as_deref(), Some("TestLab/1.2.3"));
    }

    #[test]
    fn matches_response_without_server() {
        let head = b"HTTP/1.0 404 Not Found\r\n\r\n";
        let detection = HttpDetector.match_banner(head, 8080).expect("match");
        assert_eq!(detection.version, None);
    }

    #[test]
    fn matches_tls_alert_passively() {
        assert!(HttpsDetector
            .match_banner(&[0x15, 0x03, 0x01, 0x00], 443)
            .is_some());
        assert!(HttpsDetector
            .match_banner(b"HTTP/1.1 200 OK\r\n\r\n", 443)
            .is_none());
    }

    #[test]
    fn rejects_garbage() {
        assert!(HttpDetector
            .match_banner(b"\x00\xff\x1b garbage", 80)
            .is_none());
        assert!(HttpDetector.match_banner(b"", 80).is_none());
    }
}
