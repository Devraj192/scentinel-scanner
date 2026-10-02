use std::future::Future;
use std::pin::Pin;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::detection::banner::dial;
use crate::detection::service::{Detection, Evidence, ServiceDetector};
use crate::detection::ActiveCtx;
use crate::scanner::timeout;

/// Minimal TCP DNS probe: one `version.bind` TXT query (CHAOS class), the same
/// question operators ask manually. No zone transfers, no recursion abuse.
pub struct DnsDetector;

fn build_query() -> Vec<u8> {
    let mut query = vec![
        0x12, 0x34, // id
        0x01, 0x00, // flags: recursion desired
        0x00, 0x01, // questions: 1
        0x00, 0x00, // answers: 0
        0x00, 0x00, // authority: 0
        0x00, 0x00, // additional: 0
        0x07, // label length
    ];
    query.extend_from_slice(b"version");
    query.push(0x04);
    query.extend_from_slice(b"bind");
    query.push(0x00);
    query.extend_from_slice(&[0x00, 0x10, 0x00, 0x03]); // TXT, CHAOS
    let len = query.len() as u16;
    let mut framed = len.to_be_bytes().to_vec();
    framed.extend_from_slice(&query);
    framed
}

/// Read exactly `n` bytes unless the stream ends or the deadline fires.
async fn read_exact(
    stream: &mut tokio::net::TcpStream,
    n: usize,
    timeout_ms: u64,
) -> Option<Vec<u8>> {
    let body = async {
        let mut buf = vec![0u8; n];
        stream.read_exact(&mut buf).await.ok()?;
        Some(buf)
    };
    timeout::run(timeout_ms, body).await?
}

/// Skip a DNS name (labels plus terminator or pointer), returning the offset
/// just past it. `None` on malformed input.
fn skip_name(message: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let len = *message.get(offset)?;
        if len & 0xC0 == 0xC0 {
            return Some(offset + 2);
        }
        if len == 0 {
            return Some(offset + 1);
        }
        if len > 63 {
            return None;
        }
        offset += 1 + len as usize;
        if offset >= message.len() {
            return None;
        }
    }
}

fn get_u16(message: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        message.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

/// Extract the first TXT string from a DNS response, if the header shows a
/// response with at least one answer.
fn parse_txt_version(message: &[u8]) -> Option<String> {
    if message.len() < 12 || message.get(2)? & 0x80 == 0 {
        return None;
    }
    let questions = get_u16(message, 4)? as usize;
    let answers = get_u16(message, 6)? as usize;
    if answers == 0 {
        return None;
    }
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_name(message, offset)?;
        offset = offset.checked_add(4)?;
        if offset > message.len() {
            return None;
        }
    }
    for _ in 0..answers.min(8) {
        offset = skip_name(message, offset)?;
        let record_type = get_u16(message, offset)?;
        let data_len = get_u16(message, offset + 8)? as usize;
        offset += 10;
        let data = message.get(offset..offset.checked_add(data_len)?)?;
        if record_type == 16 && !data.is_empty() {
            let txt_len = data[0] as usize;
            let text = data.get(1..1usize.checked_add(txt_len)?)?;
            let version: String = String::from_utf8_lossy(text).chars().take(128).collect();
            if !version.trim().is_empty() {
                return Some(version);
            }
        }
        offset += data_len;
    }
    None
}

impl ServiceDetector for DnsDetector {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn match_banner(&self, _banner: &[u8], _port: u16) -> Option<Detection> {
        // DNS servers do not greet on TCP; detection needs the query below.
        None
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
            let query = build_query();
            let write = async { stream.write_all(&query).await.is_ok() };
            if timeout::run(ctx.limits.probe_timeout_ms, write).await != Some(true) {
                return None;
            }
            let len_bytes = read_exact(&mut stream, 2, ctx.limits.probe_timeout_ms).await?;
            let len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
            if len == 0 || len > 4096 {
                return None;
            }
            let message = read_exact(&mut stream, len, ctx.limits.probe_timeout_ms).await?;
            let version = parse_txt_version(&message)?;
            Some(Detection::new(
                "dns",
                Some(version.clone()),
                0.9,
                vec![
                    Evidence::observation(&format!("version.bind TXT: {version}")),
                    Evidence::inference("answered version.bind query over TCP"),
                ],
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_txt_response() {
        // Header: response, 1 question, 1 answer.
        let mut message = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        // Question: version.bind TXT CHAOS.
        message.extend_from_slice(&[0x07]);
        message.extend_from_slice(b"version");
        message.extend_from_slice(&[0x04]);
        message.extend_from_slice(b"bind");
        message.extend_from_slice(&[0x00, 0x00, 0x10, 0x00, 0x03]);
        // Answer: pointer to question name, TXT, CHAOS, TTL, RDLEN, "TestDNS 1.0".
        message.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x10, 0x00, 0x03]);
        message.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x0C]);
        message.extend_from_slice(&[0x0B]);
        message.extend_from_slice(b"TestDNS 1.0");
        assert_eq!(parse_txt_version(&message).as_deref(), Some("TestDNS 1.0"));
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse_txt_version(b""), None);
        assert_eq!(parse_txt_version(&[0u8; 12]), None);
        assert_eq!(parse_txt_version(b"\x00\xff binary garbage here"), None);
    }
}
