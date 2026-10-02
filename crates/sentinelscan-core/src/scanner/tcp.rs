use std::io;
use std::net::IpAddr;
use std::time::Instant;

use tokio::net::TcpStream;

use super::timeout;
use crate::results::model::PortState;
use crate::safety::scope::ScopeGuard;

/// Outcome of one TCP connect probe.
pub struct PortOutcome {
    pub state: PortState,
    pub reason: &'static str,
    pub latency_ms: u64,
}

/// Map a connect failure to (state, reason) per PRD 3.3. Timeouts are
/// `filtered`, never `closed`; local errors are `unknown`, never a guess.
fn classify_error(error: &io::Error) -> (PortState, &'static str) {
    use std::io::ErrorKind::*;
    match error.kind() {
        ConnectionRefused | ConnectionReset => (PortState::Closed, "refused"),
        TimedOut => (PortState::Filtered, "timeout"),
        HostUnreachable => (PortState::Filtered, "host_unreachable"),
        NetworkUnreachable => (PortState::Filtered, "network_unreachable"),
        _ => (PortState::Unknown, "local_error"),
    }
}

/// Connect to one port through the scope guard. Never returns an error: every
/// outcome, including guard rejection, becomes a classified `PortOutcome`.
pub async fn connect_one(
    ip: IpAddr,
    port: u16,
    timeout_ms: u64,
    guard: &ScopeGuard,
) -> PortOutcome {
    if guard.check_ip(&ip).is_err() {
        return PortOutcome {
            state: PortState::Unknown,
            reason: "out_of_scope",
            latency_ms: 0,
        };
    }
    let start = Instant::now();
    let latency_ms = || start.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
    match timeout::run(timeout_ms, TcpStream::connect((ip, port))).await {
        None => {
            tracing::debug!(%ip, port, event = "timeout");
            PortOutcome {
                state: PortState::Filtered,
                reason: "timeout",
                latency_ms: latency_ms(),
            }
        }
        Some(Ok(_)) => PortOutcome {
            state: PortState::Open,
            reason: "handshake",
            latency_ms: latency_ms(),
        },
        Some(Err(error)) => {
            let (state, reason) = classify_error(&error);
            if state == PortState::Filtered {
                tracing::debug!(%ip, port, reason, event = "timeout");
            }
            PortOutcome {
                state,
                reason,
                latency_ms: latency_ms(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused() -> io::Error {
        io::Error::new(io::ErrorKind::ConnectionRefused, "refused")
    }

    #[test]
    fn refusal_is_closed() {
        assert_eq!(classify_error(&refused()).0, PortState::Closed);
    }

    #[test]
    fn timeout_is_never_closed() {
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::NetworkUnreachable,
        ] {
            let (state, _) = classify_error(&io::Error::new(kind, "x"));
            assert_eq!(state, PortState::Filtered, "{kind:?}");
        }
    }

    #[test]
    fn local_errors_are_unknown() {
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::AddrInUse,
            io::ErrorKind::AddrNotAvailable,
            io::ErrorKind::Interrupted,
            io::ErrorKind::Other,
        ] {
            let (state, _) = classify_error(&io::Error::new(kind, "x"));
            assert_eq!(state, PortState::Unknown, "{kind:?}");
        }
    }
}
