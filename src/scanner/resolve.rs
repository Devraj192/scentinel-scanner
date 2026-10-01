use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::errors::Error;
use crate::safety::limits::enforce_host_count;
use crate::safety::scope::{ParsedTarget, ScopeGuard};

/// One resolved scan target. `addr` is `None` when hostname resolution failed;
/// the host is still reported (as `unknown`) so one bad target never aborts
/// the scan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedHost {
    pub display: String,
    pub addr: Option<IpAddr>,
}

/// Expand parsed targets to addresses. Hostname resolution happens after
/// scope confirmation: it is the first network I/O in the program.
///
/// Every resolved address is authorized in the guard before returning, so the
/// connects that follow pass `check_ip`. Without this, hostname scans would
/// resolve and then refuse their own results.
pub async fn resolve_targets(
    targets: &[ParsedTarget],
    guard: &mut ScopeGuard,
    max_hosts: usize,
) -> Result<Vec<ResolvedHost>, Error> {
    let mut out = Vec::new();
    for target in targets {
        match target {
            ParsedTarget::Ip(ip) => out.push(ResolvedHost {
                display: ip.to_string(),
                addr: Some(*ip),
            }),
            ParsedTarget::Cidr(net) => {
                for ip in net.hosts().take(max_hosts.saturating_add(1)) {
                    out.push(ResolvedHost {
                        display: ip.to_string(),
                        addr: Some(ip),
                    });
                }
            }
            ParsedTarget::Hostname(name) => {
                guard.check_hostname(name)?;
                match tokio::net::lookup_host((name.as_str(), 0)).await {
                    Ok(addrs) => {
                        for addr in addrs {
                            guard.allow_ip(&addr.ip());
                            out.push(ResolvedHost {
                                display: name.clone(),
                                addr: Some(addr.ip()),
                            });
                        }
                    }
                    Err(_) => out.push(ResolvedHost {
                        display: name.clone(),
                        addr: None,
                    }),
                }
            }
        }
        enforce_host_count(out.len(), max_hosts)?;
    }
    Ok(out)
}

/// Re-authorize previously resolved addresses (resume path, which reuses
/// stored resolution instead of looking hostnames up again).
pub fn authorize_resolved(guard: &mut ScopeGuard, resolved: &[ResolvedHost]) {
    for host in resolved {
        if let Some(ip) = host.addr {
            guard.allow_ip(&ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolved_hostnames_pass_the_guard() {
        let targets = crate::safety::scope::parse_targets(&["localhost".to_owned()], true, 256)
            .expect("parse");
        let mut guard = ScopeGuard::from_targets(&targets);
        let resolved = resolve_targets(&targets, &mut guard, 256)
            .await
            .expect("resolve");
        assert!(!resolved.is_empty(), "localhost must resolve locally");
        for host in &resolved {
            let ip = host.addr.expect("localhost resolves to addresses");
            assert!(
                guard.check_ip(&ip).is_ok(),
                "resolved {ip} must stay in scope"
            );
        }
    }
}
