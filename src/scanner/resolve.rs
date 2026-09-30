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
pub async fn resolve_targets(
    targets: &[ParsedTarget],
    guard: &ScopeGuard,
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
