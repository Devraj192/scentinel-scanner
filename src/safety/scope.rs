use std::net::IpAddr;

use ipnet::IpNet;

use super::validator::is_valid_hostname_syntax;
use crate::errors::Error;
use crate::safety::limits::enforce_host_count;

/// A single user-supplied target after syntax validation (no DNS, no traffic).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedTarget {
    Ip(IpAddr),
    Cidr(IpNet),
    Hostname(String),
}

impl std::fmt::Display for ParsedTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Cidr(net) => write!(f, "{net}"),
            Self::Hostname(name) => write!(f, "{name}"),
        }
    }
}

/// Number of addresses a CIDR contributes to host count (saturating).
fn cidr_host_count(net: &IpNet) -> usize {
    let host_bits = match net {
        IpNet::V4(n) => 32 - n.prefix_len() as usize,
        IpNet::V6(n) => 128 - n.prefix_len() as usize,
    };
    if host_bits >= usize::BITS as usize {
        return usize::MAX;
    }
    let total: usize = 1usize << host_bits;
    match net {
        // ipnet's hosts() drops network+broadcast for prefix < 31.
        IpNet::V4(n) if n.prefix_len() < 31 => total.saturating_sub(2),
        _ => total,
    }
}

/// Parse one target string. Hostnames require the explicit opt-in flag.
pub fn parse_single_target(input: &str, allow_hostnames: bool) -> Result<ParsedTarget, Error> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(Error::target(input, "empty target"));
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(ParsedTarget::Ip(ip));
    }
    if let Ok(net) = trimmed.parse::<IpNet>() {
        return Ok(ParsedTarget::Cidr(net));
    }
    let looks_like_hostname =
        is_valid_hostname_syntax(trimmed) && trimmed.bytes().any(|b| b.is_ascii_alphabetic());
    if allow_hostnames && looks_like_hostname {
        return Ok(ParsedTarget::Hostname(trimmed.to_lowercase()));
    }
    if !allow_hostnames && looks_like_hostname {
        return Err(Error::target(
            input,
            "hostname given but hostnames are disabled (pass --allow-hostnames)",
        ));
    }
    Err(Error::target(input, "not an IPv4/IPv6 address or CIDR"))
}

/// Parse all targets and enforce max_hosts on the total host count.
pub fn parse_targets(
    inputs: &[String],
    allow_hostnames: bool,
    max_hosts: usize,
) -> Result<Vec<ParsedTarget>, Error> {
    if inputs.is_empty() {
        return Err(Error::target("", "at least one target is required"));
    }
    let mut out = Vec::with_capacity(inputs.len());
    let mut host_total: usize = 0;
    for raw in inputs {
        let parsed = parse_single_target(raw, allow_hostnames)?;
        host_total = host_total.saturating_add(match &parsed {
            ParsedTarget::Ip(_) | ParsedTarget::Hostname(_) => 1,
            ParsedTarget::Cidr(net) => cidr_host_count(net),
        });
        enforce_host_count(host_total, max_hosts)?;
        out.push(parsed);
    }
    Ok(out)
}

/// Total hosts the parsed targets represent (saturating).
pub fn host_count(targets: &[ParsedTarget]) -> usize {
    targets
        .iter()
        .map(|t| match t {
            ParsedTarget::Ip(_) | ParsedTarget::Hostname(_) => 1,
            ParsedTarget::Cidr(net) => cidr_host_count(net),
        })
        .fold(0usize, |a, b| a.saturating_add(b))
}

/// The only path to the network. Phase 2 must route every socket through this
/// guard; no code path may open a connection without calling `check_*` first.
#[derive(Debug, Clone, Default)]
pub struct ScopeGuard {
    nets: Vec<IpNet>,
    hostnames: Vec<String>,
}

impl ScopeGuard {
    /// Build the guard from already-validated targets.
    pub fn from_targets(targets: &[ParsedTarget]) -> Self {
        let mut guard = Self::default();
        for target in targets {
            match target {
                ParsedTarget::Ip(ip) => {
                    let net = match ip {
                        IpAddr::V4(v4) => {
                            IpNet::V4(ipnet::Ipv4Net::new(*v4, 32).expect("valid /32"))
                        }
                        IpAddr::V6(v6) => {
                            IpNet::V6(ipnet::Ipv6Net::new(*v6, 128).expect("valid /128"))
                        }
                    };
                    guard.nets.push(net);
                }
                ParsedTarget::Cidr(net) => guard.nets.push(*net),
                ParsedTarget::Hostname(name) => guard.hostnames.push(name.clone()),
            }
        }
        guard
    }

    /// Allow a connection to `ip` only when it falls inside the declared scope.
    pub fn check_ip(&self, ip: &IpAddr) -> Result<(), Error> {
        if self.nets.iter().any(|net| net.contains(ip)) {
            Ok(())
        } else {
            Err(Error::ScopeViolation(format!(
                "address {ip} is outside the declared scan scope"
            )))
        }
    }

    /// Allow a connection to `name` only when it was declared in scope.
    pub fn check_hostname(&self, name: &str) -> Result<(), Error> {
        let lowered = name.to_lowercase();
        if self.hostnames.iter().any(|h| h == &lowered) {
            Ok(())
        } else {
            Err(Error::ScopeViolation(format!(
                "hostname {name} is outside the declared scan scope"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_and_ipv6() {
        assert!(parse_single_target("192.168.1.1", false).is_ok());
        assert!(parse_single_target("::1", false).is_ok());
    }

    #[test]
    fn parses_cidr() {
        let t = parse_single_target("192.168.1.0/30", false).expect("cidr parses");
        assert_eq!(host_count(&[t]), 2);
    }

    #[test]
    fn rejects_malformed_targets() {
        assert!(parse_single_target("999.1.1.1", false).is_err());
        assert!(parse_single_target("", false).is_err());
        assert!(parse_single_target("not a target!!", false).is_err());
        let err = parse_single_target("999.1.1.1", false).expect_err("bad octet");
        assert!(!err.to_string().contains("--allow-hostnames"), "{err}");
    }

    #[test]
    fn hostname_needs_flag() {
        assert!(parse_single_target("example.com", false).is_err());
        assert!(parse_single_target("example.com", true).is_ok());
    }

    #[test]
    fn enforces_max_hosts() {
        let inputs = vec!["10.0.0.0/16".to_owned()];
        assert!(parse_targets(&inputs, false, 256).is_err());
    }

    #[test]
    fn guard_rejects_out_of_scope() {
        let targets = parse_targets(&["192.168.1.0/30".to_owned()], false, 256).expect("in scope");
        let guard = ScopeGuard::from_targets(&targets);
        assert!(guard.check_ip(&"192.168.1.1".parse().expect("ip")).is_ok());
        assert!(guard.check_ip(&"10.0.0.1".parse().expect("ip")).is_err());
        assert!(guard
            .check_hostname("example.com")
            .is_err_and(|e| matches!(e, Error::ScopeViolation(_))));
    }
}
