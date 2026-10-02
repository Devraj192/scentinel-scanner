//! Unix process realities: file descriptor limits and privilege detection.
//! Everything that touches the OS lives behind `cfg` gates; the pure policy
//! (`clamp_concurrency`, capability-bit parsing) is always compiled and tested.

/// File descriptors kept in reserve: stdio, SQLite, DNS, and slack.
const FD_RESERVE: u64 = 64;

/// File descriptors budgeted per concurrent probe (socket plus margin).
const FD_PER_PROBE: u64 = 2;

/// Clamp configured concurrency to what `soft_limit` file descriptors allow.
/// Returns the effective cap and whether clamping kicked in.
pub fn clamp_concurrency(configured: usize, soft_limit: u64) -> (usize, bool) {
    let usable = soft_limit.saturating_sub(FD_RESERVE) / FD_PER_PROBE;
    let effective = configured.max(1).min(usable.max(1) as usize);
    (effective, effective < configured)
}

/// Read the NOFILE limits and raise the soft limit toward the hard limit when
/// it would otherwise clamp the scan. Returns the effective concurrency plus
/// a plain-language warning when clamping kicked in anyway.
#[cfg(unix)]
pub fn apply_fd_limits(configured: usize) -> (usize, Option<String>) {
    let (mut soft, hard) = match rlimit::Resource::NOFILE.get() {
        Ok(limits) => limits,
        Err(_) => return (configured, None),
    };
    if soft < hard {
        let want = (configured as u64)
            .saturating_mul(FD_PER_PROBE)
            .saturating_add(FD_RESERVE)
            .min(hard);
        if want > soft && rlimit::Resource::NOFILE.set(want, hard).is_ok() {
            soft = want;
        }
    }
    let (effective, clamped) = clamp_concurrency(configured, soft);
    let warning = clamped.then(|| {
        format!(
            "Concurrency clamped to {effective}: the system allows {soft} open files. \
             Raise the limit (ulimit -n) or lower --concurrency; the scan continues."
        )
    });
    (effective, warning)
}

/// Non-Unix platforms have no `rlimit` knob here; configuration stands as-is.
#[cfg(not(unix))]
pub fn apply_fd_limits(configured: usize) -> (usize, Option<String>) {
    (configured, None)
}

/// What we know about our own privileges on Linux, read from
/// `/proc/self/status` with std file I/O only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Privileges {
    /// Real UID. Zero means root.
    pub uid: u32,
    /// Whether the effective set includes `CAP_NET_RAW` (bit 13).
    pub cap_net_raw: bool,
}

/// Parse the `Uid:` and `CapEff:` lines of `/proc/self/status` content.
pub fn parse_proc_status(content: &str) -> Option<Privileges> {
    let mut uid = None;
    let mut cap = None;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            uid = rest.split_whitespace().next()?.parse().ok();
        }
        if let Some(rest) = line.strip_prefix("CapEff:") {
            let bits = u64::from_str_radix(rest.trim(), 16).ok()?;
            cap = Some(bits & (1 << 13) != 0);
        }
    }
    Some(Privileges {
        uid: uid?,
        cap_net_raw: cap?,
    })
}

/// Read our own privileges. `None` off Linux or when `/proc` is unavailable.
#[cfg(target_os = "linux")]
pub fn privileges() -> Option<Privileges> {
    parse_proc_status(&std::fs::read_to_string("/proc/self/status").ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_above_the_fd_limit() {
        assert_eq!(clamp_concurrency(5000, 1024), (480, true));
        assert_eq!(clamp_concurrency(50, 1024), (50, false));
    }

    #[test]
    fn never_returns_zero() {
        assert_eq!(clamp_concurrency(50, 16), (1, true));
    }

    #[test]
    fn parses_root_with_cap_net_raw() {
        let status = "Uid:\t0\t0\t0\t0\nCapEff:\t000000ffffffffff\n";
        assert_eq!(
            parse_proc_status(status),
            Some(Privileges {
                uid: 0,
                cap_net_raw: true,
            })
        );
    }

    #[test]
    fn parses_unprivileged_user() {
        let status = "Uid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000000000\n";
        assert_eq!(
            parse_proc_status(status),
            Some(Privileges {
                uid: 1000,
                cap_net_raw: false,
            })
        );
    }

    #[test]
    fn rejects_truncated_status() {
        assert_eq!(parse_proc_status("Uid:\t1000\n"), None);
        assert_eq!(parse_proc_status(""), None);
    }
}
