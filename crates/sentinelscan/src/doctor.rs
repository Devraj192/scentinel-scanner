use serde::{Deserialize, Serialize};

use sentinelscan_core::results::model::sanitize;

/// One `doctor` finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub name: String,
    pub status: Status,
    pub detail: String,
    pub fix: Option<String>,
}

/// Pass, warn, or fail. Warnings explain themselves and suggest a fix; only
/// failures block anything, and `doctor` itself blocks nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Warn,
    Fail,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pass => write!(f, "pass"),
            Self::Warn => write!(f, "warn"),
            Self::Fail => write!(f, "fail"),
        }
    }
}

/// The full report: every check, worst first.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub checks: Vec<Check>,
}

impl DoctorReport {
    /// Build a report with worst findings first: fail, then warn, then pass.
    pub fn sorted(mut checks: Vec<Check>) -> Self {
        checks.sort_by_key(|check| match check.status {
            Status::Fail => 0,
            Status::Warn => 1,
            Status::Pass => 2,
        });
        Self { checks }
    }
    /// Human-readable table with fixes inline.
    pub fn terminal(&self) -> String {
        let mut out = String::from("CHECK\tSTATUS\tDETAIL\n");
        for check in &self.checks {
            out.push_str(&format!(
                "{}\t{}\t{}\n",
                sanitize(&check.name),
                check.status,
                sanitize(&check.detail),
            ));
            if let Some(fix) = &check.fix {
                out.push_str(&format!("\t  fix: {}\n", sanitize(fix)));
            }
        }
        out
    }
}

/// File descriptor limit: enough headroom for the default scan or a warning
/// with the exact remedy. Never fails: limits only ever clamp, never crash.
fn check_fds() -> Check {
    #[cfg(unix)]
    {
        let (soft, hard) = match rlimit::Resource::NOFILE.get() {
            Ok(limits) => limits,
            Err(e) => {
                return Check {
                    name: "file descriptors".to_owned(),
                    status: Status::Warn,
                    detail: format!("could not read NOFILE limit ({e}); using defaults blind"),
                    fix: Some("run: ulimit -n".to_owned()),
                };
            }
        };
        let (status, detail, fix) = if soft >= 1024 {
            (
                Status::Pass,
                format!("soft {soft}, hard {hard}; plenty for default scans"),
                None,
            )
        } else {
            (
                Status::Warn,
                format!("soft {soft}, hard {hard}; large scans will clamp concurrency"),
                Some("run: ulimit -n 4096 (or lower --concurrency)".to_owned()),
            )
        };
        return Check {
            name: "file descriptors".to_owned(),
            status,
            detail,
            fix,
        };
    }
    #[cfg(not(unix))]
    {
        Check {
            name: "file descriptors".to_owned(),
            status: Status::Pass,
            detail: "no rlimit knob on this platform; default concurrency is safe".to_owned(),
            fix: None,
        }
    }
}

/// Privileges: SentinelScan needs nothing special, so this check informs
/// rather than gates. Root gets a nudge, not an error.
fn check_privileges() -> Check {
    #[cfg(target_os = "linux")]
    {
        match sentinelscan_core::system::privileges() {
            Some(privs) if privs.uid == 0 => Check {
                name: "privileges".to_owned(),
                status: Status::Warn,
                detail: "running as root; connect scans do not need it".to_owned(),
                fix: Some("run as a normal user".to_owned()),
            },
            Some(privs) => Check {
                name: "privileges".to_owned(),
                status: Status::Pass,
                detail: format!(
                    "uid {}; CAP_NET_RAW {} (unused by default scans)",
                    privs.uid,
                    if privs.cap_net_raw {
                        "present"
                    } else {
                        "absent"
                    }
                ),
                fix: None,
            },
            None => Check {
                name: "privileges".to_owned(),
                status: Status::Warn,
                detail: "could not read /proc/self/status".to_owned(),
                fix: None,
            },
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Check {
            name: "privileges".to_owned(),
            status: Status::Pass,
            detail: "default scans need no privileges on this platform".to_owned(),
            fix: None,
        }
    }
}

/// DNS: resolve `localhost` only. Anything else would scan targets the user
/// never approved, so the check stays on loopback.
async fn check_dns() -> Check {
    match tokio::net::lookup_host(("localhost", 0)).await {
        Ok(addrs) => {
            let count = addrs.count();
            if count > 0 {
                Check {
                    name: "dns".to_owned(),
                    status: Status::Pass,
                    detail: format!("localhost resolves ({count} address(es))"),
                    fix: None,
                }
            } else {
                Check {
                    name: "dns".to_owned(),
                    status: Status::Fail,
                    detail: "localhost resolved to nothing".to_owned(),
                    fix: Some("check /etc/hosts contains a localhost entry".to_owned()),
                }
            }
        }
        Err(e) => Check {
            name: "dns".to_owned(),
            status: Status::Fail,
            detail: format!("localhost does not resolve ({e})"),
            fix: Some("check /etc/resolv.conf or the systemd-resolved stub".to_owned()),
        },
    }
}

/// Directories: exist and writable, with owner-only history permissions on
/// Unix. Probe with a temp file; report, never repair.
fn check_dirs() -> Vec<Check> {
    let mut checks = Vec::new();
    let data_default = sentinelscan_core::storage::default_db_path();
    let data_dir = data_default
        .parent()
        .map(|parent| parent.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    checks.push(check_writable_dir("data dir", &data_dir));
    if let Some(config_path) = sentinelscan_core::config::Config::default_path() {
        if let Some(parent) = config_path.parent() {
            checks.push(check_writable_dir("config dir", parent));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let history = data_dir.join("history.db");
        if history.exists() {
            match std::fs::metadata(&history) {
                Ok(meta) if meta.permissions().mode() & 0o077 == 0 => checks.push(Check {
                    name: "history permissions".to_owned(),
                    status: Status::Pass,
                    detail: format!("{} is owner-only", history.display()),
                    fix: None,
                }),
                _ => checks.push(Check {
                    name: "history permissions".to_owned(),
                    status: Status::Warn,
                    detail: format!("{} is readable by others", history.display()),
                    fix: Some(format!("run: chmod 600 {}", history.display())),
                }),
            }
        }
    }
    checks
}

fn check_writable_dir(name: &str, dir: &std::path::Path) -> Check {
    if !dir.exists() {
        return Check {
            name: name.to_owned(),
            status: Status::Warn,
            detail: format!(
                "{} does not exist; it is created on first use",
                dir.display()
            ),
            fix: Some(format!("run: mkdir -p {}", dir.display())),
        };
    }
    let probe = dir.join(".sentinelscan-write-test");
    match std::fs::write(&probe, b"ok").and_then(|()| std::fs::remove_file(&probe)) {
        Ok(()) => Check {
            name: name.to_owned(),
            status: Status::Pass,
            detail: format!("{} exists and is writable", dir.display()),
            fix: None,
        },
        Err(e) => Check {
            name: name.to_owned(),
            status: Status::Fail,
            detail: format!("{} is not writable ({e})", dir.display()),
            fix: Some(format!(
                "check ownership and permissions of {}",
                dir.display()
            )),
        },
    }
}

/// Install method, best effort from the binary path. Informational only.
fn check_install() -> Check {
    let exe = std::env::current_exe()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "<unknown>".to_owned());
    let method = if exe.contains(".cargo") && exe.contains("bin") {
        "cargo install (or cargo run)"
    } else if exe.contains("target/") || exe.contains("target\\") {
        "local debug build"
    } else {
        "system package, script, or container"
    };
    let build = if cfg!(debug_assertions) {
        "debug build"
    } else {
        "release build"
    };
    Check {
        name: "install".to_owned(),
        status: Status::Pass,
        detail: format!("{exe} via {method}; {build}"),
        fix: None,
    }
}

/// Run every check. Changes nothing on the system.
pub async fn run() -> DoctorReport {
    let mut checks = vec![check_fds(), check_privileges()];
    checks.push(check_dns().await);
    checks.extend(check_dirs());
    checks.push(check_install());
    DoctorReport::sorted(checks)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(status: Status) -> Check {
        Check {
            name: "dns".to_owned(),
            status,
            detail: "localhost resolves (2 address(es))".to_owned(),
            fix: None,
        }
    }

    #[test]
    fn sorts_worst_first() {
        let report = DoctorReport::sorted(vec![
            check(Status::Pass),
            check(Status::Fail),
            check(Status::Warn),
        ]);
        let order: Vec<Status> = report.checks.iter().map(|check| check.status).collect();
        assert_eq!(order, vec![Status::Fail, Status::Warn, Status::Pass]);
    }

    #[test]
    fn terminal_renders_fixes() {
        let mut failing = check(Status::Fail);
        failing.fix = Some("run: mkdir -p /tmp/x".to_owned());
        let report = DoctorReport::sorted(vec![failing]);
        let text = report.terminal();
        assert!(text.contains("fail"));
        assert!(text.contains("fix: run: mkdir -p /tmp/x"));
    }
}
