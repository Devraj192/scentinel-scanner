pub mod profiles;

use serde::{Deserialize, Serialize};

use crate::errors::Error;

fn default_max_hosts() -> usize {
    Limits::default().max_hosts
}
fn default_max_ports() -> usize {
    Limits::default().max_ports
}
fn default_max_concurrency() -> usize {
    Limits::default().max_concurrency
}
fn default_max_rate() -> u64 {
    Limits::default().max_rate
}
fn default_connect_timeout_ms() -> u64 {
    Limits::default().connect_timeout_ms
}
fn default_probe_timeout_ms() -> u64 {
    Limits::default().probe_timeout_ms
}
fn default_max_banner_size() -> usize {
    Limits::default().max_banner_size
}
fn default_max_scan_duration_secs() -> u64 {
    Limits::default().max_scan_duration_secs
}

/// Hard bounds for a scan. Every field is independently configurable and every
/// network loop in later phases must respect these caps.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Limits {
    #[serde(default = "default_max_hosts")]
    pub max_hosts: usize,
    #[serde(default = "default_max_ports")]
    pub max_ports: usize,
    #[serde(default = "default_max_concurrency")]
    pub max_concurrency: usize,
    #[serde(default = "default_max_rate")]
    pub max_rate: u64,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_probe_timeout_ms")]
    pub probe_timeout_ms: u64,
    #[serde(default = "default_max_banner_size")]
    pub max_banner_size: usize,
    #[serde(default = "default_max_scan_duration_secs")]
    pub max_scan_duration_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_hosts: 256,
            max_ports: 1024,
            max_concurrency: 50,
            max_rate: 500,
            connect_timeout_ms: 3000,
            probe_timeout_ms: 2000,
            max_banner_size: 4096,
            max_scan_duration_secs: 300,
        }
    }
}

impl Limits {
    /// Reject zero or absurd values with a clear message.
    pub fn validate(&self) -> Result<(), Error> {
        if self.max_hosts == 0 || self.max_hosts > 65536 {
            return Err(Error::Config(format!(
                "max_hosts must be 1-65536, got {}",
                self.max_hosts
            )));
        }
        if self.max_ports == 0 || self.max_ports > 65535 {
            return Err(Error::Config(format!(
                "max_ports must be 1-65535, got {}",
                self.max_ports
            )));
        }
        if self.max_concurrency == 0 || self.max_concurrency > 5000 {
            return Err(Error::Config(format!(
                "max_concurrency must be 1-5000, got {}",
                self.max_concurrency
            )));
        }
        if self.max_rate == 0 || self.max_rate > 100_000 {
            return Err(Error::Config(format!(
                "max_rate must be 1-100000, got {}",
                self.max_rate
            )));
        }
        if self.connect_timeout_ms == 0 || self.probe_timeout_ms == 0 {
            return Err(Error::Config(
                "connect and probe timeouts must be non-zero".to_owned(),
            ));
        }
        if self.max_banner_size == 0 || self.max_banner_size > 1_048_576 {
            return Err(Error::Config(format!(
                "max_banner_size must be 1-1048576, got {}",
                self.max_banner_size
            )));
        }
        if self.max_scan_duration_secs == 0 {
            return Err(Error::Config(
                "max_scan_duration_secs must be non-zero".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Per-profile overrides loaded from `[profiles.<name>]` tables. Every field
/// is optional; missing fields fall back to the built-in profile behavior.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileSettings {
    #[serde(default)]
    pub ports: Option<String>,
    #[serde(default)]
    pub service_detection: Option<bool>,
    #[serde(default)]
    pub banner: Option<bool>,
    #[serde(default)]
    pub skip_host_discovery: Option<bool>,
}

/// Top-level configuration: limits plus the path it was loaded from, if any.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub profiles: std::collections::HashMap<String, ProfileSettings>,
    #[serde(skip)]
    pub source: Option<String>,
}

impl Config {
    /// Config file used when `--config` is absent: the XDG config dir, but
    /// only when the file actually exists (otherwise built-in defaults apply,
    /// exactly as in v1).
    pub fn default_path() -> Option<std::path::PathBuf> {
        let path = crate::paths::config_home()?.join("sentinelscan/config.toml");
        path.exists().then_some(path)
    }

    /// Load TOML from `path`, or fall back to conservative defaults when
    /// `path` is `None`. A missing file with an explicit path is an error.
    pub fn load(path: Option<&str>) -> Result<Self, Error> {
        match path {
            None => {
                let cfg = Self {
                    limits: Limits::default(),
                    profiles: std::collections::HashMap::new(),
                    source: None,
                };
                cfg.limits.validate()?;
                Ok(cfg)
            }
            Some(p) => {
                let text = std::fs::read_to_string(p)
                    .map_err(|e| Error::Config(format!("cannot read {p}: {e}")))?;
                let mut cfg: Self = toml::from_str(&text)
                    .map_err(|e| Error::Config(format!("cannot parse {p}: {e}")))?;
                cfg.limits.validate()?;
                cfg.source = Some(p.to_owned());
                Ok(cfg)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        Limits::default().validate().expect("defaults valid");
    }

    #[test]
    fn rejects_zero_limits() {
        let limits = Limits {
            max_hosts: 0,
            ..Default::default()
        };
        assert!(limits.validate().is_err());
        let limits = Limits {
            max_ports: 0,
            ..Default::default()
        };
        assert!(limits.validate().is_err());
    }

    #[test]
    fn loads_toml_and_validates() {
        let dir = std::env::temp_dir();
        let path = dir.join("sentinelscan-test-config.toml");
        std::fs::write(&path, "[limits]\nmax_hosts = 16\n").expect("write fixture");
        let cfg = Config::load(Some(path.to_str().expect("utf8"))).expect("loads");
        assert_eq!(cfg.limits.max_hosts, 16);
        assert_eq!(cfg.limits.max_ports, 1024);
    }
}
