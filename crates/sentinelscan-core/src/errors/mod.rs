use thiserror::Error;

/// Crate-wide error type for Phase 1 (parsing, config, scope).
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid target '{input}': {reason}")]
    InvalidTarget { input: String, reason: String },
    #[error("invalid port spec '{input}': {reason}")]
    InvalidPort { input: String, reason: String },
    #[error("limit exceeded: {0}")]
    LimitExceeded(String),
    #[error("scope violation: {0}")]
    ScopeViolation(String),
    #[error("config error: {0}")]
    Config(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("io error: {0}")]
    Io(String),
}

impl Error {
    pub fn target(input: &str, reason: &str) -> Self {
        Self::InvalidTarget {
            input: input.to_owned(),
            reason: reason.to_owned(),
        }
    }

    pub fn port(input: &str, reason: &str) -> Self {
        Self::InvalidPort {
            input: input.to_owned(),
            reason: reason.to_owned(),
        }
    }
}
