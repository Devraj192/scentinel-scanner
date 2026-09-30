use serde::{Deserialize, Serialize};

/// Scan profile selecting default ports and detection stages (Phase 3+).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    Quick,
    #[default]
    Standard,
    Custom,
}

impl std::str::FromStr for Profile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "quick" => Ok(Self::Quick),
            "standard" => Ok(Self::Standard),
            "custom" => Ok(Self::Custom),
            other => Err(format!("unknown profile '{other}' (quick|standard|custom)")),
        }
    }
}

impl Profile {
    /// Default port spec for the profile.
    pub fn default_ports(&self) -> &'static str {
        match self {
            Self::Quick => "quick",
            Self::Standard => "standard",
            Self::Custom => "standard",
        }
    }

    /// Config-file section name for profile overrides.
    pub fn section(&self) -> &'static str {
        match self {
            Self::Quick => "quick",
            Self::Standard => "standard",
            Self::Custom => "custom",
        }
    }
}
