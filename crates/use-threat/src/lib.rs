#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
#![allow(clippy::module_name_repetitions)]

use core::{fmt, str::FromStr};
use std::error::Error;

/// Error returned when threat metadata is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreatError {
    Empty,
    Unknown,
}

impl fmt::Display for ThreatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("threat metadata cannot be empty"),
            Self::Unknown => formatter.write_str("unknown threat label"),
        }
    }
}

impl Error for ThreatError {}

macro_rules! text_newtype {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Creates non-empty threat text metadata.
            pub fn new(input: impl AsRef<str>) -> Result<Self, ThreatError> {
                let trimmed = input.as_ref().trim();
                if trimmed.is_empty() {
                    Err(ThreatError::Empty)
                } else {
                    Ok(Self(trimmed.to_owned()))
                }
            }

            /// Returns the stored text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = ThreatError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                Self::new(input)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = ThreatError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }
    };
}

macro_rules! label_enum {
    ($name:ident { $($variant:ident => $label:literal),+ $(,)? }) => {
        impl $name {
            /// Returns the stable label.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $label,)+
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = ThreatError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                let trimmed = input.trim();
                if trimmed.is_empty() {
                    return Err(ThreatError::Empty);
                }
                let normalized = trimmed.to_ascii_lowercase();
                match normalized.as_str() {
                    $($label => Ok(Self::$variant),)+
                    _ => Err(ThreatError::Unknown),
                }
            }
        }
    };
}

text_newtype!(ThreatId);
text_newtype!(ThreatSurface);

/// Threat actor labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ThreatActorKind {
    External,
    Insider,
    ThirdParty,
    Automated,
    NationState,
    Criminal,
    Researcher,
    Unknown,
}

label_enum!(ThreatActorKind {
    External => "external",
    Insider => "insider",
    ThirdParty => "third-party",
    Automated => "automated",
    NationState => "nation-state",
    Criminal => "criminal",
    Researcher => "researcher",
    Unknown => "unknown",
});

/// Threat category labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ThreatCategory {
    Spoofing,
    Tampering,
    Repudiation,
    InformationDisclosure,
    DenialOfService,
    ElevationOfPrivilege,
    SupplyChain,
    SocialEngineering,
    Other,
}

label_enum!(ThreatCategory {
    Spoofing => "spoofing",
    Tampering => "tampering",
    Repudiation => "repudiation",
    InformationDisclosure => "information-disclosure",
    DenialOfService => "denial-of-service",
    ElevationOfPrivilege => "elevation-of-privilege",
    SupplyChain => "supply-chain",
    SocialEngineering => "social-engineering",
    Other => "other",
});

/// Threat capability labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ThreatCapability {
    Low,
    Medium,
    High,
    Advanced,
}

label_enum!(ThreatCapability {
    Low => "low",
    Medium => "medium",
    High => "high",
    Advanced => "advanced",
});

/// Threat intent labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ThreatIntent {
    Curious,
    Opportunistic,
    Targeted,
    Malicious,
    Unknown,
}

label_enum!(ThreatIntent {
    Curious => "curious",
    Opportunistic => "opportunistic",
    Targeted => "targeted",
    Malicious => "malicious",
    Unknown => "unknown",
});

/// Threat model kind labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ThreatModelKind {
    Stride,
    AttackTree,
    KillChain,
    MitreAttackLike,
    Custom,
}

label_enum!(ThreatModelKind {
    Stride => "stride",
    AttackTree => "attack-tree",
    KillChain => "kill-chain",
    MitreAttackLike => "mitre-attack-like",
    Custom => "custom",
});

/// A compact threat scenario metadata record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThreatScenario {
    id: ThreatId,
    category: ThreatCategory,
    actor: ThreatActorKind,
}

impl ThreatScenario {
    /// Creates threat scenario metadata.
    #[must_use]
    pub const fn new(id: ThreatId, category: ThreatCategory, actor: ThreatActorKind) -> Self {
        Self {
            id,
            category,
            actor,
        }
    }

    /// Returns the scenario ID.
    #[must_use]
    pub const fn id(&self) -> &ThreatId {
        &self.id
    }

    /// Returns the threat category.
    #[must_use]
    pub const fn category(&self) -> ThreatCategory {
        self.category
    }

    /// Returns the actor kind.
    #[must_use]
    pub const fn actor(&self) -> ThreatActorKind {
        self.actor
    }
}

#[cfg(test)]
mod tests {
    use super::{ThreatActorKind, ThreatCategory, ThreatId, ThreatModelKind, ThreatScenario};

    #[test]
    fn validates_threat_id() {
        let id = ThreatId::new("T-1").expect("threat id");

        assert_eq!(id.as_str(), "T-1");
        assert!(ThreatId::new(" ").is_err());
    }

    #[test]
    fn parses_and_displays_labels() {
        assert_eq!(
            "spoofing".parse::<ThreatCategory>().expect("category"),
            ThreatCategory::Spoofing
        );
        assert_eq!(ThreatActorKind::ThirdParty.to_string(), "third-party");
        assert_eq!(ThreatModelKind::Stride.to_string(), "stride");
    }

    #[test]
    fn scenario_reports_metadata() {
        let scenario = ThreatScenario::new(
            ThreatId::new("T-1").expect("threat id"),
            ThreatCategory::Spoofing,
            ThreatActorKind::External,
        );

        assert_eq!(scenario.id().as_str(), "T-1");
        assert_eq!(scenario.category(), ThreatCategory::Spoofing);
    }
}
