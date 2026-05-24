#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
#![allow(clippy::module_name_repetitions)]

use core::{fmt, str::FromStr};
use std::error::Error;

/// Error returned when security risk metadata is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityRiskError {
    Empty,
    Unknown,
}

impl fmt::Display for SecurityRiskError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("security risk metadata cannot be empty"),
            Self::Unknown => formatter.write_str("unknown security risk label"),
        }
    }
}

impl Error for SecurityRiskError {}

macro_rules! text_newtype {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Creates non-empty security risk text metadata.
            pub fn new(input: impl AsRef<str>) -> Result<Self, SecurityRiskError> {
                let trimmed = input.as_ref().trim();
                if trimmed.is_empty() {
                    Err(SecurityRiskError::Empty)
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
            type Err = SecurityRiskError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                Self::new(input)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = SecurityRiskError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }
    };
}

macro_rules! label_enum {
    ($name:ident { $($variant:ident => $label:literal => $rank:expr),+ $(,)? }) => {
        impl $name {
            /// Returns the stable label.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $label,)+
                }
            }

            /// Returns a numeric rank for sorting.
            #[must_use]
            pub const fn sort_key(self) -> u8 {
                match self {
                    $(Self::$variant => $rank,)+
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = SecurityRiskError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                let trimmed = input.trim();
                if trimmed.is_empty() {
                    return Err(SecurityRiskError::Empty);
                }
                let normalized = trimmed.to_ascii_lowercase();
                match normalized.as_str() {
                    $($label => Ok(Self::$variant),)+
                    _ => Err(SecurityRiskError::Unknown),
                }
            }
        }
    };
}

text_newtype!(SecurityRiskId);
text_newtype!(RiskOwner);

/// Security risk metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityRisk {
    id: SecurityRiskId,
    severity: RiskSeverity,
    likelihood: RiskLikelihood,
    impact: RiskImpact,
    status: RiskStatus,
    category: RiskCategory,
}

impl SecurityRisk {
    /// Creates a security risk metadata record.
    #[must_use]
    pub const fn new(
        id: SecurityRiskId,
        severity: RiskSeverity,
        likelihood: RiskLikelihood,
        impact: RiskImpact,
        status: RiskStatus,
        category: RiskCategory,
    ) -> Self {
        Self {
            id,
            severity,
            likelihood,
            impact,
            status,
            category,
        }
    }

    /// Returns the risk identifier.
    #[must_use]
    pub const fn id(&self) -> &SecurityRiskId {
        &self.id
    }

    /// Returns the severity label.
    #[must_use]
    pub const fn severity(&self) -> RiskSeverity {
        self.severity
    }

    /// Returns the likelihood label.
    #[must_use]
    pub const fn likelihood(&self) -> RiskLikelihood {
        self.likelihood
    }

    /// Returns the impact label.
    #[must_use]
    pub const fn impact(&self) -> RiskImpact {
        self.impact
    }

    /// Returns the status label.
    #[must_use]
    pub const fn status(&self) -> RiskStatus {
        self.status
    }

    /// Returns the category label.
    #[must_use]
    pub const fn category(&self) -> RiskCategory {
        self.category
    }

    /// Returns a sortable priority derived from likelihood and impact.
    #[must_use]
    pub const fn priority(&self) -> RiskPriority {
        priority_from_likelihood_impact(self.likelihood, self.impact)
    }
}

/// Risk severity labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RiskSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

label_enum!(RiskSeverity {
    Informational => "informational" => 0,
    Low => "low" => 1,
    Medium => "medium" => 2,
    High => "high" => 3,
    Critical => "critical" => 4,
});

/// Risk likelihood labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RiskLikelihood {
    Rare,
    Unlikely,
    Possible,
    Likely,
    AlmostCertain,
}

label_enum!(RiskLikelihood {
    Rare => "rare" => 1,
    Unlikely => "unlikely" => 2,
    Possible => "possible" => 3,
    Likely => "likely" => 4,
    AlmostCertain => "almost-certain" => 5,
});

/// Risk impact labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RiskImpact {
    Negligible,
    Minor,
    Moderate,
    Major,
    Severe,
}

label_enum!(RiskImpact {
    Negligible => "negligible" => 1,
    Minor => "minor" => 2,
    Moderate => "moderate" => 3,
    Major => "major" => 4,
    Severe => "severe" => 5,
});

/// Sortable risk priority labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RiskPriority {
    P0,
    P1,
    P2,
    P3,
    P4,
}

impl RiskPriority {
    /// Returns a stable priority label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::P0 => "p0",
            Self::P1 => "p1",
            Self::P2 => "p2",
            Self::P3 => "p3",
            Self::P4 => "p4",
        }
    }

    /// Returns a numeric sort key where lower means more urgent.
    #[must_use]
    pub const fn sort_key(self) -> u8 {
        match self {
            Self::P0 => 0,
            Self::P1 => 1,
            Self::P2 => 2,
            Self::P3 => 3,
            Self::P4 => 4,
        }
    }
}

impl fmt::Display for RiskPriority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Risk status labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RiskStatus {
    Open,
    Accepted,
    Mitigated,
    Transferred,
    Avoided,
    Closed,
}

label_enum!(RiskStatus {
    Open => "open" => 0,
    Accepted => "accepted" => 1,
    Mitigated => "mitigated" => 2,
    Transferred => "transferred" => 3,
    Avoided => "avoided" => 4,
    Closed => "closed" => 5,
});

/// Risk treatment labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RiskTreatment {
    Accept,
    Mitigate,
    Transfer,
    Avoid,
}

label_enum!(RiskTreatment {
    Accept => "accept" => 0,
    Mitigate => "mitigate" => 1,
    Transfer => "transfer" => 2,
    Avoid => "avoid" => 3,
});

/// Risk category labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RiskCategory {
    Application,
    Infrastructure,
    Data,
    Identity,
    SupplyChain,
    Operational,
    Compliance,
    Privacy,
    Ai,
    Other,
}

label_enum!(RiskCategory {
    Application => "application" => 0,
    Infrastructure => "infrastructure" => 1,
    Data => "data" => 2,
    Identity => "identity" => 3,
    SupplyChain => "supply-chain" => 4,
    Operational => "operational" => 5,
    Compliance => "compliance" => 6,
    Privacy => "privacy" => 7,
    Ai => "ai" => 8,
    Other => "other" => 9,
});

/// Returns a sortable priority from likelihood and impact.
#[must_use]
pub const fn priority_from_likelihood_impact(
    likelihood: RiskLikelihood,
    impact: RiskImpact,
) -> RiskPriority {
    let score = likelihood.sort_key() * impact.sort_key();
    if score >= 20 {
        RiskPriority::P0
    } else if score >= 16 {
        RiskPriority::P1
    } else if score >= 9 {
        RiskPriority::P2
    } else if score >= 4 {
        RiskPriority::P3
    } else {
        RiskPriority::P4
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RiskCategory, RiskImpact, RiskLikelihood, RiskPriority, RiskSeverity, RiskStatus,
        SecurityRisk, SecurityRiskId, priority_from_likelihood_impact,
    };

    #[test]
    fn validates_risk_id() {
        let id = SecurityRiskId::new("RISK-1").expect("risk id");

        assert_eq!(id.as_str(), "RISK-1");
        assert!(SecurityRiskId::new(" ").is_err());
    }

    #[test]
    fn parses_and_displays_labels() {
        assert_eq!(
            "critical".parse::<RiskSeverity>().expect("severity"),
            RiskSeverity::Critical
        );
        assert_eq!(RiskCategory::SupplyChain.to_string(), "supply-chain");
    }

    #[test]
    fn computes_sortable_priority() {
        assert_eq!(
            priority_from_likelihood_impact(RiskLikelihood::Likely, RiskImpact::Major),
            RiskPriority::P1
        );
        assert!(RiskPriority::P0.sort_key() < RiskPriority::P4.sort_key());
    }

    #[test]
    fn risk_record_reports_priority() {
        let risk = SecurityRisk::new(
            SecurityRiskId::new("R-1").expect("risk id"),
            RiskSeverity::High,
            RiskLikelihood::AlmostCertain,
            RiskImpact::Severe,
            RiskStatus::Open,
            RiskCategory::Application,
        );

        assert_eq!(risk.priority(), RiskPriority::P0);
        assert_eq!(risk.id().as_str(), "R-1");
    }
}
