#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
#![allow(clippy::module_name_repetitions)]

use core::{fmt, str::FromStr};
use std::error::Error;

/// Error returned when finding metadata is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityFindingError {
    Empty,
    Unknown,
}

impl fmt::Display for SecurityFindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("security finding metadata cannot be empty"),
            Self::Unknown => formatter.write_str("unknown security finding label"),
        }
    }
}

impl Error for SecurityFindingError {}

macro_rules! text_newtype {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Creates non-empty security finding text metadata.
            pub fn new(input: impl AsRef<str>) -> Result<Self, SecurityFindingError> {
                let trimmed = input.as_ref().trim();
                if trimmed.is_empty() {
                    Err(SecurityFindingError::Empty)
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
            type Err = SecurityFindingError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                Self::new(input)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = SecurityFindingError;

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
            type Err = SecurityFindingError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                let trimmed = input.trim();
                if trimmed.is_empty() {
                    return Err(SecurityFindingError::Empty);
                }
                let normalized = trimmed.to_ascii_lowercase();
                match normalized.as_str() {
                    $($label => Ok(Self::$variant),)+
                    _ => Err(SecurityFindingError::Unknown),
                }
            }
        }
    };
}

text_newtype!(SecurityFindingId);
text_newtype!(FindingSource);
text_newtype!(FindingLocation);
text_newtype!(FindingEvidence);
text_newtype!(FindingReference);

/// Security finding metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityFinding {
    id: SecurityFindingId,
    kind: FindingKind,
    severity: FindingSeverity,
    status: FindingStatus,
    confidence: FindingConfidence,
    references: Vec<FindingReference>,
}

impl SecurityFinding {
    /// Creates security finding metadata.
    #[must_use]
    pub fn new(id: SecurityFindingId, kind: FindingKind, severity: FindingSeverity) -> Self {
        Self {
            id,
            kind,
            severity,
            status: FindingStatus::New,
            confidence: FindingConfidence::Low,
            references: Vec::new(),
        }
    }

    /// Returns the finding ID.
    #[must_use]
    pub const fn id(&self) -> &SecurityFindingId {
        &self.id
    }

    /// Returns the finding kind.
    #[must_use]
    pub const fn kind(&self) -> FindingKind {
        self.kind
    }

    /// Returns the severity label.
    #[must_use]
    pub const fn severity(&self) -> FindingSeverity {
        self.severity
    }

    /// Returns the status label.
    #[must_use]
    pub const fn status(&self) -> FindingStatus {
        self.status
    }

    /// Returns the confidence label.
    #[must_use]
    pub const fn confidence(&self) -> FindingConfidence {
        self.confidence
    }

    /// Returns lightweight references such as CVE, CWE, CVSS, or OWASP IDs.
    #[must_use]
    pub fn references(&self) -> &[FindingReference] {
        &self.references
    }

    /// Adds a lightweight reference to the finding.
    #[must_use]
    pub fn with_reference(mut self, reference: FindingReference) -> Self {
        self.references.push(reference);
        self
    }

    /// Returns a copy with updated status.
    #[must_use]
    pub const fn with_status(mut self, status: FindingStatus) -> Self {
        self.status = status;
        self
    }

    /// Returns a copy with updated confidence.
    #[must_use]
    pub const fn with_confidence(mut self, confidence: FindingConfidence) -> Self {
        self.confidence = confidence;
        self
    }
}

/// Finding source category labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FindingKind {
    Vulnerability,
    Weakness,
    Misconfiguration,
    Secret,
    Dependency,
    License,
    PolicyViolation,
    Malware,
    SuspiciousPattern,
    Other,
}

label_enum!(FindingKind {
    Vulnerability => "vulnerability",
    Weakness => "weakness",
    Misconfiguration => "misconfiguration",
    Secret => "secret",
    Dependency => "dependency",
    License => "license",
    PolicyViolation => "policy-violation",
    Malware => "malware",
    SuspiciousPattern => "suspicious-pattern",
    Other => "other",
});

/// Finding lifecycle status labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FindingStatus {
    New,
    Triaged,
    Confirmed,
    FalsePositive,
    AcceptedRisk,
    Fixed,
    Reopened,
    Closed,
}

label_enum!(FindingStatus {
    New => "new",
    Triaged => "triaged",
    Confirmed => "confirmed",
    FalsePositive => "false-positive",
    AcceptedRisk => "accepted-risk",
    Fixed => "fixed",
    Reopened => "reopened",
    Closed => "closed",
});

/// Finding confidence labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FindingConfidence {
    Low,
    Medium,
    High,
    Confirmed,
}

label_enum!(FindingConfidence {
    Low => "low",
    Medium => "medium",
    High => "high",
    Confirmed => "confirmed",
});

/// Finding severity labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FindingSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

label_enum!(FindingSeverity {
    Informational => "informational",
    Low => "low",
    Medium => "medium",
    High => "high",
    Critical => "critical",
});

/// Remediation status labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RemediationStatus {
    NotStarted,
    InProgress,
    Blocked,
    Remediated,
    Accepted,
    Deferred,
}

label_enum!(RemediationStatus {
    NotStarted => "not-started",
    InProgress => "in-progress",
    Blocked => "blocked",
    Remediated => "remediated",
    Accepted => "accepted",
    Deferred => "deferred",
});

/// Lightweight finding reference categories.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FindingReferenceKind {
    Cve,
    Cwe,
    Cvss,
    Owasp,
    Url,
    Other,
}

label_enum!(FindingReferenceKind {
    Cve => "cve",
    Cwe => "cwe",
    Cvss => "cvss",
    Owasp => "owasp",
    Url => "url",
    Other => "other",
});

#[cfg(test)]
mod tests {
    use super::{
        FindingConfidence, FindingKind, FindingReference, FindingSeverity, FindingStatus,
        SecurityFinding, SecurityFindingId,
    };

    #[test]
    fn validates_finding_id() {
        let id = SecurityFindingId::new("F-1").expect("finding id");

        assert_eq!(id.as_str(), "F-1");
        assert!(SecurityFindingId::new(" ").is_err());
    }

    #[test]
    fn parses_and_displays_labels() {
        assert_eq!(
            "secret".parse::<FindingKind>().expect("kind"),
            FindingKind::Secret
        );
        assert_eq!(FindingStatus::FalsePositive.to_string(), "false-positive");
    }

    #[test]
    fn finding_record_tracks_reference_metadata() {
        let finding = SecurityFinding::new(
            SecurityFindingId::new("F-1").expect("finding id"),
            FindingKind::Vulnerability,
            FindingSeverity::High,
        )
        .with_status(FindingStatus::Confirmed)
        .with_confidence(FindingConfidence::Confirmed)
        .with_reference(FindingReference::new("CVE-2024-12345").expect("reference"));

        assert_eq!(finding.kind(), FindingKind::Vulnerability);
        assert_eq!(finding.status(), FindingStatus::Confirmed);
        assert_eq!(finding.references()[0].as_str(), "CVE-2024-12345");
    }
}
