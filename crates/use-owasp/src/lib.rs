#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
#![allow(clippy::module_name_repetitions)]

use core::{fmt, str::FromStr};
use std::error::Error;

/// Error returned when an OWASP label cannot be parsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwaspParseError {
    Empty,
    Unknown,
}

impl fmt::Display for OwaspParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("OWASP label cannot be empty"),
            Self::Unknown => formatter.write_str("unknown OWASP label"),
        }
    }
}

impl Error for OwaspParseError {}

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
            type Err = OwaspParseError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                let trimmed = input.trim();
                if trimmed.is_empty() {
                    return Err(OwaspParseError::Empty);
                }
                let normalized = trimmed.to_ascii_lowercase();
                match normalized.as_str() {
                    $($label => Ok(Self::$variant),)+
                    _ => Err(OwaspParseError::Unknown),
                }
            }
        }
    };
}

/// OWASP Top 10 version labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum OwaspTop10Version {
    Top10_2017,
    Top10_2021,
    Top10_2025,
}

label_enum!(OwaspTop10Version {
    Top10_2017 => "top-10-2017",
    Top10_2021 => "top-10-2021",
    Top10_2025 => "top-10-2025",
});

/// OWASP Top 10 style category labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum OwaspTop10Category {
    BrokenAccessControl,
    CryptographicFailures,
    Injection,
    InsecureDesign,
    SecurityMisconfiguration,
    VulnerableAndOutdatedComponents,
    IdentificationAndAuthenticationFailures,
    SoftwareAndDataIntegrityFailures,
    SecurityLoggingAndMonitoringFailures,
    ServerSideRequestForgery,
    Other,
}

label_enum!(OwaspTop10Category {
    BrokenAccessControl => "broken-access-control",
    CryptographicFailures => "cryptographic-failures",
    Injection => "injection",
    InsecureDesign => "insecure-design",
    SecurityMisconfiguration => "security-misconfiguration",
    VulnerableAndOutdatedComponents => "vulnerable-and-outdated-components",
    IdentificationAndAuthenticationFailures => "identification-and-authentication-failures",
    SoftwareAndDataIntegrityFailures => "software-and-data-integrity-failures",
    SecurityLoggingAndMonitoringFailures => "security-logging-and-monitoring-failures",
    ServerSideRequestForgery => "server-side-request-forgery",
    Other => "other",
});

/// Lightweight OWASP risk identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OwaspRiskId(String);

impl OwaspRiskId {
    /// Creates a non-empty OWASP risk ID.
    pub fn new(input: impl AsRef<str>) -> Result<Self, OwaspTextError> {
        let trimmed = input.as_ref().trim();
        if trimmed.is_empty() {
            Err(OwaspTextError::Empty)
        } else {
            Ok(Self(trimmed.to_owned()))
        }
    }

    /// Returns the stored risk ID.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OwaspRiskId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Error returned when OWASP text metadata is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwaspTextError {
    Empty,
}

impl fmt::Display for OwaspTextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OWASP metadata text cannot be empty")
    }
}

impl Error for OwaspTextError {}

/// OWASP project labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum OwaspProjectKind {
    Top10,
    Asvs,
    Masvs,
    CheatSheet,
    DependencyTrack,
    Zap,
}

label_enum!(OwaspProjectKind {
    Top10 => "top-10",
    Asvs => "asvs",
    Masvs => "masvs",
    CheatSheet => "cheat-sheet",
    DependencyTrack => "dependency-track",
    Zap => "zap",
});

/// Application security control-area labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum OwaspControlArea {
    AccessControl,
    Authentication,
    Cryptography,
    InputValidation,
    LoggingAndMonitoring,
    SecureConfiguration,
    SupplyChain,
    Other,
}

label_enum!(OwaspControlArea {
    AccessControl => "access-control",
    Authentication => "authentication",
    Cryptography => "cryptography",
    InputValidation => "input-validation",
    LoggingAndMonitoring => "logging-and-monitoring",
    SecureConfiguration => "secure-configuration",
    SupplyChain => "supply-chain",
    Other => "other",
});

#[cfg(test)]
mod tests {
    use super::{OwaspProjectKind, OwaspRiskId, OwaspTop10Category, OwaspTop10Version};

    #[test]
    fn parses_and_displays_top_10_category() {
        assert_eq!(
            "broken-access-control"
                .parse::<OwaspTop10Category>()
                .expect("category"),
            OwaspTop10Category::BrokenAccessControl
        );
        assert_eq!(
            OwaspTop10Category::ServerSideRequestForgery.to_string(),
            "server-side-request-forgery"
        );
    }

    #[test]
    fn exposes_version_and_project_labels() {
        assert_eq!(OwaspTop10Version::Top10_2021.to_string(), "top-10-2021");
        assert_eq!(OwaspProjectKind::CheatSheet.to_string(), "cheat-sheet");
    }

    #[test]
    fn validates_risk_id() {
        let id = OwaspRiskId::new("A01:2021").expect("risk id");

        assert_eq!(id.as_str(), "A01:2021");
        assert!(OwaspRiskId::new(" ").is_err());
    }
}
