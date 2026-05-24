#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
#![allow(clippy::module_name_repetitions)]

use core::{fmt, str::FromStr};
use std::error::Error;

/// Error returned when a CVSS score is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CvssScoreError {
    NonFinite,
    OutOfRange,
}

impl fmt::Display for CvssScoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonFinite => formatter.write_str("CVSS score must be finite"),
            Self::OutOfRange => formatter.write_str("CVSS score must be between 0.0 and 10.0"),
        }
    }
}

impl Error for CvssScoreError {}

/// Error returned when CVSS text metadata is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CvssTextError {
    Empty,
}

impl fmt::Display for CvssTextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CVSS metadata text cannot be empty")
    }
}

impl Error for CvssTextError {}

/// Error returned when a CVSS label cannot be parsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CvssParseError {
    Empty,
    Unknown,
}

impl fmt::Display for CvssParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("CVSS label cannot be empty"),
            Self::Unknown => formatter.write_str("unknown CVSS label"),
        }
    }
}

impl Error for CvssParseError {}

/// CVSS version labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CvssVersion {
    V2,
    V3_0,
    V3_1,
    V4_0,
}

/// CVSS severity labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CvssSeverity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// CVSS attack-vector labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CvssAttackVector {
    Network,
    Adjacent,
    Local,
    Physical,
}

/// CVSS attack-complexity labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CvssAttackComplexity {
    Low,
    High,
}

/// CVSS privileges-required labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CvssPrivilegesRequired {
    None,
    Low,
    High,
}

/// CVSS user-interaction labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CvssUserInteraction {
    None,
    Required,
}

/// CVSS scope labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CvssScope {
    Unchanged,
    Changed,
}

/// CVSS impact-level labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CvssImpactLevel {
    None,
    Low,
    High,
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
            type Err = CvssParseError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                let trimmed = input.trim();
                if trimmed.is_empty() {
                    return Err(CvssParseError::Empty);
                }
                let normalized = trimmed.to_ascii_lowercase();
                match normalized.as_str() {
                    $($label => Ok(Self::$variant),)+
                    _ => Err(CvssParseError::Unknown),
                }
            }
        }
    };
}

label_enum!(CvssVersion {
    V2 => "2.0",
    V3_0 => "3.0",
    V3_1 => "3.1",
    V4_0 => "4.0",
});

label_enum!(CvssSeverity {
    None => "none",
    Low => "low",
    Medium => "medium",
    High => "high",
    Critical => "critical",
});

label_enum!(CvssAttackVector {
    Network => "network",
    Adjacent => "adjacent",
    Local => "local",
    Physical => "physical",
});

label_enum!(CvssAttackComplexity {
    Low => "low",
    High => "high",
});

label_enum!(CvssPrivilegesRequired {
    None => "none",
    Low => "low",
    High => "high",
});

label_enum!(CvssUserInteraction {
    None => "none",
    Required => "required",
});

label_enum!(CvssScope {
    Unchanged => "unchanged",
    Changed => "changed",
});

label_enum!(CvssImpactLevel {
    None => "none",
    Low => "low",
    High => "high",
});

/// A validated CVSS base score.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct CvssScore(f32);

impl CvssScore {
    /// Creates a score in the inclusive `0.0..=10.0` range.
    pub fn new(value: f32) -> Result<Self, CvssScoreError> {
        if !value.is_finite() {
            return Err(CvssScoreError::NonFinite);
        }
        if !(0.0..=10.0).contains(&value) {
            return Err(CvssScoreError::OutOfRange);
        }
        Ok(Self(value))
    }

    /// Returns the stored score.
    #[must_use]
    pub const fn value(self) -> f32 {
        self.0
    }
}

impl fmt::Display for CvssScore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:.1}", self.0)
    }
}

/// Returns the CVSS severity bucket for a validated score.
#[must_use]
pub fn severity_from_score(score: CvssScore) -> CvssSeverity {
    let value = score.value();
    if value == 0.0 {
        CvssSeverity::None
    } else if value < 4.0 {
        CvssSeverity::Low
    } else if value < 7.0 {
        CvssSeverity::Medium
    } else if value < 9.0 {
        CvssSeverity::High
    } else {
        CvssSeverity::Critical
    }
}

macro_rules! text_newtype {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Creates non-empty CVSS text metadata.
            pub fn new(input: impl AsRef<str>) -> Result<Self, CvssTextError> {
                let trimmed = input.as_ref().trim();
                if trimmed.is_empty() {
                    Err(CvssTextError::Empty)
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
            type Err = CvssTextError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                Self::new(input)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = CvssTextError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }
    };
}

text_newtype!(CvssVector);
text_newtype!(CvssMetricName);
text_newtype!(CvssMetricValue);

#[cfg(test)]
mod tests {
    use super::{
        severity_from_score, CvssAttackVector, CvssScore, CvssScoreError, CvssSeverity, CvssVector,
    };

    #[test]
    fn validates_score_range() {
        assert_eq!(CvssScore::new(0.0).expect("score").value(), 0.0);
        assert_eq!(CvssScore::new(10.0).expect("score").value(), 10.0);
        assert_eq!(CvssScore::new(-0.1), Err(CvssScoreError::OutOfRange));
        assert_eq!(CvssScore::new(10.1), Err(CvssScoreError::OutOfRange));
        assert_eq!(CvssScore::new(f32::NAN), Err(CvssScoreError::NonFinite));
    }

    #[test]
    fn maps_severity_from_score() {
        assert_eq!(
            severity_from_score(CvssScore::new(0.0).expect("score")),
            CvssSeverity::None
        );
        assert_eq!(
            severity_from_score(CvssScore::new(3.9).expect("score")),
            CvssSeverity::Low
        );
        assert_eq!(
            severity_from_score(CvssScore::new(6.9).expect("score")),
            CvssSeverity::Medium
        );
        assert_eq!(
            severity_from_score(CvssScore::new(8.9).expect("score")),
            CvssSeverity::High
        );
        assert_eq!(
            severity_from_score(CvssScore::new(9.0).expect("score")),
            CvssSeverity::Critical
        );
    }

    #[test]
    fn validates_vector_text() {
        let vector = CvssVector::new("CVSS:3.1/AV:N/AC:L").expect("vector");

        assert_eq!(vector.as_str(), "CVSS:3.1/AV:N/AC:L");
        assert!(CvssVector::new(" ").is_err());
    }

    #[test]
    fn parses_and_displays_labels() {
        assert_eq!(
            "network".parse::<CvssAttackVector>().expect("label"),
            CvssAttackVector::Network
        );
        assert_eq!(CvssSeverity::Critical.to_string(), "critical");
    }
}
