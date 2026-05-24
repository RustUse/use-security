#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
#![allow(clippy::module_name_repetitions)]

use core::{fmt, str::FromStr};
use std::error::Error;

/// Error returned when a CWE identifier is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CweIdError {
    Empty,
    InvalidPrefix,
    InvalidFormat,
    InvalidNumber,
}

impl fmt::Display for CweIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("CWE identifier cannot be empty"),
            Self::InvalidPrefix => {
                formatter.write_str("CWE identifier must start with uppercase CWE")
            }
            Self::InvalidFormat => formatter.write_str("CWE identifier must match CWE-N"),
            Self::InvalidNumber => formatter.write_str("CWE number must be ASCII digits"),
        }
    }
}

impl Error for CweIdError {}

/// Error returned when a CWE label cannot be parsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CweParseError {
    Empty,
    Unknown,
}

impl fmt::Display for CweParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("CWE label cannot be empty"),
            Self::Unknown => formatter.write_str("unknown CWE label"),
        }
    }
}

impl Error for CweParseError {}

/// Numeric CWE identifier component.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CweNumber(u32);

impl CweNumber {
    /// Creates a non-zero CWE number.
    pub const fn new(value: u32) -> Result<Self, CweIdError> {
        if value == 0 {
            Err(CweIdError::InvalidNumber)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the numeric CWE value.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

impl fmt::Display for CweNumber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl FromStr for CweNumber {
    type Err = CweIdError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_number(input)
    }
}

/// A validated CWE identifier such as `CWE-79`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CweId {
    number: CweNumber,
}

impl CweId {
    /// Creates a CWE identifier from a numeric component.
    #[must_use]
    pub const fn from_number(number: CweNumber) -> Self {
        Self { number }
    }

    /// Creates a validated CWE identifier.
    pub fn new(input: impl AsRef<str>) -> Result<Self, CweIdError> {
        let trimmed = input.as_ref().trim();
        if trimmed.is_empty() {
            return Err(CweIdError::Empty);
        }
        let (prefix, number) = trimmed.split_once('-').ok_or(CweIdError::InvalidFormat)?;
        if prefix != "CWE" {
            return Err(CweIdError::InvalidPrefix);
        }
        Ok(Self {
            number: parse_number(number)?,
        })
    }

    /// Returns the numeric CWE component.
    #[must_use]
    pub const fn number(self) -> CweNumber {
        self.number
    }

    /// Returns an owned CWE identifier string.
    #[must_use]
    pub fn as_str(&self) -> String {
        format!("CWE-{}", self.number.value())
    }
}

impl fmt::Display for CweId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "CWE-{}", self.number.value())
    }
}

impl FromStr for CweId {
    type Err = CweIdError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::new(input)
    }
}

impl TryFrom<&str> for CweId {
    type Error = CweIdError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

pub const CWE_79_XSS: CweId = CweId::from_number(CweNumber(79));
pub const CWE_89_SQL_INJECTION: CweId = CweId::from_number(CweNumber(89));
pub const CWE_352_CSRF: CweId = CweId::from_number(CweNumber(352));
pub const CWE_862_MISSING_AUTHORIZATION: CweId = CweId::from_number(CweNumber(862));
pub const CWE_287_IMPROPER_AUTHENTICATION: CweId = CweId::from_number(CweNumber(287));
pub const CWE_22_PATH_TRAVERSAL: CweId = CweId::from_number(CweNumber(22));
pub const CWE_78_OS_COMMAND_INJECTION: CweId = CweId::from_number(CweNumber(78));
pub const CWE_94_CODE_INJECTION: CweId = CweId::from_number(CweNumber(94));
pub const CWE_200_SENSITIVE_INFORMATION_EXPOSURE: CweId = CweId::from_number(CweNumber(200));
pub const CWE_918_SSRF: CweId = CweId::from_number(CweNumber(918));

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
            type Err = CweParseError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                let trimmed = input.trim();
                if trimmed.is_empty() {
                    return Err(CweParseError::Empty);
                }
                let normalized = trimmed.to_ascii_lowercase();
                match normalized.as_str() {
                    $($label => Ok(Self::$variant),)+
                    _ => Err(CweParseError::Unknown),
                }
            }
        }
    };
}

/// CWE weakness category labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CweWeaknessKind {
    Injection,
    CrossSiteScripting,
    CrossSiteRequestForgery,
    MissingAuthorization,
    MissingAuthentication,
    PathTraversal,
    CommandInjection,
    CodeInjection,
    BufferOverflow,
    OutOfBoundsRead,
    OutOfBoundsWrite,
    UseAfterFree,
    SensitiveInformationExposure,
    Ssrf,
    ResourceExhaustion,
    Other,
}

label_enum!(CweWeaknessKind {
    Injection => "injection",
    CrossSiteScripting => "cross-site-scripting",
    CrossSiteRequestForgery => "cross-site-request-forgery",
    MissingAuthorization => "missing-authorization",
    MissingAuthentication => "missing-authentication",
    PathTraversal => "path-traversal",
    CommandInjection => "command-injection",
    CodeInjection => "code-injection",
    BufferOverflow => "buffer-overflow",
    OutOfBoundsRead => "out-of-bounds-read",
    OutOfBoundsWrite => "out-of-bounds-write",
    UseAfterFree => "use-after-free",
    SensitiveInformationExposure => "sensitive-information-exposure",
    Ssrf => "ssrf",
    ResourceExhaustion => "resource-exhaustion",
    Other => "other",
});

/// CWE impact category labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CweImpactKind {
    Confidentiality,
    Integrity,
    Availability,
    AccessControl,
    Accountability,
    Other,
}

label_enum!(CweImpactKind {
    Confidentiality => "confidentiality",
    Integrity => "integrity",
    Availability => "availability",
    AccessControl => "access-control",
    Accountability => "accountability",
    Other => "other",
});

/// CWE likelihood labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CweLikelihood {
    Low,
    Medium,
    High,
    Unknown,
}

label_enum!(CweLikelihood {
    Low => "low",
    Medium => "medium",
    High => "high",
    Unknown => "unknown",
});

/// CWE taxonomy source labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CweTaxonomySource {
    Cwe,
    Owasp,
    Nist,
    Custom,
}

label_enum!(CweTaxonomySource {
    Cwe => "cwe",
    Owasp => "owasp",
    Nist => "nist",
    Custom => "custom",
});

fn parse_number(input: &str) -> Result<CweNumber, CweIdError> {
    if input.is_empty() || !input.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CweIdError::InvalidNumber);
    }
    let value = input
        .parse::<u32>()
        .map_err(|_error| CweIdError::InvalidNumber)?;
    CweNumber::new(value)
}

#[cfg(test)]
mod tests {
    use super::{
        CweId, CweIdError, CweWeaknessKind, CWE_352_CSRF, CWE_79_XSS, CWE_89_SQL_INJECTION,
    };

    #[test]
    fn parses_valid_cwe_id() {
        let id: CweId = "CWE-79".parse().expect("valid CWE should parse");

        assert_eq!(id, CWE_79_XSS);
        assert_eq!(id.number().value(), 79);
        assert_eq!(id.to_string(), "CWE-79");
    }

    #[test]
    fn rejects_invalid_cwe_ids() {
        assert_eq!(CweId::new(""), Err(CweIdError::Empty));
        assert_eq!(CweId::new("cwe-79"), Err(CweIdError::InvalidPrefix));
        assert_eq!(CweId::new("CWE"), Err(CweIdError::InvalidFormat));
        assert_eq!(CweId::new("CWE-"), Err(CweIdError::InvalidNumber));
        assert_eq!(CweId::new("CWE-7A"), Err(CweIdError::InvalidNumber));
    }

    #[test]
    fn exposes_common_constants() {
        assert_eq!(CWE_89_SQL_INJECTION.to_string(), "CWE-89");
        assert_eq!(CWE_352_CSRF.to_string(), "CWE-352");
    }

    #[test]
    fn parses_and_displays_weakness_kind() {
        assert_eq!(
            "cross-site-scripting"
                .parse::<CweWeaknessKind>()
                .expect("weakness"),
            CweWeaknessKind::CrossSiteScripting
        );
        assert_eq!(CweWeaknessKind::Ssrf.to_string(), "ssrf");
    }
}
