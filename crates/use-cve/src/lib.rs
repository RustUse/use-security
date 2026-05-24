#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
#![allow(clippy::module_name_repetitions)]

use core::{fmt, str::FromStr};
use std::error::Error;

/// Error returned when a CVE identifier is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CveIdError {
    /// The identifier is empty after trimming.
    Empty,
    /// The identifier does not start with uppercase `CVE`.
    InvalidPrefix,
    /// The identifier does not have the expected `CVE-YYYY-NNNN` shape.
    InvalidFormat,
    /// The year is not exactly four ASCII digits.
    InvalidYear,
    /// The sequence is not at least four ASCII digits.
    InvalidSequence,
}

impl fmt::Display for CveIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("CVE identifier cannot be empty"),
            Self::InvalidPrefix => {
                formatter.write_str("CVE identifier must start with uppercase CVE")
            }
            Self::InvalidFormat => formatter.write_str("CVE identifier must match CVE-YYYY-NNNN"),
            Self::InvalidYear => formatter.write_str("CVE year must be exactly four digits"),
            Self::InvalidSequence => {
                formatter.write_str("CVE sequence must be at least four digits")
            }
        }
    }
}

impl Error for CveIdError {}

/// A four-digit CVE year.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CveYear(u16);

impl CveYear {
    /// Creates a CVE year from a four-digit year value.
    pub fn new(value: u16) -> Result<Self, CveIdError> {
        if (1000..=9999).contains(&value) {
            Ok(Self(value))
        } else {
            Err(CveIdError::InvalidYear)
        }
    }

    /// Returns the numeric year.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }
}

impl fmt::Display for CveYear {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:04}", self.0)
    }
}

impl FromStr for CveYear {
    type Err = CveIdError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_year(input)
    }
}

/// A CVE sequence component with at least four digits.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CveSequence(String);

impl CveSequence {
    /// Creates a CVE sequence from ASCII digits.
    pub fn new(input: impl AsRef<str>) -> Result<Self, CveIdError> {
        let trimmed = input.as_ref().trim();
        if trimmed.len() < 4 || !trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(CveIdError::InvalidSequence);
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// Returns the stored sequence.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CveSequence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for CveSequence {
    type Err = CveIdError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::new(input)
    }
}

/// A validated CVE identifier such as `CVE-2024-12345`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CveId {
    value: String,
    year: CveYear,
    sequence: CveSequence,
}

impl CveId {
    /// Creates a validated CVE identifier.
    pub fn new(input: impl AsRef<str>) -> Result<Self, CveIdError> {
        let trimmed = input.as_ref().trim();
        if trimmed.is_empty() {
            return Err(CveIdError::Empty);
        }
        let mut parts = trimmed.split('-');
        let prefix = parts.next().ok_or(CveIdError::InvalidFormat)?;
        let year = parts.next().ok_or(CveIdError::InvalidFormat)?;
        let sequence = parts.next().ok_or(CveIdError::InvalidFormat)?;
        if parts.next().is_some() {
            return Err(CveIdError::InvalidFormat);
        }
        if prefix != "CVE" {
            return Err(CveIdError::InvalidPrefix);
        }
        let year = parse_year(year)?;
        let sequence = CveSequence::new(sequence)?;
        Ok(Self {
            value: trimmed.to_owned(),
            year,
            sequence,
        })
    }

    /// Returns the canonical identifier string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Returns the parsed CVE year.
    #[must_use]
    pub const fn year(&self) -> CveYear {
        self.year
    }

    /// Returns the parsed CVE sequence.
    #[must_use]
    pub const fn sequence(&self) -> &CveSequence {
        &self.sequence
    }
}

impl fmt::Display for CveId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for CveId {
    type Err = CveIdError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::new(input)
    }
}

impl TryFrom<&str> for CveId {
    type Error = CveIdError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// CVE publication status metadata.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CveStatus {
    Reserved,
    Published,
    Rejected,
    Disputed,
    Unknown,
}

impl CveStatus {
    /// Returns the stable status label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Published => "published",
            Self::Rejected => "rejected",
            Self::Disputed => "disputed",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for CveStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A lightweight CVE reference URL or label.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CveReference(String);

impl CveReference {
    /// Creates a non-empty CVE reference label.
    pub fn new(input: impl AsRef<str>) -> Result<Self, CveTextError> {
        non_empty(input.as_ref()).map(Self)
    }

    /// Returns the stored reference label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CveReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A lightweight source label for CVE metadata.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CveSource(String);

impl CveSource {
    /// Creates a non-empty CVE source label.
    pub fn new(input: impl AsRef<str>) -> Result<Self, CveTextError> {
        non_empty(input.as_ref()).map(Self)
    }

    /// Returns the stored source label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CveSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// CVE record kind metadata.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CveRecordKind {
    Vulnerability,
    Rejection,
    Advisory,
    Reference,
}

impl CveRecordKind {
    /// Returns the stable record-kind label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Vulnerability => "vulnerability",
            Self::Rejection => "rejection",
            Self::Advisory => "advisory",
            Self::Reference => "reference",
        }
    }
}

impl fmt::Display for CveRecordKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Error returned when CVE text metadata is empty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CveTextError {
    Empty,
}

impl fmt::Display for CveTextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CVE metadata text cannot be empty")
    }
}

impl Error for CveTextError {}

fn parse_year(input: &str) -> Result<CveYear, CveIdError> {
    if input.len() != 4 || !input.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CveIdError::InvalidYear);
    }
    let value = input
        .parse::<u16>()
        .map_err(|_error| CveIdError::InvalidYear)?;
    CveYear::new(value)
}

fn non_empty(input: &str) -> Result<String, CveTextError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        Err(CveTextError::Empty)
    } else {
        Ok(trimmed.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::{CveId, CveIdError, CveRecordKind, CveSequence, CveStatus, CveYear};

    #[test]
    fn parses_valid_cve_id() {
        let id: CveId = "CVE-2024-12345".parse().expect("valid CVE should parse");

        assert_eq!(id.as_str(), "CVE-2024-12345");
        assert_eq!(id.year().value(), 2024);
        assert_eq!(id.sequence().as_str(), "12345");
        assert_eq!(id.to_string(), "CVE-2024-12345");
    }

    #[test]
    fn rejects_invalid_cve_ids() {
        assert_eq!(CveId::new(""), Err(CveIdError::Empty));
        assert_eq!(CveId::new("cve-2024-1234"), Err(CveIdError::InvalidPrefix));
        assert_eq!(CveId::new("CVE-24-1234"), Err(CveIdError::InvalidYear));
        assert_eq!(CveId::new("CVE-2024-123"), Err(CveIdError::InvalidSequence));
        assert_eq!(
            CveId::new("CVE-2024-12A4"),
            Err(CveIdError::InvalidSequence)
        );
    }

    #[test]
    fn parses_components() {
        assert_eq!(CveYear::new(2024).expect("year").to_string(), "2024");
        assert_eq!(CveSequence::new("0001").expect("sequence").as_str(), "0001");
    }

    #[test]
    fn displays_status_and_record_kind() {
        assert_eq!(CveStatus::Published.to_string(), "published");
        assert_eq!(CveRecordKind::Vulnerability.to_string(), "vulnerability");
    }
}
