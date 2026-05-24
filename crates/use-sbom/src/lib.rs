#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
#![allow(clippy::module_name_repetitions)]

use core::{fmt, str::FromStr};
use std::error::Error;

/// Error returned when SBOM text metadata is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SbomTextError {
    Empty,
    ContainsWhitespace,
    InvalidPackageUrl,
}

impl fmt::Display for SbomTextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("SBOM metadata text cannot be empty"),
            Self::ContainsWhitespace => {
                formatter.write_str("SBOM metadata text cannot contain whitespace")
            }
            Self::InvalidPackageUrl => formatter.write_str("SBOM package URL must start with pkg:"),
        }
    }
}

impl Error for SbomTextError {}

/// Error returned when an SBOM label cannot be parsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SbomParseError {
    Empty,
    Unknown,
}

impl fmt::Display for SbomParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("SBOM label cannot be empty"),
            Self::Unknown => formatter.write_str("unknown SBOM label"),
        }
    }
}

impl Error for SbomParseError {}

macro_rules! text_newtype {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Creates non-empty SBOM text metadata.
            pub fn new(input: impl AsRef<str>) -> Result<Self, SbomTextError> {
                let trimmed = input.as_ref().trim();
                if trimmed.is_empty() {
                    Err(SbomTextError::Empty)
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
            type Err = SbomTextError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                Self::new(input)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = SbomTextError;

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
            type Err = SbomParseError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                let trimmed = input.trim();
                if trimmed.is_empty() {
                    return Err(SbomParseError::Empty);
                }
                let normalized = trimmed.to_ascii_lowercase();
                match normalized.as_str() {
                    $($label => Ok(Self::$variant),)+
                    _ => Err(SbomParseError::Unknown),
                }
            }
        }
    };
}

text_newtype!(SbomComponentName);
text_newtype!(SbomComponentVersion);
text_newtype!(SbomDigest);
text_newtype!(SbomLicenseExpression);

/// A package URL metadata value.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SbomPackageUrl(String);

impl SbomPackageUrl {
    /// Creates a package URL metadata value that starts with `pkg:`.
    pub fn new(input: impl AsRef<str>) -> Result<Self, SbomTextError> {
        let trimmed = input.as_ref().trim();
        if trimmed.is_empty() {
            return Err(SbomTextError::Empty);
        }
        if trimmed.chars().any(char::is_whitespace) {
            return Err(SbomTextError::ContainsWhitespace);
        }
        if !trimmed.starts_with("pkg:") {
            return Err(SbomTextError::InvalidPackageUrl);
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// Returns the package URL metadata.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SbomPackageUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for SbomPackageUrl {
    type Err = SbomTextError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::new(input)
    }
}

impl TryFrom<&str> for SbomPackageUrl {
    type Error = SbomTextError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// SBOM format labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SbomFormat {
    CycloneDx,
    Spdx,
    Custom,
}

label_enum!(SbomFormat {
    CycloneDx => "cyclonedx",
    Spdx => "spdx",
    Custom => "custom",
});

/// SBOM component metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SbomComponent {
    name: SbomComponentName,
    version: SbomComponentVersion,
}

impl SbomComponent {
    /// Creates SBOM component metadata.
    #[must_use]
    pub const fn new(name: SbomComponentName, version: SbomComponentVersion) -> Self {
        Self { name, version }
    }

    /// Returns the component name.
    #[must_use]
    pub const fn name(&self) -> &SbomComponentName {
        &self.name
    }

    /// Returns the component version.
    #[must_use]
    pub const fn version(&self) -> &SbomComponentVersion {
        &self.version
    }
}

/// SBOM relationship labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SbomRelationshipKind {
    Contains,
    DependsOn,
    DependencyOf,
    Describes,
    GeneratedFrom,
    DistributedWith,
    Unknown,
}

label_enum!(SbomRelationshipKind {
    Contains => "contains",
    DependsOn => "depends-on",
    DependencyOf => "dependency-of",
    Describes => "describes",
    GeneratedFrom => "generated-from",
    DistributedWith => "distributed-with",
    Unknown => "unknown",
});

/// Supply-chain risk labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SupplyChainRiskKind {
    VulnerableDependency,
    OutdatedDependency,
    MaliciousPackage,
    Typosquatting,
    DependencyConfusion,
    UnpinnedDependency,
    UnknownProvenance,
    Other,
}

label_enum!(SupplyChainRiskKind {
    VulnerableDependency => "vulnerable-dependency",
    OutdatedDependency => "outdated-dependency",
    MaliciousPackage => "malicious-package",
    Typosquatting => "typosquatting",
    DependencyConfusion => "dependency-confusion",
    UnpinnedDependency => "unpinned-dependency",
    UnknownProvenance => "unknown-provenance",
    Other => "other",
});

#[cfg(test)]
mod tests {
    use super::{
        SbomComponent, SbomComponentName, SbomComponentVersion, SbomFormat, SbomPackageUrl,
        SbomTextError, SupplyChainRiskKind,
    };

    #[test]
    fn validates_component_text() {
        let component = SbomComponent::new(
            SbomComponentName::new("example").expect("name"),
            SbomComponentVersion::new("1.0.0").expect("version"),
        );

        assert_eq!(component.name().as_str(), "example");
        assert!(SbomComponentName::new(" ").is_err());
    }

    #[test]
    fn validates_package_url() {
        let package_url = SbomPackageUrl::new("pkg:cargo/use-sbom@0.0.1").expect("purl");

        assert_eq!(package_url.as_str(), "pkg:cargo/use-sbom@0.0.1");
        assert_eq!(
            SbomPackageUrl::new("cargo/use-sbom"),
            Err(SbomTextError::InvalidPackageUrl)
        );
    }

    #[test]
    fn parses_and_displays_labels() {
        assert_eq!(
            "spdx".parse::<SbomFormat>().expect("format"),
            SbomFormat::Spdx
        );
        assert_eq!(
            SupplyChainRiskKind::DependencyConfusion.to_string(),
            "dependency-confusion"
        );
    }
}
