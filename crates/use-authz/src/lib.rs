#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
#![allow(clippy::module_name_repetitions)]

use core::{fmt, str::FromStr};
use std::error::Error;

/// Error returned when authorization names are invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthzNameError {
    Empty,
    NonAscii,
    InvalidCharacter,
}

impl fmt::Display for AuthzNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("authorization name cannot be empty"),
            Self::NonAscii => formatter.write_str("authorization name must be ASCII"),
            Self::InvalidCharacter => {
                formatter.write_str("authorization name contains an invalid character")
            }
        }
    }
}

impl Error for AuthzNameError {}

/// Error returned when an authorization label cannot be parsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthzParseError {
    Empty,
    Unknown,
}

impl fmt::Display for AuthzParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("authorization label cannot be empty"),
            Self::Unknown => formatter.write_str("unknown authorization label"),
        }
    }
}

impl Error for AuthzParseError {}

macro_rules! ascii_name {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Creates a non-empty ASCII-safe authorization name.
            pub fn new(input: impl AsRef<str>) -> Result<Self, AuthzNameError> {
                let trimmed = input.as_ref().trim();
                validate_name(trimmed)?;
                Ok(Self(trimmed.to_owned()))
            }

            /// Returns the stored name.
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
            type Err = AuthzNameError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                Self::new(input)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = AuthzNameError;

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
            type Err = AuthzParseError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                let trimmed = input.trim();
                if trimmed.is_empty() {
                    return Err(AuthzParseError::Empty);
                }
                let normalized = trimmed.to_ascii_lowercase();
                match normalized.as_str() {
                    $($label => Ok(Self::$variant),)+
                    _ => Err(AuthzParseError::Unknown),
                }
            }
        }
    };
}

ascii_name!(PermissionName);
ascii_name!(RoleName);
ascii_name!(ScopeName);
ascii_name!(ClaimName);
ascii_name!(AccessSubject);
ascii_name!(AccessResource);
ascii_name!(AccessAction);

/// Authorization model labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AuthorizationModel {
    Rbac,
    Abac,
    Rebac,
    Acl,
    Capability,
    PolicyBased,
    Custom,
}

label_enum!(AuthorizationModel {
    Rbac => "rbac",
    Abac => "abac",
    Rebac => "rebac",
    Acl => "acl",
    Capability => "capability",
    PolicyBased => "policy-based",
    Custom => "custom",
});

/// Access decision labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AccessDecision {
    Allow,
    Deny,
    Abstain,
    NotApplicable,
}

label_enum!(AccessDecision {
    Allow => "allow",
    Deny => "deny",
    Abstain => "abstain",
    NotApplicable => "not-applicable",
});

/// Policy effect labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PolicyEffect {
    Allow,
    Deny,
}

label_enum!(PolicyEffect {
    Allow => "allow",
    Deny => "deny",
});

fn validate_name(value: &str) -> Result<(), AuthzNameError> {
    if value.is_empty() {
        return Err(AuthzNameError::Empty);
    }
    if !value.is_ascii() {
        return Err(AuthzNameError::NonAscii);
    }
    if value.bytes().all(is_ascii_safe_name_byte) {
        Ok(())
    } else {
        Err(AuthzNameError::InvalidCharacter)
    }
}

const fn is_ascii_safe_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'*')
}

#[cfg(test)]
mod tests {
    use super::{
        AccessAction, AccessDecision, AuthorizationModel, AuthzNameError, PermissionName,
        PolicyEffect, RoleName,
    };

    #[test]
    fn validates_ascii_safe_names() {
        let permission = PermissionName::new("document:read").expect("permission");

        assert_eq!(permission.as_str(), "document:read");
        assert_eq!(RoleName::new(" "), Err(AuthzNameError::Empty));
        assert_eq!(
            RoleName::new("read write"),
            Err(AuthzNameError::InvalidCharacter)
        );
        assert_eq!(
            AccessAction::new("lire-ecrire-\u{00e9}"),
            Err(AuthzNameError::NonAscii)
        );
    }

    #[test]
    fn parses_and_displays_labels() {
        assert_eq!(
            "rbac".parse::<AuthorizationModel>().expect("model"),
            AuthorizationModel::Rbac
        );
        assert_eq!(AccessDecision::NotApplicable.to_string(), "not-applicable");
        assert_eq!(PolicyEffect::Deny.to_string(), "deny");
    }
}
