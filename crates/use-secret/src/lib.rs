#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
#![allow(clippy::module_name_repetitions)]

use core::{fmt, str::FromStr};
use std::error::Error;

/// Error returned when secret text metadata is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretTextError {
    Empty,
}

impl fmt::Display for SecretTextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("secret metadata text cannot be empty")
    }
}

impl Error for SecretTextError {}

/// Error returned when a secret label cannot be parsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretParseError {
    Empty,
    Unknown,
}

impl fmt::Display for SecretParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("secret label cannot be empty"),
            Self::Unknown => formatter.write_str("unknown secret label"),
        }
    }
}

impl Error for SecretParseError {}

macro_rules! text_newtype {
    ($name:ident, $redacted_debug:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Creates non-empty secret text metadata.
            pub fn new(input: impl AsRef<str>) -> Result<Self, SecretTextError> {
                let trimmed = input.as_ref().trim();
                if trimmed.is_empty() {
                    Err(SecretTextError::Empty)
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

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                if $redacted_debug {
                    formatter.write_str(concat!(stringify!($name), "(\"<redacted>\")"))
                } else {
                    formatter
                        .debug_tuple(stringify!($name))
                        .field(&self.0)
                        .finish()
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = SecretTextError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                Self::new(input)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = SecretTextError;

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
            type Err = SecretParseError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                let trimmed = input.trim();
                if trimmed.is_empty() {
                    return Err(SecretParseError::Empty);
                }
                let normalized = trimmed.to_ascii_lowercase();
                match normalized.as_str() {
                    $($label => Ok(Self::$variant),)+
                    _ => Err(SecretParseError::Unknown),
                }
            }
        }
    };
}

text_newtype!(SecretName, false);
text_newtype!(SecretReference, true);

/// Secret kind labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SecretKind {
    ApiKey,
    AccessToken,
    RefreshToken,
    Password,
    ClientSecret,
    PrivateKey,
    Certificate,
    WebhookSecret,
    SigningSecret,
    DatabaseUrl,
    ConnectionString,
    SshKey,
    Unknown,
}

label_enum!(SecretKind {
    ApiKey => "api-key",
    AccessToken => "access-token",
    RefreshToken => "refresh-token",
    Password => "password",
    ClientSecret => "client-secret",
    PrivateKey => "private-key",
    Certificate => "certificate",
    WebhookSecret => "webhook-secret",
    SigningSecret => "signing-secret",
    DatabaseUrl => "database-url",
    ConnectionString => "connection-string",
    SshKey => "ssh-key",
    Unknown => "unknown",
});

/// Secret provider labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SecretProvider {
    Environment,
    File,
    Vault,
    CloudSecretManager,
    KubernetesSecret,
    CiSecretStore,
    LocalConfig,
    Unknown,
}

label_enum!(SecretProvider {
    Environment => "environment",
    File => "file",
    Vault => "vault",
    CloudSecretManager => "cloud-secret-manager",
    KubernetesSecret => "kubernetes-secret",
    CiSecretStore => "ci-secret-store",
    LocalConfig => "local-config",
    Unknown => "unknown",
});

/// Secret scope labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SecretScope {
    Local,
    Project,
    Organization,
    Environment,
    Global,
}

label_enum!(SecretScope {
    Local => "local",
    Project => "project",
    Organization => "organization",
    Environment => "environment",
    Global => "global",
});

/// Secret sensitivity labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SecretSensitivity {
    Low,
    Medium,
    High,
    Critical,
}

label_enum!(SecretSensitivity {
    Low => "low",
    Medium => "medium",
    High => "high",
    Critical => "critical",
});

/// Secret rotation status labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SecretRotationStatus {
    Unknown,
    Current,
    RotationDue,
    Rotating,
    Revoked,
    Expired,
}

label_enum!(SecretRotationStatus {
    Unknown => "unknown",
    Current => "current",
    RotationDue => "rotation-due",
    Rotating => "rotating",
    Revoked => "revoked",
    Expired => "expired",
});

/// Secret redaction strategy labels.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecretRedaction {
    All,
    KeepLast(usize),
    KeepPrefixSuffix { prefix: usize, suffix: usize },
}

impl SecretRedaction {
    /// Applies this redaction strategy to a value.
    #[must_use]
    pub fn apply(self, value: &str) -> String {
        match self {
            Self::All => mask_all(value),
            Self::KeepLast(count) => mask_keep_last(value, count),
            Self::KeepPrefixSuffix { prefix, suffix } => {
                mask_keep_prefix_suffix(value, prefix, suffix)
            }
        }
    }
}

/// A wrapper that never exposes its value through `Debug` or `Display`.
#[derive(Clone, Eq, PartialEq)]
pub struct MaskedSecret(String);

impl MaskedSecret {
    /// Stores a secret value for explicit masking workflows.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the wrapped secret value by reference.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Returns a fully masked representation.
    #[must_use]
    pub fn redacted(&self) -> String {
        mask_all(&self.0)
    }
}

impl fmt::Debug for MaskedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MaskedSecret(\"<redacted>\")")
    }
}

impl fmt::Display for MaskedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// Masks every character in a value.
#[must_use]
pub fn mask_all(value: &str) -> String {
    "*".repeat(value.chars().count())
}

/// Masks all but the last `count` characters in a value.
#[must_use]
pub fn mask_keep_last(value: &str, count: usize) -> String {
    let chars: Vec<char> = value.chars().collect();
    if count >= chars.len() {
        return value.to_owned();
    }
    let masked = "*".repeat(chars.len() - count);
    let suffix: String = chars[chars.len() - count..].iter().collect();
    format!("{masked}{suffix}")
}

/// Masks the middle while keeping a prefix and suffix.
#[must_use]
pub fn mask_keep_prefix_suffix(value: &str, prefix: usize, suffix: usize) -> String {
    let chars: Vec<char> = value.chars().collect();
    if prefix + suffix >= chars.len() {
        return value.to_owned();
    }
    let prefix_text: String = chars[..prefix].iter().collect();
    let suffix_text: String = chars[chars.len() - suffix..].iter().collect();
    let masked = "*".repeat(chars.len() - prefix - suffix);
    format!("{prefix_text}{masked}{suffix_text}")
}

#[cfg(test)]
mod tests {
    use super::{
        MaskedSecret, SecretKind, SecretProvider, SecretRedaction, SecretReference, mask_all,
        mask_keep_last, mask_keep_prefix_suffix,
    };

    #[test]
    fn masks_secret_values() {
        assert_eq!(mask_all("abcd"), "****");
        assert_eq!(mask_keep_last("abcdef", 2), "****ef");
        assert_eq!(mask_keep_prefix_suffix("abcdefgh", 2, 2), "ab****gh");
        assert_eq!(SecretRedaction::KeepLast(3).apply("abcdef"), "***def");
    }

    #[test]
    fn redacts_debug_for_secret_wrappers() {
        let reference = SecretReference::new("prod/db/password").expect("reference");
        let secret = MaskedSecret::new("very-secret-token");

        assert_eq!(format!("{reference:?}"), "SecretReference(\"<redacted>\")");
        assert_eq!(format!("{secret:?}"), "MaskedSecret(\"<redacted>\")");
        assert!(!format!("{secret:?}").contains("very-secret-token"));
        assert_eq!(secret.to_string(), "<redacted>");
    }

    #[test]
    fn parses_and_displays_labels() {
        assert_eq!(
            "api-key".parse::<SecretKind>().expect("kind"),
            SecretKind::ApiKey
        );
        assert_eq!(
            SecretProvider::KubernetesSecret.to_string(),
            "kubernetes-secret"
        );
    }
}
