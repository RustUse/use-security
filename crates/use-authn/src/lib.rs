#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
#![allow(clippy::module_name_repetitions)]

use core::{fmt, str::FromStr};
use std::error::Error;

/// Error returned when an authentication label cannot be parsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthnParseError {
    Empty,
    Unknown,
}

impl fmt::Display for AuthnParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("authentication label cannot be empty"),
            Self::Unknown => formatter.write_str("unknown authentication label"),
        }
    }
}

impl Error for AuthnParseError {}

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
            type Err = AuthnParseError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                let trimmed = input.trim();
                if trimmed.is_empty() {
                    return Err(AuthnParseError::Empty);
                }
                let normalized = trimmed.to_ascii_lowercase();
                match normalized.as_str() {
                    $($label => Ok(Self::$variant),)+
                    _ => Err(AuthnParseError::Unknown),
                }
            }
        }
    };
}

/// Authentication method labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AuthenticationMethod {
    Password,
    Passkey,
    Totp,
    Hotp,
    SmsOtp,
    EmailOtp,
    MagicLink,
    OAuth2,
    OpenIdConnect,
    Sso,
    Certificate,
    ApiKey,
    BearerToken,
    MutualTls,
}

label_enum!(AuthenticationMethod {
    Password => "password",
    Passkey => "passkey",
    Totp => "totp",
    Hotp => "hotp",
    SmsOtp => "sms-otp",
    EmailOtp => "email-otp",
    MagicLink => "magic-link",
    OAuth2 => "oauth2",
    OpenIdConnect => "openid-connect",
    Sso => "sso",
    Certificate => "certificate",
    ApiKey => "api-key",
    BearerToken => "bearer-token",
    MutualTls => "mutual-tls",
});

/// Authentication factor labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AuthenticationFactor {
    Knowledge,
    Possession,
    Inherence,
    Location,
    Behavior,
}

label_enum!(AuthenticationFactor {
    Knowledge => "knowledge",
    Possession => "possession",
    Inherence => "inherence",
    Location => "location",
    Behavior => "behavior",
});

/// HTTP or application authentication scheme labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AuthenticationScheme {
    Basic,
    Bearer,
    Digest,
    Mutual,
    Negotiate,
    ApiKey,
    Custom,
}

label_enum!(AuthenticationScheme {
    Basic => "basic",
    Bearer => "bearer",
    Digest => "digest",
    Mutual => "mutual",
    Negotiate => "negotiate",
    ApiKey => "api-key",
    Custom => "custom",
});

/// Credential kind labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CredentialKind {
    Password,
    ApiKey,
    AccessToken,
    RefreshToken,
    IdToken,
    ClientSecret,
    Certificate,
    PrivateKey,
    Passkey,
}

label_enum!(CredentialKind {
    Password => "password",
    ApiKey => "api-key",
    AccessToken => "access-token",
    RefreshToken => "refresh-token",
    IdToken => "id-token",
    ClientSecret => "client-secret",
    Certificate => "certificate",
    PrivateKey => "private-key",
    Passkey => "passkey",
});

/// Session kind labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SessionKind {
    Browser,
    Api,
    Service,
    Device,
    Sso,
    Unknown,
}

label_enum!(SessionKind {
    Browser => "browser",
    Api => "api",
    Service => "service",
    Device => "device",
    Sso => "sso",
    Unknown => "unknown",
});

/// Token binding kind labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TokenBindingKind {
    None,
    Cookie,
    Header,
    MutualTls,
    Dpop,
    HolderOfKey,
    Unknown,
}

label_enum!(TokenBindingKind {
    None => "none",
    Cookie => "cookie",
    Header => "header",
    MutualTls => "mutual-tls",
    Dpop => "dpop",
    HolderOfKey => "holder-of-key",
    Unknown => "unknown",
});

/// Password policy strength labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PasswordPolicyLevel {
    None,
    Basic,
    Strong,
    Strict,
}

label_enum!(PasswordPolicyLevel {
    None => "none",
    Basic => "basic",
    Strong => "strong",
    Strict => "strict",
});

/// MFA status labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MfaStatus {
    Disabled,
    Optional,
    Required,
    Enforced,
}

label_enum!(MfaStatus {
    Disabled => "disabled",
    Optional => "optional",
    Required => "required",
    Enforced => "enforced",
});

#[cfg(test)]
mod tests {
    use super::{AuthenticationFactor, AuthenticationMethod, AuthenticationScheme, MfaStatus};

    #[test]
    fn displays_authentication_labels() {
        assert_eq!(AuthenticationMethod::Passkey.to_string(), "passkey");
        assert_eq!(AuthenticationFactor::Knowledge.to_string(), "knowledge");
        assert_eq!(MfaStatus::Enforced.to_string(), "enforced");
    }

    #[test]
    fn parses_authentication_labels() {
        assert_eq!(
            "bearer".parse::<AuthenticationScheme>().expect("scheme"),
            AuthenticationScheme::Bearer
        );
        assert_eq!(
            "api-key".parse::<AuthenticationMethod>().expect("method"),
            AuthenticationMethod::ApiKey
        );
    }
}
