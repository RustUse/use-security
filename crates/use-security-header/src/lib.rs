#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
#![allow(clippy::module_name_repetitions)]

use core::{fmt, str::FromStr};
use std::error::Error;

/// Error returned when a security header name is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityHeaderNameError {
    Empty,
    NonAscii,
    InvalidCharacter,
}

impl fmt::Display for SecurityHeaderNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("security header name cannot be empty"),
            Self::NonAscii => formatter.write_str("security header name must be ASCII"),
            Self::InvalidCharacter => {
                formatter.write_str("security header name contains an invalid character")
            }
        }
    }
}

impl Error for SecurityHeaderNameError {}

/// Error returned when a security header label cannot be parsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityHeaderParseError {
    Empty,
    Unknown,
}

impl fmt::Display for SecurityHeaderParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("security header label cannot be empty"),
            Self::Unknown => formatter.write_str("unknown security header label"),
        }
    }
}

impl Error for SecurityHeaderParseError {}

/// A validated HTTP security header name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecurityHeaderName(String);

impl SecurityHeaderName {
    /// Creates a security header name from an HTTP token-shaped string.
    pub fn new(input: impl AsRef<str>) -> Result<Self, SecurityHeaderNameError> {
        let trimmed = input.as_ref().trim();
        validate_header_name(trimmed)?;
        Ok(Self(trimmed.to_owned()))
    }

    /// Returns the stored header name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecurityHeaderName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for SecurityHeaderName {
    type Err = SecurityHeaderNameError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::new(input)
    }
}

impl TryFrom<&str> for SecurityHeaderName {
    type Error = SecurityHeaderNameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
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
            type Err = SecurityHeaderParseError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                let trimmed = input.trim();
                if trimmed.is_empty() {
                    return Err(SecurityHeaderParseError::Empty);
                }
                let normalized = trimmed.to_ascii_lowercase();
                match normalized.as_str() {
                    $($label => Ok(Self::$variant),)+
                    _ => Err(SecurityHeaderParseError::Unknown),
                }
            }
        }
    };
}

/// Security header categories.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SecurityHeaderKind {
    ContentSecurityPolicy,
    StrictTransportSecurity,
    XContentTypeOptions,
    XFrameOptions,
    ReferrerPolicy,
    PermissionsPolicy,
    CrossOriginOpenerPolicy,
    CrossOriginResourcePolicy,
    CrossOriginEmbedderPolicy,
    CacheControl,
}

impl SecurityHeaderKind {
    /// Returns the canonical HTTP header name.
    #[must_use]
    pub const fn header_name(self) -> &'static str {
        match self {
            Self::ContentSecurityPolicy => "Content-Security-Policy",
            Self::StrictTransportSecurity => "Strict-Transport-Security",
            Self::XContentTypeOptions => "X-Content-Type-Options",
            Self::XFrameOptions => "X-Frame-Options",
            Self::ReferrerPolicy => "Referrer-Policy",
            Self::PermissionsPolicy => "Permissions-Policy",
            Self::CrossOriginOpenerPolicy => "Cross-Origin-Opener-Policy",
            Self::CrossOriginResourcePolicy => "Cross-Origin-Resource-Policy",
            Self::CrossOriginEmbedderPolicy => "Cross-Origin-Embedder-Policy",
            Self::CacheControl => "Cache-Control",
        }
    }
}

label_enum!(SecurityHeaderKind {
    ContentSecurityPolicy => "content-security-policy",
    StrictTransportSecurity => "strict-transport-security",
    XContentTypeOptions => "x-content-type-options",
    XFrameOptions => "x-frame-options",
    ReferrerPolicy => "referrer-policy",
    PermissionsPolicy => "permissions-policy",
    CrossOriginOpenerPolicy => "cross-origin-opener-policy",
    CrossOriginResourcePolicy => "cross-origin-resource-policy",
    CrossOriginEmbedderPolicy => "cross-origin-embedder-policy",
    CacheControl => "cache-control",
});

/// Content Security Policy directive labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ContentSecurityPolicyDirective {
    DefaultSrc,
    ScriptSrc,
    StyleSrc,
    ImgSrc,
    ConnectSrc,
    FrameAncestors,
    BaseUri,
    FormAction,
    UpgradeInsecureRequests,
    Other,
}

label_enum!(ContentSecurityPolicyDirective {
    DefaultSrc => "default-src",
    ScriptSrc => "script-src",
    StyleSrc => "style-src",
    ImgSrc => "img-src",
    ConnectSrc => "connect-src",
    FrameAncestors => "frame-ancestors",
    BaseUri => "base-uri",
    FormAction => "form-action",
    UpgradeInsecureRequests => "upgrade-insecure-requests",
    Other => "other",
});

/// Referrer policy labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ReferrerPolicyKind {
    NoReferrer,
    NoReferrerWhenDowngrade,
    Origin,
    OriginWhenCrossOrigin,
    SameOrigin,
    StrictOrigin,
    StrictOriginWhenCrossOrigin,
    UnsafeUrl,
}

label_enum!(ReferrerPolicyKind {
    NoReferrer => "no-referrer",
    NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
    Origin => "origin",
    OriginWhenCrossOrigin => "origin-when-cross-origin",
    SameOrigin => "same-origin",
    StrictOrigin => "strict-origin",
    StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
    UnsafeUrl => "unsafe-url",
});

/// X-Frame-Options labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FrameOptionsKind {
    Deny,
    SameOrigin,
}

label_enum!(FrameOptionsKind {
    Deny => "deny",
    SameOrigin => "sameorigin",
});

/// Strict-Transport-Security directive labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TransportSecurityDirective {
    MaxAge,
    IncludeSubDomains,
    Preload,
}

label_enum!(TransportSecurityDirective {
    MaxAge => "max-age",
    IncludeSubDomains => "includesubdomains",
    Preload => "preload",
});

/// CORS policy labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CorsPolicyKind {
    DenyAll,
    SameOrigin,
    AllowList,
    AllowAll,
}

label_enum!(CorsPolicyKind {
    DenyAll => "deny-all",
    SameOrigin => "same-origin",
    AllowList => "allow-list",
    AllowAll => "allow-all",
});

/// Permissions policy directive labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PermissionsPolicyDirective {
    Geolocation,
    Camera,
    Microphone,
    Payment,
    Usb,
    Fullscreen,
    Other,
}

label_enum!(PermissionsPolicyDirective {
    Geolocation => "geolocation",
    Camera => "camera",
    Microphone => "microphone",
    Payment => "payment",
    Usb => "usb",
    Fullscreen => "fullscreen",
    Other => "other",
});

fn validate_header_name(value: &str) -> Result<(), SecurityHeaderNameError> {
    if value.is_empty() {
        return Err(SecurityHeaderNameError::Empty);
    }
    if !value.is_ascii() {
        return Err(SecurityHeaderNameError::NonAscii);
    }
    if value.bytes().all(is_token_byte) {
        Ok(())
    } else {
        Err(SecurityHeaderNameError::InvalidCharacter)
    }
}

const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[cfg(test)]
mod tests {
    use super::{
        ContentSecurityPolicyDirective, ReferrerPolicyKind, SecurityHeaderKind, SecurityHeaderName,
        SecurityHeaderNameError,
    };

    #[test]
    fn validates_header_names() {
        let name = SecurityHeaderName::new("Content-Security-Policy").expect("header name");

        assert_eq!(name.as_str(), "Content-Security-Policy");
        assert_eq!(
            SecurityHeaderName::new(" "),
            Err(SecurityHeaderNameError::Empty)
        );
        assert_eq!(
            SecurityHeaderName::new("Bad Header"),
            Err(SecurityHeaderNameError::InvalidCharacter)
        );
    }

    #[test]
    fn parses_and_displays_labels() {
        assert_eq!(
            "script-src"
                .parse::<ContentSecurityPolicyDirective>()
                .expect("directive"),
            ContentSecurityPolicyDirective::ScriptSrc
        );
        assert_eq!(
            ReferrerPolicyKind::StrictOriginWhenCrossOrigin.to_string(),
            "strict-origin-when-cross-origin"
        );
    }

    #[test]
    fn exposes_canonical_header_name() {
        assert_eq!(
            SecurityHeaderKind::StrictTransportSecurity.header_name(),
            "Strict-Transport-Security"
        );
    }
}
