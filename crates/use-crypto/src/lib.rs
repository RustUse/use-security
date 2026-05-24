#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
#![allow(clippy::module_name_repetitions)]

use core::{fmt, str::FromStr};
use std::error::Error;

/// Error returned when a crypto label cannot be parsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoParseError {
    Empty,
    Unknown,
}

impl fmt::Display for CryptoParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("crypto label cannot be empty"),
            Self::Unknown => formatter.write_str("unknown crypto label"),
        }
    }
}

impl Error for CryptoParseError {}

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
            type Err = CryptoParseError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                let trimmed = input.trim();
                if trimmed.is_empty() {
                    return Err(CryptoParseError::Empty);
                }
                let normalized = trimmed.to_ascii_lowercase();
                match normalized.as_str() {
                    $($label => Ok(Self::$variant),)+
                    _ => Err(CryptoParseError::Unknown),
                }
            }
        }
    };
}

/// Broad cryptographic algorithm category labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CryptoAlgorithm {
    Hash,
    Signature,
    Encryption,
    KeyAgreement,
    KeyDerivation,
    Unknown,
}

label_enum!(CryptoAlgorithm {
    Hash => "hash",
    Signature => "signature",
    Encryption => "encryption",
    KeyAgreement => "key-agreement",
    KeyDerivation => "key-derivation",
    Unknown => "unknown",
});

/// Hash algorithm labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    Blake2b,
    Blake2s,
    Md5,
    Sha1,
    Unknown,
}

label_enum!(HashAlgorithm {
    Sha256 => "sha-256",
    Sha384 => "sha-384",
    Sha512 => "sha-512",
    Blake2b => "blake2b",
    Blake2s => "blake2s",
    Md5 => "md5",
    Sha1 => "sha-1",
    Unknown => "unknown",
});

impl HashAlgorithm {
    /// Returns strength metadata for this hash label.
    #[must_use]
    pub const fn strength(self) -> CryptoStrength {
        match self {
            Self::Md5 | Self::Sha1 => CryptoStrength::Deprecated,
            Self::Unknown => CryptoStrength::Unknown,
            Self::Sha256 | Self::Sha384 | Self::Sha512 | Self::Blake2b | Self::Blake2s => {
                CryptoStrength::Strong
            }
        }
    }

    /// Returns `true` for deprecated or weak hash labels.
    #[must_use]
    pub const fn is_deprecated_like(self) -> bool {
        matches!(self, Self::Md5 | Self::Sha1)
    }
}

/// Signature algorithm labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SignatureAlgorithm {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    RsaPss,
    RsaPkcs1v15,
    Unknown,
}

label_enum!(SignatureAlgorithm {
    Ed25519 => "ed25519",
    EcdsaP256 => "ecdsa-p256",
    EcdsaP384 => "ecdsa-p384",
    RsaPss => "rsa-pss",
    RsaPkcs1v15 => "rsa-pkcs1-v1-5",
    Unknown => "unknown",
});

/// Encryption algorithm labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EncryptionAlgorithm {
    AesGcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
    RsaOaep,
    Unknown,
}

label_enum!(EncryptionAlgorithm {
    AesGcm => "aes-gcm",
    ChaCha20Poly1305 => "chacha20-poly1305",
    XChaCha20Poly1305 => "xchacha20-poly1305",
    RsaOaep => "rsa-oaep",
    Unknown => "unknown",
});

/// Key algorithm labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum KeyAlgorithm {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    Rsa,
    Aes,
    ChaCha20,
    Unknown,
}

label_enum!(KeyAlgorithm {
    Ed25519 => "ed25519",
    EcdsaP256 => "ecdsa-p256",
    EcdsaP384 => "ecdsa-p384",
    Rsa => "rsa",
    Aes => "aes",
    ChaCha20 => "chacha20",
    Unknown => "unknown",
});

/// Key kind labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum KeyKind {
    Public,
    Private,
    Symmetric,
    Secret,
    Certificate,
}

label_enum!(KeyKind {
    Public => "public",
    Private => "private",
    Symmetric => "symmetric",
    Secret => "secret",
    Certificate => "certificate",
});

/// Key usage labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum KeyUsage {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    Wrap,
    Unwrap,
    Derive,
    Authenticate,
}

label_enum!(KeyUsage {
    Sign => "sign",
    Verify => "verify",
    Encrypt => "encrypt",
    Decrypt => "decrypt",
    Wrap => "wrap",
    Unwrap => "unwrap",
    Derive => "derive",
    Authenticate => "authenticate",
});

/// Cryptographic encoding labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CryptoEncoding {
    Pem,
    Der,
    Jwk,
    Base64,
    Hex,
    Raw,
    Unknown,
}

label_enum!(CryptoEncoding {
    Pem => "pem",
    Der => "der",
    Jwk => "jwk",
    Base64 => "base64",
    Hex => "hex",
    Raw => "raw",
    Unknown => "unknown",
});

/// Cryptographic strength labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CryptoStrength {
    Deprecated,
    Weak,
    Acceptable,
    Strong,
    Unknown,
}

label_enum!(CryptoStrength {
    Deprecated => "deprecated",
    Weak => "weak",
    Acceptable => "acceptable",
    Strong => "strong",
    Unknown => "unknown",
});

/// Returns `true` when a hash algorithm label is deprecated-like.
#[must_use]
pub const fn is_deprecated_like(algorithm: HashAlgorithm) -> bool {
    algorithm.is_deprecated_like()
}

#[cfg(test)]
mod tests {
    use super::{CryptoStrength, HashAlgorithm, SignatureAlgorithm, is_deprecated_like};

    #[test]
    fn marks_legacy_hash_labels() {
        assert!(HashAlgorithm::Md5.is_deprecated_like());
        assert!(HashAlgorithm::Sha1.is_deprecated_like());
        assert!(is_deprecated_like(HashAlgorithm::Md5));
        assert_eq!(HashAlgorithm::Sha256.strength(), CryptoStrength::Strong);
    }

    #[test]
    fn parses_and_displays_labels() {
        assert_eq!(
            "ed25519".parse::<SignatureAlgorithm>().expect("signature"),
            SignatureAlgorithm::Ed25519
        );
        assert_eq!(HashAlgorithm::Sha512.to_string(), "sha-512");
    }
}
