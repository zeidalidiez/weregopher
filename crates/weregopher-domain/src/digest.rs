//! Cryptographic digest value types.

use std::{borrow::Cow, fmt, str::FromStr};

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use thiserror::Error;

const SHA256_LEN: usize = 32;
const SHA256_TEXT_PREFIX: &str = "sha256:";

/// A SHA-256 digest serialized as lowercase `sha256:<hex>` text.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest([u8; SHA256_LEN]);

impl JsonSchema for Sha256Digest {
    fn schema_name() -> Cow<'static, str> {
        "Sha256Digest".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::Sha256Digest").into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "A SHA-256 digest serialized as lowercase `sha256:<hex>` text.",
            "type": "string",
            "minLength": 71,
            "maxLength": 71,
            "pattern": "^sha256:[0-9a-f]{64}$"
        })
    }
}

impl Sha256Digest {
    /// Creates a digest from its exact 32-byte representation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SHA256_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the exact digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SHA256_LEN] {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SHA256_TEXT_PREFIX)?;
        formatter.write_str(&hex::encode(self.0))
    }
}

impl FromStr for Sha256Digest {
    type Err = Sha256DigestError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let hex_value = value
            .strip_prefix(SHA256_TEXT_PREFIX)
            .ok_or(Sha256DigestError::MissingPrefix)?;
        if hex_value.len() != SHA256_LEN * 2 {
            return Err(Sha256DigestError::InvalidLength {
                actual: hex_value.len(),
            });
        }
        if hex_value.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(Sha256DigestError::UppercaseHex);
        }

        let mut bytes = [0_u8; SHA256_LEN];
        hex::decode_to_slice(hex_value, &mut bytes).map_err(|_| Sha256DigestError::InvalidHex)?;
        Ok(Self(bytes))
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(D::Error::custom)
    }
}

/// A malformed SHA-256 textual digest.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum Sha256DigestError {
    /// The required algorithm prefix was absent.
    #[error("SHA-256 digest must start with `sha256:`")]
    MissingPrefix,
    /// The hexadecimal payload had the wrong length.
    #[error("SHA-256 hex payload must be 64 bytes, got {actual}")]
    InvalidLength {
        /// Observed hexadecimal character count.
        actual: usize,
    },
    /// Uppercase digest text is noncanonical.
    #[error("SHA-256 digest must use lowercase hexadecimal")]
    UppercaseHex,
    /// The payload was not hexadecimal.
    #[error("SHA-256 digest contains invalid hexadecimal")]
    InvalidHex,
}
