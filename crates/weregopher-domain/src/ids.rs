//! Strongly typed identifiers shared by Weregopher components.

use std::{borrow::Cow, fmt, str::FromStr};

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// An invalid stable string identifier.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("invalid {kind} identifier `{value}`: {reason}")]
pub struct IdentifierError {
    kind: &'static str,
    value: String,
    reason: &'static str,
}

fn validate_stable_name(kind: &'static str, value: String) -> Result<String, IdentifierError> {
    if value.is_empty() {
        return Err(IdentifierError {
            kind,
            value,
            reason: "must not be empty",
        });
    }
    if value.len() > 255 {
        return Err(IdentifierError {
            kind,
            value,
            reason: "must not exceed 255 bytes",
        });
    }
    if value.starts_with(['.', '-', '_']) || value.ends_with(['.', '-', '_']) {
        return Err(IdentifierError {
            kind,
            value,
            reason: "must start and end with an ASCII lowercase letter or digit",
        });
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-_".contains(&byte))
    {
        return Err(IdentifierError {
            kind,
            value,
            reason: "contains a character outside [a-z0-9._-]",
        });
    }
    if value.contains("..") {
        return Err(IdentifierError {
            kind,
            value,
            reason: "must not contain an empty dotted segment",
        });
    }
    Ok(value)
}

macro_rules! stable_string_id {
    ($name:ident, $kind:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl JsonSchema for $name {
            fn schema_name() -> Cow<'static, str> {
                stringify!($name).into()
            }

            fn schema_id() -> Cow<'static, str> {
                concat!(module_path!(), "::", stringify!($name)).into()
            }

            fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
                json_schema!({
                    "description": $doc,
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 255,
                    "pattern": "^(?!.*\\.\\.)[a-z0-9](?:[a-z0-9._-]{0,253}[a-z0-9])?$"
                })
            }
        }

        impl $name {
            /// Validates and constructs the identifier.
            ///
            /// # Errors
            ///
            /// Returns [`IdentifierError`] when the value is empty, too long, or
            /// contains characters outside the canonical stable-name grammar.
            pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
                validate_stable_name($kind, value.into()).map(Self)
            }

            /// Returns the canonical identifier text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = IdentifierError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdentifierError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

stable_string_id!(
    ApplicationFamilyId,
    "application family",
    "A durable application-family identifier, such as `openai.chatgpt`."
);
stable_string_id!(AdapterId, "adapter", "A durable adapter identifier.");
stable_string_id!(
    BuildId,
    "build",
    "A catalog identifier for an immutable build."
);
stable_string_id!(
    FeatureId,
    "feature",
    "A durable application-workflow or compatibility-feature identifier."
);
stable_string_id!(ProfileId, "profile", "An application profile identifier.");
stable_string_id!(
    ScenarioId,
    "scenario",
    "A certification scenario identifier."
);

macro_rules! uuid_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(
            Clone,
            Copy,
            Debug,
            Eq,
            Hash,
            JsonSchema,
            Ord,
            PartialEq,
            PartialOrd,
            Serialize,
            Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Wraps a UUID supplied by the owning authority.
            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            /// Returns the wrapped UUID.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

uuid_id!(AppInstanceId, "A unique application launch identity.");
uuid_id!(RuntimeId, "A unique worker-runtime identity.");
uuid_id!(
    ProtocolSessionId,
    "An authenticated protocol-session identity."
);
uuid_id!(
    CapabilityGrantId,
    "A host-issued capability-grant reference."
);
uuid_id!(
    UserActivationId,
    "A host-issued, short-lived user-activation reference."
);
uuid_id!(TraceId, "A distributed trace identity.");

macro_rules! numeric_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(
            Clone,
            Copy,
            Debug,
            Eq,
            Hash,
            JsonSchema,
            Ord,
            PartialEq,
            PartialOrd,
            Serialize,
            Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(u64);

        impl $name {
            /// Constructs an owner-scoped numeric identifier.
            #[must_use]
            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            /// Returns the numeric value.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }
        }
    };
}

numeric_id!(RendererId, "An application-scoped renderer identifier.");
numeric_id!(WindowId, "An application-scoped shell-window identifier.");
numeric_id!(ObjectId, "An application-scoped remote-object identifier.");
