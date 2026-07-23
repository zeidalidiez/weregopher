//! Role-distinct SHA-256 identities used by execution contracts and authorization.
//!
//! Every wrapper is wire-compatible with [`Sha256Digest`] but prevents a digest from one semantic
//! role being silently assigned to another role in Rust code.
//!
//! ```compile_fail
//! use weregopher_domain::{ExecutableDigest, ExecutionArtifactSourceDigest, Sha256Digest};
//!
//! let source = ExecutionArtifactSourceDigest::new(Sha256Digest::from_bytes([7; 32]));
//! let executable: ExecutableDigest = source;
//! ```

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::Sha256Digest;

macro_rules! execution_digest_role {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd,
            Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(Sha256Digest);

        impl $name {
            /// Assigns an already computed SHA-256 identity to this exact semantic role.
            #[must_use]
            pub const fn new(digest: Sha256Digest) -> Self {
                Self(digest)
            }

            /// Returns the underlying SHA-256 identity.
            #[must_use]
            pub const fn as_sha256(&self) -> &Sha256Digest {
                &self.0
            }

            /// Consumes the role wrapper and returns the underlying SHA-256 identity.
            #[must_use]
            pub const fn into_sha256(self) -> Sha256Digest {
                self.0
            }
        }

        impl From<Sha256Digest> for $name {
            fn from(digest: Sha256Digest) -> Self {
                Self::new(digest)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

execution_digest_role!(
    /// Canonical static execution-target contract identity.
    ExecutionContractDigest
);
execution_digest_role!(
    /// Canonical generated execution-resolution evidence identity.
    ExecutionResolutionEvidenceDigest
);
execution_digest_role!(
    /// Package-tree or managed-manifest identity containing an executable.
    ExecutionArtifactSourceDigest
);
execution_digest_role!(
    /// Exact executable byte identity.
    ExecutableDigest
);
execution_digest_role!(
    /// Artifact trust-evidence identity.
    ArtifactTrustEvidenceDigest
);
execution_digest_role!(
    /// Artifact provenance-evidence identity.
    ProvenanceEvidenceDigest
);
execution_digest_role!(
    /// Complete compatibility-analysis identity.
    CompatibilityAnalysisDigest
);
execution_digest_role!(
    /// Capability-policy identity.
    CapabilityPolicyDigest
);
execution_digest_role!(
    /// State-policy identity.
    StatePolicyDigest
);
execution_digest_role!(
    /// Current user-policy or consent identity.
    UserPolicyDigest
);
execution_digest_role!(
    /// Complete live execution-authorization decision identity.
    AuthorizationContextDigest
);
