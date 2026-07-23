//! Bounded digest verification for certification evidence artifacts.

use std::{collections::BTreeMap, fmt};

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use weregopher_domain::{
    CERTIFICATION_FIXED_CHECK_COUNT, CertificationArtifactDigest, CertificationArtifactRef,
    MAX_CERTIFICATION_EVIDENCE_REFS, MAX_CERTIFICATION_WORKFLOWS, Sha256Digest,
    StructurallyValidatedCertificationEvidence,
};

/// Hard ceiling for unique artifact references in one structurally valid evidence document.
pub const MAX_CERTIFICATION_ARTIFACT_REFERENCES: usize = (CERTIFICATION_FIXED_CHECK_COUNT
    + MAX_CERTIFICATION_WORKFLOWS)
    * MAX_CERTIFICATION_EVIDENCE_REFS;

/// Hard per-artifact byte ceiling for certification evidence verification.
pub const MAX_CERTIFICATION_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
/// Hard aggregate byte ceiling for one certification evidence verification.
pub const MAX_TOTAL_CERTIFICATION_ARTIFACT_BYTES: usize = 128 * 1024 * 1024;

/// Caller-selected certification artifact verification bounds.
///
/// Callers may tighten these limits but cannot raise the implementation ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificationArtifactVerificationLimits {
    per_artifact: usize,
    aggregate: usize,
}

impl CertificationArtifactVerificationLimits {
    /// Constructs nonzero per-artifact and aggregate limits under the implementation ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`CertificationArtifactVerificationError::InvalidLimits`] for zero limits, or
    /// [`CertificationArtifactVerificationError::LimitsExceedImplementationMaximum`] when a limit
    /// exceeds its implementation ceiling.
    pub const fn new(
        max_artifact_bytes: usize,
        max_total_bytes: usize,
    ) -> Result<Self, CertificationArtifactVerificationError> {
        if max_artifact_bytes == 0 || max_total_bytes == 0 {
            return Err(CertificationArtifactVerificationError::InvalidLimits);
        }
        if max_artifact_bytes > MAX_CERTIFICATION_ARTIFACT_BYTES
            || max_total_bytes > MAX_TOTAL_CERTIFICATION_ARTIFACT_BYTES
        {
            return Err(CertificationArtifactVerificationError::LimitsExceedImplementationMaximum);
        }
        Ok(Self {
            per_artifact: max_artifact_bytes,
            aggregate: max_total_bytes,
        })
    }
}

/// Opaque proof that exact supplied bytes match every artifact referenced by validated evidence.
///
/// This proof retains the borrowed artifact bytes and the consuming profile/evidence structural
/// proof. It establishes bounded digest conformance only, not artifact semantics, producer trust,
/// target approval, certification class, publication, transformation, or execution authority.
#[must_use = "verified artifact bytes do not themselves grant certification or authority"]
pub struct VerifiedCertificationArtifacts<'artifacts, 'bytes> {
    structural_validation: StructurallyValidatedCertificationEvidence,
    artifacts: &'artifacts BTreeMap<CertificationArtifactRef, &'bytes [u8]>,
    total_bytes: usize,
}

impl fmt::Debug for VerifiedCertificationArtifacts<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedCertificationArtifacts")
            .field("artifact_count", &self.artifacts.len())
            .field("total_bytes", &self.total_bytes)
            .field("target", self.structural_validation.evidence().target())
            .field(
                "profile_digest",
                self.structural_validation.evidence().profile_digest(),
            )
            .finish_non_exhaustive()
    }
}

impl<'artifacts, 'bytes> VerifiedCertificationArtifacts<'artifacts, 'bytes> {
    /// Returns the retained profile/evidence structural proof.
    pub const fn structural_validation(&self) -> &StructurallyValidatedCertificationEvidence {
        &self.structural_validation
    }

    /// Returns exact verified artifact bytes in deterministic reference order.
    #[must_use]
    pub const fn artifacts(&self) -> &'artifacts BTreeMap<CertificationArtifactRef, &'bytes [u8]> {
        self.artifacts
    }

    /// Returns the number of unique verified artifact references.
    #[must_use]
    pub fn artifact_count(&self) -> usize {
        self.artifacts.len()
    }

    /// Returns the checked aggregate byte length of unique supplied artifacts.
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }
}

/// Verifies exact bounded bytes for every artifact referenced by structurally validated evidence.
///
/// Coverage and all byte limits are checked before any supplied artifact is hashed. The returned
/// proof retains both the structural validation and the borrowed byte map so later consumers cannot
/// substitute an unverified map through this API.
///
/// # Errors
///
/// Returns [`CertificationArtifactVerificationError`] for invalid limits, excessive input,
/// missing or unexpected references, aggregate overflow, or any content-digest mismatch.
pub fn verify_certification_artifacts<'artifacts, 'bytes>(
    structural_validation: StructurallyValidatedCertificationEvidence,
    artifacts: &'artifacts BTreeMap<CertificationArtifactRef, &'bytes [u8]>,
    limits: CertificationArtifactVerificationLimits,
) -> Result<
    VerifiedCertificationArtifacts<'artifacts, 'bytes>,
    CertificationArtifactVerificationError,
> {
    if artifacts.len() > MAX_CERTIFICATION_ARTIFACT_REFERENCES {
        return Err(CertificationArtifactVerificationError::TooManyArtifacts);
    }

    let mut expected = Vec::new();
    expected
        .try_reserve_exact(MAX_CERTIFICATION_ARTIFACT_REFERENCES)
        .map_err(|_| CertificationArtifactVerificationError::ReferenceAllocationFailed)?;
    expected.extend(structural_validation.evidence().artifact_references());
    expected.sort_unstable();
    expected.dedup();

    for reference in &expected {
        if !artifacts.contains_key(*reference) {
            return Err(CertificationArtifactVerificationError::MissingArtifact(
                (*reference).clone(),
            ));
        }
    }
    for reference in artifacts.keys() {
        if expected.binary_search(&reference).is_err() {
            return Err(CertificationArtifactVerificationError::UnexpectedArtifact(
                reference.clone(),
            ));
        }
    }

    let mut total_bytes = 0_usize;
    for (reference, bytes) in artifacts {
        if bytes.len() > limits.per_artifact {
            return Err(CertificationArtifactVerificationError::ArtifactTooLarge {
                artifact: reference.clone(),
                actual_bytes: bytes.len(),
                max_bytes: limits.per_artifact,
            });
        }
        total_bytes = total_bytes.checked_add(bytes.len()).ok_or(
            CertificationArtifactVerificationError::TotalBytesExceeded {
                actual_bytes: usize::MAX,
                max_bytes: limits.aggregate,
            },
        )?;
        if total_bytes > limits.aggregate {
            return Err(CertificationArtifactVerificationError::TotalBytesExceeded {
                actual_bytes: total_bytes,
                max_bytes: limits.aggregate,
            });
        }
    }

    for (reference, bytes) in artifacts {
        let actual = CertificationArtifactDigest::new(Sha256Digest::from_bytes(
            Sha256::digest(bytes).into(),
        ));
        if actual != reference.digest {
            return Err(CertificationArtifactVerificationError::DigestMismatch(
                reference.clone(),
            ));
        }
    }

    Ok(VerifiedCertificationArtifacts {
        structural_validation,
        artifacts,
        total_bytes,
    })
}

/// Failure to verify exact bounded certification artifact bytes.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CertificationArtifactVerificationError {
    /// One or more caller-selected limits were zero.
    #[error("certification artifact verification limits must be nonzero")]
    InvalidLimits,
    /// Caller-selected limits exceeded implementation ceilings.
    #[error("certification artifact verification limits exceed implementation ceilings")]
    LimitsExceedImplementationMaximum,
    /// More unique artifacts were supplied than any valid evidence document can reference.
    #[error("certification artifact count exceeds the implementation ceiling")]
    TooManyArtifacts,
    /// Memory for the bounded expected-reference index could not be reserved.
    #[error("certification artifact reference index allocation failed")]
    ReferenceAllocationFailed,
    /// A referenced artifact had no supplied bytes.
    #[error("missing referenced certification artifact {0:?}")]
    MissingArtifact(CertificationArtifactRef),
    /// Supplied bytes were not referenced by the evidence.
    #[error("unexpected certification artifact {0:?}")]
    UnexpectedArtifact(CertificationArtifactRef),
    /// One supplied artifact exceeded its caller-selected byte limit.
    #[error("certification artifact {artifact:?} is {actual_bytes} bytes; limit is {max_bytes}")]
    ArtifactTooLarge {
        /// Exact artifact whose bytes exceeded the limit.
        artifact: CertificationArtifactRef,
        /// Actual supplied byte length.
        actual_bytes: usize,
        /// Caller-selected maximum byte length.
        max_bytes: usize,
    },
    /// All supplied artifacts together exceeded their caller-selected aggregate limit.
    #[error("certification artifacts total {actual_bytes} bytes; limit is {max_bytes}")]
    TotalBytesExceeded {
        /// Actual aggregate length, or `usize::MAX` on arithmetic overflow.
        actual_bytes: usize,
        /// Caller-selected aggregate maximum.
        max_bytes: usize,
    },
    /// Supplied bytes did not match the role-specific referenced digest.
    #[error("certification artifact digest mismatch for {0:?}")]
    DigestMismatch(CertificationArtifactRef),
}
