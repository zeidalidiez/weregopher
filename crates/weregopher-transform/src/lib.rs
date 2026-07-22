//! Semantic-transform planning, deterministic in-memory emission, and artifact verification.
//!
//! Planning validates exact static module matches and emits in-memory edits. Emission applies one
//! exact plan to digest-matched source bytes without filesystem access. Artifact verification
//! establishes byte-for-digest conformance. None of these boundaries authenticates adapter
//! signatures, materializes source, authorizes execution, or authorizes launch.

#![forbid(unsafe_code)]

use std::{collections::BTreeMap, fmt};

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use weregopher_domain::{
    GeneratedTransformOverlay, Sha256Digest, StructurallyValidatedTransformOverlay, TransformRuleId,
};

mod emission;
mod planning;
mod source_map;

pub use emission::{
    EmittedMatchEvidence, EmittedTransformedSource, MatchEvidenceError, MatchEvidenceLimits,
    TransformEmissionError, TransformEmissionLimits, emit_match_evidence, emit_transformed_source,
};
pub use planning::{
    PlannerLimits, SourceUnitInput, StaticImportRewrite, StaticImportSpecifier, TextEdit,
    TransformPlan, TransformPlanError, plan_static_import_rewrite,
};
pub use source_map::{EmittedSourceMap, SourceMapError, SourceMapLimits, emit_source_map};

/// Artifact category covered by one generated transform rebinding.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransformArtifactKind {
    /// Original source-unit bytes selected by semantic matching.
    Source,
    /// Evidence emitted by the semantic matcher.
    MatchEvidence,
    /// Source bytes emitted by the static transform rule.
    TransformedSource,
    /// Source map emitted with transformed source.
    SourceMap,
    /// Audit record emitted for the transform application.
    AuditLog,
}

/// Borrowed bytes for every artifact referenced by one transform rebinding.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TransformArtifactBytes<'a> {
    source: &'a [u8],
    match_evidence: &'a [u8],
    transformed_source: &'a [u8],
    source_map: &'a [u8],
    audit_log: &'a [u8],
}

impl fmt::Debug for TransformArtifactBytes<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransformArtifactBytes")
            .field("source_length", &self.source.len())
            .field("match_evidence_length", &self.match_evidence.len())
            .field("transformed_source_length", &self.transformed_source.len())
            .field("source_map_length", &self.source_map.len())
            .field("audit_log_length", &self.audit_log.len())
            .finish()
    }
}

impl<'a> TransformArtifactBytes<'a> {
    /// Constructs one borrowed artifact bundle without copying its bytes.
    #[must_use]
    pub const fn new(
        source: &'a [u8],
        match_evidence: &'a [u8],
        transformed_source: &'a [u8],
        source_map: &'a [u8],
        audit_log: &'a [u8],
    ) -> Self {
        Self {
            source,
            match_evidence,
            transformed_source,
            source_map,
            audit_log,
        }
    }

    /// Returns original source-unit bytes.
    #[must_use]
    pub const fn source(&self) -> &'a [u8] {
        self.source
    }

    /// Returns semantic-match evidence bytes.
    #[must_use]
    pub const fn match_evidence(&self) -> &'a [u8] {
        self.match_evidence
    }

    /// Returns transformed-source bytes.
    #[must_use]
    pub const fn transformed_source(&self) -> &'a [u8] {
        self.transformed_source
    }

    /// Returns source-map bytes.
    #[must_use]
    pub const fn source_map(&self) -> &'a [u8] {
        self.source_map
    }

    /// Returns transform audit-log bytes.
    #[must_use]
    pub const fn audit_log(&self) -> &'a [u8] {
        self.audit_log
    }
}

/// Caller-selected byte limits for transform-artifact verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransformArtifactLimits {
    per_artifact: ArtifactByteLimits,
    aggregate: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArtifactByteLimits {
    source: usize,
    match_evidence: usize,
    transformed_source: usize,
    source_map: usize,
    audit_log: usize,
}

impl TransformArtifactLimits {
    /// Constructs nonzero per-artifact and aggregate verification limits.
    ///
    /// # Errors
    ///
    /// Returns [`TransformArtifactError::InvalidLimits`] when any limit is zero.
    pub const fn new(
        max_source_bytes: usize,
        max_match_evidence_bytes: usize,
        max_transformed_source_bytes: usize,
        max_source_map_bytes: usize,
        max_audit_log_bytes: usize,
        max_total_bytes: usize,
    ) -> Result<Self, TransformArtifactError> {
        if max_source_bytes == 0
            || max_match_evidence_bytes == 0
            || max_transformed_source_bytes == 0
            || max_source_map_bytes == 0
            || max_audit_log_bytes == 0
            || max_total_bytes == 0
        {
            return Err(TransformArtifactError::InvalidLimits);
        }
        Ok(Self {
            per_artifact: ArtifactByteLimits {
                source: max_source_bytes,
                match_evidence: max_match_evidence_bytes,
                transformed_source: max_transformed_source_bytes,
                source_map: max_source_map_bytes,
                audit_log: max_audit_log_bytes,
            },
            aggregate: max_total_bytes,
        })
    }
}

/// Opaque evidence that supplied bytes were checked against one generated overlay.
///
/// This value proves digest conformance only; it carries no authentication or execution authority.
#[derive(Debug)]
pub struct VerifiedTransformArtifacts<'overlay, 'authority, 'artifacts, 'bytes> {
    structural_validation: StructurallyValidatedTransformOverlay<'overlay, 'authority>,
    artifacts: &'artifacts BTreeMap<TransformRuleId, TransformArtifactBytes<'bytes>>,
}

impl<'overlay, 'authority, 'artifacts, 'bytes>
    VerifiedTransformArtifacts<'overlay, 'authority, 'artifacts, 'bytes>
{
    /// Returns the structurally referenced overlay.
    #[must_use]
    pub const fn overlay(&self) -> &'overlay GeneratedTransformOverlay {
        self.structural_validation.overlay()
    }

    /// Returns the structural-conformance proof required to verify these artifact bytes.
    #[must_use]
    pub const fn structural_validation(
        &self,
    ) -> &StructurallyValidatedTransformOverlay<'overlay, 'authority> {
        &self.structural_validation
    }

    /// Returns the number of verified rule artifact bundles.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.artifacts.len()
    }

    /// Returns verified artifact bundles in deterministic rule order.
    #[must_use]
    pub const fn artifacts(
        &self,
    ) -> &'artifacts BTreeMap<TransformRuleId, TransformArtifactBytes<'bytes>> {
        self.artifacts
    }
}

/// Checks supplied transform-artifact bytes against one structurally validated generated overlay.
///
/// Requiring the opaque structural proof prevents this API from producing verified artifact
/// evidence for a raw overlay that has not been checked against exact source identities and an
/// authority object. Neither the structural proof nor this verification authenticates those
/// inputs or grants transformation, execution, launch, or certification authority.
///
/// # Errors
///
/// Returns [`TransformArtifactError`] when artifact coverage, limits, or digests do not conform.
pub fn verify_transform_artifacts<'overlay, 'authority, 'artifacts, 'bytes>(
    structural_validation: StructurallyValidatedTransformOverlay<'overlay, 'authority>,
    artifacts: &'artifacts BTreeMap<TransformRuleId, TransformArtifactBytes<'bytes>>,
    limits: TransformArtifactLimits,
) -> Result<
    VerifiedTransformArtifacts<'overlay, 'authority, 'artifacts, 'bytes>,
    TransformArtifactError,
> {
    let overlay = structural_validation.overlay();
    for rule_id in overlay.rebindings().keys() {
        if !artifacts.contains_key(rule_id) {
            return Err(TransformArtifactError::MissingArtifactBundle(
                rule_id.clone(),
            ));
        }
    }
    for rule_id in artifacts.keys() {
        if !overlay.rebindings().contains_key(rule_id) {
            return Err(TransformArtifactError::UnexpectedArtifactBundle(
                rule_id.clone(),
            ));
        }
    }
    let mut total_bytes = 0_usize;
    for (rule_id, bytes) in artifacts {
        for (kind, actual, max_bytes) in bounded_artifacts(bytes, limits) {
            if actual.len() > max_bytes {
                return Err(TransformArtifactError::ArtifactTooLarge {
                    rule_id: rule_id.clone(),
                    artifact: kind,
                    actual_bytes: actual.len(),
                    max_bytes,
                });
            }
            total_bytes = total_bytes.checked_add(actual.len()).ok_or(
                TransformArtifactError::TotalBytesExceeded {
                    actual_bytes: usize::MAX,
                    max_bytes: limits.aggregate,
                },
            )?;
        }
    }
    if total_bytes > limits.aggregate {
        return Err(TransformArtifactError::TotalBytesExceeded {
            actual_bytes: total_bytes,
            max_bytes: limits.aggregate,
        });
    }

    for (rule_id, rebinding) in overlay.rebindings() {
        let bytes = artifacts
            .get(rule_id)
            .ok_or_else(|| TransformArtifactError::MissingArtifactBundle(rule_id.clone()))?;
        for (kind, actual, expected) in [
            (
                TransformArtifactKind::Source,
                bytes.source,
                rebinding.source().source_digest(),
            ),
            (
                TransformArtifactKind::MatchEvidence,
                bytes.match_evidence,
                rebinding.match_evidence_digest(),
            ),
            (
                TransformArtifactKind::TransformedSource,
                bytes.transformed_source,
                rebinding.transformed_source_digest(),
            ),
            (
                TransformArtifactKind::SourceMap,
                bytes.source_map,
                rebinding.source_map_digest(),
            ),
            (
                TransformArtifactKind::AuditLog,
                bytes.audit_log,
                rebinding.audit_log_digest(),
            ),
        ] {
            if digest(actual) != *expected {
                return Err(TransformArtifactError::DigestMismatch {
                    rule_id: rule_id.clone(),
                    artifact: kind,
                });
            }
        }
    }
    Ok(VerifiedTransformArtifacts {
        structural_validation,
        artifacts,
    })
}

fn bounded_artifacts<'a>(
    bytes: &TransformArtifactBytes<'a>,
    limits: TransformArtifactLimits,
) -> [(TransformArtifactKind, &'a [u8], usize); 5] {
    [
        (
            TransformArtifactKind::Source,
            bytes.source,
            limits.per_artifact.source,
        ),
        (
            TransformArtifactKind::MatchEvidence,
            bytes.match_evidence,
            limits.per_artifact.match_evidence,
        ),
        (
            TransformArtifactKind::TransformedSource,
            bytes.transformed_source,
            limits.per_artifact.transformed_source,
        ),
        (
            TransformArtifactKind::SourceMap,
            bytes.source_map,
            limits.per_artifact.source_map,
        ),
        (
            TransformArtifactKind::AuditLog,
            bytes.audit_log,
            limits.per_artifact.audit_log,
        ),
    ]
}

/// Failure verifying transform-artifact bytes.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransformArtifactError {
    /// One or more byte limits were zero.
    #[error("transform artifact limits must be nonzero")]
    InvalidLimits,
    /// The generated overlay referenced a rule with no supplied artifact bundle.
    #[error("missing transform artifact bundle for rule `{0}`")]
    MissingArtifactBundle(TransformRuleId),
    /// The caller supplied an artifact bundle absent from the generated overlay.
    #[error("unexpected transform artifact bundle for rule `{0}`")]
    UnexpectedArtifactBundle(TransformRuleId),
    /// Supplied bytes did not match an artifact digest in the generated overlay.
    #[error("{artifact:?} digest mismatch for transform rule `{rule_id}`")]
    DigestMismatch {
        /// Rule whose artifact bytes did not match.
        rule_id: TransformRuleId,
        /// Artifact category whose digest did not match.
        artifact: TransformArtifactKind,
    },
    /// One artifact exceeded its caller-selected byte limit.
    #[error(
        "{artifact:?} artifact for transform rule `{rule_id}` is {actual_bytes} bytes; limit is {max_bytes}"
    )]
    ArtifactTooLarge {
        /// Rule whose artifact exceeded its limit.
        rule_id: TransformRuleId,
        /// Artifact category whose bytes exceeded its limit.
        artifact: TransformArtifactKind,
        /// Actual supplied byte length.
        actual_bytes: usize,
        /// Caller-selected maximum byte length.
        max_bytes: usize,
    },
    /// All supplied artifacts together exceeded the caller-selected byte limit.
    #[error("transform artifacts total {actual_bytes} bytes; limit is {max_bytes}")]
    TotalBytesExceeded {
        /// Actual aggregate byte length, or `usize::MAX` when addition overflowed.
        actual_bytes: usize,
        /// Caller-selected aggregate maximum.
        max_bytes: usize,
    },
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}
