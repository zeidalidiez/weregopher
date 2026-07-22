//! Canonical audit emission and complete in-memory transform-artifact assembly.

use std::fmt;

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use weregopher_domain::{Sha256Digest, TransformRebinding};

use crate::{
    EmittedMatchEvidence, EmittedSourceMap, EmittedTransformedSource, TransformArtifactBytes,
};

const DIGEST_TEXT_LENGTH: usize = 71;
const AUDIT_PREFIX: &[u8] =
    br#"{"format_version":"1","operation":"static_import_rewrite","rule_id":""#;
const AUDIT_RULE_DIGEST: &[u8] = br#"","rule_digest":""#;
const AUDIT_SOURCE: &[u8] = br#"","source":{"unit_id":""#;
const AUDIT_SOURCE_DIGEST: &[u8] = br#"","source_digest":""#;
const AUDIT_MATCH_EVIDENCE: &[u8] = br#""},"artifacts":{"match_evidence_digest":""#;
const AUDIT_TRANSFORMED_SOURCE: &[u8] = br#"","transformed_source_digest":""#;
const AUDIT_SOURCE_MAP: &[u8] = br#"","source_map_digest":""#;
const AUDIT_EDIT_COUNT: &[u8] = br#""},"edit_count":"#;
const AUDIT_SUFFIX: &[u8] = b"}";

/// Caller-selected bounds for complete in-memory transform-artifact assembly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransformBundleLimits {
    source: usize,
    audit_log: usize,
    aggregate: usize,
}

impl TransformBundleLimits {
    /// Constructs nonzero source, audit-log, and aggregate artifact limits.
    ///
    /// # Errors
    ///
    /// Returns [`TransformBundleError::InvalidLimits`] when any limit is zero.
    pub const fn new(
        max_source_bytes: usize,
        max_audit_log_bytes: usize,
        max_aggregate_bytes: usize,
    ) -> Result<Self, TransformBundleError> {
        if max_source_bytes == 0 || max_audit_log_bytes == 0 || max_aggregate_bytes == 0 {
            return Err(TransformBundleError::InvalidLimits);
        }
        Ok(Self {
            source: max_source_bytes,
            audit_log: max_audit_log_bytes,
            aggregate: max_aggregate_bytes,
        })
    }
}

/// One complete in-memory, content-addressed transform artifact bundle.
///
/// The bundle retains exact content lineage across source, transformed source, semantic-match
/// evidence, and source-map outputs. It emits the canonical audit record last and constructs the
/// corresponding [`TransformRebinding`]. This is generated correlation evidence, not authority,
/// authentication, materialization, execution, compatibility proof, or certification.
#[derive(Eq, PartialEq)]
pub struct EmittedTransformArtifactBundle<'artifacts, 'map_emission, 'plan> {
    source: &'artifacts [u8],
    transformed_source: &'artifacts EmittedTransformedSource<'plan>,
    match_evidence: &'artifacts EmittedMatchEvidence<'plan>,
    source_map: &'artifacts EmittedSourceMap<'map_emission, 'plan>,
    audit_log: Vec<u8>,
    audit_log_digest: Sha256Digest,
    rebinding: TransformRebinding,
    total_bytes: usize,
}

impl fmt::Debug for EmittedTransformArtifactBundle<'_, '_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmittedTransformArtifactBundle")
            .field("rule_id", self.transformed_source.plan().rule_id())
            .field("source", self.transformed_source.plan().source())
            .field("match_evidence_digest", self.match_evidence.digest())
            .field(
                "transformed_source_digest",
                self.transformed_source.transformed_source_digest(),
            )
            .field("source_map_digest", self.source_map.digest())
            .field("audit_log_digest", &self.audit_log_digest)
            .field("audit_log_length", &self.audit_log.len())
            .field("total_bytes", &self.total_bytes)
            .finish()
    }
}

impl<'artifacts, 'map_emission, 'plan>
    EmittedTransformArtifactBundle<'artifacts, 'map_emission, 'plan>
{
    /// Returns the canonical compact UTF-8 audit-log JSON bytes.
    #[must_use]
    pub fn audit_log(&self) -> &[u8] {
        &self.audit_log
    }

    /// Returns the SHA-256 identity of the canonical audit-log bytes.
    #[must_use]
    pub const fn audit_log_digest(&self) -> &Sha256Digest {
        &self.audit_log_digest
    }

    /// Returns the exact generated rebinding for all five artifact identities.
    #[must_use]
    pub const fn rebinding(&self) -> &TransformRebinding {
        &self.rebinding
    }

    /// Returns borrowed bytes for all five artifact categories.
    #[must_use]
    pub fn artifacts(&self) -> TransformArtifactBytes<'_> {
        TransformArtifactBytes {
            source: self.source,
            match_evidence: self.match_evidence.bytes(),
            transformed_source: self.transformed_source.transformed_source(),
            source_map: self.source_map.bytes(),
            audit_log: &self.audit_log,
        }
    }

    /// Returns the checked aggregate byte length of all five artifact categories.
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Returns the exact transformed-source emission retained by this bundle.
    #[must_use]
    pub const fn transformed_source(&self) -> &'artifacts EmittedTransformedSource<'plan> {
        self.transformed_source
    }

    /// Returns the exact semantic-match evidence retained by this bundle.
    #[must_use]
    pub const fn match_evidence(&self) -> &'artifacts EmittedMatchEvidence<'plan> {
        self.match_evidence
    }

    /// Returns the exact source map retained by this bundle.
    #[must_use]
    pub const fn source_map(&self) -> &'artifacts EmittedSourceMap<'map_emission, 'plan> {
        self.source_map
    }
}

/// Emits a canonical audit record and assembles all five content-addressed artifacts.
///
/// Source length is bounded before hashing. Existing emitted artifacts must retain the exact same
/// plan and transformed-source content. Audit and aggregate lengths are computed and
/// checked before the sole audit allocation.
///
/// # Errors
///
/// Returns [`TransformBundleError`] when limits, source identity, artifact lineage, checked length
/// arithmetic, bounded allocation, or exact canonical emission fail.
pub fn assemble_transform_artifacts<'artifacts, 'map_emission, 'plan>(
    source: &'artifacts [u8],
    transformed_source: &'artifacts EmittedTransformedSource<'plan>,
    match_evidence: &'artifacts EmittedMatchEvidence<'plan>,
    source_map: &'artifacts EmittedSourceMap<'map_emission, 'plan>,
    limits: TransformBundleLimits,
) -> Result<EmittedTransformArtifactBundle<'artifacts, 'map_emission, 'plan>, TransformBundleError>
{
    if source.len() > limits.source {
        return Err(TransformBundleError::SourceTooLarge {
            actual_bytes: source.len(),
            max_bytes: limits.source,
        });
    }
    let plan = transformed_source.plan();
    if plan != match_evidence.plan() {
        return Err(TransformBundleError::ArtifactPlanMismatch);
    }
    if source_map.transformed_source() != transformed_source {
        return Err(TransformBundleError::SourceMapLineageMismatch);
    }
    if digest(source) != *plan.source().source_digest() {
        return Err(TransformBundleError::SourceDigestMismatch);
    }

    let edit_count_length = decimal_length(plan.edits().len());
    let audit_length = audit_length(
        plan.rule_id().as_str().len(),
        plan.source().unit_id().as_str().len(),
        edit_count_length,
    )?;
    if audit_length > limits.audit_log {
        return Err(TransformBundleError::AuditLogTooLarge {
            actual_bytes: audit_length,
            max_bytes: limits.audit_log,
        });
    }
    let total_bytes = aggregate_length(
        source.len(),
        match_evidence.bytes().len(),
        transformed_source.transformed_source().len(),
        source_map.bytes().len(),
        audit_length,
    )?;
    if total_bytes > limits.aggregate {
        return Err(TransformBundleError::AggregateTooLarge {
            actual_bytes: total_bytes,
            max_bytes: limits.aggregate,
        });
    }

    let mut audit_log = Vec::new();
    audit_log.try_reserve_exact(audit_length).map_err(|_| {
        TransformBundleError::AllocationFailed {
            requested_bytes: audit_length,
        }
    })?;
    audit_log.extend_from_slice(AUDIT_PREFIX);
    audit_log.extend_from_slice(plan.rule_id().as_str().as_bytes());
    audit_log.extend_from_slice(AUDIT_RULE_DIGEST);
    append_digest(&mut audit_log, plan.rule_digest());
    audit_log.extend_from_slice(AUDIT_SOURCE);
    audit_log.extend_from_slice(plan.source().unit_id().as_str().as_bytes());
    audit_log.extend_from_slice(AUDIT_SOURCE_DIGEST);
    append_digest(&mut audit_log, plan.source().source_digest());
    audit_log.extend_from_slice(AUDIT_MATCH_EVIDENCE);
    append_digest(&mut audit_log, match_evidence.digest());
    audit_log.extend_from_slice(AUDIT_TRANSFORMED_SOURCE);
    append_digest(
        &mut audit_log,
        transformed_source.transformed_source_digest(),
    );
    audit_log.extend_from_slice(AUDIT_SOURCE_MAP);
    append_digest(&mut audit_log, source_map.digest());
    audit_log.extend_from_slice(AUDIT_EDIT_COUNT);
    audit_log.extend_from_slice(plan.edits().len().to_string().as_bytes());
    audit_log.extend_from_slice(AUDIT_SUFFIX);
    if audit_log.len() != audit_length {
        return Err(TransformBundleError::AuditLengthMismatch {
            expected_bytes: audit_length,
            actual_bytes: audit_log.len(),
        });
    }

    let audit_log_digest = digest(&audit_log);
    let rebinding = TransformRebinding::new(
        *plan.rule_digest(),
        plan.source().clone(),
        *match_evidence.digest(),
        *transformed_source.transformed_source_digest(),
        *source_map.digest(),
        audit_log_digest,
    );

    Ok(EmittedTransformArtifactBundle {
        source,
        transformed_source,
        match_evidence,
        source_map,
        audit_log,
        audit_log_digest,
        rebinding,
        total_bytes,
    })
}

fn audit_length(
    rule_id_length: usize,
    source_unit_id_length: usize,
    edit_count_length: usize,
) -> Result<usize, TransformBundleError> {
    let mut length = 0_usize;
    for fixed in [
        AUDIT_PREFIX,
        AUDIT_RULE_DIGEST,
        AUDIT_SOURCE,
        AUDIT_SOURCE_DIGEST,
        AUDIT_MATCH_EVIDENCE,
        AUDIT_TRANSFORMED_SOURCE,
        AUDIT_SOURCE_MAP,
        AUDIT_EDIT_COUNT,
        AUDIT_SUFFIX,
    ] {
        length = length
            .checked_add(fixed.len())
            .ok_or(TransformBundleError::AuditLengthOverflow)?;
    }
    for variable in [
        rule_id_length,
        source_unit_id_length,
        DIGEST_TEXT_LENGTH,
        DIGEST_TEXT_LENGTH,
        DIGEST_TEXT_LENGTH,
        DIGEST_TEXT_LENGTH,
        DIGEST_TEXT_LENGTH,
        edit_count_length,
    ] {
        length = length
            .checked_add(variable)
            .ok_or(TransformBundleError::AuditLengthOverflow)?;
    }
    Ok(length)
}

fn aggregate_length(
    source: usize,
    match_evidence: usize,
    transformed_source: usize,
    source_map: usize,
    audit_log: usize,
) -> Result<usize, TransformBundleError> {
    let mut total = 0_usize;
    for length in [
        source,
        match_evidence,
        transformed_source,
        source_map,
        audit_log,
    ] {
        total = total
            .checked_add(length)
            .ok_or(TransformBundleError::AggregateLengthOverflow)?;
    }
    Ok(total)
}

fn decimal_length(mut value: usize) -> usize {
    let mut length = 1_usize;
    while value >= 10 {
        value /= 10;
        length += 1;
    }
    length
}

fn append_digest(output: &mut Vec<u8>, value: &Sha256Digest) {
    output.extend_from_slice(value.to_string().as_bytes());
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

/// Failure emitting the canonical audit record or assembling a complete artifact bundle.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransformBundleError {
    /// One or more caller-selected limits were zero.
    #[error("transform bundle limits must be nonzero")]
    InvalidLimits,
    /// Source exceeded the caller-selected pre-hash limit.
    #[error("source is {actual_bytes} bytes; bundle limit is {max_bytes}")]
    SourceTooLarge {
        /// Exact supplied source length.
        actual_bytes: usize,
        /// Caller-selected source limit.
        max_bytes: usize,
    },
    /// Semantic-match evidence did not retain the exact transformed-source plan content.
    #[error("emitted artifacts do not share the exact transform plan content")]
    ArtifactPlanMismatch,
    /// Source-map evidence did not retain the exact transformed-source content.
    #[error("source map does not share the exact transformed-source content")]
    SourceMapLineageMismatch,
    /// Supplied source did not match the exact retained plan source digest.
    #[error("source bytes do not match the transform plan source digest")]
    SourceDigestMismatch,
    /// Checked canonical audit length arithmetic overflowed.
    #[error("audit-log length overflowed the platform byte index")]
    AuditLengthOverflow,
    /// Canonical audit bytes exceeded the caller-selected pre-allocation limit.
    #[error("audit log is {actual_bytes} bytes; bundle limit is {max_bytes}")]
    AuditLogTooLarge {
        /// Exact computed audit-log length.
        actual_bytes: usize,
        /// Caller-selected audit-log limit.
        max_bytes: usize,
    },
    /// Checked aggregate artifact length arithmetic overflowed.
    #[error("aggregate artifact length overflowed the platform byte index")]
    AggregateLengthOverflow,
    /// Aggregate bytes exceeded the caller-selected pre-allocation limit.
    #[error("artifact bundle is {actual_bytes} bytes; aggregate limit is {max_bytes}")]
    AggregateTooLarge {
        /// Exact aggregate artifact length.
        actual_bytes: usize,
        /// Caller-selected aggregate limit.
        max_bytes: usize,
    },
    /// Exact-capacity audit-log allocation failed.
    #[error("could not allocate {requested_bytes} audit-log bytes")]
    AllocationFailed {
        /// Exact requested audit-log capacity.
        requested_bytes: usize,
    },
    /// Emitted audit length differed from its exact precomputed length.
    #[error("emitted {actual_bytes} audit-log bytes; expected {expected_bytes}")]
    AuditLengthMismatch {
        /// Exact precomputed audit length.
        expected_bytes: usize,
        /// Actual emitted audit length.
        actual_bytes: usize,
    },
}
