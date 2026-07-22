//! Deterministic, bounded in-memory emission from parser-backed transform plans.

use std::fmt;

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use weregopher_domain::Sha256Digest;

use crate::TransformPlan;

const DIGEST_TEXT_LENGTH: usize = 71;
const EVIDENCE_PREFIX: &[u8] =
    br#"{"format_version":"1","kind":"static_module_specifier_matches","rule_id":""#;
const EVIDENCE_RULE_DIGEST: &[u8] = br#"","rule_digest":""#;
const EVIDENCE_SOURCE_UNIT: &[u8] = br#"","source":{"unit_id":""#;
const EVIDENCE_SOURCE_DIGEST: &[u8] = br#"","source_digest":""#;
const EVIDENCE_MATCHES: &[u8] = br#""},"matches":["#;
const MATCH_START: &[u8] = br#"{"start_byte":"#;
const MATCH_END: &[u8] = br#","end_byte":"#;
const EVIDENCE_SUFFIX: &[u8] = b"]}";
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

/// Caller-selected byte limits for one transformed-source emission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransformEmissionLimits {
    source_bytes: usize,
    transformed_source_bytes: usize,
}

impl TransformEmissionLimits {
    /// Constructs nonzero source and transformed-output limits.
    ///
    /// # Errors
    ///
    /// Returns [`TransformEmissionError::InvalidLimits`] when either limit is zero.
    pub const fn new(
        max_source_bytes: usize,
        max_transformed_source_bytes: usize,
    ) -> Result<Self, TransformEmissionError> {
        if max_source_bytes == 0 || max_transformed_source_bytes == 0 {
            return Err(TransformEmissionError::InvalidLimits);
        }
        Ok(Self {
            source_bytes: max_source_bytes,
            transformed_source_bytes: max_transformed_source_bytes,
        })
    }
}

/// Owned transformed source emitted from one exact in-memory plan.
///
/// This value proves only deterministic application of the retained edits to source bytes matching
/// the plan's content identity. It does not authenticate the plan or source, materialize files, or
/// authorize transformation, execution, launch, or certification.
#[derive(Eq, PartialEq)]
pub struct EmittedTransformedSource<'plan> {
    plan: &'plan TransformPlan,
    transformed_source: Vec<u8>,
    transformed_source_digest: Sha256Digest,
}

impl fmt::Debug for EmittedTransformedSource<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmittedTransformedSource")
            .field("rule_id", self.plan.rule_id())
            .field("source", self.plan.source())
            .field("transformed_source_length", &self.transformed_source.len())
            .field("transformed_source_digest", &self.transformed_source_digest)
            .finish()
    }
}

impl<'plan> EmittedTransformedSource<'plan> {
    /// Returns the exact in-memory plan applied to produce these bytes.
    #[must_use]
    pub const fn plan(&self) -> &'plan TransformPlan {
        self.plan
    }

    /// Returns the emitted transformed-source bytes.
    #[must_use]
    pub fn transformed_source(&self) -> &[u8] {
        &self.transformed_source
    }

    /// Returns the SHA-256 identity of the emitted transformed-source bytes.
    #[must_use]
    pub const fn transformed_source_digest(&self) -> &Sha256Digest {
        &self.transformed_source_digest
    }
}

/// Applies one exact transform plan to immutable source bytes entirely in memory.
///
/// Source and output lengths are bounded before hashing or output allocation respectively. The
/// source digest is checked against the plan before any edit is applied. This function performs no
/// filesystem access, materialization, authentication, execution, or authorization decision.
///
/// # Errors
///
/// Returns [`TransformEmissionError`] when source identity, limits, edit ranges, output arithmetic,
/// or bounded allocation fails.
pub fn emit_transformed_source<'plan>(
    plan: &'plan TransformPlan,
    source: &[u8],
    limits: TransformEmissionLimits,
) -> Result<EmittedTransformedSource<'plan>, TransformEmissionError> {
    if source.len() > limits.source_bytes {
        return Err(TransformEmissionError::SourceTooLarge {
            actual_bytes: source.len(),
            max_bytes: limits.source_bytes,
        });
    }
    if digest(source) != *plan.source().source_digest() {
        return Err(TransformEmissionError::SourceDigestMismatch);
    }

    let mut transformed_length = source.len();
    let mut previous_end = 0_usize;
    for edit in plan.edits() {
        let start = usize::try_from(edit.start_byte()).map_err(|_| {
            TransformEmissionError::EditOffsetOutOfRange {
                offset: edit.start_byte(),
            }
        })?;
        let end = usize::try_from(edit.end_byte()).map_err(|_| {
            TransformEmissionError::EditOffsetOutOfRange {
                offset: edit.end_byte(),
            }
        })?;
        if start < previous_end || end < start || end > source.len() {
            return Err(TransformEmissionError::InvalidEditRange {
                start_byte: edit.start_byte(),
                end_byte: edit.end_byte(),
                previous_end,
                source_bytes: source.len(),
            });
        }
        transformed_length = transformed_length
            .checked_sub(end - start)
            .and_then(|length| length.checked_add(edit.replacement().len()))
            .ok_or(TransformEmissionError::TransformedSourceLengthOverflow)?;
        previous_end = end;
    }
    if transformed_length > limits.transformed_source_bytes {
        return Err(TransformEmissionError::TransformedSourceTooLarge {
            actual_bytes: transformed_length,
            max_bytes: limits.transformed_source_bytes,
        });
    }

    let mut transformed_source = Vec::new();
    transformed_source
        .try_reserve_exact(transformed_length)
        .map_err(|_| TransformEmissionError::AllocationFailed {
            requested_bytes: transformed_length,
        })?;
    let mut source_cursor = 0_usize;
    for edit in plan.edits() {
        let start = usize::try_from(edit.start_byte()).map_err(|_| {
            TransformEmissionError::EditOffsetOutOfRange {
                offset: edit.start_byte(),
            }
        })?;
        let end = usize::try_from(edit.end_byte()).map_err(|_| {
            TransformEmissionError::EditOffsetOutOfRange {
                offset: edit.end_byte(),
            }
        })?;
        let unchanged =
            source
                .get(source_cursor..start)
                .ok_or(TransformEmissionError::InvalidEditRange {
                    start_byte: edit.start_byte(),
                    end_byte: edit.end_byte(),
                    previous_end: source_cursor,
                    source_bytes: source.len(),
                })?;
        transformed_source.extend_from_slice(unchanged);
        transformed_source.extend_from_slice(edit.replacement().as_bytes());
        source_cursor = end;
    }
    let tail = source
        .get(source_cursor..)
        .ok_or(TransformEmissionError::InvalidTailOffset {
            source_cursor,
            source_bytes: source.len(),
        })?;
    transformed_source.extend_from_slice(tail);
    if transformed_source.len() != transformed_length {
        return Err(TransformEmissionError::EmittedLengthMismatch {
            expected_bytes: transformed_length,
            actual_bytes: transformed_source.len(),
        });
    }
    let transformed_source_digest = digest(&transformed_source);

    Ok(EmittedTransformedSource {
        plan,
        transformed_source,
        transformed_source_digest,
    })
}

/// Caller-selected byte limit for canonical semantic-match evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatchEvidenceLimits {
    evidence_bytes: usize,
}

impl MatchEvidenceLimits {
    /// Constructs a nonzero canonical-evidence byte limit.
    ///
    /// # Errors
    ///
    /// Returns [`MatchEvidenceError::InvalidLimit`] when the limit is zero.
    pub const fn new(max_evidence_bytes: usize) -> Result<Self, MatchEvidenceError> {
        if max_evidence_bytes == 0 {
            return Err(MatchEvidenceError::InvalidLimit);
        }
        Ok(Self {
            evidence_bytes: max_evidence_bytes,
        })
    }
}

/// Canonical semantic-match evidence emitted from one exact transform plan.
///
/// The evidence records stable identities and parser-selected byte ranges. It does not contain
/// source bytes, authenticate the plan, prove matcher correctness, or authorize later effects.
#[derive(Eq, PartialEq)]
pub struct EmittedMatchEvidence<'plan> {
    plan: &'plan TransformPlan,
    bytes: Vec<u8>,
    digest: Sha256Digest,
}

impl fmt::Debug for EmittedMatchEvidence<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmittedMatchEvidence")
            .field("rule_id", self.plan.rule_id())
            .field("source", self.plan.source())
            .field("evidence_length", &self.bytes.len())
            .field("evidence_digest", &self.digest)
            .finish()
    }
}

impl<'plan> EmittedMatchEvidence<'plan> {
    /// Returns the exact plan whose semantic matches are recorded.
    #[must_use]
    pub const fn plan(&self) -> &'plan TransformPlan {
        self.plan
    }

    /// Returns canonical compact UTF-8 JSON evidence bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the SHA-256 identity of the canonical evidence bytes.
    #[must_use]
    pub const fn digest(&self) -> &Sha256Digest {
        &self.digest
    }
}

/// Emits canonical semantic-match evidence for one exact transform plan.
///
/// The exact output length is computed and checked before fallible allocation. Stable identifiers
/// are emitted directly because their domain grammar excludes JSON metacharacters; digest and
/// decimal encodings are written without intermediate allocations.
///
/// # Errors
///
/// Returns [`MatchEvidenceError`] when output length arithmetic, limits, allocation, or canonical
/// numeric encoding fails.
pub fn emit_match_evidence(
    plan: &TransformPlan,
    limits: MatchEvidenceLimits,
) -> Result<EmittedMatchEvidence<'_>, MatchEvidenceError> {
    let evidence_length = match_evidence_length(plan)?;
    if evidence_length > limits.evidence_bytes {
        return Err(MatchEvidenceError::EvidenceTooLarge {
            actual_bytes: evidence_length,
            max_bytes: limits.evidence_bytes,
        });
    }

    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(evidence_length)
        .map_err(|_| MatchEvidenceError::AllocationFailed {
            requested_bytes: evidence_length,
        })?;
    bytes.extend_from_slice(EVIDENCE_PREFIX);
    bytes.extend_from_slice(plan.rule_id().as_str().as_bytes());
    bytes.extend_from_slice(EVIDENCE_RULE_DIGEST);
    append_digest(&mut bytes, plan.rule_digest());
    bytes.extend_from_slice(EVIDENCE_SOURCE_UNIT);
    bytes.extend_from_slice(plan.source().unit_id().as_str().as_bytes());
    bytes.extend_from_slice(EVIDENCE_SOURCE_DIGEST);
    append_digest(&mut bytes, plan.source().source_digest());
    bytes.extend_from_slice(EVIDENCE_MATCHES);
    for (index, edit) in plan.edits().iter().enumerate() {
        if index > 0 {
            bytes.push(b',');
        }
        bytes.extend_from_slice(MATCH_START);
        append_u32(&mut bytes, edit.start_byte())?;
        bytes.extend_from_slice(MATCH_END);
        append_u32(&mut bytes, edit.end_byte())?;
        bytes.push(b'}');
    }
    bytes.extend_from_slice(EVIDENCE_SUFFIX);
    if bytes.len() != evidence_length {
        return Err(MatchEvidenceError::EmittedLengthMismatch {
            expected_bytes: evidence_length,
            actual_bytes: bytes.len(),
        });
    }
    let digest = digest(&bytes);
    Ok(EmittedMatchEvidence {
        plan,
        bytes,
        digest,
    })
}

fn match_evidence_length(plan: &TransformPlan) -> Result<usize, MatchEvidenceError> {
    let mut length = 0_usize;
    for fixed in [
        EVIDENCE_PREFIX,
        EVIDENCE_RULE_DIGEST,
        EVIDENCE_SOURCE_UNIT,
        EVIDENCE_SOURCE_DIGEST,
        EVIDENCE_MATCHES,
        EVIDENCE_SUFFIX,
    ] {
        length = checked_evidence_add(length, fixed.len())?;
    }
    length = checked_evidence_add(length, plan.rule_id().as_str().len())?;
    length = checked_evidence_add(length, DIGEST_TEXT_LENGTH)?;
    length = checked_evidence_add(length, plan.source().unit_id().as_str().len())?;
    length = checked_evidence_add(length, DIGEST_TEXT_LENGTH)?;
    for (index, edit) in plan.edits().iter().enumerate() {
        if index > 0 {
            length = checked_evidence_add(length, 1)?;
        }
        length = checked_evidence_add(length, MATCH_START.len())?;
        length = checked_evidence_add(length, decimal_length(edit.start_byte()))?;
        length = checked_evidence_add(length, MATCH_END.len())?;
        length = checked_evidence_add(length, decimal_length(edit.end_byte()))?;
        length = checked_evidence_add(length, 1)?;
    }
    Ok(length)
}

fn checked_evidence_add(current: usize, additional: usize) -> Result<usize, MatchEvidenceError> {
    current
        .checked_add(additional)
        .ok_or(MatchEvidenceError::EvidenceLengthOverflow)
}

fn decimal_length(mut value: u32) -> usize {
    let mut length = 1_usize;
    while value >= 10 {
        value /= 10;
        length += 1;
    }
    length
}

fn append_u32(output: &mut Vec<u8>, mut value: u32) -> Result<(), MatchEvidenceError> {
    let mut encoded = [0_u8; 10];
    let mut position = encoded.len();
    loop {
        position = position
            .checked_sub(1)
            .ok_or(MatchEvidenceError::IntegerEncodingFailed)?;
        let slot = encoded
            .get_mut(position)
            .ok_or(MatchEvidenceError::IntegerEncodingFailed)?;
        *slot = b'0'
            + u8::try_from(value % 10).map_err(|_| MatchEvidenceError::IntegerEncodingFailed)?;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    output.extend_from_slice(
        encoded
            .get(position..)
            .ok_or(MatchEvidenceError::IntegerEncodingFailed)?,
    );
    Ok(())
}

fn append_digest(output: &mut Vec<u8>, value: &Sha256Digest) {
    output.extend_from_slice(b"sha256:");
    for byte in value.as_bytes() {
        output.push(LOWER_HEX[usize::from(byte >> 4)]);
        output.push(LOWER_HEX[usize::from(byte & 0x0f)]);
    }
}

/// Failure emitting canonical semantic-match evidence.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MatchEvidenceError {
    /// The caller-selected evidence limit was zero.
    #[error("match-evidence byte limit must be nonzero")]
    InvalidLimit,
    /// Checked canonical-evidence length arithmetic overflowed.
    #[error("match-evidence length overflowed the platform byte index")]
    EvidenceLengthOverflow,
    /// Canonical evidence exceeded the caller-selected pre-allocation limit.
    #[error("match evidence is {actual_bytes} bytes; emission limit is {max_bytes}")]
    EvidenceTooLarge {
        /// Exact computed evidence length.
        actual_bytes: usize,
        /// Caller-selected evidence limit.
        max_bytes: usize,
    },
    /// Bounded canonical-evidence allocation failed.
    #[error("could not allocate {requested_bytes} bytes for match evidence")]
    AllocationFailed {
        /// Exact precomputed allocation request.
        requested_bytes: usize,
    },
    /// A bounded decimal byte offset could not be encoded.
    #[error("could not encode a match-evidence byte offset")]
    IntegerEncodingFailed,
    /// Emitted bytes differed from the precomputed exact length.
    #[error("emitted {actual_bytes} evidence bytes; expected {expected_bytes}")]
    EmittedLengthMismatch {
        /// Precomputed exact evidence length.
        expected_bytes: usize,
        /// Actual emitted evidence length.
        actual_bytes: usize,
    },
}

/// Failure emitting transformed source from one exact in-memory plan.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransformEmissionError {
    /// One or more caller-selected byte limits were zero.
    #[error("transform emission limits must be nonzero")]
    InvalidLimits,
    /// Source bytes exceeded the caller-selected pre-hash limit.
    #[error("source is {actual_bytes} bytes; emission limit is {max_bytes}")]
    SourceTooLarge {
        /// Actual supplied source length.
        actual_bytes: usize,
        /// Caller-selected source limit.
        max_bytes: usize,
    },
    /// Supplied source bytes did not match the plan's source content identity.
    #[error("source bytes do not match the transform plan source digest")]
    SourceDigestMismatch,
    /// One plan edit offset could not be represented by this platform.
    #[error("transform edit offset {offset} cannot be represented on this platform")]
    EditOffsetOutOfRange {
        /// Parser-produced byte offset.
        offset: u32,
    },
    /// Plan edits were overlapping, unordered, reversed, or outside the exact source.
    #[error(
        "invalid transform edit {start_byte}..{end_byte}; previous end is {previous_end}, source is {source_bytes} bytes"
    )]
    InvalidEditRange {
        /// Inclusive edit start.
        start_byte: u32,
        /// Exclusive edit end.
        end_byte: u32,
        /// End of the prior edit in source bytes.
        previous_end: usize,
        /// Exact supplied source length.
        source_bytes: usize,
    },
    /// The validated final edit offset was outside the exact source.
    #[error("invalid transform tail offset {source_cursor}; source is {source_bytes} bytes")]
    InvalidTailOffset {
        /// End of the final edit.
        source_cursor: usize,
        /// Exact supplied source length.
        source_bytes: usize,
    },
    /// Checked transformed-source length arithmetic overflowed.
    #[error("transformed-source length overflowed the platform byte index")]
    TransformedSourceLengthOverflow,
    /// Transformed source exceeded the caller-selected pre-allocation limit.
    #[error("transformed source is {actual_bytes} bytes; emission limit is {max_bytes}")]
    TransformedSourceTooLarge {
        /// Exact computed output length.
        actual_bytes: usize,
        /// Caller-selected transformed-source limit.
        max_bytes: usize,
    },
    /// Bounded transformed-source allocation failed.
    #[error("could not allocate {requested_bytes} bytes for transformed source")]
    AllocationFailed {
        /// Exact precomputed allocation request.
        requested_bytes: usize,
    },
    /// Emitted bytes differed from the precomputed exact length.
    #[error("emitted {actual_bytes} transformed bytes; expected {expected_bytes}")]
    EmittedLengthMismatch {
        /// Precomputed exact output length.
        expected_bytes: usize,
        /// Actual emitted output length.
        actual_bytes: usize,
    },
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}
