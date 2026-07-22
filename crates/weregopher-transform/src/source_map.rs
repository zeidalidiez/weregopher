//! Deterministic Source Map v3 emission for in-memory transformed source.

use std::{fmt, str};

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use weregopher_domain::Sha256Digest;

use crate::EmittedTransformedSource;

const DIGEST_TEXT_LENGTH: usize = 71;
const MAP_PREFIX: &[u8] = br#"{"version":3,"sources":[""#;
const MAP_MAPPINGS: &[u8] = br#""],"names":[],"mappings":""#;
const MAP_EXTENSION: &[u8] = br#"","x_weregopher":{"format_version":"1","rule_id":""#;
const MAP_RULE_DIGEST: &[u8] = br#"","rule_digest":""#;
const MAP_SOURCE_DIGEST: &[u8] = br#"","source_digest":""#;
const MAP_TRANSFORMED_DIGEST: &[u8] = br#"","transformed_source_digest":""#;
const MAP_SUFFIX: &[u8] = b"\"}}";
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Caller-selected bounds for one deterministic source-map emission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceMapLimits {
    source_bytes: usize,
    transformed_source_bytes: usize,
    segments: usize,
    source_map_bytes: usize,
}

impl SourceMapLimits {
    /// Constructs nonzero source, transformed-source, segment, and output limits.
    ///
    /// # Errors
    ///
    /// Returns [`SourceMapError::InvalidLimits`] when any limit is zero.
    pub const fn new(
        max_source_bytes: usize,
        max_transformed_source_bytes: usize,
        max_segments: usize,
        max_source_map_bytes: usize,
    ) -> Result<Self, SourceMapError> {
        if max_source_bytes == 0
            || max_transformed_source_bytes == 0
            || max_segments == 0
            || max_source_map_bytes == 0
        {
            return Err(SourceMapError::InvalidLimits);
        }
        Ok(Self {
            source_bytes: max_source_bytes,
            transformed_source_bytes: max_transformed_source_bytes,
            segments: max_segments,
            source_map_bytes: max_source_map_bytes,
        })
    }
}

/// Canonical Source Map v3 bytes for one emitted transformed source.
///
/// The map retains no source content. Its extension binds the map to exact rule, source, and
/// transformed-source identities. This is correlation evidence, not authentication or authority.
#[derive(Eq, PartialEq)]
pub struct EmittedSourceMap<'emission, 'plan> {
    transformed_source: &'emission EmittedTransformedSource<'plan>,
    bytes: Vec<u8>,
    digest: Sha256Digest,
    segment_count: usize,
}

impl fmt::Debug for EmittedSourceMap<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmittedSourceMap")
            .field("rule_id", self.transformed_source.plan().rule_id())
            .field("source", self.transformed_source.plan().source())
            .field("source_map_length", &self.bytes.len())
            .field("source_map_digest", &self.digest)
            .field("segment_count", &self.segment_count)
            .finish()
    }
}

impl<'emission, 'plan> EmittedSourceMap<'emission, 'plan> {
    /// Returns the exact transformed-source result represented by this map.
    #[must_use]
    pub const fn transformed_source(&self) -> &'emission EmittedTransformedSource<'plan> {
        self.transformed_source
    }

    /// Returns canonical compact UTF-8 Source Map v3 JSON bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the SHA-256 identity of the canonical source-map bytes.
    #[must_use]
    pub const fn digest(&self) -> &Sha256Digest {
        &self.digest
    }

    /// Returns the number of retained mapping segments.
    #[must_use]
    pub const fn segment_count(&self) -> usize {
        self.segment_count
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ByteAnchor {
    generated: usize,
    original: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LineColumn {
    line: usize,
    column: usize,
}

/// Emits a canonical Source Map v3 document for one in-memory transformed source.
///
/// A segment is retained at every generated line start and at both sides of every replacement.
/// Columns are counted in UTF-16 code units, and CRLF, CR, LF, U+2028, and U+2029 are treated as
/// line terminators. `sourcesContent` is intentionally omitted to avoid copying proprietary source.
///
/// # Errors
///
/// Returns [`SourceMapError`] when identities, UTF-8, limits, mapping invariants, arithmetic,
/// canonical VLQ encoding, or bounded allocation fail.
pub fn emit_source_map<'emission, 'plan>(
    transformed_source: &'emission EmittedTransformedSource<'plan>,
    source: &[u8],
    limits: SourceMapLimits,
) -> Result<EmittedSourceMap<'emission, 'plan>, SourceMapError> {
    if source.len() > limits.source_bytes {
        return Err(SourceMapError::SourceTooLarge {
            actual_bytes: source.len(),
            max_bytes: limits.source_bytes,
        });
    }
    if transformed_source.transformed_source().len() > limits.transformed_source_bytes {
        return Err(SourceMapError::TransformedSourceTooLarge {
            actual_bytes: transformed_source.transformed_source().len(),
            max_bytes: limits.transformed_source_bytes,
        });
    }
    let plan = transformed_source.plan();
    if digest(source) != *plan.source().source_digest() {
        return Err(SourceMapError::SourceDigestMismatch);
    }
    let source_text = str::from_utf8(source).map_err(|_| SourceMapError::SourceNotUtf8)?;
    let transformed_text = str::from_utf8(transformed_source.transformed_source())
        .map_err(|_| SourceMapError::TransformedSourceNotUtf8)?;

    let line_count = count_line_starts(source_text)?;
    let edit_segments = plan
        .edits()
        .len()
        .checked_mul(2)
        .ok_or(SourceMapError::SegmentCountOverflow)?;
    let required_segments = line_count
        .checked_add(edit_segments)
        .ok_or(SourceMapError::SegmentCountOverflow)?;
    if required_segments > limits.segments {
        return Err(SourceMapError::SegmentLimitExceeded {
            required_segments,
            max_segments: limits.segments,
        });
    }

    let line_starts = collect_line_starts(source_text, line_count)?;
    let mut anchors = allocate_vec(required_segments, "source-map anchors")?;
    append_line_anchors(&mut anchors, &line_starts, plan)?;
    append_edit_anchors(&mut anchors, plan, source.len())?;
    anchors.sort_unstable();
    anchors.dedup();
    for pair in anchors.windows(2) {
        let first = pair.first().ok_or(SourceMapError::AnchorOrderingFailed)?;
        let second = pair.get(1).ok_or(SourceMapError::AnchorOrderingFailed)?;
        if first.generated == second.generated && first.original != second.original {
            return Err(SourceMapError::AmbiguousGeneratedAnchor {
                generated_byte: first.generated,
            });
        }
    }

    let generated_positions = resolve_positions(
        transformed_text,
        &anchors,
        |anchor| anchor.generated,
        "generated positions",
    )?;
    let original_positions = resolve_positions(
        source_text,
        &anchors,
        |anchor| anchor.original,
        "original positions",
    )?;
    let mappings_length = mappings_length(&generated_positions, &original_positions)?;
    let map_length = source_map_length(
        mappings_length,
        plan.source().unit_id().as_str().len(),
        plan.rule_id().as_str().len(),
    )?;
    if map_length > limits.source_map_bytes {
        return Err(SourceMapError::SourceMapTooLarge {
            actual_bytes: map_length,
            max_bytes: limits.source_map_bytes,
        });
    }

    let mut bytes = allocate_vec(map_length, "source-map bytes")?;
    bytes.extend_from_slice(MAP_PREFIX);
    bytes.extend_from_slice(plan.source().unit_id().as_str().as_bytes());
    bytes.extend_from_slice(MAP_MAPPINGS);
    append_mappings(&mut bytes, &generated_positions, &original_positions)?;
    bytes.extend_from_slice(MAP_EXTENSION);
    bytes.extend_from_slice(plan.rule_id().as_str().as_bytes());
    bytes.extend_from_slice(MAP_RULE_DIGEST);
    append_digest(&mut bytes, plan.rule_digest());
    bytes.extend_from_slice(MAP_SOURCE_DIGEST);
    append_digest(&mut bytes, plan.source().source_digest());
    bytes.extend_from_slice(MAP_TRANSFORMED_DIGEST);
    append_digest(&mut bytes, transformed_source.transformed_source_digest());
    bytes.extend_from_slice(MAP_SUFFIX);
    if bytes.len() != map_length {
        return Err(SourceMapError::EmittedLengthMismatch {
            expected_bytes: map_length,
            actual_bytes: bytes.len(),
        });
    }
    let map_digest = digest(&bytes);

    Ok(EmittedSourceMap {
        transformed_source,
        bytes,
        digest: map_digest,
        segment_count: anchors.len(),
    })
}

fn count_line_starts(text: &str) -> Result<usize, SourceMapError> {
    let mut count = 1_usize;
    let mut previous_was_cr = false;
    for character in text.chars() {
        match character {
            '\r' => {
                count = count
                    .checked_add(1)
                    .ok_or(SourceMapError::SegmentCountOverflow)?;
                previous_was_cr = true;
            }
            '\n' if previous_was_cr => previous_was_cr = false,
            '\n' | '\u{2028}' | '\u{2029}' => {
                count = count
                    .checked_add(1)
                    .ok_or(SourceMapError::SegmentCountOverflow)?;
                previous_was_cr = false;
            }
            _ => previous_was_cr = false,
        }
    }
    Ok(count)
}

fn collect_line_starts(text: &str, count: usize) -> Result<Vec<usize>, SourceMapError> {
    let mut starts = allocate_vec(count, "source line starts")?;
    starts.push(0);
    let mut previous_was_cr = false;
    for (index, character) in text.char_indices() {
        match character {
            '\r' => {
                starts.push(
                    index
                        .checked_add(character.len_utf8())
                        .ok_or(SourceMapError::OffsetOverflow)?,
                );
                previous_was_cr = true;
            }
            '\n' if previous_was_cr => {
                let last = starts
                    .last_mut()
                    .ok_or(SourceMapError::LineStartCollectionFailed)?;
                *last = index
                    .checked_add(character.len_utf8())
                    .ok_or(SourceMapError::OffsetOverflow)?;
                previous_was_cr = false;
            }
            '\n' | '\u{2028}' | '\u{2029}' => {
                starts.push(
                    index
                        .checked_add(character.len_utf8())
                        .ok_or(SourceMapError::OffsetOverflow)?,
                );
                previous_was_cr = false;
            }
            _ => previous_was_cr = false,
        }
    }
    if starts.len() != count {
        return Err(SourceMapError::LineStartCountMismatch {
            expected: count,
            actual: starts.len(),
        });
    }
    Ok(starts)
}

fn append_line_anchors(
    anchors: &mut Vec<ByteAnchor>,
    line_starts: &[usize],
    plan: &crate::TransformPlan,
) -> Result<(), SourceMapError> {
    let mut edit_index = 0_usize;
    let mut removed_bytes = 0_usize;
    let mut replacement_bytes = 0_usize;
    for &original in line_starts {
        while let Some(edit) = plan.edits().get(edit_index) {
            let start = usize::try_from(edit.start_byte())
                .map_err(|_| SourceMapError::EditOffsetOutOfRange(edit.start_byte()))?;
            let end = usize::try_from(edit.end_byte())
                .map_err(|_| SourceMapError::EditOffsetOutOfRange(edit.end_byte()))?;
            if end > original {
                if start < original {
                    return Err(SourceMapError::LineStartInsideEdit {
                        line_start: original,
                        edit_start: start,
                        edit_end: end,
                    });
                }
                break;
            }
            removed_bytes = removed_bytes
                .checked_add(
                    end.checked_sub(start)
                        .ok_or(SourceMapError::InvalidEditRange)?,
                )
                .ok_or(SourceMapError::OffsetOverflow)?;
            replacement_bytes = replacement_bytes
                .checked_add(edit.replacement().len())
                .ok_or(SourceMapError::OffsetOverflow)?;
            edit_index = edit_index
                .checked_add(1)
                .ok_or(SourceMapError::OffsetOverflow)?;
        }
        let generated = original
            .checked_sub(removed_bytes)
            .and_then(|offset| offset.checked_add(replacement_bytes))
            .ok_or(SourceMapError::OffsetOverflow)?;
        anchors.push(ByteAnchor {
            generated,
            original,
        });
    }
    Ok(())
}

fn append_edit_anchors(
    anchors: &mut Vec<ByteAnchor>,
    plan: &crate::TransformPlan,
    source_bytes: usize,
) -> Result<(), SourceMapError> {
    let mut source_cursor = 0_usize;
    let mut generated_cursor = 0_usize;
    for edit in plan.edits() {
        let start = usize::try_from(edit.start_byte())
            .map_err(|_| SourceMapError::EditOffsetOutOfRange(edit.start_byte()))?;
        let end = usize::try_from(edit.end_byte())
            .map_err(|_| SourceMapError::EditOffsetOutOfRange(edit.end_byte()))?;
        if start < source_cursor || end < start || end > source_bytes {
            return Err(SourceMapError::InvalidEditRange);
        }
        let generated_start = generated_cursor
            .checked_add(start - source_cursor)
            .ok_or(SourceMapError::OffsetOverflow)?;
        let generated_end = generated_start
            .checked_add(edit.replacement().len())
            .ok_or(SourceMapError::OffsetOverflow)?;
        anchors.push(ByteAnchor {
            generated: generated_start,
            original: start,
        });
        anchors.push(ByteAnchor {
            generated: generated_end,
            original: end,
        });
        source_cursor = end;
        generated_cursor = generated_end;
    }
    Ok(())
}

fn resolve_positions<F>(
    text: &str,
    anchors: &[ByteAnchor],
    offset: F,
    purpose: &'static str,
) -> Result<Vec<LineColumn>, SourceMapError>
where
    F: Fn(&ByteAnchor) -> usize,
{
    let mut positions = allocate_vec(anchors.len(), purpose)?;
    let mut characters = text.char_indices();
    let mut next_character = characters.next();
    let mut byte_cursor = 0_usize;
    let mut line = 0_usize;
    let mut column = 0_usize;
    let mut previous_was_cr = false;
    let mut previous_target = 0_usize;

    for anchor in anchors {
        let target = offset(anchor);
        if target < previous_target || target > text.len() || !text.is_char_boundary(target) {
            return Err(SourceMapError::InvalidAnchorOffset { offset: target });
        }
        while byte_cursor < target {
            let (index, character) =
                next_character.ok_or(SourceMapError::PositionResolutionFailed)?;
            if index != byte_cursor {
                return Err(SourceMapError::PositionResolutionFailed);
            }
            let next_cursor = index
                .checked_add(character.len_utf8())
                .ok_or(SourceMapError::OffsetOverflow)?;
            if next_cursor > target {
                return Err(SourceMapError::InvalidAnchorOffset { offset: target });
            }
            match character {
                '\r' => {
                    line = line
                        .checked_add(1)
                        .ok_or(SourceMapError::PositionOverflow)?;
                    column = 0;
                    previous_was_cr = true;
                }
                '\n' if previous_was_cr => {
                    column = 0;
                    previous_was_cr = false;
                }
                '\n' | '\u{2028}' | '\u{2029}' => {
                    line = line
                        .checked_add(1)
                        .ok_or(SourceMapError::PositionOverflow)?;
                    column = 0;
                    previous_was_cr = false;
                }
                _ => {
                    column = column
                        .checked_add(character.len_utf16())
                        .ok_or(SourceMapError::PositionOverflow)?;
                    previous_was_cr = false;
                }
            }
            byte_cursor = next_cursor;
            next_character = characters.next();
        }
        positions.push(LineColumn { line, column });
        previous_target = target;
    }
    Ok(positions)
}

#[derive(Clone, Copy, Debug)]
struct MappingCursor {
    generated_line: usize,
    generated_column: usize,
    original_line: usize,
    original_column: usize,
    has_segment: bool,
}

impl MappingCursor {
    const fn new() -> Self {
        Self {
            generated_line: 0,
            generated_column: 0,
            original_line: 0,
            original_column: 0,
            has_segment: false,
        }
    }

    fn step(
        &mut self,
        generated: LineColumn,
        original: LineColumn,
    ) -> Result<MappingStep, SourceMapError> {
        if generated.line < self.generated_line {
            return Err(SourceMapError::MappingOrderInvalid);
        }
        let new_lines = generated.line - self.generated_line;
        if new_lines > 0 {
            self.generated_line = generated.line;
            self.generated_column = 0;
            self.has_segment = false;
        }
        if generated.column < self.generated_column {
            return Err(SourceMapError::MappingOrderInvalid);
        }
        let comma = self.has_segment;
        let deltas = [
            signed_delta(generated.column, self.generated_column)?,
            0,
            signed_delta(original.line, self.original_line)?,
            signed_delta(original.column, self.original_column)?,
        ];
        self.generated_column = generated.column;
        self.original_line = original.line;
        self.original_column = original.column;
        self.has_segment = true;
        Ok(MappingStep {
            new_lines,
            comma,
            deltas,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct MappingStep {
    new_lines: usize,
    comma: bool,
    deltas: [i64; 4],
}

fn mappings_length(
    generated: &[LineColumn],
    original: &[LineColumn],
) -> Result<usize, SourceMapError> {
    if generated.len() != original.len() {
        return Err(SourceMapError::PositionCountMismatch);
    }
    let mut cursor = MappingCursor::new();
    let mut length = 0_usize;
    for (&generated_position, &original_position) in generated.iter().zip(original) {
        let step = cursor.step(generated_position, original_position)?;
        length = length
            .checked_add(step.new_lines)
            .ok_or(SourceMapError::SourceMapLengthOverflow)?;
        if step.comma {
            length = length
                .checked_add(1)
                .ok_or(SourceMapError::SourceMapLengthOverflow)?;
        }
        for delta in step.deltas {
            length = length
                .checked_add(vlq_length(delta))
                .ok_or(SourceMapError::SourceMapLengthOverflow)?;
        }
    }
    Ok(length)
}

fn append_mappings(
    output: &mut Vec<u8>,
    generated: &[LineColumn],
    original: &[LineColumn],
) -> Result<(), SourceMapError> {
    if generated.len() != original.len() {
        return Err(SourceMapError::PositionCountMismatch);
    }
    let mut cursor = MappingCursor::new();
    for (&generated_position, &original_position) in generated.iter().zip(original) {
        let step = cursor.step(generated_position, original_position)?;
        for _ in 0..step.new_lines {
            output.push(b';');
        }
        if step.comma {
            output.push(b',');
        }
        for delta in step.deltas {
            append_vlq(output, delta)?;
        }
    }
    Ok(())
}

fn signed_delta(current: usize, previous: usize) -> Result<i64, SourceMapError> {
    if current >= previous {
        i64::try_from(current - previous).map_err(|_| SourceMapError::PositionDeltaOutOfRange)
    } else {
        let magnitude = i64::try_from(previous - current)
            .map_err(|_| SourceMapError::PositionDeltaOutOfRange)?;
        Ok(-magnitude)
    }
}

fn vlq_value(value: i64) -> u64 {
    let sign = u64::from(value < 0);
    value.unsigned_abs().saturating_mul(2) | sign
}

fn vlq_length(value: i64) -> usize {
    let mut remaining = vlq_value(value);
    let mut length = 1_usize;
    while remaining >= 32 {
        remaining >>= 5;
        length += 1;
    }
    length
}

fn append_vlq(output: &mut Vec<u8>, value: i64) -> Result<(), SourceMapError> {
    let mut remaining = vlq_value(value);
    loop {
        let mut digit =
            u8::try_from(remaining & 31).map_err(|_| SourceMapError::VlqEncodingFailed)?;
        remaining >>= 5;
        if remaining > 0 {
            digit |= 32;
        }
        output.push(
            *BASE64
                .get(usize::from(digit))
                .ok_or(SourceMapError::VlqEncodingFailed)?,
        );
        if remaining == 0 {
            return Ok(());
        }
    }
}

fn source_map_length(
    mappings_length: usize,
    source_id_length: usize,
    rule_id_length: usize,
) -> Result<usize, SourceMapError> {
    let mut length = 0_usize;
    for fixed in [
        MAP_PREFIX,
        MAP_MAPPINGS,
        MAP_EXTENSION,
        MAP_RULE_DIGEST,
        MAP_SOURCE_DIGEST,
        MAP_TRANSFORMED_DIGEST,
        MAP_SUFFIX,
    ] {
        length = length
            .checked_add(fixed.len())
            .ok_or(SourceMapError::SourceMapLengthOverflow)?;
    }
    for variable in [
        source_id_length,
        mappings_length,
        rule_id_length,
        DIGEST_TEXT_LENGTH,
        DIGEST_TEXT_LENGTH,
        DIGEST_TEXT_LENGTH,
    ] {
        length = length
            .checked_add(variable)
            .ok_or(SourceMapError::SourceMapLengthOverflow)?;
    }
    Ok(length)
}

fn allocate_vec<T>(items: usize, purpose: &'static str) -> Result<Vec<T>, SourceMapError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(items)
        .map_err(|_| SourceMapError::AllocationFailed { purpose, items })?;
    Ok(output)
}

fn append_digest(output: &mut Vec<u8>, value: &Sha256Digest) {
    output.extend_from_slice(value.to_string().as_bytes());
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

/// Failure emitting a bounded deterministic Source Map v3 document.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SourceMapError {
    /// One or more caller-selected limits were zero.
    #[error("source-map limits must be nonzero")]
    InvalidLimits,
    /// Source exceeded the caller-selected pre-hash limit.
    #[error("source is {actual_bytes} bytes; source-map limit is {max_bytes}")]
    SourceTooLarge {
        /// Exact supplied source length.
        actual_bytes: usize,
        /// Caller-selected source limit.
        max_bytes: usize,
    },
    /// Transformed source exceeded the caller-selected pre-scan limit.
    #[error("transformed source is {actual_bytes} bytes; source-map limit is {max_bytes}")]
    TransformedSourceTooLarge {
        /// Exact transformed-source length.
        actual_bytes: usize,
        /// Caller-selected transformed-source limit.
        max_bytes: usize,
    },
    /// Supplied source did not match the exact plan source digest.
    #[error("source bytes do not match the transform plan source digest")]
    SourceDigestMismatch,
    /// Digest-matched source was unexpectedly not UTF-8.
    #[error("source bytes are not UTF-8")]
    SourceNotUtf8,
    /// Emitted transformed source was unexpectedly not UTF-8.
    #[error("transformed source bytes are not UTF-8")]
    TransformedSourceNotUtf8,
    /// The conservative line-plus-edit segment count overflowed.
    #[error("source-map segment count overflowed")]
    SegmentCountOverflow,
    /// The conservative line-plus-edit segment requirement exceeded its limit.
    #[error("source map requires at most {required_segments} segments; limit is {max_segments}")]
    SegmentLimitExceeded {
        /// Line-start plus edit-boundary segment requirement before deduplication.
        required_segments: usize,
        /// Caller-selected segment limit.
        max_segments: usize,
    },
    /// A bounded source-map allocation failed.
    #[error("could not allocate {items} items for {purpose}")]
    AllocationFailed {
        /// Safe allocation purpose label.
        purpose: &'static str,
        /// Exact requested item or byte capacity.
        items: usize,
    },
    /// A source offset computation overflowed.
    #[error("source-map byte offset overflowed")]
    OffsetOverflow,
    /// A line/column position computation overflowed.
    #[error("source-map line or column overflowed")]
    PositionOverflow,
    /// An edit offset could not be represented by this platform.
    #[error("edit offset {0} cannot be represented on this platform")]
    EditOffsetOutOfRange(u32),
    /// A retained edit range violated plan invariants.
    #[error("invalid retained edit range")]
    InvalidEditRange,
    /// A source line start unexpectedly fell inside a replacement range.
    #[error("line start {line_start} falls inside edit {edit_start}..{edit_end}")]
    LineStartInsideEdit {
        /// Original line-start byte offset.
        line_start: usize,
        /// Inclusive edit start.
        edit_start: usize,
        /// Exclusive edit end.
        edit_end: usize,
    },
    /// Counted and collected line starts differed.
    #[error("collected {actual} line starts; expected {expected}")]
    LineStartCountMismatch {
        /// Precomputed line-start count.
        expected: usize,
        /// Collected line-start count.
        actual: usize,
    },
    /// The first line-start entry was unexpectedly unavailable.
    #[error("source line-start collection failed")]
    LineStartCollectionFailed,
    /// Anchor ordering could not be inspected.
    #[error("source-map anchor ordering failed")]
    AnchorOrderingFailed,
    /// One generated byte offset mapped to two distinct original offsets.
    #[error("generated byte {generated_byte} has ambiguous original anchors")]
    AmbiguousGeneratedAnchor {
        /// Conflicting generated byte offset.
        generated_byte: usize,
    },
    /// An anchor was unordered, outside text, or not at a UTF-8 boundary.
    #[error("invalid source-map anchor byte offset {offset}")]
    InvalidAnchorOffset {
        /// Invalid generated or original byte offset.
        offset: usize,
    },
    /// A text position could not be resolved from a byte anchor.
    #[error("source-map position resolution failed")]
    PositionResolutionFailed,
    /// Generated and original position counts differed.
    #[error("generated and original source-map position counts differ")]
    PositionCountMismatch,
    /// Mapping segments were not in generated order.
    #[error("source-map segments are not in generated order")]
    MappingOrderInvalid,
    /// A line or column delta could not fit Source Map v3 encoding.
    #[error("source-map position delta is outside the supported range")]
    PositionDeltaOutOfRange,
    /// A Base64 VLQ value could not be encoded canonically.
    #[error("source-map Base64 VLQ encoding failed")]
    VlqEncodingFailed,
    /// Checked source-map length arithmetic overflowed.
    #[error("source-map length overflowed the platform byte index")]
    SourceMapLengthOverflow,
    /// Canonical source-map bytes exceeded the caller-selected pre-allocation limit.
    #[error("source map is {actual_bytes} bytes; emission limit is {max_bytes}")]
    SourceMapTooLarge {
        /// Exact computed map length.
        actual_bytes: usize,
        /// Caller-selected source-map limit.
        max_bytes: usize,
    },
    /// Emitted bytes differed from the precomputed exact length.
    #[error("emitted {actual_bytes} source-map bytes; expected {expected_bytes}")]
    EmittedLengthMismatch {
        /// Precomputed exact map length.
        expected_bytes: usize,
        /// Actual emitted map length.
        actual_bytes: usize,
    },
}
