//! Parser-backed deterministic transform planning.

use std::{fmt, num::NonZeroU16, sync::Arc};

use oxc_allocator::Allocator;
use oxc_ast::ast::{Statement, StringLiteral};
use oxc_parser::{ParseOptions, Parser};
use oxc_span::SourceType;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use weregopher_domain::{AdapterTransformAuthority, Sha256Digest, SourceUnitRef, TransformRuleId};

const STATIC_IMPORT_REWRITE_DOMAIN: &[u8] = b"weregopher.static-import-rewrite.v1\0";

/// One deterministic semantic rule replacing exact static module specifiers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticImportRewrite {
    from: String,
    from_byte_length: u32,
    to: String,
    to_byte_length: u32,
    exact_match_count: NonZeroU16,
}

/// Identifies one side of a static module-specifier rewrite rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticImportSpecifier {
    /// Exact decoded module specifier to match.
    From,
    /// Canonical module specifier to emit.
    To,
}

impl StaticImportRewrite {
    /// Constructs one static module-specifier rewrite rule.
    ///
    /// # Errors
    ///
    /// Returns [`TransformPlanError`] when either specifier is invalid.
    pub fn new(
        from: String,
        to: String,
        exact_match_count: NonZeroU16,
    ) -> Result<Self, TransformPlanError> {
        let from_byte_length = validate_specifier(&from, StaticImportSpecifier::From)?;
        let to_byte_length = validate_specifier(&to, StaticImportSpecifier::To)?;
        if from == to {
            return Err(TransformPlanError::EquivalentSpecifiers);
        }
        Ok(Self {
            from,
            from_byte_length,
            to,
            to_byte_length,
            exact_match_count,
        })
    }

    /// Computes the domain-separated canonical rule identity.
    #[must_use]
    pub fn canonical_digest(&self) -> Sha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(STATIC_IMPORT_REWRITE_DOMAIN);
        hasher.update(self.from_byte_length.to_be_bytes());
        hasher.update(self.from.as_bytes());
        hasher.update(self.to_byte_length.to_be_bytes());
        hasher.update(self.to.as_bytes());
        hasher.update(self.exact_match_count.get().to_be_bytes());
        Sha256Digest::from_bytes(hasher.finalize().into())
    }
}

fn validate_specifier(
    specifier: &str,
    side: StaticImportSpecifier,
) -> Result<u32, TransformPlanError> {
    if specifier.is_empty() {
        return Err(TransformPlanError::EmptySpecifier(side));
    }
    let byte_length =
        u32::try_from(specifier.len()).map_err(|_| TransformPlanError::SpecifierTooLong {
            side,
            actual_bytes: specifier.len(),
        })?;
    if specifier.chars().any(char::is_control) {
        return Err(TransformPlanError::ControlCharacterInSpecifier(side));
    }
    Ok(byte_length)
}

/// Exact source identity paired with already-obtained source bytes.
pub struct SourceUnitInput<'a> {
    source: SourceUnitRef,
    bytes: &'a [u8],
}

impl fmt::Debug for SourceUnitInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceUnitInput")
            .field("source", &self.source)
            .field("byte_length", &self.bytes.len())
            .finish()
    }
}

impl<'a> SourceUnitInput<'a> {
    /// Pairs one content-addressed source-unit identity with its bytes.
    #[must_use]
    pub const fn new(source: SourceUnitRef, bytes: &'a [u8]) -> Self {
        Self { source, bytes }
    }
}

/// Caller-selected resource limits for one planning operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlannerLimits {
    source_bytes: usize,
    edits: usize,
    replacement_bytes: usize,
}

impl PlannerLimits {
    /// Constructs planning limits.
    ///
    /// # Errors
    ///
    /// Returns [`TransformPlanError::InvalidLimits`] when any limit is zero, or
    /// [`TransformPlanError::SourceByteLimitExceedsParserCapacity`] when the source limit cannot be
    /// represented by parser spans.
    pub fn new(
        max_source_bytes: usize,
        max_edits: usize,
        max_replacement_bytes: usize,
    ) -> Result<Self, TransformPlanError> {
        if max_source_bytes == 0 || max_edits == 0 || max_replacement_bytes == 0 {
            return Err(TransformPlanError::InvalidLimits);
        }
        let parser_capacity = usize::try_from(u32::MAX).unwrap_or(usize::MAX);
        if max_source_bytes > parser_capacity {
            return Err(TransformPlanError::SourceByteLimitExceedsParserCapacity {
                requested_bytes: max_source_bytes,
                max_bytes: parser_capacity,
            });
        }
        Ok(Self {
            source_bytes: max_source_bytes,
            edits: max_edits,
            replacement_bytes: max_replacement_bytes,
        })
    }

    /// Returns the maximum bytes allowed in one canonical replacement literal.
    #[must_use]
    pub const fn max_replacement_bytes(&self) -> usize {
        self.replacement_bytes
    }
}

/// One byte-range replacement in an immutable source unit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextEdit {
    start_byte: u32,
    end_byte: u32,
    replacement: Arc<str>,
}

impl TextEdit {
    /// Returns the inclusive start byte offset.
    #[must_use]
    pub const fn start_byte(&self) -> u32 {
        self.start_byte
    }

    /// Returns the exclusive end byte offset.
    #[must_use]
    pub const fn end_byte(&self) -> u32 {
        self.end_byte
    }

    /// Returns the canonical replacement JavaScript literal.
    #[must_use]
    pub fn replacement(&self) -> &str {
        &self.replacement
    }
}

/// Deterministic in-memory output from static transform analysis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransformPlan {
    rule_id: TransformRuleId,
    rule_digest: Sha256Digest,
    source: SourceUnitRef,
    edits: Vec<TextEdit>,
}

impl TransformPlan {
    /// Returns the exact authorized rule identifier.
    #[must_use]
    pub const fn rule_id(&self) -> &TransformRuleId {
        &self.rule_id
    }

    /// Returns the canonical rule digest.
    #[must_use]
    pub const fn rule_digest(&self) -> &Sha256Digest {
        &self.rule_digest
    }

    /// Returns the exact source-unit identity.
    #[must_use]
    pub const fn source(&self) -> &SourceUnitRef {
        &self.source
    }

    /// Returns byte-ordered, non-overlapping edits.
    #[must_use]
    pub fn edits(&self) -> &[TextEdit] {
        &self.edits
    }
}

/// Plans exact static ECMAScript module-specifier replacements.
///
/// This verifies structural rule and source identities and emits an in-memory plan. It does not
/// authenticate authority, mutate source bytes, materialize files, or authorize execution.
///
/// # Errors
///
/// Returns [`TransformPlanError`] when identities, bounds, parser diagnostics, or exact-match requirements fail.
pub fn plan_static_import_rewrite(
    authority: &AdapterTransformAuthority,
    rule_id: &TransformRuleId,
    rule: &StaticImportRewrite,
    source: SourceUnitInput<'_>,
    limits: PlannerLimits,
) -> Result<TransformPlan, TransformPlanError> {
    let expected_edits = usize::from(rule.exact_match_count.get());
    if expected_edits > limits.edits {
        return Err(TransformPlanError::ExpectedMatchCountExceedsLimit {
            expected: rule.exact_match_count.get(),
            max_edits: limits.edits,
        });
    }
    if rule.from.len() > limits.source_bytes {
        return Err(TransformPlanError::MatchSpecifierTooLarge {
            actual_bytes: rule.from.len(),
            max_bytes: limits.source_bytes,
        });
    }
    let replacement_byte_length = canonical_replacement_byte_length(&rule.to)
        .ok_or(TransformPlanError::ReplacementLengthOverflow)?;
    if replacement_byte_length > limits.replacement_bytes {
        return Err(TransformPlanError::ReplacementTooLarge {
            actual_bytes: replacement_byte_length,
            max_bytes: limits.replacement_bytes,
        });
    }
    if source.bytes.len() > limits.source_bytes {
        return Err(TransformPlanError::SourceTooLarge {
            actual_bytes: source.bytes.len(),
            max_bytes: limits.source_bytes,
        });
    }
    let rule_digest = rule.canonical_digest();
    let authorized_rule = authority
        .rules()
        .get(rule_id)
        .ok_or_else(|| TransformPlanError::UnknownRule(rule_id.clone()))?;
    if authorized_rule.rule_digest() != &rule_digest {
        return Err(TransformPlanError::RuleDigestMismatch(rule_id.clone()));
    }
    if digest(source.bytes) != *source.source.source_digest() {
        return Err(TransformPlanError::SourceDigestMismatch);
    }
    let source_text =
        std::str::from_utf8(source.bytes).map_err(|_| TransformPlanError::InvalidUtf8)?;
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source_text, SourceType::mjs())
        .with_options(ParseOptions {
            parse_regular_expression: true,
            ..ParseOptions::default()
        })
        .parse();
    if !parsed.errors.is_empty() {
        return Err(TransformPlanError::ParseFailed {
            diagnostic_count: parsed.errors.len(),
        });
    }

    let replacement: Arc<str> = quote_specifier(&rule.to, replacement_byte_length).into();
    let mut edits = Vec::with_capacity(expected_edits);
    for statement in &parsed.program.body {
        let Some(literal) = static_module_specifier(statement) else {
            continue;
        };
        if literal.value.as_str() != rule.from {
            continue;
        }
        if edits.len() == expected_edits {
            return Err(TransformPlanError::MatchCountMismatch {
                expected: rule.exact_match_count.get(),
                actual: expected_edits + 1,
            });
        }
        edits.push(TextEdit {
            start_byte: literal.span.start,
            end_byte: literal.span.end,
            replacement: Arc::clone(&replacement),
        });
    }

    if edits.len() != expected_edits {
        return Err(TransformPlanError::MatchCountMismatch {
            expected: rule.exact_match_count.get(),
            actual: edits.len(),
        });
    }

    Ok(TransformPlan {
        rule_id: rule_id.clone(),
        rule_digest,
        source: source.source,
        edits,
    })
}

fn static_module_specifier<'ast, 'node>(
    statement: &'node Statement<'ast>,
) -> Option<&'node StringLiteral<'ast>> {
    match statement {
        Statement::ImportDeclaration(declaration) => Some(&declaration.source),
        Statement::ExportNamedDeclaration(declaration) => declaration.source.as_ref(),
        Statement::ExportAllDeclaration(declaration) => Some(&declaration.source),
        _ => None,
    }
}

fn canonical_replacement_byte_length(specifier: &str) -> Option<usize> {
    specifier.chars().try_fold(2_usize, |length, character| {
        let encoded_length = match character {
            '"' | '\\' => 2,
            '\u{2028}' | '\u{2029}' => 6,
            _ => character.len_utf8(),
        };
        length.checked_add(encoded_length)
    })
}

fn quote_specifier(specifier: &str, byte_length: usize) -> String {
    let mut quoted = String::with_capacity(byte_length);
    quoted.push('"');
    for character in specifier.chars() {
        match character {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\u{2028}' => quoted.push_str("\\u2028"),
            '\u{2029}' => quoted.push_str("\\u2029"),
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}

/// Failure planning one deterministic static transform.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransformPlanError {
    /// One rule specifier was empty.
    #[error("static import rewrite {0:?} specifier must not be empty")]
    EmptySpecifier(StaticImportSpecifier),
    /// Matching and replacement specifiers were identical.
    #[error("static import rewrite specifiers must differ")]
    EquivalentSpecifiers,
    /// One rule specifier contained a control character.
    #[error("static import rewrite {0:?} specifier contains a control character")]
    ControlCharacterInSpecifier(StaticImportSpecifier),
    /// One rule specifier could not be represented by the canonical `u32` byte length.
    #[error("static import rewrite {side:?} specifier is {actual_bytes} bytes; limit is u32::MAX")]
    SpecifierTooLong {
        /// Side of the rewrite containing the oversized specifier.
        side: StaticImportSpecifier,
        /// Actual UTF-8 byte length.
        actual_bytes: usize,
    },
    /// The rule's exact match count exceeded the caller-selected edit limit.
    #[error("transform rule expects {expected} edits; planning limit is {max_edits}")]
    ExpectedMatchCountExceedsLimit {
        /// Exact match count committed by the rule.
        expected: u16,
        /// Caller-selected edit limit.
        max_edits: usize,
    },
    /// The decoded match specifier cannot fit inside any permitted source input.
    #[error("the match specifier is {actual_bytes} bytes, above source limit {max_bytes}")]
    MatchSpecifierTooLarge {
        /// Decoded match-specifier byte length.
        actual_bytes: usize,
        /// Caller-selected source byte limit.
        max_bytes: usize,
    },
    /// The canonical replacement literal length overflowed the platform byte index.
    #[error("the canonical replacement byte length overflows the platform byte index")]
    ReplacementLengthOverflow,
    /// The canonical replacement literal exceeded the caller-selected bound.
    #[error("the canonical replacement requires {actual_bytes} bytes, above limit {max_bytes}")]
    ReplacementTooLarge {
        /// Canonical replacement literal length.
        actual_bytes: usize,
        /// Caller-selected replacement limit.
        max_bytes: usize,
    },
    /// The source-byte limit exceeded the parser's span representation.
    #[error("source-byte limit is {requested_bytes}; parser capacity is {max_bytes}")]
    SourceByteLimitExceedsParserCapacity {
        /// Requested caller-selected source byte limit.
        requested_bytes: usize,
        /// Maximum source byte length representable by parser spans.
        max_bytes: usize,
    },
    /// A caller-selected planning limit was zero.
    #[error("transform planner limits must be nonzero")]
    InvalidLimits,
    /// Source bytes exceeded the caller-selected pre-parse limit.
    #[error("source is {actual_bytes} bytes; planning limit is {max_bytes}")]
    SourceTooLarge {
        /// Actual source byte length.
        actual_bytes: usize,
        /// Caller-selected source byte limit.
        max_bytes: usize,
    },
    /// The supplied authority did not contain the selected rule identifier.
    #[error("transform authority does not contain rule `{0}`")]
    UnknownRule(TransformRuleId),
    /// Canonical rule bytes did not match the authority commitment.
    #[error("canonical transform rule digest does not match authority for `{0}`")]
    RuleDigestMismatch(TransformRuleId),
    /// Supplied source bytes did not match the source-unit content identity.
    #[error("source bytes do not match the source-unit digest")]
    SourceDigestMismatch,
    /// Source bytes were not valid UTF-8.
    #[error("source bytes are not valid UTF-8")]
    InvalidUtf8,
    /// ECMAScript module parsing produced diagnostics.
    #[error("ECMAScript module parser returned {diagnostic_count} diagnostic(s)")]
    ParseFailed {
        /// Number of parser diagnostics; diagnostic text is intentionally not retained.
        diagnostic_count: usize,
    },
    /// Semantic matching did not produce exactly the rule-declared count.
    #[error("transform rule expected {expected} matches but found {actual}")]
    MatchCountMismatch {
        /// Exact match count committed by the rule.
        expected: u16,
        /// Observed match count when planning stopped; exact for undercounts and a lower bound for
        /// excess matches.
        actual: usize,
    },
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}
