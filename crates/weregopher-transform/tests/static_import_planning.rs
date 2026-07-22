//! Behavior tests for deterministic static-import rewrite planning.

use std::{collections::BTreeMap, num::NonZeroU16};

use sha2::{Digest as _, Sha256};
use weregopher_domain::{
    AdapterId, AdapterTransformAuthority, ApplicationFamilyId, AuthorizedTransformRuleRef,
    Sha256Digest, SourceUnitId, SourceUnitRef, TransformRuleId,
};
use weregopher_transform::{
    PlannerLimits, SourceUnitInput, StaticImportRewrite, StaticImportSpecifier, TransformPlanError,
    plan_static_import_rewrite,
};

const SOURCE: &str = r#"import primary from "node-pty";
import "node-pty";
export { primary as pty } from "node-pty";
export * from "node-pty";
"#;
const MAX_REPLACEMENT_BYTES: usize = 1_024;

#[test]
fn authorized_static_module_specifiers_produce_ordered_edits()
-> Result<(), Box<dyn std::error::Error>> {
    let rule_id = TransformRuleId::new("main.replace-node-pty")?;
    let expected_matches = NonZeroU16::new(4).ok_or("test match count must be nonzero")?;
    let rule = StaticImportRewrite::new(
        "node-pty".to_owned(),
        "compat:openai/conpty".to_owned(),
        expected_matches,
    )?;
    let authority = authority(rule_id.clone(), rule.canonical_digest())?;
    let source = SourceUnitRef::new(
        SourceUnitId::new("module.main.bootstrap")?,
        digest(SOURCE.as_bytes()),
    );

    let plan = plan_static_import_rewrite(
        &authority,
        &rule_id,
        &rule,
        SourceUnitInput::new(source.clone(), SOURCE.as_bytes()),
        PlannerLimits::new(SOURCE.len(), 4, MAX_REPLACEMENT_BYTES)?,
    )?;

    assert_eq!(plan.rule_id(), &rule_id);
    assert_eq!(plan.rule_digest(), &rule.canonical_digest());
    assert_eq!(plan.source(), &source);
    assert_eq!(plan.edits().len(), 4);
    assert!(
        plan.edits()
            .windows(2)
            .all(|pair| pair[0].end_byte() <= pair[1].start_byte())
    );
    assert!(
        plan.edits()
            .iter()
            .all(|edit| edit.replacement() == r#""compat:openai/conpty""#)
    );
    assert_eq!(
        apply_edits(SOURCE, plan.edits())?,
        r#"import primary from "compat:openai/conpty";
import "compat:openai/conpty";
export { primary as pty } from "compat:openai/conpty";
export * from "compat:openai/conpty";
"#
    );
    Ok(())
}

#[test]
fn invalid_rule_specifiers_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let one = NonZeroU16::new(1).ok_or("test match count must be nonzero")?;
    let cases = [
        (
            "",
            "replacement",
            TransformPlanError::EmptySpecifier(StaticImportSpecifier::From),
        ),
        (
            "original",
            "",
            TransformPlanError::EmptySpecifier(StaticImportSpecifier::To),
        ),
        ("same", "same", TransformPlanError::EquivalentSpecifiers),
        (
            "bad\0source",
            "replacement",
            TransformPlanError::ControlCharacterInSpecifier(StaticImportSpecifier::From),
        ),
        (
            "original",
            "bad\nreplacement",
            TransformPlanError::ControlCharacterInSpecifier(StaticImportSpecifier::To),
        ),
    ];

    for (from, to, expected) in cases {
        assert_eq!(
            StaticImportRewrite::new(from.to_owned(), to.to_owned(), one),
            Err(expected)
        );
    }
    Ok(())
}

#[test]
fn invalid_planner_limits_are_rejected() {
    assert_eq!(
        PlannerLimits::new(0, 1, 1),
        Err(TransformPlanError::InvalidLimits)
    );
    assert_eq!(
        PlannerLimits::new(1, 0, 1),
        Err(TransformPlanError::InvalidLimits)
    );
    assert_eq!(
        PlannerLimits::new(1, 1, 0),
        Err(TransformPlanError::InvalidLimits)
    );
    if let Ok(over_parser_capacity) = usize::try_from(u64::from(u32::MAX) + 1) {
        assert_eq!(
            PlannerLimits::new(over_parser_capacity, 1, 1),
            Err(TransformPlanError::SourceByteLimitExceedsParserCapacity {
                requested_bytes: over_parser_capacity,
                max_bytes: over_parser_capacity - 1,
            })
        );
    }
}

#[test]
fn rule_match_count_must_fit_edit_limit_before_source_processing()
-> Result<(), Box<dyn std::error::Error>> {
    let rule_id = TransformRuleId::new("main.replace-node-pty")?;
    let two = NonZeroU16::new(2).ok_or("test match count must be nonzero")?;
    let rule = StaticImportRewrite::new(
        "node-pty".to_owned(),
        "compat:openai/conpty".to_owned(),
        two,
    )?;
    let authority = authority(rule_id.clone(), rule.canonical_digest())?;
    let deliberately_wrong_source_identity = SourceUnitRef::new(
        SourceUnitId::new("module.main.bootstrap")?,
        digest(b"different source"),
    );

    let result = plan_static_import_rewrite(
        &authority,
        &rule_id,
        &rule,
        SourceUnitInput::new(deliberately_wrong_source_identity, SOURCE.as_bytes()),
        PlannerLimits::new(SOURCE.len(), 1, MAX_REPLACEMENT_BYTES)?,
    );
    let Err(error) = result else {
        return Err("an impossible rule match count must fail before source processing".into());
    };

    assert_eq!(
        error,
        TransformPlanError::ExpectedMatchCountExceedsLimit {
            expected: 2,
            max_edits: 1,
        }
    );
    Ok(())
}

#[test]
fn match_specifier_bytes_are_bounded_before_source_processing()
-> Result<(), Box<dyn std::error::Error>> {
    let rule = StaticImportRewrite::new(
        "oversized-match".to_owned(),
        "x".to_owned(),
        NonZeroU16::new(1).ok_or("expected a nonzero match count")?,
    )?;
    let rule_id = TransformRuleId::new("rewrite.static-import")?;
    let authority = authority(rule_id.clone(), rule.canonical_digest())?;
    let bytes = b"?";
    let source = SourceUnitRef::new(
        SourceUnitId::new("module.main.bootstrap")?,
        digest(b"different bytes"),
    );

    assert_eq!(
        plan_static_import_rewrite(
            &authority,
            &rule_id,
            &rule,
            SourceUnitInput::new(source, bytes),
            PlannerLimits::new(4, 1, 16)?,
        ),
        Err(TransformPlanError::MatchSpecifierTooLarge {
            actual_bytes: 15,
            max_bytes: 4,
        })
    );
    Ok(())
}

#[test]
fn canonical_replacement_bytes_are_bounded_before_source_processing()
-> Result<(), Box<dyn std::error::Error>> {
    let rule = StaticImportRewrite::new(
        "x".to_owned(),
        "abc".to_owned(),
        NonZeroU16::new(1).ok_or("expected a nonzero match count")?,
    )?;
    let rule_id = TransformRuleId::new("rewrite.static-import")?;
    let authority = authority(rule_id.clone(), rule.canonical_digest())?;
    let bytes = br#"import "x";"#;
    let source = SourceUnitRef::new(
        SourceUnitId::new("module.main.bootstrap")?,
        digest(b"different bytes"),
    );

    let result = plan_static_import_rewrite(
        &authority,
        &rule_id,
        &rule,
        SourceUnitInput::new(source, bytes),
        PlannerLimits::new(bytes.len(), 1, 4)?,
    );
    let Err(error) = result else {
        return Err("the quoted replacement must be rejected before source processing".into());
    };

    assert_eq!(
        error,
        TransformPlanError::ReplacementTooLarge {
            actual_bytes: 5,
            max_bytes: 4,
        }
    );

    let matching_source =
        SourceUnitRef::new(SourceUnitId::new("module.main.bootstrap")?, digest(bytes));
    let plan = plan_static_import_rewrite(
        &authority,
        &rule_id,
        &rule,
        SourceUnitInput::new(matching_source, bytes),
        PlannerLimits::new(bytes.len(), 1, 5)?,
    )?;
    let Some(edit) = plan.edits().first() else {
        return Err("the exact replacement-byte boundary must permit one edit".into());
    };
    assert_eq!(edit.replacement(), r#""abc""#);
    Ok(())
}

#[test]
fn matching_uses_decoded_static_specifiers_only() -> Result<(), Box<dyn std::error::Error>> {
    const SEMANTIC_SOURCE: &str = r#"// node-pty
const ordinary = "node-pty";
const template = `node-pty`;
require("node-pty");
import("node-pty");
import primary from "node\x2dpty";
"#;
    let rule_id = TransformRuleId::new("main.replace-node-pty")?;
    let one = NonZeroU16::new(1).ok_or("test match count must be nonzero")?;
    let rule = StaticImportRewrite::new(
        "node-pty".to_owned(),
        "compat:openai/conpty".to_owned(),
        one,
    )?;
    let authority = authority(rule_id.clone(), rule.canonical_digest())?;
    let source = SourceUnitRef::new(
        SourceUnitId::new("module.main.bootstrap")?,
        digest(SEMANTIC_SOURCE.as_bytes()),
    );

    let plan = plan_static_import_rewrite(
        &authority,
        &rule_id,
        &rule,
        SourceUnitInput::new(source, SEMANTIC_SOURCE.as_bytes()),
        PlannerLimits::new(SEMANTIC_SOURCE.len(), 1, MAX_REPLACEMENT_BYTES)?,
    )?;

    assert_eq!(plan.edits().len(), 1);
    let edit = &plan.edits()[0];
    let start = usize::try_from(edit.start_byte())?;
    let end = usize::try_from(edit.end_byte())?;
    assert_eq!(&SEMANTIC_SOURCE[start..end], r#""node\x2dpty""#);
    assert_eq!(edit.replacement(), r#""compat:openai/conpty""#);
    Ok(())
}

#[test]
fn canonical_rule_digest_has_a_stable_framed_test_vector() -> Result<(), Box<dyn std::error::Error>>
{
    let four = NonZeroU16::new(4).ok_or("test match count must be nonzero")?;
    let rule = StaticImportRewrite::new(
        "node-pty".to_owned(),
        "compat:openai/conpty".to_owned(),
        four,
    )?;
    assert_eq!(
        rule.canonical_digest().to_string(),
        "sha256:9d8271cf8e312c10f6335e21c6a21ee9dfdf12c5e226294c5ef197fd6bf93771"
    );

    let one = NonZeroU16::new(1).ok_or("test match count must be nonzero")?;
    let left_framing = StaticImportRewrite::new("ab".to_owned(), "c".to_owned(), one)?;
    let right_framing = StaticImportRewrite::new("a".to_owned(), "bc".to_owned(), one)?;
    assert_ne!(
        left_framing.canonical_digest(),
        right_framing.canonical_digest()
    );
    Ok(())
}

#[test]
fn planner_rejects_unbounded_or_mismatched_identities() -> Result<(), Box<dyn std::error::Error>> {
    const ONE_IMPORT: &str = r#"import "node-pty";"#;
    let rule_id = TransformRuleId::new("main.replace-node-pty")?;
    let other_rule_id = TransformRuleId::new("main.other-rule")?;
    let one = NonZeroU16::new(1).ok_or("test match count must be nonzero")?;
    let rule = StaticImportRewrite::new(
        "node-pty".to_owned(),
        "compat:openai/conpty".to_owned(),
        one,
    )?;
    let valid_source = SourceUnitRef::new(
        SourceUnitId::new("module.main.bootstrap")?,
        digest(ONE_IMPORT.as_bytes()),
    );
    let valid_authority = authority(rule_id.clone(), rule.canonical_digest())?;

    assert_eq!(
        plan_static_import_rewrite(
            &valid_authority,
            &rule_id,
            &rule,
            SourceUnitInput::new(valid_source.clone(), ONE_IMPORT.as_bytes()),
            PlannerLimits::new(ONE_IMPORT.len() - 1, 1, MAX_REPLACEMENT_BYTES)?,
        ),
        Err(TransformPlanError::SourceTooLarge {
            actual_bytes: ONE_IMPORT.len(),
            max_bytes: ONE_IMPORT.len() - 1,
        })
    );

    let unrelated_authority = authority(other_rule_id, rule.canonical_digest())?;
    assert_eq!(
        plan_static_import_rewrite(
            &unrelated_authority,
            &rule_id,
            &rule,
            SourceUnitInput::new(valid_source.clone(), ONE_IMPORT.as_bytes()),
            PlannerLimits::new(ONE_IMPORT.len(), 1, MAX_REPLACEMENT_BYTES)?,
        ),
        Err(TransformPlanError::UnknownRule(rule_id.clone()))
    );

    let wrong_rule_authority = authority(rule_id.clone(), digest(b"different rule"))?;
    assert_eq!(
        plan_static_import_rewrite(
            &wrong_rule_authority,
            &rule_id,
            &rule,
            SourceUnitInput::new(valid_source.clone(), ONE_IMPORT.as_bytes()),
            PlannerLimits::new(ONE_IMPORT.len(), 1, MAX_REPLACEMENT_BYTES)?,
        ),
        Err(TransformPlanError::RuleDigestMismatch(rule_id.clone()))
    );

    let wrong_source = SourceUnitRef::new(
        SourceUnitId::new("module.main.bootstrap")?,
        digest(b"different source"),
    );
    assert_eq!(
        plan_static_import_rewrite(
            &valid_authority,
            &rule_id,
            &rule,
            SourceUnitInput::new(wrong_source, ONE_IMPORT.as_bytes()),
            PlannerLimits::new(ONE_IMPORT.len(), 1, MAX_REPLACEMENT_BYTES)?,
        ),
        Err(TransformPlanError::SourceDigestMismatch)
    );
    Ok(())
}

#[test]
fn invalid_source_and_match_cardinality_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    const INVALID_MODULE: &str = "import {";
    const TWO_IMPORTS: &str = "import 'node-pty';\nimport 'node-pty';\n";
    const NO_MATCH: &str = "export const ready = true;\n";

    let rule_id = TransformRuleId::new("main.replace-node-pty")?;
    let one = NonZeroU16::new(1).ok_or("test match count must be nonzero")?;
    let rule = StaticImportRewrite::new(
        "node-pty".to_owned(),
        "compat:openai/conpty".to_owned(),
        one,
    )?;
    let authority = authority(rule_id.clone(), rule.canonical_digest())?;

    let invalid_utf8 = [0xff_u8];
    let invalid_utf8_ref = SourceUnitRef::new(
        SourceUnitId::new("module.main.bootstrap")?,
        digest(&invalid_utf8),
    );
    assert_eq!(
        plan_static_import_rewrite(
            &authority,
            &rule_id,
            &rule,
            SourceUnitInput::new(invalid_utf8_ref, &invalid_utf8),
            PlannerLimits::new("node-pty".len(), 1, MAX_REPLACEMENT_BYTES)?,
        ),
        Err(TransformPlanError::InvalidUtf8)
    );

    let invalid_module_ref = SourceUnitRef::new(
        SourceUnitId::new("module.main.bootstrap")?,
        digest(INVALID_MODULE.as_bytes()),
    );
    let parse_result = plan_static_import_rewrite(
        &authority,
        &rule_id,
        &rule,
        SourceUnitInput::new(invalid_module_ref, INVALID_MODULE.as_bytes()),
        PlannerLimits::new(INVALID_MODULE.len(), 1, MAX_REPLACEMENT_BYTES)?,
    );
    let Err(TransformPlanError::ParseFailed { diagnostic_count }) = parse_result else {
        return Err("invalid ECMAScript module syntax must fail with parser diagnostics".into());
    };
    assert!(diagnostic_count > 0);

    let two_imports_ref = SourceUnitRef::new(
        SourceUnitId::new("module.main.bootstrap")?,
        digest(TWO_IMPORTS.as_bytes()),
    );
    assert_eq!(
        plan_static_import_rewrite(
            &authority,
            &rule_id,
            &rule,
            SourceUnitInput::new(two_imports_ref, TWO_IMPORTS.as_bytes()),
            PlannerLimits::new(TWO_IMPORTS.len(), 1, MAX_REPLACEMENT_BYTES)?,
        ),
        Err(TransformPlanError::MatchCountMismatch {
            expected: 1,
            actual: 2,
        })
    );

    let no_match_ref = SourceUnitRef::new(
        SourceUnitId::new("module.main.bootstrap")?,
        digest(NO_MATCH.as_bytes()),
    );
    assert_eq!(
        plan_static_import_rewrite(
            &authority,
            &rule_id,
            &rule,
            SourceUnitInput::new(no_match_ref, NO_MATCH.as_bytes()),
            PlannerLimits::new(NO_MATCH.len(), 1, MAX_REPLACEMENT_BYTES)?,
        ),
        Err(TransformPlanError::MatchCountMismatch {
            expected: 1,
            actual: 0,
        })
    );
    Ok(())
}

#[test]
fn planner_stops_at_the_first_excess_match() -> Result<(), Box<dyn std::error::Error>> {
    const THREE_IMPORTS: &str = "import 'node-pty';\nimport 'node-pty';\nimport 'node-pty';\n";
    let rule_id = TransformRuleId::new("main.replace-node-pty")?;
    let one = NonZeroU16::new(1).ok_or("test match count must be nonzero")?;
    let rule = StaticImportRewrite::new(
        "node-pty".to_owned(),
        "compat:openai/conpty".to_owned(),
        one,
    )?;
    let authority = authority(rule_id.clone(), rule.canonical_digest())?;
    let source = SourceUnitRef::new(
        SourceUnitId::new("module.main.bootstrap")?,
        digest(THREE_IMPORTS.as_bytes()),
    );

    assert_eq!(
        plan_static_import_rewrite(
            &authority,
            &rule_id,
            &rule,
            SourceUnitInput::new(source, THREE_IMPORTS.as_bytes()),
            PlannerLimits::new(THREE_IMPORTS.len(), 3, MAX_REPLACEMENT_BYTES)?,
        ),
        Err(TransformPlanError::MatchCountMismatch {
            expected: 1,
            actual: 2,
        })
    );
    Ok(())
}

#[test]
fn lone_surrogate_specifier_escapes_do_not_alias_utf8_text()
-> Result<(), Box<dyn std::error::Error>> {
    const LITERAL_REPLACEMENT_TEXT: &str = "import \"\u{fffd}d800\";";
    let rule_id = TransformRuleId::new("main.replace-ambiguous-specifier")?;
    let one = NonZeroU16::new(1).ok_or("test match count must be nonzero")?;
    let rule = StaticImportRewrite::new(
        "\u{fffd}d800".to_owned(),
        "compat:unambiguous".to_owned(),
        one,
    )?;
    let authority = authority(rule_id.clone(), rule.canonical_digest())?;
    let ambiguous_sources = [
        r#"import "\uD800";"#,
        r#"import "\uDC00";"#,
        r#"import "\u{D800}";"#,
    ];
    for (case_index, ambiguous_bytes) in ambiguous_sources.into_iter().enumerate() {
        let ambiguous_source = SourceUnitRef::new(
            SourceUnitId::new(format!("module.main.ambiguous-{case_index}"))?,
            digest(ambiguous_bytes.as_bytes()),
        );
        assert_eq!(
            plan_static_import_rewrite(
                &authority,
                &rule_id,
                &rule,
                SourceUnitInput::new(ambiguous_source, ambiguous_bytes.as_bytes()),
                PlannerLimits::new(ambiguous_bytes.len(), 1, MAX_REPLACEMENT_BYTES)?,
            ),
            Err(TransformPlanError::LoneSurrogateEscape { start_byte: 7 })
        );
    }

    let literal_source = SourceUnitRef::new(
        SourceUnitId::new("module.main.literal")?,
        digest(LITERAL_REPLACEMENT_TEXT.as_bytes()),
    );
    assert!(
        plan_static_import_rewrite(
            &authority,
            &rule_id,
            &rule,
            SourceUnitInput::new(literal_source, LITERAL_REPLACEMENT_TEXT.as_bytes()),
            PlannerLimits::new(LITERAL_REPLACEMENT_TEXT.len(), 1, MAX_REPLACEMENT_BYTES)?,
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn surrogate_pairs_and_escaped_backslashes_remain_matchable()
-> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (r#"import "\uD83D\uDE00";"#, "😀"),
        (r#"import "\\uD800";"#, r"\uD800"),
    ];
    for (case_index, (source_bytes, decoded_specifier)) in cases.into_iter().enumerate() {
        let rule_id = TransformRuleId::new(format!("main.rewrite-surrogate-case-{case_index}"))?;
        let one = NonZeroU16::new(1).ok_or("test match count must be nonzero")?;
        let rule = StaticImportRewrite::new(
            decoded_specifier.to_owned(),
            "compat:unambiguous".to_owned(),
            one,
        )?;
        let authority = authority(rule_id.clone(), rule.canonical_digest())?;
        let source = SourceUnitRef::new(
            SourceUnitId::new(format!("module.main.surrogate-case-{case_index}"))?,
            digest(source_bytes.as_bytes()),
        );
        assert!(
            plan_static_import_rewrite(
                &authority,
                &rule_id,
                &rule,
                SourceUnitInput::new(source, source_bytes.as_bytes()),
                PlannerLimits::new(source_bytes.len(), 1, MAX_REPLACEMENT_BYTES)?,
            )
            .is_ok()
        );
    }
    Ok(())
}

#[test]
fn malformed_regular_expression_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    const MALFORMED_SOURCE: &str = r#"import "node-pty"; const broken = /(/;"#;
    let rule_id = TransformRuleId::new("main.replace-node-pty")?;
    let one = NonZeroU16::new(1).ok_or("test match count must be nonzero")?;
    let rule = StaticImportRewrite::new(
        "node-pty".to_owned(),
        "compat:openai/conpty".to_owned(),
        one,
    )?;
    let authority = authority(rule_id.clone(), rule.canonical_digest())?;
    let source = SourceUnitRef::new(
        SourceUnitId::new("module.main.bootstrap")?,
        digest(MALFORMED_SOURCE.as_bytes()),
    );

    let result = plan_static_import_rewrite(
        &authority,
        &rule_id,
        &rule,
        SourceUnitInput::new(source, MALFORMED_SOURCE.as_bytes()),
        PlannerLimits::new(MALFORMED_SOURCE.len(), 1, MAX_REPLACEMENT_BYTES)?,
    );
    let Err(TransformPlanError::ParseFailed { diagnostic_count }) = result else {
        return Err("malformed regular-expression syntax must fail closed".into());
    };
    assert!(diagnostic_count > 0);
    Ok(())
}

#[test]
fn replacements_are_canonical_and_source_debug_is_redacted()
-> Result<(), Box<dyn std::error::Error>> {
    const ONE_IMPORT: &str = r#"import "node-pty";"#;
    let rule_id = TransformRuleId::new("main.replace-node-pty")?;
    let one = NonZeroU16::new(1).ok_or("test match count must be nonzero")?;
    let rule = StaticImportRewrite::new(
        "node-pty".to_owned(),
        "compat:\"quoted\"\\path\u{2028}\u{2029}".to_owned(),
        one,
    )?;
    let authority = authority(rule_id.clone(), rule.canonical_digest())?;
    let source = SourceUnitRef::new(
        SourceUnitId::new("module.main.bootstrap")?,
        digest(ONE_IMPORT.as_bytes()),
    );
    let debug = format!(
        "{:?}",
        SourceUnitInput::new(source.clone(), b"SECRET_SOURCE_BYTES")
    );
    assert!(!debug.contains("SECRET_SOURCE_BYTES"));
    assert!(debug.contains("byte_length"));

    let plan = plan_static_import_rewrite(
        &authority,
        &rule_id,
        &rule,
        SourceUnitInput::new(source, ONE_IMPORT.as_bytes()),
        PlannerLimits::new(ONE_IMPORT.len(), 1, MAX_REPLACEMENT_BYTES)?,
    )?;
    let Some(edit) = plan.edits().first() else {
        return Err("one canonical replacement edit was expected".into());
    };
    assert_eq!(
        edit.replacement(),
        "\"compat:\\\"quoted\\\"\\\\path\\u2028\\u2029\""
    );
    Ok(())
}

fn authority(
    rule_id: TransformRuleId,
    rule_digest: Sha256Digest,
) -> Result<AdapterTransformAuthority, Box<dyn std::error::Error>> {
    Ok(AdapterTransformAuthority::new(
        AdapterId::new("openai.desktop")?,
        ApplicationFamilyId::new("openai.chatgpt.windows")?,
        digest(b"adapter"),
        BTreeMap::from([(rule_id, AuthorizedTransformRuleRef::new(rule_digest))]),
    )?)
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn apply_edits(
    source: &str,
    edits: &[weregopher_transform::TextEdit],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut transformed = source.to_owned();
    for edit in edits.iter().rev() {
        let start = usize::try_from(edit.start_byte())?;
        let end = usize::try_from(edit.end_byte())?;
        transformed.replace_range(start..end, edit.replacement());
    }
    Ok(transformed)
}
