//! Behavior tests for bounded deterministic transformed-source emission.

use std::{collections::BTreeMap, num::NonZeroU16};

use sha2::{Digest as _, Sha256};
use weregopher_domain::{
    AdapterId, AdapterTransformAuthority, ApplicationFamilyId, AuthorizedTransformRuleRef,
    Sha256Digest, SourceUnitId, SourceUnitRef, TransformRuleId,
};
use weregopher_transform::{
    MatchEvidenceError, MatchEvidenceLimits, PlannerLimits, SourceMapError, SourceMapLimits,
    SourceUnitInput, StaticImportRewrite, TransformEmissionError, TransformEmissionLimits,
    emit_match_evidence, emit_source_map, emit_transformed_source, plan_static_import_rewrite,
};

const SOURCE: &[u8] =
    b"import pty from 'node-pty';\nexport * from \"node-pty\";\n// PRIVATE_SOURCE_MARKER\n";
const TRANSFORMED: &[u8] = b"import pty from \"compat:openai/conpty\";\nexport * from \"compat:openai/conpty\";\n// PRIVATE_SOURCE_MARKER\n";

#[test]
fn exact_plan_emits_deterministic_transformed_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let plan = plan()?;
    let limits = TransformEmissionLimits::new(SOURCE.len(), TRANSFORMED.len())?;

    let first = emit_transformed_source(&plan, SOURCE, limits)?;
    let second = emit_transformed_source(&plan, SOURCE, limits)?;

    assert_eq!(first.transformed_source(), TRANSFORMED);
    assert_eq!(first.transformed_source_digest(), &digest(TRANSFORMED));
    assert_eq!(first.transformed_source(), second.transformed_source());
    assert_eq!(
        first.transformed_source_digest(),
        second.transformed_source_digest()
    );
    assert_eq!(first.plan(), &plan);
    Ok(())
}

#[test]
fn source_and_output_limits_fail_closed_before_emission() -> Result<(), Box<dyn std::error::Error>>
{
    let plan = plan()?;
    assert_eq!(
        emit_transformed_source(
            &plan,
            SOURCE,
            TransformEmissionLimits::new(SOURCE.len() - 1, TRANSFORMED.len())?,
        ),
        Err(TransformEmissionError::SourceTooLarge {
            actual_bytes: SOURCE.len(),
            max_bytes: SOURCE.len() - 1,
        })
    );
    assert_eq!(
        emit_transformed_source(
            &plan,
            SOURCE,
            TransformEmissionLimits::new(SOURCE.len(), TRANSFORMED.len() - 1)?,
        ),
        Err(TransformEmissionError::TransformedSourceTooLarge {
            actual_bytes: TRANSFORMED.len(),
            max_bytes: TRANSFORMED.len() - 1,
        })
    );
    assert!(
        emit_transformed_source(
            &plan,
            SOURCE,
            TransformEmissionLimits::new(SOURCE.len(), TRANSFORMED.len())?,
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn mismatched_source_identity_cannot_be_emitted() -> Result<(), Box<dyn std::error::Error>> {
    let plan = plan()?;
    let mut tampered = SOURCE.to_vec();
    tampered[0] = b'e';

    assert_eq!(
        emit_transformed_source(
            &plan,
            &tampered,
            TransformEmissionLimits::new(tampered.len(), TRANSFORMED.len())?,
        ),
        Err(TransformEmissionError::SourceDigestMismatch)
    );
    Ok(())
}

#[test]
fn emission_limits_must_be_nonzero() {
    assert_eq!(
        TransformEmissionLimits::new(0, 1),
        Err(TransformEmissionError::InvalidLimits)
    );
    assert_eq!(
        TransformEmissionLimits::new(1, 0),
        Err(TransformEmissionError::InvalidLimits)
    );
}

#[test]
fn emitted_debug_output_redacts_transformed_source() -> Result<(), Box<dyn std::error::Error>> {
    let plan = plan()?;
    let emitted = emit_transformed_source(
        &plan,
        SOURCE,
        TransformEmissionLimits::new(SOURCE.len(), TRANSFORMED.len())?,
    )?;

    let debug = format!("{emitted:?}");
    assert!(!debug.contains("PRIVATE_SOURCE_MARKER"));
    assert!(debug.contains("transformed_source_length"));
    assert!(debug.contains("transformed_source_digest"));
    Ok(())
}

#[test]
fn match_evidence_has_one_canonical_bounded_representation()
-> Result<(), Box<dyn std::error::Error>> {
    let plan = plan()?;
    let emitted = emit_match_evidence(&plan, MatchEvidenceLimits::new(2_048)?)?;
    let matches = plan
        .edits()
        .iter()
        .map(|edit| {
            format!(
                r#"{{"start_byte":{},"end_byte":{}}}"#,
                edit.start_byte(),
                edit.end_byte()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let expected = format!(
        r#"{{"format_version":"1","kind":"static_module_specifier_matches","rule_id":"{}","rule_digest":"{}","source":{{"unit_id":"{}","source_digest":"{}"}},"matches":[{matches}]}}"#,
        plan.rule_id(),
        plan.rule_digest(),
        plan.source().unit_id(),
        plan.source().source_digest(),
    );

    assert_eq!(emitted.bytes(), expected.as_bytes());
    assert_eq!(emitted.digest(), &digest(expected.as_bytes()));
    assert_eq!(
        emitted.digest().to_string(),
        "sha256:8554d8bc4dc7ffde03e11bcd8ecb9d2da0d27ae679a99c9f9fe467e40e486137"
    );
    let parsed: serde_json::Value = serde_json::from_slice(emitted.bytes())?;
    assert_eq!(parsed["matches"].as_array().map(Vec::len), Some(2));
    assert_eq!(emitted.plan(), &plan);
    assert!(emit_match_evidence(&plan, MatchEvidenceLimits::new(expected.len())?).is_ok());
    assert_eq!(
        emit_match_evidence(&plan, MatchEvidenceLimits::new(expected.len() - 1)?,),
        Err(MatchEvidenceError::EvidenceTooLarge {
            actual_bytes: expected.len(),
            max_bytes: expected.len() - 1,
        })
    );
    Ok(())
}

#[test]
fn match_evidence_limits_and_debug_output_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        MatchEvidenceLimits::new(0),
        Err(MatchEvidenceError::InvalidLimit)
    );
    let plan = plan()?;
    let emitted = emit_match_evidence(&plan, MatchEvidenceLimits::new(2_048)?)?;
    let debug = format!("{emitted:?}");
    assert!(!debug.contains("PRIVATE_SOURCE_MARKER"));
    assert!(debug.contains("evidence_length"));
    assert!(debug.contains("evidence_digest"));
    Ok(())
}

#[test]
fn source_map_v3_is_canonical_and_maps_every_edit_boundary()
-> Result<(), Box<dyn std::error::Error>> {
    let plan = plan()?;
    let transformed = emit_transformed_source(
        &plan,
        SOURCE,
        TransformEmissionLimits::new(SOURCE.len(), TRANSFORMED.len())?,
    )?;
    let emitted = emit_source_map(
        &transformed,
        SOURCE,
        SourceMapLimits::new(SOURCE.len(), TRANSFORMED.len(), 8, 2_048)?,
    )?;
    let mappings = "AAAA,gBAAgB,sBAAU;AAC1B,cAAc,sBAAU;AACxB;AACA";
    let expected = format!(
        r#"{{"version":3,"sources":["{}"],"names":[],"mappings":"{mappings}","x_weregopher":{{"format_version":"1","rule_id":"{}","rule_digest":"{}","source_digest":"{}","transformed_source_digest":"{}"}}}}"#,
        plan.source().unit_id(),
        plan.rule_id(),
        plan.rule_digest(),
        plan.source().source_digest(),
        transformed.transformed_source_digest(),
    );

    assert_eq!(emitted.bytes(), expected.as_bytes());
    assert_eq!(emitted.digest(), &digest(expected.as_bytes()));
    assert_eq!(
        emitted.digest().to_string(),
        "sha256:d04815969760ee6702ac42647ac0117bbda9a67ba5b35612cc0dccd4624b1dd6"
    );
    assert_eq!(emitted.segment_count(), 8);
    assert_eq!(emitted.transformed_source(), &transformed);
    let debug = format!("{emitted:?}");
    assert!(!debug.contains("PRIVATE_SOURCE_MARKER"));
    assert!(debug.contains("source_map_length"));
    let parsed: serde_json::Value = serde_json::from_slice(emitted.bytes())?;
    assert_eq!(parsed["version"].as_u64(), Some(3));
    assert_eq!(parsed["mappings"].as_str(), Some(mappings));
    assert!(
        emit_source_map(
            &transformed,
            SOURCE,
            SourceMapLimits::new(SOURCE.len(), TRANSFORMED.len(), 8, expected.len())?,
        )
        .is_ok()
    );
    assert_eq!(
        emit_source_map(
            &transformed,
            SOURCE,
            SourceMapLimits::new(SOURCE.len(), TRANSFORMED.len(), 8, expected.len() - 1)?,
        ),
        Err(SourceMapError::SourceMapTooLarge {
            actual_bytes: expected.len(),
            max_bytes: expected.len() - 1,
        })
    );
    Ok(())
}

#[test]
fn source_map_limits_and_source_identity_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        SourceMapLimits::new(0, 1, 1, 1),
        Err(SourceMapError::InvalidLimits)
    );
    assert_eq!(
        SourceMapLimits::new(1, 0, 1, 1),
        Err(SourceMapError::InvalidLimits)
    );
    assert_eq!(
        SourceMapLimits::new(1, 1, 0, 1),
        Err(SourceMapError::InvalidLimits)
    );
    assert_eq!(
        SourceMapLimits::new(1, 1, 1, 0),
        Err(SourceMapError::InvalidLimits)
    );
    let plan = plan()?;
    let transformed = emit_transformed_source(
        &plan,
        SOURCE,
        TransformEmissionLimits::new(SOURCE.len(), TRANSFORMED.len())?,
    )?;
    assert_eq!(
        emit_source_map(
            &transformed,
            SOURCE,
            SourceMapLimits::new(SOURCE.len() - 1, TRANSFORMED.len(), 8, 2_048)?,
        ),
        Err(SourceMapError::SourceTooLarge {
            actual_bytes: SOURCE.len(),
            max_bytes: SOURCE.len() - 1,
        })
    );
    assert_eq!(
        emit_source_map(
            &transformed,
            SOURCE,
            SourceMapLimits::new(SOURCE.len(), TRANSFORMED.len() - 1, 8, 2_048)?,
        ),
        Err(SourceMapError::TransformedSourceTooLarge {
            actual_bytes: TRANSFORMED.len(),
            max_bytes: TRANSFORMED.len() - 1,
        })
    );
    assert_eq!(
        emit_source_map(
            &transformed,
            SOURCE,
            SourceMapLimits::new(SOURCE.len(), TRANSFORMED.len(), 7, 2_048)?,
        ),
        Err(SourceMapError::SegmentLimitExceeded {
            required_segments: 8,
            max_segments: 7,
        })
    );
    let mut tampered = SOURCE.to_vec();
    tampered[0] = b'e';
    assert_eq!(
        emit_source_map(
            &transformed,
            &tampered,
            SourceMapLimits::new(SOURCE.len(), TRANSFORMED.len(), 8, 2_048)?,
        ),
        Err(SourceMapError::SourceDigestMismatch)
    );
    Ok(())
}

#[test]
fn source_map_columns_are_utf16_and_crlf_is_one_line_break()
-> Result<(), Box<dyn std::error::Error>> {
    const SOURCE_WITH_ASTRAL: &[u8] = "import \"😀\"; export * from \"node-pty\";\r\n".as_bytes();
    const TRANSFORMED_WITH_ASTRAL: &[u8] = "import \"😀\"; export * from \"x\";\r\n".as_bytes();
    let rule_id = TransformRuleId::new("main.replace-node-pty-utf16")?;
    let one = NonZeroU16::new(1).ok_or("test match count must be nonzero")?;
    let rule = StaticImportRewrite::new("node-pty".to_owned(), "x".to_owned(), one)?;
    let authority = AdapterTransformAuthority::new(
        AdapterId::new("openai.desktop")?,
        ApplicationFamilyId::new("openai.chatgpt.windows")?,
        digest(b"adapter"),
        BTreeMap::from([(
            rule_id.clone(),
            AuthorizedTransformRuleRef::new(rule.canonical_digest()),
        )]),
    )?;
    let source_ref = SourceUnitRef::new(
        SourceUnitId::new("module.main.utf16")?,
        digest(SOURCE_WITH_ASTRAL),
    );
    let plan = plan_static_import_rewrite(
        &authority,
        &rule_id,
        &rule,
        SourceUnitInput::new(source_ref, SOURCE_WITH_ASTRAL),
        PlannerLimits::new(SOURCE_WITH_ASTRAL.len(), 1, 8)?,
    )?;
    let transformed = emit_transformed_source(
        &plan,
        SOURCE_WITH_ASTRAL,
        TransformEmissionLimits::new(SOURCE_WITH_ASTRAL.len(), TRANSFORMED_WITH_ASTRAL.len())?,
    )?;
    let emitted = emit_source_map(
        &transformed,
        SOURCE_WITH_ASTRAL,
        SourceMapLimits::new(
            SOURCE_WITH_ASTRAL.len(),
            TRANSFORMED_WITH_ASTRAL.len(),
            4,
            2_048,
        )?,
    )?;
    let parsed: serde_json::Value = serde_json::from_slice(emitted.bytes())?;
    assert_eq!(parsed["mappings"].as_str(), Some("AAAA,2BAA2B,GAAU;AACrC"));
    assert_eq!(emitted.segment_count(), 4);
    Ok(())
}

fn plan() -> Result<weregopher_transform::TransformPlan, Box<dyn std::error::Error>> {
    let rule_id = TransformRuleId::new("main.replace-node-pty")?;
    let two = NonZeroU16::new(2).ok_or("test match count must be nonzero")?;
    let rule = StaticImportRewrite::new(
        "node-pty".to_owned(),
        "compat:openai/conpty".to_owned(),
        two,
    )?;
    let authority = AdapterTransformAuthority::new(
        AdapterId::new("openai.desktop")?,
        ApplicationFamilyId::new("openai.chatgpt.windows")?,
        digest(b"adapter"),
        BTreeMap::from([(
            rule_id.clone(),
            AuthorizedTransformRuleRef::new(rule.canonical_digest()),
        )]),
    )?;
    let source = SourceUnitRef::new(SourceUnitId::new("module.main.bootstrap")?, digest(SOURCE));
    Ok(plan_static_import_rewrite(
        &authority,
        &rule_id,
        &rule,
        SourceUnitInput::new(source, SOURCE),
        PlannerLimits::new(SOURCE.len(), 2, 64)?,
    )?)
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}
