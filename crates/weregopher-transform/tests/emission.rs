//! Behavior tests for bounded deterministic transformed-source emission.

use std::{collections::BTreeMap, num::NonZeroU16};

use sha2::{Digest as _, Sha256};
use weregopher_domain::{
    AdapterId, AdapterTransformAuthority, ApplicationFamilyId, AuthorizedTransformRuleRef,
    Sha256Digest, SourceUnitId, SourceUnitRef, TransformRuleId,
};
use weregopher_transform::{
    PlannerLimits, SourceUnitInput, StaticImportRewrite, TransformEmissionError,
    TransformEmissionLimits, emit_transformed_source, plan_static_import_rewrite,
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
