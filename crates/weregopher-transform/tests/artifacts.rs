//! Behavior tests for transform-artifact byte verification.

use std::collections::BTreeMap;

use sha2::{Digest as _, Sha256};
use weregopher_domain::{
    AdapterId, AdapterTransformAuthority, ApplicationFamilyId, AuthorizedTransformRuleRef,
    GeneratedTransformOverlay, Sha256Digest, SourceUnitId, SourceUnitRef,
    StructurallyValidatedTransformOverlay, TransformContractError, TransformOverlayBinding,
    TransformRebinding, TransformRuleId,
};
use weregopher_transform::{
    TransformArtifactBytes, TransformArtifactError, TransformArtifactKind, TransformArtifactLimits,
    verify_transform_artifacts,
};

const SOURCE: &[u8] = b"import pty from 'node-pty';";
const MATCH_EVIDENCE: &[u8] = br#"{"matcher":"import","specifier":"node-pty"}"#;
const TRANSFORMED_SOURCE: &[u8] = b"import pty from 'compat:openai/conpty';";
const SOURCE_MAP: &[u8] = br#"{"version":3,"mappings":"AAAA"}"#;
const AUDIT_LOG: &[u8] = br#"{"rule":"main.replace-node-pty","matches":1}"#;

#[test]
fn exact_artifact_bytes_are_verified() -> Result<(), Box<dyn std::error::Error>> {
    let rule_id = TransformRuleId::new("main.replace-node-pty")?;
    let fixture = overlay_fixture(
        rule_id.clone(),
        SOURCE,
        MATCH_EVIDENCE,
        TRANSFORMED_SOURCE,
        SOURCE_MAP,
        AUDIT_LOG,
    )?;
    let artifacts = BTreeMap::from([(
        rule_id.clone(),
        TransformArtifactBytes::new(
            SOURCE,
            MATCH_EVIDENCE,
            TRANSFORMED_SOURCE,
            SOURCE_MAP,
            AUDIT_LOG,
        ),
    )]);
    let limits = TransformArtifactLimits::new(64, 64, 64, 64, 64, 320)?;

    let verified =
        verify_transform_artifacts(fixture.structurally_validated()?, &artifacts, limits)?;

    assert_eq!(verified.rule_count(), 1);
    assert_eq!(verified.overlay(), &fixture.overlay);
    assert_eq!(
        verified.structural_validation().authority(),
        &fixture.authority
    );
    let verified_bytes = verified
        .artifacts()
        .get(&rule_id)
        .ok_or("verified rule artifacts must be retained")?;
    assert_eq!(verified_bytes.source(), SOURCE);
    assert_eq!(verified_bytes.match_evidence(), MATCH_EVIDENCE);
    assert_eq!(verified_bytes.transformed_source(), TRANSFORMED_SOURCE);
    assert_eq!(verified_bytes.source_map(), SOURCE_MAP);
    assert_eq!(verified_bytes.audit_log(), AUDIT_LOG);
    Ok(())
}

#[test]
fn missing_artifact_bundle_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let rule_id = TransformRuleId::new("main.replace-node-pty")?;
    let fixture = overlay_fixture(
        rule_id.clone(),
        SOURCE,
        MATCH_EVIDENCE,
        TRANSFORMED_SOURCE,
        SOURCE_MAP,
        AUDIT_LOG,
    )?;

    let Err(error) = verify_transform_artifacts(
        fixture.structurally_validated()?,
        &BTreeMap::new(),
        TransformArtifactLimits::new(64, 64, 64, 64, 64, 320)?,
    ) else {
        return Err("missing transform artifacts must fail closed".into());
    };

    assert_eq!(
        error,
        TransformArtifactError::MissingArtifactBundle(rule_id)
    );
    Ok(())
}

#[test]
fn unexpected_artifact_bundle_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let rule_id = TransformRuleId::new("main.replace-node-pty")?;
    let unexpected_rule_id = TransformRuleId::new("main.unexpected")?;
    let fixture = overlay_fixture(
        rule_id.clone(),
        SOURCE,
        MATCH_EVIDENCE,
        TRANSFORMED_SOURCE,
        SOURCE_MAP,
        AUDIT_LOG,
    )?;
    let artifacts = BTreeMap::from([
        (rule_id, artifact_bytes()),
        (unexpected_rule_id.clone(), artifact_bytes()),
    ]);

    let Err(error) = verify_transform_artifacts(
        fixture.structurally_validated()?,
        &artifacts,
        TransformArtifactLimits::new(64, 64, 64, 64, 64, 320)?,
    ) else {
        return Err("unexpected transform artifacts must fail closed".into());
    };

    assert_eq!(
        error,
        TransformArtifactError::UnexpectedArtifactBundle(unexpected_rule_id)
    );
    Ok(())
}

#[test]
fn every_artifact_digest_must_match() -> Result<(), Box<dyn std::error::Error>> {
    let rule_id = TransformRuleId::new("main.replace-node-pty")?;
    let fixture = overlay_fixture(
        rule_id.clone(),
        SOURCE,
        MATCH_EVIDENCE,
        TRANSFORMED_SOURCE,
        SOURCE_MAP,
        AUDIT_LOG,
    )?;
    let cases = [
        (
            TransformArtifactKind::Source,
            TransformArtifactBytes::new(
                b"tampered source",
                MATCH_EVIDENCE,
                TRANSFORMED_SOURCE,
                SOURCE_MAP,
                AUDIT_LOG,
            ),
        ),
        (
            TransformArtifactKind::MatchEvidence,
            TransformArtifactBytes::new(
                SOURCE,
                b"tampered evidence",
                TRANSFORMED_SOURCE,
                SOURCE_MAP,
                AUDIT_LOG,
            ),
        ),
        (
            TransformArtifactKind::TransformedSource,
            TransformArtifactBytes::new(
                SOURCE,
                MATCH_EVIDENCE,
                b"tampered transform",
                SOURCE_MAP,
                AUDIT_LOG,
            ),
        ),
        (
            TransformArtifactKind::SourceMap,
            TransformArtifactBytes::new(
                SOURCE,
                MATCH_EVIDENCE,
                TRANSFORMED_SOURCE,
                b"tampered source map",
                AUDIT_LOG,
            ),
        ),
        (
            TransformArtifactKind::AuditLog,
            TransformArtifactBytes::new(
                SOURCE,
                MATCH_EVIDENCE,
                TRANSFORMED_SOURCE,
                SOURCE_MAP,
                b"tampered audit log",
            ),
        ),
    ];

    for (kind, bytes) in cases {
        let artifacts = BTreeMap::from([(rule_id.clone(), bytes)]);
        let Err(error) = verify_transform_artifacts(
            fixture.structurally_validated()?,
            &artifacts,
            TransformArtifactLimits::new(64, 64, 64, 64, 64, 320)?,
        ) else {
            return Err(format!("tampered {kind:?} bytes must fail closed").into());
        };
        assert_eq!(
            error,
            TransformArtifactError::DigestMismatch {
                rule_id: rule_id.clone(),
                artifact: kind,
            }
        );
    }
    Ok(())
}

#[test]
fn every_artifact_kind_is_bounded_before_hashing() -> Result<(), Box<dyn std::error::Error>> {
    let rule_id = TransformRuleId::new("main.replace-node-pty")?;
    let fixture = overlay_fixture(
        rule_id.clone(),
        SOURCE,
        MATCH_EVIDENCE,
        TRANSFORMED_SOURCE,
        SOURCE_MAP,
        AUDIT_LOG,
    )?;
    let artifacts = BTreeMap::from([(rule_id.clone(), artifact_bytes())]);
    let cases = [
        (
            TransformArtifactKind::Source,
            SOURCE.len(),
            TransformArtifactLimits::new(SOURCE.len() - 1, 64, 64, 64, 64, 320)?,
        ),
        (
            TransformArtifactKind::MatchEvidence,
            MATCH_EVIDENCE.len(),
            TransformArtifactLimits::new(64, MATCH_EVIDENCE.len() - 1, 64, 64, 64, 320)?,
        ),
        (
            TransformArtifactKind::TransformedSource,
            TRANSFORMED_SOURCE.len(),
            TransformArtifactLimits::new(64, 64, TRANSFORMED_SOURCE.len() - 1, 64, 64, 320)?,
        ),
        (
            TransformArtifactKind::SourceMap,
            SOURCE_MAP.len(),
            TransformArtifactLimits::new(64, 64, 64, SOURCE_MAP.len() - 1, 64, 320)?,
        ),
        (
            TransformArtifactKind::AuditLog,
            AUDIT_LOG.len(),
            TransformArtifactLimits::new(64, 64, 64, 64, AUDIT_LOG.len() - 1, 320)?,
        ),
    ];

    for (kind, actual_bytes, limits) in cases {
        let Err(error) =
            verify_transform_artifacts(fixture.structurally_validated()?, &artifacts, limits)
        else {
            return Err(format!("oversized {kind:?} bytes must fail closed").into());
        };
        assert_eq!(
            error,
            TransformArtifactError::ArtifactTooLarge {
                rule_id: rule_id.clone(),
                artifact: kind,
                actual_bytes,
                max_bytes: actual_bytes - 1,
            }
        );
    }
    Ok(())
}

#[test]
fn aggregate_byte_limit_is_exact() -> Result<(), Box<dyn std::error::Error>> {
    let rule_id = TransformRuleId::new("main.replace-node-pty")?;
    let fixture = overlay_fixture(
        rule_id.clone(),
        SOURCE,
        MATCH_EVIDENCE,
        TRANSFORMED_SOURCE,
        SOURCE_MAP,
        AUDIT_LOG,
    )?;
    let artifacts = BTreeMap::from([(rule_id, artifact_bytes())]);
    let total_bytes = SOURCE.len()
        + MATCH_EVIDENCE.len()
        + TRANSFORMED_SOURCE.len()
        + SOURCE_MAP.len()
        + AUDIT_LOG.len();

    let Err(error) = verify_transform_artifacts(
        fixture.structurally_validated()?,
        &artifacts,
        TransformArtifactLimits::new(64, 64, 64, 64, 64, total_bytes - 1)?,
    ) else {
        return Err("aggregate artifact bytes above the exact limit must fail".into());
    };
    assert_eq!(
        error,
        TransformArtifactError::TotalBytesExceeded {
            actual_bytes: total_bytes,
            max_bytes: total_bytes - 1,
        }
    );

    verify_transform_artifacts(
        fixture.structurally_validated()?,
        &artifacts,
        TransformArtifactLimits::new(
            SOURCE.len(),
            MATCH_EVIDENCE.len(),
            TRANSFORMED_SOURCE.len(),
            SOURCE_MAP.len(),
            AUDIT_LOG.len(),
            total_bytes,
        )?,
    )?;
    Ok(())
}

#[test]
fn zero_byte_limits_are_rejected() {
    let cases = [
        (0, 1, 1, 1, 1, 1),
        (1, 0, 1, 1, 1, 1),
        (1, 1, 0, 1, 1, 1),
        (1, 1, 1, 0, 1, 1),
        (1, 1, 1, 1, 0, 1),
        (1, 1, 1, 1, 1, 0),
    ];

    for (source, evidence, transformed, source_map, audit, total) in cases {
        assert_eq!(
            TransformArtifactLimits::new(source, evidence, transformed, source_map, audit, total,),
            Err(TransformArtifactError::InvalidLimits)
        );
    }
}

#[test]
fn debug_output_redacts_artifact_contents() {
    let bytes = TransformArtifactBytes::new(
        b"PRIVATE_SOURCE_MARKER",
        b"PRIVATE_EVIDENCE_MARKER",
        b"PRIVATE_TRANSFORM_MARKER",
        b"PRIVATE_SOURCE_MAP_MARKER",
        b"PRIVATE_AUDIT_MARKER",
    );

    let debug = format!("{bytes:?}");

    for marker in [
        "PRIVATE_SOURCE_MARKER",
        "PRIVATE_EVIDENCE_MARKER",
        "PRIVATE_TRANSFORM_MARKER",
        "PRIVATE_SOURCE_MAP_MARKER",
        "PRIVATE_AUDIT_MARKER",
    ] {
        assert!(!debug.contains(marker));
    }
    assert!(debug.contains("source_length"));
    assert!(debug.contains("audit_log_length"));
}

struct OverlayFixture {
    authority: AdapterTransformAuthority,
    overlay: GeneratedTransformOverlay,
}

impl OverlayFixture {
    fn structurally_validated(
        &self,
    ) -> Result<StructurallyValidatedTransformOverlay<'_, '_>, TransformContractError> {
        self.overlay.validate_against(
            &self.authority,
            digest(b"source-build"),
            digest(b"build-descriptor"),
        )
    }
}

fn overlay_fixture(
    rule_id: TransformRuleId,
    source: &[u8],
    match_evidence: &[u8],
    transformed_source: &[u8],
    source_map: &[u8],
    audit_log: &[u8],
) -> Result<OverlayFixture, Box<dyn std::error::Error>> {
    let adapter_id = AdapterId::new("openai.desktop")?;
    let family = ApplicationFamilyId::new("openai.chatgpt.windows")?;
    let adapter_content_digest = digest(b"adapter");
    let rule_digest = digest(b"replace-node-pty-rule-v1");
    let authority = AdapterTransformAuthority::new(
        adapter_id.clone(),
        family.clone(),
        adapter_content_digest,
        BTreeMap::from([(
            rule_id.clone(),
            AuthorizedTransformRuleRef::new(rule_digest),
        )]),
    )?;
    let overlay = GeneratedTransformOverlay::windows_x64(
        TransformOverlayBinding::new(
            digest(b"source-build"),
            family,
            adapter_id,
            adapter_content_digest,
            authority.canonical_document_digest(),
            digest(b"build-descriptor"),
        ),
        BTreeMap::from([(
            rule_id,
            TransformRebinding::new(
                rule_digest,
                SourceUnitRef::new(SourceUnitId::new("module.main.bootstrap")?, digest(source)),
                digest(match_evidence),
                digest(transformed_source),
                digest(source_map),
                digest(audit_log),
            ),
        )]),
    )?;
    Ok(OverlayFixture { authority, overlay })
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn artifact_bytes() -> TransformArtifactBytes<'static> {
    TransformArtifactBytes::new(
        SOURCE,
        MATCH_EVIDENCE,
        TRANSFORMED_SOURCE,
        SOURCE_MAP,
        AUDIT_LOG,
    )
}
