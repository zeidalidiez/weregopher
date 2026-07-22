//! End-to-end in-memory composition regression for the transform trust boundaries.

use std::{collections::BTreeMap, num::NonZeroU16};

use sha2::{Digest as _, Sha256};
use weregopher_domain::{
    AdapterId, AdapterTransformAuthority, ApplicationFamilyId, AuthorizedTransformRuleRef,
    GeneratedTransformOverlay, Sha256Digest, SourceUnitId, SourceUnitRef, TransformOverlayBinding,
    TransformRuleId,
};
use weregopher_transform::{
    MatchEvidenceLimits, MaterializationManifestError, MaterializationManifestLimits,
    PlannerLimits, SourceMapLimits, SourceUnitInput, StaticImportRewrite, TransformArtifactLimits,
    TransformBundleLimits, TransformEmissionLimits, assemble_transform_artifacts,
    emit_match_evidence, emit_source_map, emit_transformed_source,
    plan_content_addressed_materialization, plan_static_import_rewrite, verify_transform_artifacts,
};

const SOURCE: &[u8] = b"import pty from 'node-pty';\n";
const TRANSFORMED_SOURCE: &[u8] = b"import pty from \"compat:openai/conpty\";\n";

#[test]
fn exact_plan_composes_through_overlay_validation_and_artifact_verification()
-> Result<(), Box<dyn std::error::Error>> {
    let rule_id = TransformRuleId::new("main.replace-node-pty")?;
    let one = NonZeroU16::new(1).ok_or("test match count must be nonzero")?;
    let rule = StaticImportRewrite::new(
        "node-pty".to_owned(),
        "compat:openai/conpty".to_owned(),
        one,
    )?;
    let adapter_id = AdapterId::new("openai.desktop")?;
    let family = ApplicationFamilyId::new("openai.chatgpt.windows")?;
    let adapter_content_digest = digest(b"adapter");
    let authority = AdapterTransformAuthority::new(
        adapter_id.clone(),
        family.clone(),
        adapter_content_digest,
        BTreeMap::from([(
            rule_id.clone(),
            AuthorizedTransformRuleRef::new(rule.canonical_digest()),
        )]),
    )?;
    let source_ref =
        SourceUnitRef::new(SourceUnitId::new("module.main.bootstrap")?, digest(SOURCE));
    let plan = plan_static_import_rewrite(
        &authority,
        &rule_id,
        &rule,
        SourceUnitInput::new(source_ref, SOURCE),
        PlannerLimits::new(SOURCE.len(), 1, 64)?,
    )?;
    let transformed = emit_transformed_source(
        &plan,
        SOURCE,
        TransformEmissionLimits::new(SOURCE.len(), TRANSFORMED_SOURCE.len())?,
    )?;
    let match_evidence = emit_match_evidence(&plan, MatchEvidenceLimits::new(2_048)?)?;
    let source_map = emit_source_map(
        &transformed,
        SOURCE,
        SourceMapLimits::new(SOURCE.len(), TRANSFORMED_SOURCE.len(), 4, 2_048)?,
    )?;
    let bundle = assemble_transform_artifacts(
        SOURCE,
        &transformed,
        &match_evidence,
        &source_map,
        TransformBundleLimits::new(SOURCE.len(), 2_048, 8_192)?,
    )?;

    let source_build_digest = digest(b"source-build");
    let build_descriptor_digest = digest(b"build-descriptor");
    let overlay = GeneratedTransformOverlay::windows_x64(
        TransformOverlayBinding::new(
            source_build_digest,
            family,
            adapter_id,
            adapter_content_digest,
            authority.canonical_document_digest(),
            build_descriptor_digest,
        ),
        BTreeMap::from([(rule_id.clone(), bundle.rebinding().clone())]),
    )?;
    let structural_validation =
        overlay.validate_against(&authority, source_build_digest, build_descriptor_digest)?;
    let artifact_bytes = bundle.artifacts();
    let artifacts = BTreeMap::from([(rule_id, artifact_bytes)]);
    let verified = verify_transform_artifacts(
        structural_validation,
        &artifacts,
        TransformArtifactLimits::new(
            artifact_bytes.source().len(),
            artifact_bytes.match_evidence().len(),
            artifact_bytes.transformed_source().len(),
            artifact_bytes.source_map().len(),
            artifact_bytes.audit_log().len(),
            bundle.total_bytes(),
        )?,
    )?;

    assert_eq!(verified.overlay(), &overlay);
    assert_eq!(verified.rule_count(), 1);
    assert_eq!(verified.artifacts(), &artifacts);
    assert_eq!(verified.structural_validation().authority(), &authority);
    assert_materialization_manifest(&verified)?;
    Ok(())
}

fn assert_materialization_manifest(
    verified: &weregopher_transform::VerifiedTransformArtifacts<'_, '_, '_, '_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = plan_content_addressed_materialization(
        verified,
        MaterializationManifestLimits::new(1, 5, 5, 4_096)?,
    )?;
    assert_eq!(manifest.rule_count(), 1);
    assert_eq!(manifest.reference_count(), 5);
    assert_eq!(manifest.blob_count(), 5);
    assert_eq!(manifest.verified_artifacts().overlay(), verified.overlay());
    let parsed: serde_json::Value = serde_json::from_slice(manifest.bytes())?;
    assert_eq!(parsed["format_version"].as_str(), Some("1"));
    assert_eq!(parsed["layout"].as_str(), Some("sha256-fanout-v1"));
    assert_eq!(parsed["target"].as_str(), Some("windows-x86_64"));
    assert_eq!(parsed["rules"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        parsed["rules"][0]["artifacts"].as_array().map(Vec::len),
        Some(5)
    );
    assert_eq!(
        parsed["rules"][0]["artifacts"][0]["path"].as_str(),
        Some("sha256/3c/d297afb3f4857b9c794d2f8495f5c5ecc766bfd8d1fc3598e819d46cd929df")
    );
    assert_eq!(
        manifest.digest().to_string(),
        "sha256:11c9347d5e7dda52dd9e1831694166023bed103caf8a72e15a775a7dc8d7adf5"
    );
    for (blob_digest, bytes) in manifest.blobs() {
        assert_eq!(&digest(bytes), blob_digest);
    }
    assert!(
        plan_content_addressed_materialization(
            verified,
            MaterializationManifestLimits::new(1, 5, 5, manifest.bytes().len())?,
        )
        .is_ok()
    );
    assert!(matches!(
        plan_content_addressed_materialization(
            verified,
            MaterializationManifestLimits::new(1, 5, 5, manifest.bytes().len() - 1)?,
        ),
        Err(MaterializationManifestError::ManifestTooLarge {
            actual_bytes,
            max_bytes,
        }) if actual_bytes == manifest.bytes().len()
            && max_bytes == manifest.bytes().len() - 1
    ));
    assert!(matches!(
        plan_content_addressed_materialization(
            verified,
            MaterializationManifestLimits::new(1, 4, 5, 4_096)?,
        ),
        Err(MaterializationManifestError::ReferenceLimitExceeded { actual: 5, max: 4 })
    ));
    assert!(matches!(
        plan_content_addressed_materialization(
            verified,
            MaterializationManifestLimits::new(1, 5, 4, 4_096)?,
        ),
        Err(MaterializationManifestError::BlobLimitExceeded { max: 4 })
    ));
    let debug = format!("{manifest:?}");
    assert!(!debug.contains("node-pty"));
    assert!(
        !manifest
            .bytes()
            .windows(b"import pty".len())
            .any(|window| window == b"import pty")
    );
    assert!(debug.contains("manifest_digest"));
    Ok(())
}

#[test]
fn materialization_manifest_limits_must_be_nonzero() {
    for limits in [(0, 1, 1, 1), (1, 0, 1, 1), (1, 1, 0, 1), (1, 1, 1, 0)] {
        assert_eq!(
            MaterializationManifestLimits::new(limits.0, limits.1, limits.2, limits.3),
            Err(MaterializationManifestError::InvalidLimits)
        );
    }
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}
