//! Canonical multi-rule materialization-manifest regressions.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest as _, Sha256};
use weregopher_domain::{
    AdapterId, AdapterTransformAuthority, ApplicationFamilyId, AuthorizedTransformRuleRef,
    GeneratedTransformOverlay, Sha256Digest, SourceUnitId, SourceUnitRef,
    StructurallyValidatedTransformOverlay, TransformContractError, TransformOverlayBinding,
    TransformRebinding, TransformRuleId,
};
use weregopher_transform::{
    MaterializationManifestError, MaterializationManifestLimits, TransformArtifactBytes,
    TransformArtifactLimits, plan_content_addressed_materialization, verify_transform_artifacts,
};

const SHARED_SOURCE_AND_MAP: &[u8] = b"shared-source-and-map";
const SHARED_AUDIT: &[u8] = b"shared-audit";
const ALPHA_EVIDENCE: &[u8] = b"alpha-evidence";
const ALPHA_TRANSFORMED: &[u8] = b"alpha-transformed";
const ZETA_EVIDENCE: &[u8] = b"zeta-evidence";
const ZETA_TRANSFORMED: &[u8] = b"zeta-transformed";

#[test]
fn multi_rule_manifest_is_canonical_across_input_order() -> Result<(), Box<dyn std::error::Error>> {
    let forward = manifest_fixture(false)?;
    let reverse = manifest_fixture(true)?;
    let forward_validation = forward.structurally_validated()?;
    let reverse_validation = reverse.structurally_validated()?;
    let forward_verified =
        verify_transform_artifacts(forward_validation, &forward.artifacts, artifact_limits()?)?;
    let reverse_verified =
        verify_transform_artifacts(reverse_validation, &reverse.artifacts, artifact_limits()?)?;
    let forward_manifest = plan_content_addressed_materialization(
        &forward_verified,
        MaterializationManifestLimits::new(2, 10, 6, 8_192)?,
    )?;
    let reverse_manifest = plan_content_addressed_materialization(
        &reverse_verified,
        MaterializationManifestLimits::new(2, 10, 6, 8_192)?,
    )?;

    assert_eq!(forward_manifest.bytes(), reverse_manifest.bytes());
    assert_eq!(forward_manifest.digest(), reverse_manifest.digest());
    assert_eq!(forward_manifest.blobs(), reverse_manifest.blobs());
    let document: serde_json::Value = serde_json::from_slice(forward_manifest.bytes())?;
    let rule_ids = document["rules"]
        .as_array()
        .ok_or("manifest rules must be an array")?
        .iter()
        .map(|rule| {
            rule["rule_id"]
                .as_str()
                .ok_or("manifest rule id must be text")
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(rule_ids, ["main.alpha", "main.zeta"]);
    Ok(())
}

#[test]
fn duplicate_artifact_bytes_deduplicate_without_losing_references()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = manifest_fixture(false)?;
    let verified = verify_transform_artifacts(
        fixture.structurally_validated()?,
        &fixture.artifacts,
        artifact_limits()?,
    )?;
    let manifest = plan_content_addressed_materialization(
        &verified,
        MaterializationManifestLimits::new(2, 10, 6, 8_192)?,
    )?;
    let document: serde_json::Value = serde_json::from_slice(manifest.bytes())?;
    let rules = document["rules"]
        .as_array()
        .ok_or("manifest rules must be an array")?;
    let references = rules
        .iter()
        .map(|rule| rule["artifacts"].as_array().map_or(0, std::vec::Vec::len))
        .sum::<usize>();
    assert_eq!(references, 10);
    assert_eq!(manifest.reference_count(), 10);

    let expected_unique = fixture
        .artifacts
        .values()
        .flat_map(artifact_values)
        .map(digest)
        .collect::<BTreeSet<_>>();
    assert_eq!(expected_unique.len(), 6);
    assert_eq!(manifest.blob_count(), expected_unique.len());
    assert_eq!(
        manifest.blobs().keys().copied().collect::<BTreeSet<_>>(),
        expected_unique
    );

    let shared_digest = digest(SHARED_SOURCE_AND_MAP).to_string();
    let shared_reference_count = rules
        .iter()
        .flat_map(|rule| rule["artifacts"].as_array().into_iter().flatten())
        .filter(|artifact| artifact["digest"].as_str() == Some(shared_digest.as_str()))
        .count();
    assert_eq!(shared_reference_count, 4);

    let ordered_digests = manifest
        .blobs()
        .keys()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    assert!(ordered_digests.windows(2).all(|pair| pair[0] < pair[1]));
    Ok(())
}

#[test]
fn multi_rule_limits_report_exact_counts_before_manifest_emission()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = manifest_fixture(false)?;
    let verified = verify_transform_artifacts(
        fixture.structurally_validated()?,
        &fixture.artifacts,
        artifact_limits()?,
    )?;

    assert_eq!(
        plan_content_addressed_materialization(
            &verified,
            MaterializationManifestLimits::new(1, 10, 6, 8_192)?,
        )
        .err(),
        Some(MaterializationManifestError::RuleLimitExceeded { actual: 2, max: 1 })
    );
    assert_eq!(
        plan_content_addressed_materialization(
            &verified,
            MaterializationManifestLimits::new(2, 9, 6, 8_192)?,
        )
        .err(),
        Some(MaterializationManifestError::ReferenceLimitExceeded { actual: 10, max: 9 })
    );
    assert_eq!(
        plan_content_addressed_materialization(
            &verified,
            MaterializationManifestLimits::new(2, 10, 5, 8_192)?,
        )
        .err(),
        Some(MaterializationManifestError::BlobLimitExceeded { max: 5 })
    );
    Ok(())
}

#[test]
fn every_artifact_position_retains_kind_digest_length_and_path()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = manifest_fixture(false)?;
    let verified = verify_transform_artifacts(
        fixture.structurally_validated()?,
        &fixture.artifacts,
        artifact_limits()?,
    )?;
    let manifest = plan_content_addressed_materialization(
        &verified,
        MaterializationManifestLimits::new(2, 10, 6, 8_192)?,
    )?;
    let document: serde_json::Value = serde_json::from_slice(manifest.bytes())?;
    let rules = document["rules"]
        .as_array()
        .ok_or("manifest rules must be an array")?;

    for rule in rules {
        let rule_id = rule["rule_id"]
            .as_str()
            .ok_or("manifest rule id must be text")?;
        let expected = fixture
            .artifacts
            .get(&TransformRuleId::new(rule_id)?)
            .ok_or("manifest rule must retain verified bytes")?;
        let artifacts = rule["artifacts"]
            .as_array()
            .ok_or("manifest artifacts must be an array")?;
        let expected_artifacts = [
            ("source", expected.source()),
            ("match_evidence", expected.match_evidence()),
            ("transformed_source", expected.transformed_source()),
            ("source_map", expected.source_map()),
            ("audit_log", expected.audit_log()),
        ];
        assert_eq!(artifacts.len(), expected_artifacts.len());
        for (artifact, (expected_kind, expected_bytes)) in artifacts.iter().zip(expected_artifacts)
        {
            let expected_digest = digest(expected_bytes);
            assert_eq!(artifact["kind"].as_str(), Some(expected_kind));
            assert_eq!(
                artifact["digest"].as_str(),
                Some(expected_digest.to_string().as_str())
            );
            assert_eq!(
                artifact["bytes"].as_u64(),
                u64::try_from(expected_bytes.len()).ok()
            );
            assert_eq!(
                artifact["path"].as_str(),
                Some(expected_content_path(&expected_digest).as_str())
            );
            assert_eq!(
                manifest.blobs().get(&expected_digest),
                Some(&expected_bytes)
            );
        }
    }
    Ok(())
}

struct ManifestFixture {
    authority: AdapterTransformAuthority,
    overlay: GeneratedTransformOverlay,
    artifacts: BTreeMap<TransformRuleId, TransformArtifactBytes<'static>>,
}

impl ManifestFixture {
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

#[derive(Clone, Copy)]
struct RuleDefinition {
    rule_id: &'static str,
    source_unit_id: &'static str,
    rule_digest_seed: &'static [u8],
    artifacts: TransformArtifactBytes<'static>,
}

fn manifest_fixture(reverse: bool) -> Result<ManifestFixture, Box<dyn std::error::Error>> {
    let alpha = RuleDefinition {
        rule_id: "main.alpha",
        source_unit_id: "module.alpha",
        rule_digest_seed: b"alpha-rule",
        artifacts: TransformArtifactBytes::new(
            SHARED_SOURCE_AND_MAP,
            ALPHA_EVIDENCE,
            ALPHA_TRANSFORMED,
            SHARED_SOURCE_AND_MAP,
            SHARED_AUDIT,
        ),
    };
    let zeta = RuleDefinition {
        rule_id: "main.zeta",
        source_unit_id: "module.zeta",
        rule_digest_seed: b"zeta-rule",
        artifacts: TransformArtifactBytes::new(
            SHARED_SOURCE_AND_MAP,
            ZETA_EVIDENCE,
            ZETA_TRANSFORMED,
            SHARED_SOURCE_AND_MAP,
            SHARED_AUDIT,
        ),
    };
    let definitions = if reverse {
        [zeta, alpha]
    } else {
        [alpha, zeta]
    };

    let mut authority_rules = BTreeMap::new();
    let mut rebindings = BTreeMap::new();
    let mut artifacts = BTreeMap::new();
    for definition in definitions {
        let rule_id = TransformRuleId::new(definition.rule_id)?;
        let rule_digest = digest(definition.rule_digest_seed);
        authority_rules.insert(
            rule_id.clone(),
            AuthorizedTransformRuleRef::new(rule_digest),
        );
        rebindings.insert(
            rule_id.clone(),
            TransformRebinding::new(
                rule_digest,
                SourceUnitRef::new(
                    SourceUnitId::new(definition.source_unit_id)?,
                    digest(definition.artifacts.source()),
                ),
                digest(definition.artifacts.match_evidence()),
                digest(definition.artifacts.transformed_source()),
                digest(definition.artifacts.source_map()),
                digest(definition.artifacts.audit_log()),
            ),
        );
        artifacts.insert(rule_id, definition.artifacts);
    }

    let adapter_id = AdapterId::new("openai.desktop")?;
    let family = ApplicationFamilyId::new("openai.chatgpt.windows")?;
    let adapter_content_digest = digest(b"adapter");
    let authority = AdapterTransformAuthority::new(
        adapter_id.clone(),
        family.clone(),
        adapter_content_digest,
        authority_rules,
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
        rebindings,
    )?;
    Ok(ManifestFixture {
        authority,
        overlay,
        artifacts,
    })
}

fn artifact_values(bytes: &TransformArtifactBytes<'static>) -> [&'static [u8]; 5] {
    [
        bytes.source(),
        bytes.match_evidence(),
        bytes.transformed_source(),
        bytes.source_map(),
        bytes.audit_log(),
    ]
}

fn artifact_limits() -> Result<TransformArtifactLimits, weregopher_transform::TransformArtifactError>
{
    TransformArtifactLimits::new(64, 64, 64, 64, 64, 640)
}

fn expected_content_path(digest: &Sha256Digest) -> String {
    let text = digest.to_string();
    let hexadecimal = text.strip_prefix("sha256:").unwrap_or_default();
    format!("sha256/{}/{}", &hexadecimal[..2], &hexadecimal[2..])
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}
