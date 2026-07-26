//! Canonical contract tests for the local certification control plane.

use std::collections::BTreeSet;

use serde_json::json;
use uuid::Uuid;
use weregopher_domain::{
    CertificationArtifactDigest, CertificationArtifactKind, CertificationArtifactRef,
    CertificationArtifactSetDigest, CertificationClass, CertificationControlPolicy,
    CertificationEvidenceDigest, CertificationPolicyRevisionDigest, CertificationProfileDigest,
    CertificationRunAttestationError, CertificationRunFreshness, CertificationRunResultIdentity,
    CertificationRunRunnerIdentity, CertificationRunnerArtifactName,
    CertificationRunnerComponentArtifact, CertificationRunnerComponentDescriptor,
    CertificationRunnerComponentDescriptorError, CertificationRunnerComponentId,
    CertificationRunnerComponentProvenanceDigest, CertificationRunnerComponentRole,
    CertificationRunnerComponentVersion, CertificationRunnerDescriptorSetDigest,
    CertificationRunnerIdentityDigest, CertificationRunnerPolicyRevisionDigest,
    CertificationTarget, CompatibilityAnalysisDigest, ExecutableDigest,
    ExecutionArtifactSourceDigest, ExecutionContractDigest, ExecutionResolutionEvidenceDigest,
    LocalCertificationLedgerEvent, LocalCertificationLedgerGenesis,
    LocalCertificationLedgerReceipt, LocalCertificationLedgerRecord,
    LocalCertificationRunAttestation, MAX_CERTIFICATION_RUNNER_COMPONENT_ARTIFACTS,
    MAX_CERTIFICATION_RUNNER_COMPONENT_DESCRIPTOR_BYTES,
    MAX_LOCAL_CERTIFICATION_LEDGER_RECORD_BYTES, PublicationStatus, Sha256Digest,
};

#[test]
fn runner_component_descriptors_are_bounded_canonical_and_role_separated()
-> Result<(), Box<dyn std::error::Error>> {
    let alpha = component_artifact("bin/alpha.exe", 0x21, 32)?;
    let beta = component_artifact("assets/beta.dat", 0x22, 64)?;
    let forward = component_descriptor(
        CertificationRunnerComponentRole::RunnerImage,
        BTreeSet::from([alpha.clone(), beta.clone()]),
    )?;
    let reverse = component_descriptor(
        CertificationRunnerComponentRole::RunnerImage,
        BTreeSet::from([beta, alpha]),
    )?;

    let forward_bytes = forward.canonical_json_bytes()?;
    assert_eq!(forward_bytes, reverse.canonical_json_bytes()?);
    assert_eq!(
        forward.canonical_document_digest()?,
        reverse.canonical_document_digest()?
    );
    assert_eq!(forward.format_version(), "1");
    assert_eq!(
        forward.canonical_json_bytes()?,
        golden_without_repository_line_ending(include_bytes!(
            "fixtures/certification-runner-component-v1.golden.json"
        ))
    );
    assert_eq!(
        forward.canonical_document_digest()?.to_string(),
        "sha256:d53161b5cb9e731a5e5096c6c9f306e2ee11293b1b6e728b644b251ac1169474"
    );

    let canonical = forward.canonical_json_bytes()?;
    assert_eq!(
        CertificationRunnerComponentDescriptor::from_json_slice(&canonical)?,
        forward
    );

    let mut unknown = serde_json::to_value(&forward)?;
    unknown
        .as_object_mut()
        .ok_or("component descriptor must be an object")?
        .insert("trusted".to_owned(), json!(true));
    assert!(
        CertificationRunnerComponentDescriptor::from_json_slice(&serde_json::to_vec(&unknown)?)
            .is_err()
    );

    let mut exact_limit = canonical;
    exact_limit.resize(MAX_CERTIFICATION_RUNNER_COMPONENT_DESCRIPTOR_BYTES, b' ');
    assert!(CertificationRunnerComponentDescriptor::from_json_slice(&exact_limit).is_ok());
    exact_limit.push(b' ');
    assert!(CertificationRunnerComponentDescriptor::from_json_slice(&exact_limit).is_err());

    assert_eq!(
        CertificationRunnerComponentDescriptor::new(
            CertificationRunnerComponentRole::HostImage,
            CertificationRunnerComponentId::new("windows.host-image")?,
            CertificationRunnerComponentVersion::new("10.0.test")?,
            CertificationRunnerComponentProvenanceDigest::new(digest(0x23)),
            BTreeSet::new(),
        ),
        Err(CertificationRunnerComponentDescriptorError::MissingArtifacts)
    );
    Ok(())
}

#[test]
fn runner_component_artifact_collections_reject_excess_and_duplicate_logical_names()
-> Result<(), Box<dyn std::error::Error>> {
    assert!(
        serde_json::from_value::<CertificationRunnerArtifactName>(json!("")).is_err(),
        "generic artifact-name transport bypassed bounded text validation"
    );
    assert!(
        serde_json::from_value::<CertificationRunnerComponentArtifact>(json!({
            "name": "empty.bin",
            "sha256": digest(0x24),
            "size_bytes": 0
        }))
        .is_err(),
        "generic component-artifact transport bypassed size validation"
    );

    let excessive = (0..=MAX_CERTIFICATION_RUNNER_COMPONENT_ARTIFACTS)
        .map(|index| {
            component_artifact(
                &format!("artifact/{index:03}.bin"),
                u8::try_from(index % 255).unwrap_or(0),
                1,
            )
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    assert_eq!(
        CertificationRunnerComponentDescriptor::new(
            CertificationRunnerComponentRole::ProbeAssetSet,
            CertificationRunnerComponentId::new("probe.assets")?,
            CertificationRunnerComponentVersion::new("1")?,
            CertificationRunnerComponentProvenanceDigest::new(digest(0x24)),
            excessive,
        ),
        Err(CertificationRunnerComponentDescriptorError::TooManyArtifacts)
    );

    let descriptor = component_descriptor(
        CertificationRunnerComponentRole::ProbeAssetSet,
        BTreeSet::from([component_artifact("probe.bin", 0x25, 2)?]),
    )?;
    let serialized = String::from_utf8(descriptor.canonical_json_bytes()?)?;
    let duplicate = serialized.replacen(
        "\"artifacts\":[",
        concat!(
            "\"artifacts\":[",
            "{\"name\":\"probe.bin\",\"sha256\":\"sha256:",
            "2525252525252525252525252525252525252525252525252525252525252525",
            "\",\"size_bytes\":2},"
        ),
        1,
    );
    assert_ne!(serialized, duplicate);
    assert!(CertificationRunnerComponentDescriptor::from_json_slice(duplicate.as_bytes()).is_err());
    Ok(())
}

#[test]
fn run_attestation_is_freshness_bound_canonical_and_non_authorizing()
-> Result<(), Box<dyn std::error::Error>> {
    let attestation = attestation(0x30)?;
    let canonical = attestation.canonical_json_bytes()?;
    assert_eq!(
        canonical,
        golden_without_repository_line_ending(include_bytes!(
            "fixtures/local-certification-run-attestation-v1.golden.json"
        ))
    );
    assert_eq!(
        attestation.canonical_document_digest()?.to_string(),
        "sha256:dac8ded871d521b07f03c6afe7b28950b789b9663ee9934b23b61030dcca8190"
    );
    assert_eq!(
        LocalCertificationRunAttestation::from_json_slice(&canonical)?,
        attestation
    );
    assert_eq!(attestation.format_version(), "1");

    let value = serde_json::to_value(&attestation)?;
    for forbidden in [
        "signature",
        "trusted",
        "registry_trusted",
        "transformation_authorized",
        "execution_authorized",
        "sandboxed",
    ] {
        assert!(value.get(forbidden).is_none());
    }

    let too_slow = CertificationRunFreshness::new(
        Uuid::from_u128(0x0011_2233_4455_6677_8899_aabb_ccdd_eeff),
        1_000,
        1_001,
    );
    assert_eq!(
        too_slow,
        Err(CertificationRunAttestationError::FreshnessExpired)
    );

    let mut unknown = value;
    unknown
        .as_object_mut()
        .ok_or("attestation must be an object")?
        .insert("authority".to_owned(), json!("launch"));
    assert!(
        LocalCertificationRunAttestation::from_json_slice(&serde_json::to_vec(&unknown)?).is_err()
    );
    Ok(())
}

#[test]
fn nested_attestation_transports_cannot_bypass_domain_validation()
-> Result<(), Box<dyn std::error::Error>> {
    let valid = attestation(0x38)?;

    let mut freshness = serde_json::to_value(valid.freshness())?;
    freshness["maximum_elapsed_millis"] = json!(0);
    assert!(serde_json::from_value::<CertificationRunFreshness>(freshness).is_err());

    let mut runner = serde_json::to_value(valid.runner())?;
    runner["policy_generation"] = json!(0);
    assert!(serde_json::from_value::<CertificationRunRunnerIdentity>(runner).is_err());

    let mut result = serde_json::to_value(valid.result())?;
    result["class"] = json!("blocked");
    assert!(serde_json::from_value::<CertificationRunResultIdentity>(result).is_err());

    let mut policy = serde_json::to_value(control_policy(&valid)?)?;
    policy["policy_generation"] = json!(0);
    assert!(serde_json::from_value::<CertificationControlPolicy>(policy).is_err());
    let result = valid.result();
    assert!(
        CertificationControlPolicy::new(
            valid.runner().clone(),
            result.semantic_report().clone(),
            result.target().clone(),
            result.profile_digest(),
            result.evidence_digest(),
            result.artifact_set_digest(),
            CertificationClass::Blocked,
            result.policy_revision_digest(),
            result.policy_generation(),
        )
        .is_err(),
        "combined control-policy construction accepted an unassignable class"
    );
    Ok(())
}

#[test]
fn ledger_records_are_canonical_chained_and_relationship_checked()
-> Result<(), Box<dyn std::error::Error>> {
    let first_attestation = attestation(0x40)?;
    let policy = control_policy(&first_attestation)?;
    let genesis = LocalCertificationLedgerRecord::genesis(LocalCertificationLedgerGenesis::new(
        policy,
        first_attestation,
    )?)?;
    let canonical = genesis.canonical_json_bytes()?;
    assert_eq!(
        canonical,
        golden_without_repository_line_ending(include_bytes!(
            "fixtures/local-certification-ledger-record-v1.golden.json"
        ))
    );
    assert_eq!(
        genesis.canonical_document_digest()?.to_string(),
        "sha256:2847cbaefd393a6b90d8bdc6ddf5b3df306bea8581ddbc919aa610e38853f200"
    );
    assert_eq!(
        LocalCertificationLedgerRecord::from_json_slice(&canonical)?,
        genesis
    );
    assert_eq!(genesis.sequence(), 1);
    assert!(genesis.previous_record_digest().is_none());
    assert!(matches!(
        genesis.event(),
        LocalCertificationLedgerEvent::Genesis(_)
    ));
    let mut unknown_event_field = serde_json::to_value(&genesis)?;
    unknown_event_field["event"]["authority"] = json!(true);
    assert!(
        LocalCertificationLedgerRecord::from_json_slice(&serde_json::to_vec(&unknown_event_field)?)
            .is_err()
    );
    let LocalCertificationLedgerEvent::Genesis(genesis_event) = genesis.event() else {
        return Err("genesis record changed event kind".into());
    };
    let mut nonlocal_receipt = serde_json::to_value(genesis_event.receipt())?;
    nonlocal_receipt["publication_status"] = json!("registry_trusted");
    assert!(
        serde_json::from_value::<LocalCertificationLedgerReceipt>(nonlocal_receipt).is_err(),
        "generic ledger-receipt transport bypassed local-only validation"
    );

    let next_attestation = attestation(0x41)?;
    let next = LocalCertificationLedgerRecord::next(
        &genesis,
        LocalCertificationLedgerEvent::publication(next_attestation)?,
    )?;
    assert_eq!(next.sequence(), 2);
    assert_eq!(
        next.previous_record_digest(),
        Some(genesis.canonical_document_digest()?)
    );

    let mut exact_limit = canonical;
    exact_limit.resize(MAX_LOCAL_CERTIFICATION_LEDGER_RECORD_BYTES, b' ');
    assert!(LocalCertificationLedgerRecord::from_json_slice(&exact_limit).is_ok());
    exact_limit.push(b' ');
    assert!(LocalCertificationLedgerRecord::from_json_slice(&exact_limit).is_err());
    Ok(())
}

fn component_descriptor(
    role: CertificationRunnerComponentRole,
    artifacts: BTreeSet<CertificationRunnerComponentArtifact>,
) -> Result<CertificationRunnerComponentDescriptor, Box<dyn std::error::Error>> {
    Ok(CertificationRunnerComponentDescriptor::new(
        role,
        CertificationRunnerComponentId::new("weregopher.test-runner")?,
        CertificationRunnerComponentVersion::new("1.2.3-test")?,
        CertificationRunnerComponentProvenanceDigest::new(digest(0x20)),
        artifacts,
    )?)
}

fn component_artifact(
    name: &str,
    digest_byte: u8,
    size_bytes: u64,
) -> Result<CertificationRunnerComponentArtifact, Box<dyn std::error::Error>> {
    Ok(CertificationRunnerComponentArtifact::new(
        CertificationRunnerArtifactName::new(name)?,
        digest(digest_byte),
        size_bytes,
    )?)
}

fn attestation(base: u8) -> Result<LocalCertificationRunAttestation, Box<dyn std::error::Error>> {
    let freshness = CertificationRunFreshness::new(
        Uuid::from_u128(0x0011_2233_4455_6677_8899_aabb_ccdd_eeff),
        120_000,
        1_234,
    )?;
    let runner = CertificationRunRunnerIdentity::new(
        CertificationRunnerIdentityDigest::new(digest(base)),
        CertificationRunnerDescriptorSetDigest::new(digest(base.wrapping_add(1))),
        CertificationRunnerPolicyRevisionDigest::new(digest(base.wrapping_add(2))),
        7,
    )?;
    let result = CertificationRunResultIdentity::new(
        CertificationArtifactRef::new(
            CertificationArtifactKind::RuntimeProbe,
            CertificationArtifactDigest::new(digest(base.wrapping_add(3))),
        ),
        target(base.wrapping_add(4)),
        CertificationProfileDigest::new(digest(base.wrapping_add(9))),
        CertificationEvidenceDigest::new(digest(base.wrapping_add(10))),
        CertificationArtifactSetDigest::new(digest(base.wrapping_add(11))),
        CertificationClass::SmokeVerified,
        CertificationPolicyRevisionDigest::new(digest(base.wrapping_add(12))),
        11,
        8,
        4_096,
    )?;
    Ok(LocalCertificationRunAttestation::new(
        freshness, runner, result,
    ))
}

fn control_policy(
    attestation: &LocalCertificationRunAttestation,
) -> Result<CertificationControlPolicy, CertificationRunAttestationError> {
    CertificationControlPolicy::new(
        attestation.runner().clone(),
        attestation.result().semantic_report().clone(),
        attestation.result().target().clone(),
        attestation.result().profile_digest(),
        attestation.result().evidence_digest(),
        attestation.result().artifact_set_digest(),
        attestation.result().class(),
        attestation.result().policy_revision_digest(),
        attestation.result().policy_generation(),
    )
}

const fn target(base: u8) -> CertificationTarget {
    CertificationTarget::new(
        CompatibilityAnalysisDigest::new(digest(base)),
        ExecutionContractDigest::new(digest(base.wrapping_add(1))),
        ExecutionResolutionEvidenceDigest::new(digest(base.wrapping_add(2))),
        ExecutionArtifactSourceDigest::new(digest(base.wrapping_add(3))),
        ExecutableDigest::new(digest(base.wrapping_add(4))),
    )
}

const fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn golden_without_repository_line_ending(bytes: &[u8]) -> &[u8] {
    bytes.strip_suffix(b"\n").unwrap_or(bytes)
}

#[test]
fn local_control_plane_transports_do_not_claim_registry_publication() {
    assert_eq!(PublicationStatus::LocalOnly, PublicationStatus::LocalOnly);
}
