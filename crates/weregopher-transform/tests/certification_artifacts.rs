//! Behavior tests for bounded certification-artifact byte verification.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest as _, Sha256};
use weregopher_domain::{
    CERTIFICATION_FIXED_CHECK_COUNT, CertificationArtifactDigest, CertificationArtifactKind,
    CertificationArtifactRef, CertificationCheckAssessment, CertificationCheckStatus,
    CertificationChecks, CertificationClass, CertificationEvidence, CertificationEvidenceDigest,
    CertificationExpectedStatus, CertificationProfile, CertificationProfileChecks,
    CertificationProfileClass, CertificationProfileDigest, CertificationTarget,
    CompatibilityAnalysisDigest, ExecutableDigest, ExecutionArtifactSourceDigest,
    ExecutionContractDigest, ExecutionResolutionEvidenceDigest, FeatureId, Sha256Digest,
    StructurallyValidatedCertificationEvidence,
};
use weregopher_transform::{
    CertificationArtifactVerificationError, CertificationArtifactVerificationLimits,
    CertificationPolicyError, CertificationPolicyRevisionDigest,
    CertificationPolicyRevocationDigest, LocalCertificationPolicy, LocalCertificationPolicyStore,
    MAX_CERTIFICATION_ARTIFACT_BYTES, MAX_CERTIFICATION_ARTIFACT_REFERENCES,
    MAX_TOTAL_CERTIFICATION_ARTIFACT_BYTES, assign_local_certification,
    verify_certification_artifacts,
};

const FIXED_BYTES: &[u8] = b"fixed-proof";
const WORKFLOW_BYTES: &[u8] = b"workflow-proof";

#[test]
fn exact_verified_artifacts_receive_a_current_local_certification_class()
-> Result<(), Box<dyn std::error::Error>> {
    let (proof, fixed, workflow) = fixture()?;
    let artifacts = artifact_map(&fixed, FIXED_BYTES, &workflow, WORKFLOW_BYTES);
    let policy = local_policy_for(&proof, CertificationClass::ContractVerified, 0x50)?;
    let verified = verify_certification_artifacts(
        proof,
        &artifacts,
        CertificationArtifactVerificationLimits::new(64, 128)?,
    )?;
    let store = LocalCertificationPolicyStore::new(policy);

    let certified = assign_local_certification(verified, &store)?;

    assert_eq!(
        certified.current_class()?,
        CertificationClass::ContractVerified
    );
    assert_eq!(certified.policy_generation(), 1);
    assert_eq!(certified.verified_artifacts().artifacts(), &artifacts);
    certified.verify_current_policy()?;
    let debug = format!("{certified:?}");
    assert!(debug.contains("ContractVerified"));
    assert!(!debug.contains("fixed-proof"));
    assert!(!debug.contains("workflow-proof"));
    Ok(())
}

#[test]
fn local_certification_fails_closed_after_replacement_revocation_or_store_loss()
-> Result<(), Box<dyn std::error::Error>> {
    let (proof, fixed, workflow) = fixture()?;
    let artifacts = artifact_map(&fixed, FIXED_BYTES, &workflow, WORKFLOW_BYTES);
    let policy = local_policy_for(&proof, CertificationClass::ContractVerified, 0x50)?;
    let store = LocalCertificationPolicyStore::new(policy.clone());
    let certified = assign_local_certification(
        verify_certification_artifacts(
            proof,
            &artifacts,
            CertificationArtifactVerificationLimits::new(64, 128)?,
        )?,
        &store,
    )?;
    store.replace_policy(policy)?;
    assert!(matches!(
        certified.current_class(),
        Err(CertificationPolicyError::PolicyChanged)
    ));

    let (proof, fixed, workflow) = fixture()?;
    let artifacts = artifact_map(&fixed, FIXED_BYTES, &workflow, WORKFLOW_BYTES);
    let policy = local_policy_for(&proof, CertificationClass::ContractVerified, 0x51)?;
    let store = LocalCertificationPolicyStore::new(policy);
    let certified = assign_local_certification(
        verify_certification_artifacts(
            proof,
            &artifacts,
            CertificationArtifactVerificationLimits::new(64, 128)?,
        )?,
        &store,
    )?;
    store.revoke(CertificationPolicyRevocationDigest::new(digest(0x60)))?;
    assert!(matches!(
        certified.current_class(),
        Err(CertificationPolicyError::PolicyRevoked)
    ));
    let (proof, fixed, workflow) = fixture()?;
    let artifacts = artifact_map(&fixed, FIXED_BYTES, &workflow, WORKFLOW_BYTES);
    assert!(matches!(
        assign_local_certification(
            verify_certification_artifacts(
                proof,
                &artifacts,
                CertificationArtifactVerificationLimits::new(64, 128)?,
            )?,
            &store,
        ),
        Err(CertificationPolicyError::PolicyRevoked)
    ));

    let (proof, fixed, workflow) = fixture()?;
    let artifacts = artifact_map(&fixed, FIXED_BYTES, &workflow, WORKFLOW_BYTES);
    let policy = local_policy_for(&proof, CertificationClass::ContractVerified, 0x52)?;
    let store = LocalCertificationPolicyStore::new(policy);
    let certified = assign_local_certification(
        verify_certification_artifacts(
            proof,
            &artifacts,
            CertificationArtifactVerificationLimits::new(64, 128)?,
        )?,
        &store,
    )?;
    drop(store);
    assert!(matches!(
        certified.current_class(),
        Err(CertificationPolicyError::PolicyStoreUnavailable)
    ));
    Ok(())
}

#[test]
fn local_certification_requires_exact_target_profile_evidence_and_class_pins()
-> Result<(), Box<dyn std::error::Error>> {
    let (proof, fixed, workflow) = fixture()?;
    let artifacts = artifact_map(&fixed, FIXED_BYTES, &workflow, WORKFLOW_BYTES);
    let policy = LocalCertificationPolicy::new(
        different_target(),
        *proof.evidence().profile_digest(),
        proof.evidence().canonical_document_digest()?,
        CertificationClass::ContractVerified,
        CertificationPolicyRevisionDigest::new(digest(0x50)),
    )?;
    assert!(matches!(
        assign_local_certification(
            verify_certification_artifacts(
                proof,
                &artifacts,
                CertificationArtifactVerificationLimits::new(64, 128)?,
            )?,
            &LocalCertificationPolicyStore::new(policy),
        ),
        Err(CertificationPolicyError::TargetMismatch)
    ));

    let (proof, fixed, workflow) = fixture()?;
    let artifacts = artifact_map(&fixed, FIXED_BYTES, &workflow, WORKFLOW_BYTES);
    let policy = LocalCertificationPolicy::new(
        proof.evidence().target().clone(),
        CertificationProfileDigest::new(digest(0x70)),
        proof.evidence().canonical_document_digest()?,
        CertificationClass::ContractVerified,
        CertificationPolicyRevisionDigest::new(digest(0x51)),
    )?;
    assert!(matches!(
        assign_local_certification(
            verify_certification_artifacts(
                proof,
                &artifacts,
                CertificationArtifactVerificationLimits::new(64, 128)?,
            )?,
            &LocalCertificationPolicyStore::new(policy),
        ),
        Err(CertificationPolicyError::ProfileDigestMismatch)
    ));

    let (proof, fixed, workflow) = fixture()?;
    let artifacts = artifact_map(&fixed, FIXED_BYTES, &workflow, WORKFLOW_BYTES);
    let policy = LocalCertificationPolicy::new(
        proof.evidence().target().clone(),
        *proof.evidence().profile_digest(),
        CertificationEvidenceDigest::new(digest(0x71)),
        CertificationClass::ContractVerified,
        CertificationPolicyRevisionDigest::new(digest(0x52)),
    )?;
    assert!(matches!(
        assign_local_certification(
            verify_certification_artifacts(
                proof,
                &artifacts,
                CertificationArtifactVerificationLimits::new(64, 128)?,
            )?,
            &LocalCertificationPolicyStore::new(policy),
        ),
        Err(CertificationPolicyError::EvidenceDigestMismatch)
    ));

    let (proof, fixed, workflow) = fixture()?;
    let artifacts = artifact_map(&fixed, FIXED_BYTES, &workflow, WORKFLOW_BYTES);
    let policy = local_policy_for(&proof, CertificationClass::ExactCertified, 0x53)?;
    assert!(matches!(
        assign_local_certification(
            verify_certification_artifacts(
                proof,
                &artifacts,
                CertificationArtifactVerificationLimits::new(64, 128)?,
            )?,
            &LocalCertificationPolicyStore::new(policy),
        ),
        Err(CertificationPolicyError::ClassMismatch)
    ));
    Ok(())
}

#[test]
fn blocked_and_provisional_classes_cannot_be_assigned_by_local_policy()
-> Result<(), Box<dyn std::error::Error>> {
    let (proof, _, _) = fixture()?;
    let target = proof.evidence().target().clone();
    let profile_digest = *proof.evidence().profile_digest();
    let evidence_digest = proof.evidence().canonical_document_digest()?;
    for class in [CertificationClass::Blocked, CertificationClass::Provisional] {
        assert!(matches!(
            LocalCertificationPolicy::new(
                target.clone(),
                profile_digest,
                evidence_digest,
                class,
                CertificationPolicyRevisionDigest::new(digest(0x72)),
            ),
            Err(CertificationPolicyError::UnassignableClass)
        ));
    }
    Ok(())
}

#[test]
fn every_profile_class_maps_only_to_its_matching_trusted_class()
-> Result<(), Box<dyn std::error::Error>> {
    for (declared, trusted, revision) in [
        (
            CertificationProfileClass::StructuralVerified,
            CertificationClass::StructuralVerified,
            0x80,
        ),
        (
            CertificationProfileClass::SmokeVerified,
            CertificationClass::SmokeVerified,
            0x81,
        ),
        (
            CertificationProfileClass::ContractVerified,
            CertificationClass::ContractVerified,
            0x82,
        ),
        (
            CertificationProfileClass::ExactCertified,
            CertificationClass::ExactCertified,
            0x83,
        ),
    ] {
        let (proof, fixed, workflow) = fixture_for_profile_class(declared)?;
        let artifacts = artifact_map(&fixed, FIXED_BYTES, &workflow, WORKFLOW_BYTES);
        let policy = local_policy_for(&proof, trusted, revision)?;
        let store = LocalCertificationPolicyStore::new(policy);
        let certified = assign_local_certification(
            verify_certification_artifacts(
                proof,
                &artifacts,
                CertificationArtifactVerificationLimits::new(64, 128)?,
            )?,
            &store,
        )?;
        assert_eq!(certified.current_class()?, trusted);
    }
    Ok(())
}

#[test]
fn exact_referenced_artifacts_are_verified_and_retained() -> Result<(), Box<dyn std::error::Error>>
{
    let (proof, fixed, workflow) = fixture()?;
    let artifacts = artifact_map(&fixed, FIXED_BYTES, &workflow, WORKFLOW_BYTES);
    let verified = verify_certification_artifacts(
        proof,
        &artifacts,
        CertificationArtifactVerificationLimits::new(64, 128)?,
    )?;

    assert_eq!(verified.artifact_count(), 2);
    assert_eq!(
        verified.total_bytes(),
        FIXED_BYTES.len() + WORKFLOW_BYTES.len()
    );
    assert_eq!(verified.artifacts(), &artifacts);
    let debug = format!("{verified:?}");
    assert!(debug.contains("artifact_count: 2"));
    assert!(!debug.contains("fixed-proof"));
    assert!(!debug.contains("workflow-proof"));
    assert_eq!(
        verified
            .structural_validation()
            .evidence()
            .artifact_references()
            .count(),
        14
    );
    Ok(())
}

#[test]
fn missing_unexpected_and_digest_mismatched_artifacts_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let (proof, fixed, _) = fixture()?;
    assert_eq!(
        verify_certification_artifacts(
            proof,
            &BTreeMap::new(),
            CertificationArtifactVerificationLimits::new(64, 128)?,
        )
        .err(),
        Some(CertificationArtifactVerificationError::MissingArtifact(
            fixed.clone()
        ))
    );

    let (proof, fixed, workflow) = fixture()?;
    let unexpected = artifact(CertificationArtifactKind::SecurityProbe, b"unexpected");
    let mut artifacts = artifact_map(&fixed, FIXED_BYTES, &workflow, WORKFLOW_BYTES);
    artifacts.insert(unexpected.clone(), b"unexpected");
    assert_eq!(
        verify_certification_artifacts(
            proof,
            &artifacts,
            CertificationArtifactVerificationLimits::new(64, 128)?,
        )
        .err(),
        Some(CertificationArtifactVerificationError::UnexpectedArtifact(
            unexpected
        ))
    );

    let (proof, fixed, workflow) = fixture()?;
    let artifacts = artifact_map(&fixed, b"tampered", &workflow, WORKFLOW_BYTES);
    assert_eq!(
        verify_certification_artifacts(
            proof,
            &artifacts,
            CertificationArtifactVerificationLimits::new(64, 128)?,
        )
        .err(),
        Some(CertificationArtifactVerificationError::DigestMismatch(
            fixed
        ))
    );
    Ok(())
}

#[test]
fn artifact_and_aggregate_limits_are_checked_before_hashing()
-> Result<(), Box<dyn std::error::Error>> {
    let (proof, fixed, workflow) = fixture()?;
    let artifacts = artifact_map(&fixed, FIXED_BYTES, &workflow, WORKFLOW_BYTES);
    assert!(matches!(
        verify_certification_artifacts(
            proof,
            &artifacts,
            CertificationArtifactVerificationLimits::new(FIXED_BYTES.len() - 1, 128)?,
        ),
        Err(CertificationArtifactVerificationError::ArtifactTooLarge {
            artifact,
            actual_bytes,
            max_bytes,
        }) if artifact == fixed
            && actual_bytes == FIXED_BYTES.len()
            && max_bytes == FIXED_BYTES.len() - 1
    ));

    let (proof, fixed, workflow) = fixture()?;
    let artifacts = artifact_map(&fixed, FIXED_BYTES, &workflow, WORKFLOW_BYTES);
    let total = FIXED_BYTES.len() + WORKFLOW_BYTES.len();
    assert_eq!(
        verify_certification_artifacts(
            proof,
            &artifacts,
            CertificationArtifactVerificationLimits::new(64, total - 1)?,
        )
        .err(),
        Some(CertificationArtifactVerificationError::TotalBytesExceeded {
            actual_bytes: total,
            max_bytes: total - 1,
        })
    );
    Ok(())
}

#[test]
fn callers_cannot_disable_certification_artifact_ceilings() {
    assert_eq!(CERTIFICATION_FIXED_CHECK_COUNT, 13);
    assert_eq!(MAX_CERTIFICATION_ARTIFACT_REFERENCES, 9_024);
    assert_eq!(
        CertificationArtifactVerificationLimits::new(0, 1),
        Err(CertificationArtifactVerificationError::InvalidLimits)
    );
    assert_eq!(
        CertificationArtifactVerificationLimits::new(1, 0),
        Err(CertificationArtifactVerificationError::InvalidLimits)
    );
    assert_eq!(
        CertificationArtifactVerificationLimits::new(MAX_CERTIFICATION_ARTIFACT_BYTES + 1, 1),
        Err(CertificationArtifactVerificationError::LimitsExceedImplementationMaximum)
    );
    assert_eq!(
        CertificationArtifactVerificationLimits::new(
            MAX_CERTIFICATION_ARTIFACT_BYTES,
            MAX_TOTAL_CERTIFICATION_ARTIFACT_BYTES + 1,
        ),
        Err(CertificationArtifactVerificationError::LimitsExceedImplementationMaximum)
    );
    assert!(
        CertificationArtifactVerificationLimits::new(
            MAX_CERTIFICATION_ARTIFACT_BYTES,
            MAX_TOTAL_CERTIFICATION_ARTIFACT_BYTES,
        )
        .is_ok()
    );
}

#[test]
fn supplied_artifact_count_has_an_implementation_ceiling() -> Result<(), Box<dyn std::error::Error>>
{
    let (proof, _, _) = fixture()?;
    let mut artifacts = BTreeMap::new();
    for index in 0..=MAX_CERTIFICATION_ARTIFACT_REFERENCES {
        artifacts.insert(
            artifact(
                CertificationArtifactKind::PackageIdentity,
                &index.to_le_bytes(),
            ),
            &[][..],
        );
    }
    assert_eq!(artifacts.len(), MAX_CERTIFICATION_ARTIFACT_REFERENCES + 1);
    assert_eq!(
        verify_certification_artifacts(
            proof,
            &artifacts,
            CertificationArtifactVerificationLimits::new(1, 1)?,
        )
        .err(),
        Some(CertificationArtifactVerificationError::TooManyArtifacts)
    );
    Ok(())
}

fn fixture() -> Result<
    (
        StructurallyValidatedCertificationEvidence,
        CertificationArtifactRef,
        CertificationArtifactRef,
    ),
    Box<dyn std::error::Error>,
> {
    fixture_for_profile_class(CertificationProfileClass::ContractVerified)
}

fn fixture_for_profile_class(
    profile_class: CertificationProfileClass,
) -> Result<
    (
        StructurallyValidatedCertificationEvidence,
        CertificationArtifactRef,
        CertificationArtifactRef,
    ),
    Box<dyn std::error::Error>,
> {
    let workflow_id = FeatureId::new("workflow.chat")?;
    let profile = CertificationProfile::new(
        profile_class,
        profile_checks(CertificationExpectedStatus::Passed),
        BTreeSet::from([workflow_id.clone()]),
    )?;
    let fixed = artifact(CertificationArtifactKind::StaticAnalysis, FIXED_BYTES);
    let workflow = artifact(CertificationArtifactKind::WorkflowProbe, WORKFLOW_BYTES);
    let fixed_assessment =
        CertificationCheckAssessment::new(CertificationCheckStatus::Passed, [fixed.clone()])?;
    let workflow_assessment =
        CertificationCheckAssessment::new(CertificationCheckStatus::Passed, [workflow.clone()])?;
    let evidence = CertificationEvidence::new(
        target(),
        profile.canonical_document_digest()?,
        checks(fixed_assessment),
        BTreeMap::from([(workflow_id, workflow_assessment)]),
    )?;
    Ok((evidence.validate_against_profile(profile)?, fixed, workflow))
}

fn artifact_map<'a>(
    fixed: &CertificationArtifactRef,
    fixed_bytes: &'a [u8],
    workflow: &CertificationArtifactRef,
    workflow_bytes: &'a [u8],
) -> BTreeMap<CertificationArtifactRef, &'a [u8]> {
    BTreeMap::from([
        (fixed.clone(), fixed_bytes),
        (workflow.clone(), workflow_bytes),
    ])
}

fn artifact(kind: CertificationArtifactKind, bytes: &[u8]) -> CertificationArtifactRef {
    CertificationArtifactRef::new(
        kind,
        CertificationArtifactDigest::new(Sha256Digest::from_bytes(Sha256::digest(bytes).into())),
    )
}

fn target() -> CertificationTarget {
    CertificationTarget::new(
        CompatibilityAnalysisDigest::new(digest(0x10)),
        ExecutionContractDigest::new(digest(0x11)),
        ExecutionResolutionEvidenceDigest::new(digest(0x12)),
        ExecutionArtifactSourceDigest::new(digest(0x13)),
        ExecutableDigest::new(digest(0x14)),
    )
}

fn different_target() -> CertificationTarget {
    CertificationTarget::new(
        CompatibilityAnalysisDigest::new(digest(0x20)),
        ExecutionContractDigest::new(digest(0x21)),
        ExecutionResolutionEvidenceDigest::new(digest(0x22)),
        ExecutionArtifactSourceDigest::new(digest(0x23)),
        ExecutableDigest::new(digest(0x24)),
    )
}

fn local_policy_for(
    proof: &StructurallyValidatedCertificationEvidence,
    approved_class: CertificationClass,
    revision_byte: u8,
) -> Result<LocalCertificationPolicy, Box<dyn std::error::Error>> {
    Ok(LocalCertificationPolicy::new(
        proof.evidence().target().clone(),
        *proof.evidence().profile_digest(),
        proof.evidence().canonical_document_digest()?,
        approved_class,
        CertificationPolicyRevisionDigest::new(digest(revision_byte)),
    )?)
}

fn checks(assessment: CertificationCheckAssessment) -> CertificationChecks {
    CertificationChecks {
        package_identity: assessment.clone(),
        entry_point_resolution: assessment.clone(),
        transform_matches: assessment.clone(),
        module_graph: assessment.clone(),
        native_dependencies: assessment.clone(),
        runtime_bootstrap: assessment.clone(),
        renderer_bootstrap: assessment.clone(),
        preload_handshake: assessment.clone(),
        state_safety: assessment.clone(),
        helper_lifecycle: assessment.clone(),
        security_contract: assessment.clone(),
        resource_scenario: assessment.clone(),
        declared_exceptions: assessment,
    }
}

fn profile_checks(expected: CertificationExpectedStatus) -> CertificationProfileChecks {
    CertificationProfileChecks {
        package_identity: expected,
        entry_point_resolution: expected,
        transform_matches: expected,
        module_graph: expected,
        native_dependencies: expected,
        runtime_bootstrap: expected,
        renderer_bootstrap: expected,
        preload_handshake: expected,
        state_safety: expected,
        helper_lifecycle: expected,
        security_contract: expected,
        resource_scenario: expected,
        declared_exceptions: expected,
    }
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}
