//! Windows live execution-authorization regressions over retained executable capabilities.

#![cfg(windows)]

use std::{collections::BTreeMap, fs};

use sha2::{Digest as _, Sha256};
use tempfile::tempdir;
use weregopher_domain::{
    AdapterExecutionAuthority, AdapterId, ApplicationFamilyId, AuthorizedExecutionTargetRef,
    CompatibilityAnalysis, CompatibilityDimensions, CompatibilityEvidenceKind,
    CompatibilityEvidenceRef, CompatibilityTarget, DimensionAssessment, DimensionStatus,
    EffectiveSecurityPosture, ExecutionArgument, ExecutionArtifactBinding,
    ExecutionArtifactDigests, ExecutionArtifactLocator, ExecutionArtifactSource,
    ExecutionLaunchPolicy, ExecutionOverlayBinding, ExecutionOverlayContext,
    ExecutionPolicyDigests, ExecutionResolutionDigests, ExecutionResolutionEvidence,
    ExecutionResourceLimits, ExecutionStateMode, ExecutionTargetContract, ExecutionTargetId,
    ExecutionTargetKind, GeneratedExecutionOverlay, Sha256Digest, TrustMode,
};
use weregopher_fingerprint::{PackageTreeObservationLimits, observe_package_tree};
use weregopher_transform::{
    ExecutionAuthorityPins, ExecutionAuthorizationError, ExecutionAuthorizationLimits,
    ExecutionAuthorizationRequest, ExecutionContextPins, ExecutionPolicyEvidence,
    ExecutionTargetPins, LocalExecutionPolicy, LocalExecutionPolicyStore, ManagedArtifactStore,
    ManagedStoreRootLimits, PackageSnapshotLease, PackageSnapshotWriteLimits,
    RetainedExecutionArtifact, authorize_execution,
};

const TRUST_EVIDENCE: &[u8] = b"locally approved adapter trust evidence";
const PROVENANCE_EVIDENCE: &[u8] = b"locally approved package provenance";
const CAPABILITY_POLICY: &[u8] = b"capability policy v1: helper only";
const STATE_POLICY: &[u8] = b"state policy v1: disposable";
const USER_POLICY: &[u8] = b"user policy v1: approved";

macro_rules! authorize_snapshot {
    ($snapshot:expr, $documents:expr, $path:expr, $evidence:expr, $limits:expr) => {{
        let structural = $documents
            .overlay
            .validate_against(&$documents.authority, $documents.context)?;
        let executable = $snapshot.lock_executable($path, 64)?;
        authorize_execution(ExecutionAuthorizationRequest {
            structural_overlay: &structural,
            target_contract: &$documents.target_contract,
            resolution_evidence: &$documents.resolution,
            compatibility_analysis: &$documents.compatibility,
            policy_store: &$documents.policy_store,
            policy_evidence: $evidence,
            retained_artifact: RetainedExecutionArtifact::PackageSnapshot(executable),
            limits: $limits,
        })
    }};
}

#[test]
fn exact_retained_package_executable_is_authorized_until_policy_revocation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let vendor = fixture.path().join("vendor");
    let store_root = fixture.path().join("store");
    fs::create_dir(&vendor)?;
    fs::create_dir(&store_root)?;
    fs::write(vendor.join("helper.exe"), b"exact helper executable")?;

    let observation = observe_package_tree(
        &vendor,
        PackageTreeObservationLimits::new(8, 8, 4, 1_024, 4_096, 4_096)?,
    )?;
    let store = ManagedArtifactStore::open(&store_root, &vendor, ManagedStoreRootLimits::new(64)?)?;
    let snapshot = store.snapshot_package(
        &observation,
        PackageSnapshotWriteLimits::new(8, 8, 1_024, 4_096, 8)?,
    )?;
    let executable_digest = observation
        .manifest()
        .files()
        .iter()
        .find(|file| file.normalized_path == "helper.exe")
        .ok_or("helper executable must be listed")?
        .sha256;

    let documents = authorization_documents(
        *snapshot.package_tree_merkle(),
        executable_digest,
        DimensionStatus::Satisfied,
    )?;
    let structural = documents
        .overlay
        .validate_against(&documents.authority, documents.context)?;
    let executable = snapshot.lock_executable("helper.exe", 64)?;
    let authorized = authorize_execution(ExecutionAuthorizationRequest {
        structural_overlay: &structural,
        target_contract: &documents.target_contract,
        resolution_evidence: &documents.resolution,
        compatibility_analysis: &documents.compatibility,
        policy_store: &documents.policy_store,
        policy_evidence: ExecutionPolicyEvidence {
            artifact_trust: TRUST_EVIDENCE,
            provenance: PROVENANCE_EVIDENCE,
            capability_policy: CAPABILITY_POLICY,
            state_policy: STATE_POLICY,
            user_policy: USER_POLICY,
        },
        retained_artifact: RetainedExecutionArtifact::PackageSnapshot(executable),
        limits: ExecutionAuthorizationLimits::new(1_024, 4_096)?,
    })?;

    assert_eq!(authorized.target_id(), &documents.target_id);
    assert_eq!(authorized.trust_mode(), TrustMode::LocallyTrusted);
    assert_eq!(authorized.arguments()[0].as_str(), "--serve");
    assert_eq!(
        authorized.launch_policy(),
        documents.target_contract.launch_policy()
    );
    assert!(!format!("{authorized:?}").contains("--serve"));
    authorized.verify_current_policy()?;

    documents.policy_store.revoke(digest(0xff))?;
    assert_eq!(
        authorized.verify_current_policy(),
        Err(ExecutionAuthorizationError::PolicyRevoked)
    );
    Ok(())
}

#[test]
fn incomplete_compatibility_is_denied_even_when_exactly_pinned()
-> Result<(), Box<dyn std::error::Error>> {
    with_snapshot_fixture(DimensionStatus::Unsatisfied, None, |snapshot, documents| {
        let result = authorize_snapshot!(
            snapshot,
            documents,
            "helper.exe",
            policy_evidence(),
            ExecutionAuthorizationLimits::new(1_024, 4_096)?
        );
        assert!(matches!(
            result,
            Err(ExecutionAuthorizationError::CompatibilityDenied)
        ));
        Ok(())
    })
}

#[test]
fn policy_evidence_is_bounded_and_must_match_every_exact_pin()
-> Result<(), Box<dyn std::error::Error>> {
    with_snapshot_fixture(DimensionStatus::Satisfied, None, |snapshot, documents| {
        let tampered = ExecutionPolicyEvidence {
            artifact_trust: b"different trust evidence",
            ..policy_evidence()
        };
        let result = authorize_snapshot!(
            snapshot,
            documents,
            "helper.exe",
            tampered,
            ExecutionAuthorizationLimits::new(1_024, 4_096)?
        );
        assert!(matches!(
            result,
            Err(ExecutionAuthorizationError::ArtifactTrustEvidenceMismatch)
        ));

        let result = authorize_snapshot!(
            snapshot,
            documents,
            "helper.exe",
            policy_evidence(),
            ExecutionAuthorizationLimits::new(1, 4_096)?
        );
        assert!(matches!(
            result,
            Err(ExecutionAuthorizationError::EvidenceByteLimitExceeded)
        ));

        let result = authorize_snapshot!(
            snapshot,
            documents,
            "helper.exe",
            policy_evidence(),
            ExecutionAuthorizationLimits::new(1_024, 1)?
        );
        assert!(matches!(
            result,
            Err(ExecutionAuthorizationError::AggregateEvidenceByteLimitExceeded)
        ));
        Ok(())
    })
}

#[test]
fn retained_package_artifact_must_match_the_exact_locator_and_source()
-> Result<(), Box<dyn std::error::Error>> {
    with_snapshot_fixture(DimensionStatus::Satisfied, None, |snapshot, documents| {
        let result = authorize_snapshot!(
            snapshot,
            documents,
            "other.exe",
            policy_evidence(),
            ExecutionAuthorizationLimits::new(1_024, 4_096)?
        );
        assert!(matches!(
            result,
            Err(ExecutionAuthorizationError::RetainedArtifactLocatorMismatch)
        ));
        Ok(())
    })?;

    with_snapshot_fixture(
        DimensionStatus::Satisfied,
        Some(digest(0xfe)),
        |snapshot, documents| {
            let result = authorize_snapshot!(
                snapshot,
                documents,
                "helper.exe",
                policy_evidence(),
                ExecutionAuthorizationLimits::new(1_024, 4_096)?
            );
            assert!(matches!(
                result,
                Err(ExecutionAuthorizationError::RetainedArtifactSourceDigestMismatch)
            ));
            Ok(())
        },
    )
}

#[test]
fn authorization_is_invalidated_by_policy_replacement_or_store_loss()
-> Result<(), Box<dyn std::error::Error>> {
    with_snapshot_fixture(DimensionStatus::Satisfied, None, |snapshot, documents| {
        let authorized = authorize_snapshot!(
            snapshot,
            documents,
            "helper.exe",
            policy_evidence(),
            ExecutionAuthorizationLimits::new(1_024, 4_096)?
        )?;
        documents
            .policy_store
            .replace_policy(documents.policy.clone())?;
        assert_eq!(
            authorized.verify_current_policy(),
            Err(ExecutionAuthorizationError::PolicyChanged)
        );
        drop(documents);
        assert_eq!(
            authorized.verify_current_policy(),
            Err(ExecutionAuthorizationError::PolicyStoreUnavailable)
        );
        Ok(())
    })
}

#[test]
fn preexisting_revocation_prevents_authorization() -> Result<(), Box<dyn std::error::Error>> {
    with_snapshot_fixture(DimensionStatus::Satisfied, None, |snapshot, documents| {
        documents.policy_store.revoke(digest(0xfd))?;
        let result = authorize_snapshot!(
            snapshot,
            documents,
            "helper.exe",
            policy_evidence(),
            ExecutionAuthorizationLimits::new(1_024, 4_096)?
        );
        assert!(matches!(
            result,
            Err(ExecutionAuthorizationError::PolicyRevoked)
        ));
        Ok(())
    })
}

#[test]
fn local_policy_accepts_only_implemented_trust_modes_and_safe_developer_state()
-> Result<(), Box<dyn std::error::Error>> {
    with_snapshot_fixture(DimensionStatus::Satisfied, None, |_snapshot, documents| {
        let policy = &documents.policy;
        assert!(matches!(
            LocalExecutionPolicy::new(
                TrustMode::RegistryTrusted,
                policy.authority_pins().clone(),
                policy.context_pins(),
                policy.target_pins().clone(),
                digest(0x50),
            ),
            Err(ExecutionAuthorizationError::UnsupportedTrustMode)
        ));

        let mut production_target = policy.target_pins().clone();
        production_target.state_mode = ExecutionStateMode::Production;
        assert!(matches!(
            LocalExecutionPolicy::new(
                TrustMode::Developer,
                policy.authority_pins().clone(),
                policy.context_pins(),
                production_target,
                digest(0x51),
            ),
            Err(ExecutionAuthorizationError::DeveloperModeRequiresDisposableState)
        ));
        assert!(
            LocalExecutionPolicy::new(
                TrustMode::Developer,
                policy.authority_pins().clone(),
                policy.context_pins(),
                policy.target_pins().clone(),
                digest(0x52),
            )
            .is_ok()
        );
        Ok(())
    })
}

#[test]
fn locally_pinned_build_context_cannot_be_replayed_across_an_overlay()
-> Result<(), Box<dyn std::error::Error>> {
    with_snapshot_fixture(DimensionStatus::Satisfied, None, |snapshot, documents| {
        let policy = &documents.policy;
        let mut wrong_context = policy.context_pins();
        wrong_context.build_descriptor_digest = digest(0x53);
        documents
            .policy_store
            .replace_policy(LocalExecutionPolicy::new(
                TrustMode::LocallyTrusted,
                policy.authority_pins().clone(),
                wrong_context,
                policy.target_pins().clone(),
                digest(0x54),
            )?)?;

        let result = authorize_snapshot!(
            snapshot,
            documents,
            "helper.exe",
            policy_evidence(),
            ExecutionAuthorizationLimits::new(1_024, 4_096)?
        );
        assert!(matches!(
            result,
            Err(ExecutionAuthorizationError::BuildDescriptorContextMismatch)
        ));
        Ok(())
    })
}

struct AuthorizationDocuments {
    target_id: ExecutionTargetId,
    context: ExecutionOverlayContext,
    compatibility: CompatibilityAnalysis,
    target_contract: ExecutionTargetContract,
    resolution: ExecutionResolutionEvidence,
    authority: AdapterExecutionAuthority,
    overlay: GeneratedExecutionOverlay,
    policy: LocalExecutionPolicy,
    policy_store: LocalExecutionPolicyStore,
}

fn authorization_documents(
    artifact_source_digest: Sha256Digest,
    executable_digest: Sha256Digest,
    compatibility_status: DimensionStatus,
) -> Result<AuthorizationDocuments, Box<dyn std::error::Error>> {
    let target_id = ExecutionTargetId::new("helper.allowed")?;
    let context = ExecutionOverlayContext {
        source_build_fingerprint_digest: digest(0x10),
        package_tree_merkle: artifact_source_digest,
        execution_environment_digest: digest(0x11),
        build_descriptor_digest: digest(0x12),
    };
    let compatibility = compatibility_analysis(context, compatibility_status)?;
    let compatibility_digest = canonical_digest(&compatibility)?;
    let policy_digests = ExecutionPolicyDigests {
        compatibility_analysis_digest: compatibility_digest,
        capability_policy_digest: bytes_digest(CAPABILITY_POLICY),
        state_policy_digest: bytes_digest(STATE_POLICY),
        user_policy_digest: bytes_digest(USER_POLICY),
    };
    let locator = ExecutionArtifactLocator::package_snapshot("helper.exe")?;
    let target_contract = ExecutionTargetContract::new(
        target_id.clone(),
        ExecutionTargetKind::VendorHelper,
        locator.clone(),
        ExecutionLaunchPolicy::new(
            vec![ExecutionArgument::new("--serve")?],
            EffectiveSecurityPosture::VendorEquivalentFullTrust,
            ExecutionStateMode::Disposable,
            ExecutionResourceLimits::new(2, 64 * 1024 * 1024, 128 * 1024 * 1024)?,
            policy_digests,
        )?,
    );
    let target_contract_digest = target_contract.canonical_document_digest()?;
    let resolution = ExecutionResolutionEvidence::new(
        target_id.clone(),
        locator,
        ExecutionResolutionDigests {
            execution_contract_digest: target_contract_digest,
            artifact_source_digest,
            executable_digest,
            artifact_trust_evidence_digest: bytes_digest(TRUST_EVIDENCE),
            provenance_evidence_digest: bytes_digest(PROVENANCE_EVIDENCE),
        },
    );
    let resolution_digest = resolution.canonical_document_digest()?;
    let authority = AdapterExecutionAuthority::new(
        AdapterId::new("local.test-adapter")?,
        ApplicationFamilyId::new("local.test-family")?,
        digest(0x20),
        BTreeMap::from([(
            target_id.clone(),
            AuthorizedExecutionTargetRef::new(
                ExecutionTargetKind::VendorHelper,
                ExecutionArtifactSource::PackageSnapshot,
                target_contract_digest,
            ),
        )]),
    )?;
    let overlay = GeneratedExecutionOverlay::windows_x64(
        ExecutionOverlayBinding::new(context, &authority),
        BTreeMap::from([(
            target_id.clone(),
            ExecutionArtifactBinding::new(ExecutionArtifactDigests {
                execution_contract_digest: target_contract_digest,
                artifact_source_digest,
                executable_digest,
                resolution_evidence_digest: resolution_digest,
            }),
        )]),
    )?;
    let policy = LocalExecutionPolicy::new(
        TrustMode::LocallyTrusted,
        authority_pins(&authority),
        context_pins(context),
        ExecutionTargetPins {
            target_id: target_id.clone(),
            target_contract_digest,
            resolution_evidence_digest: resolution_digest,
            artifact_trust_evidence_digest: bytes_digest(TRUST_EVIDENCE),
            provenance_evidence_digest: bytes_digest(PROVENANCE_EVIDENCE),
            compatibility_analysis_digest: compatibility_digest,
            capability_policy_digest: bytes_digest(CAPABILITY_POLICY),
            state_policy_digest: bytes_digest(STATE_POLICY),
            user_policy_digest: bytes_digest(USER_POLICY),
            security_posture: EffectiveSecurityPosture::VendorEquivalentFullTrust,
            state_mode: ExecutionStateMode::Disposable,
        },
        digest(0x30),
    )?;
    Ok(AuthorizationDocuments {
        target_id,
        context,
        compatibility,
        target_contract,
        resolution,
        authority,
        overlay,
        policy_store: LocalExecutionPolicyStore::new(policy.clone()),
        policy,
    })
}

fn with_snapshot_fixture(
    status: DimensionStatus,
    source_override: Option<Sha256Digest>,
    test: impl FnOnce(
        &PackageSnapshotLease<'_>,
        AuthorizationDocuments,
    ) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let vendor = fixture.path().join("vendor");
    let store_root = fixture.path().join("store");
    fs::create_dir(&vendor)?;
    fs::create_dir(&store_root)?;
    fs::write(vendor.join("helper.exe"), b"exact helper executable")?;
    fs::write(vendor.join("other.exe"), b"other executable")?;
    let observation = observe_package_tree(
        &vendor,
        PackageTreeObservationLimits::new(8, 8, 4, 1_024, 4_096, 4_096)?,
    )?;
    let store = ManagedArtifactStore::open(&store_root, &vendor, ManagedStoreRootLimits::new(64)?)?;
    let snapshot = store.snapshot_package(
        &observation,
        PackageSnapshotWriteLimits::new(8, 8, 1_024, 4_096, 8)?,
    )?;
    let executable_digest = observation
        .manifest()
        .files()
        .iter()
        .find(|file| file.normalized_path == "helper.exe")
        .ok_or("helper executable must be listed")?
        .sha256;
    let source_digest = source_override.unwrap_or(*snapshot.package_tree_merkle());
    let documents = authorization_documents(source_digest, executable_digest, status)?;
    test(&snapshot, documents)
}

fn policy_evidence() -> ExecutionPolicyEvidence<'static> {
    ExecutionPolicyEvidence {
        artifact_trust: TRUST_EVIDENCE,
        provenance: PROVENANCE_EVIDENCE,
        capability_policy: CAPABILITY_POLICY,
        state_policy: STATE_POLICY,
        user_policy: USER_POLICY,
    }
}

fn authority_pins(authority: &AdapterExecutionAuthority) -> ExecutionAuthorityPins {
    ExecutionAuthorityPins {
        adapter_id: authority.adapter_id().clone(),
        family: authority.family().clone(),
        adapter_content_digest: *authority.adapter_content_digest(),
        authority_document_digest: authority.canonical_document_digest(),
    }
}

fn context_pins(context: ExecutionOverlayContext) -> ExecutionContextPins {
    ExecutionContextPins {
        source_build_fingerprint_digest: context.source_build_fingerprint_digest,
        package_tree_merkle: context.package_tree_merkle,
        execution_environment_digest: context.execution_environment_digest,
        build_descriptor_digest: context.build_descriptor_digest,
    }
}

fn compatibility_analysis(
    context: ExecutionOverlayContext,
    status: DimensionStatus,
) -> Result<CompatibilityAnalysis, Box<dyn std::error::Error>> {
    let evidence =
        CompatibilityEvidenceRef::new(CompatibilityEvidenceKind::StaticAnalysis, digest(0x40));
    let assessment = match status {
        DimensionStatus::Unknown => DimensionAssessment::unknown(),
        DimensionStatus::Satisfied
        | DimensionStatus::Unsatisfied
        | DimensionStatus::NotApplicable => DimensionAssessment::new(status, [evidence])?,
    };
    let dimensions = CompatibilityDimensions {
        package: assessment.clone(),
        main_runtime: assessment.clone(),
        renderer: assessment.clone(),
        preload: assessment.clone(),
        electron_api: assessment.clone(),
        node_api: assessment.clone(),
        native_modules: assessment.clone(),
        helpers: assessment.clone(),
        state: assessment.clone(),
        security: assessment,
    };
    Ok(CompatibilityAnalysis::new(
        context.source_build_fingerprint_digest,
        CompatibilityTarget::windows_x64(
            digest(0x41),
            digest(0x42),
            digest(0x43),
            context.execution_environment_digest,
        ),
        dimensions,
        BTreeMap::new(),
    )?)
}

fn canonical_digest<T: serde::Serialize>(value: &T) -> serde_json::Result<Sha256Digest> {
    Ok(bytes_digest(&serde_json::to_vec(value)?))
}

fn bytes_digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}
