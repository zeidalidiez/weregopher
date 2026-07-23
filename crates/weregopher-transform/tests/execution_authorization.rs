//! Windows live execution-authorization regressions over retained executable capabilities.

#![cfg(windows)]

use std::{collections::BTreeMap, fs, path::Path, time::Duration};

use sha2::{Digest as _, Sha256};
use tempfile::tempdir;
use weregopher_domain::{
    AdapterExecutionAuthority, AdapterId, AdapterTransformAuthority, ApplicationFamilyId,
    AuthorizationContextDigest, AuthorizedExecutionTargetRef, AuthorizedTransformRuleRef,
    CompatibilityAnalysis, CompatibilityDimensions, CompatibilityEvidenceKind,
    CompatibilityEvidenceRef, CompatibilityTarget, DimensionAssessment, DimensionStatus,
    EffectiveSecurityPosture, ExecutionArgument, ExecutionArtifactBinding,
    ExecutionArtifactDigests, ExecutionArtifactLocator, ExecutionDependencyPolicy,
    ExecutionLaunchPolicy, ExecutionOverlayBinding, ExecutionOverlayContext,
    ExecutionPolicyRequirements, ExecutionResolutionDigests, ExecutionResolutionEvidence,
    ExecutionResourceLimits, ExecutionStateMode, ExecutionTargetContract, ExecutionTargetId,
    ExecutionTargetKind, GeneratedExecutionOverlay, GeneratedTransformOverlay,
    RequiredSecurityPosture, Sha256Digest, SourceUnitId, SourceUnitRef, TransformOverlayBinding,
    TransformRebinding, TransformRuleId, TrustMode,
};
use weregopher_fingerprint::{PackageTreeObservationLimits, observe_package_tree};
use weregopher_transform::{
    AuthorizedExecution, ExecutionAuthorityPins, ExecutionAuthorizationError,
    ExecutionAuthorizationLimits, ExecutionAuthorizationRequest, ExecutionContextPins,
    ExecutionPolicyEvidence, ExecutionTargetPins, LocalExecutionPolicy, LocalExecutionPolicyStore,
    ManagedArtifactLease, ManagedArtifactLeaseLimits, ManagedArtifactStore, ManagedStoreRootLimits,
    MaterializationManifestLimits, MaterializationWriteLimits, PackageSnapshotLease,
    PackageSnapshotWriteLimits, RetainedExecutionArtifact, SupervisedExecutionError,
    SupervisionError, SupervisionLimits, SupervisionOutcome, TransformArtifactBytes,
    TransformArtifactLimits, authorize_execution, launch_authorized_execution,
    plan_content_addressed_materialization, supervise_execution, verify_transform_artifacts,
};

const TRUST_EVIDENCE: &[u8] = b"locally approved adapter trust evidence";
const PROVENANCE_EVIDENCE: &[u8] = b"locally approved package provenance";
const CAPABILITY_POLICY: &[u8] = b"capability policy v1: helper only";
const STATE_POLICY: &[u8] = b"state policy v1: disposable";
const USER_POLICY: &[u8] = b"user policy v1: approved";
const UPDATED_USER_POLICY: &[u8] = b"user policy v2: separately approved";

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
        authorized.authorization_context_digest().to_string(),
        "sha256:adf18464d9a9eeea99b35a0801aa679e1754a85102d8b0a36c15dd552cef6136"
    );
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
fn one_shot_authorization_is_consumed_into_a_job_owned_launch()
-> Result<(), Box<dyn std::error::Error>> {
    with_authorized_test_binary(
        "authorized_launch_child_helper",
        |authorization, _policy| {
            let context_digest: AuthorizationContextDigest =
                authorization.authorization_context_digest();
            let launch_policy = authorization.launch_policy().clone();
            let process = launch_authorized_execution(authorization)?;
            assert!(process.id() != 0);
            assert!(process.is_in_job()?);
            assert_eq!(process.authorization_context_digest(), context_digest);
            assert_eq!(process.trust_mode(), TrustMode::LocallyTrusted);
            assert_eq!(process.launch_policy(), &launch_policy);
            assert_eq!(process.wait_for(Duration::from_secs(5))?, Some(0));
            Ok(())
        },
    )
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the test keeps the complete managed-capability lifetime chain visible"
)]
fn managed_artifact_authorization_retains_its_manifest_through_launch()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let vendor = fixture.path().join("vendor");
    let store_root = fixture.path().join("store");
    fs::create_dir(&vendor)?;
    fs::create_dir(&store_root)?;

    let executable_bytes = fs::read(std::env::current_exe()?)?;
    let source = b"managed source artifact";
    let match_evidence = b"managed match evidence";
    let source_map = b"managed source map";
    let audit_log = b"managed audit log";
    let executable_digest = bytes_digest(&executable_bytes);
    let rule_id = TransformRuleId::new("managed.test-executable")?;
    let rule_digest = digest(0x60);
    let transform_authority = AdapterTransformAuthority::new(
        AdapterId::new("local.managed-transform")?,
        ApplicationFamilyId::new("local.managed-family")?,
        digest(0x61),
        BTreeMap::from([(
            rule_id.clone(),
            AuthorizedTransformRuleRef::new(rule_digest),
        )]),
    )?;
    let artifact_bytes = TransformArtifactBytes::new(
        source,
        match_evidence,
        &executable_bytes,
        source_map,
        audit_log,
    );
    let transform_overlay = GeneratedTransformOverlay::windows_x64(
        TransformOverlayBinding::new(
            digest(0x62),
            transform_authority.family().clone(),
            transform_authority.adapter_id().clone(),
            *transform_authority.adapter_content_digest(),
            transform_authority.canonical_document_digest(),
            digest(0x63),
        ),
        BTreeMap::from([(
            rule_id.clone(),
            TransformRebinding::new(
                rule_digest,
                SourceUnitRef::new(
                    SourceUnitId::new("managed.test-source")?,
                    bytes_digest(source),
                ),
                bytes_digest(match_evidence),
                executable_digest,
                bytes_digest(source_map),
                bytes_digest(audit_log),
            ),
        )]),
    )?;
    let structural =
        transform_overlay.validate_against(&transform_authority, digest(0x62), digest(0x63))?;
    let artifacts = BTreeMap::from([(rule_id, artifact_bytes)]);
    let verified = verify_transform_artifacts(
        structural,
        &artifacts,
        managed_test_artifact_limits(
            source,
            match_evidence,
            &executable_bytes,
            source_map,
            audit_log,
        )?,
    )?;
    let manifest = plan_content_addressed_materialization(
        &verified,
        MaterializationManifestLimits::new(1, 5, 5, 4_096)?,
    )?;
    let max_blob_bytes = manifest
        .blobs()
        .values()
        .map(|bytes| bytes.len())
        .max()
        .ok_or("managed test manifest must contain a blob")?;
    let total_blob_bytes = manifest
        .blobs()
        .values()
        .try_fold(0_usize, |total, bytes| total.checked_add(bytes.len()))
        .ok_or("managed test manifest byte count overflowed")?;
    let store = ManagedArtifactStore::open(&store_root, &vendor, ManagedStoreRootLimits::new(64)?)?;
    store.materialize(
        &manifest,
        MaterializationWriteLimits::new(
            manifest.blob_count(),
            max_blob_bytes,
            total_blob_bytes,
            8,
        )?,
    )?;
    let lease = store.lease_manifest(
        &manifest,
        ManagedArtifactLeaseLimits::new(manifest.blob_count(), max_blob_bytes, total_blob_bytes)?,
    )?;
    exercise_managed_artifact_authorization(
        &lease,
        *manifest.digest(),
        executable_digest,
        &store_root,
        &fixture.path().join("store-moved"),
    )
}

fn managed_test_artifact_limits(
    source: &[u8],
    match_evidence: &[u8],
    transformed_source: &[u8],
    source_map: &[u8],
    audit_log: &[u8],
) -> Result<TransformArtifactLimits, Box<dyn std::error::Error>> {
    let lengths = [
        source.len(),
        match_evidence.len(),
        transformed_source.len(),
        source_map.len(),
        audit_log.len(),
    ];
    let total = lengths
        .into_iter()
        .try_fold(0_usize, usize::checked_add)
        .ok_or("managed test artifact byte count overflowed")?;
    Ok(TransformArtifactLimits::new(
        lengths[0], lengths[1], lengths[2], lengths[3], lengths[4], total,
    )?)
}

fn exercise_managed_artifact_authorization(
    lease: &ManagedArtifactLease<'_>,
    manifest_digest: Sha256Digest,
    executable_digest: Sha256Digest,
    store_root: &Path,
    moved_store_root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let launch_arguments = [
        "--ignored",
        "--exact",
        "managed_authorized_launch_child_helper",
        "--test-threads=1",
    ]
    .into_iter()
    .map(ExecutionArgument::new)
    .collect::<Result<Vec<_>, _>>()?;
    let mismatched_documents =
        authorization_documents_for_locator(&AuthorizationDocumentOptions {
            locator: ExecutionArtifactLocator::managed_artifact(executable_digest.into()),
            dependency_policy: ExecutionDependencyPolicy::VendorDefaultAmbient,
            artifact_source_digest: digest(0xee),
            executable_digest,
            compatibility_status: DimensionStatus::Satisfied,
            arguments: launch_arguments.clone(),
            required_security_posture: RequiredSecurityPosture::VendorEquivalentFullTrust,
            state_mode: ExecutionStateMode::VendorDefault,
        })?;
    let mismatched_structural = mismatched_documents.overlay.validate_against(
        &mismatched_documents.authority,
        mismatched_documents.context,
    )?;
    let mismatched_executable = lease.lock_executable(&executable_digest, 64)?;
    assert!(matches!(
        authorize_execution(ExecutionAuthorizationRequest {
            structural_overlay: &mismatched_structural,
            target_contract: &mismatched_documents.target_contract,
            resolution_evidence: &mismatched_documents.resolution,
            compatibility_analysis: &mismatched_documents.compatibility,
            policy_store: &mismatched_documents.policy_store,
            policy_evidence: policy_evidence(),
            retained_artifact: RetainedExecutionArtifact::ManagedArtifact(mismatched_executable),
            limits: ExecutionAuthorizationLimits::new(1_024, 4_096)?,
        }),
        Err(ExecutionAuthorizationError::RetainedArtifactSourceDigestMismatch)
    ));
    let documents = authorization_documents_for_locator(&AuthorizationDocumentOptions {
        locator: ExecutionArtifactLocator::managed_artifact(executable_digest.into()),
        dependency_policy: ExecutionDependencyPolicy::VendorDefaultAmbient,
        artifact_source_digest: manifest_digest,
        executable_digest,
        compatibility_status: DimensionStatus::Satisfied,
        arguments: launch_arguments,
        required_security_posture: RequiredSecurityPosture::VendorEquivalentFullTrust,
        state_mode: ExecutionStateMode::VendorDefault,
    })?;
    let execution_structural = documents
        .overlay
        .validate_against(&documents.authority, documents.context)?;
    let executable = lease.lock_executable(&executable_digest, 64)?;
    let authorization = authorize_execution(ExecutionAuthorizationRequest {
        structural_overlay: &execution_structural,
        target_contract: &documents.target_contract,
        resolution_evidence: &documents.resolution,
        compatibility_analysis: &documents.compatibility,
        policy_store: &documents.policy_store,
        policy_evidence: policy_evidence(),
        retained_artifact: RetainedExecutionArtifact::ManagedArtifact(executable),
        limits: ExecutionAuthorizationLimits::new(1_024, 4_096)?,
    })?;
    let process = launch_authorized_execution(authorization)?;
    assert!(process.is_in_job()?);
    assert_eq!(process.wait_for(Duration::from_secs(5))?, Some(0));
    assert!(fs::rename(store_root, moved_store_root).is_err());
    Ok(())
}

#[test]
fn running_process_owner_preserves_revocation_currentness() -> Result<(), Box<dyn std::error::Error>>
{
    with_authorized_test_binary(
        "authorized_launch_long_running_child_helper",
        |authorization, policy| {
            let process = launch_authorized_execution(authorization)?;
            policy.revoke(digest(0xfa))?;
            assert_eq!(
                process.verify_current_policy(),
                Err(ExecutionAuthorizationError::PolicyRevoked)
            );
            process.terminate(73)?;
            assert_eq!(process.wait_for(Duration::from_secs(5))?, Some(73));
            Ok(())
        },
    )
}

#[test]
fn blocking_supervisor_terminates_revoked_execution_and_reports_exact_identity()
-> Result<(), Box<dyn std::error::Error>> {
    with_authorized_test_binary(
        "authorized_launch_long_running_child_helper",
        |authorization, policy| {
            let target_id = authorization.target_id().clone();
            let context_digest = authorization.authorization_context_digest();
            let process = launch_authorized_execution(authorization)?;
            let report = std::thread::scope(|scope| -> Result<_, Box<dyn std::error::Error>> {
                let supervisor = scope.spawn(move || {
                    supervise_execution(
                        process,
                        SupervisionLimits::new(Duration::from_millis(5), Duration::from_secs(5))?,
                    )
                });
                std::thread::sleep(Duration::from_millis(25));
                policy.revoke(digest(0xf9))?;
                Ok(supervisor
                    .join()
                    .map_err(|_| std::io::Error::other("execution supervisor thread panicked"))??)
            })?;
            assert_eq!(report.target_id(), &target_id);
            assert_eq!(report.authorization_context_digest(), context_digest);
            assert_eq!(
                report.outcome(),
                &SupervisionOutcome::PolicyInvalidated {
                    reason: ExecutionAuthorizationError::PolicyRevoked,
                }
            );
            Ok(())
        },
    )
}

#[test]
fn blocking_supervisor_enforces_a_stricter_runtime_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    with_authorized_test_binary(
        "authorized_launch_long_running_child_helper",
        |authorization, _policy| {
            let process = launch_authorized_execution(authorization)?;
            let report = supervise_execution(
                process,
                SupervisionLimits::new(Duration::from_millis(5), Duration::from_millis(25))?,
            )?;
            assert_eq!(report.outcome(), &SupervisionOutcome::RuntimeExceeded);
            Ok(())
        },
    )
}

#[test]
fn blocking_supervisor_reports_natural_primary_exit() -> Result<(), Box<dyn std::error::Error>> {
    with_authorized_test_binary(
        "authorized_launch_child_helper",
        |authorization, _policy| {
            let process = launch_authorized_execution(authorization)?;
            let report = supervise_execution(
                process,
                SupervisionLimits::new(Duration::from_millis(5), Duration::from_secs(5))?,
            )?;
            assert_eq!(report.outcome(), &SupervisionOutcome::Exited { code: 0 });
            Ok(())
        },
    )
}

#[test]
fn supervision_limits_are_nonzero_bounded_and_ordered() {
    assert!(matches!(
        SupervisionLimits::new(Duration::ZERO, Duration::from_secs(1)),
        Err(SupervisionError::InvalidLimits)
    ));
    assert!(matches!(
        SupervisionLimits::new(Duration::from_nanos(1), Duration::from_secs(1)),
        Err(SupervisionError::InvalidLimits)
    ));
    assert!(matches!(
        SupervisionLimits::new(Duration::from_secs(2), Duration::from_secs(1)),
        Err(SupervisionError::InvalidLimits)
    ));
    assert!(matches!(
        SupervisionLimits::new(Duration::from_secs(61), Duration::from_secs(61)),
        Err(SupervisionError::InvalidLimits)
    ));
}

#[test]
#[ignore = "spawned by the authorized supervisor launch regression"]
fn authorized_launch_child_helper() {
    if std::env::vars_os().next().is_some() {
        std::process::exit(74);
    }
}

#[test]
#[ignore = "spawned by the managed-artifact supervisor launch regression"]
fn managed_authorized_launch_child_helper() {
    if std::env::vars_os().next().is_some() {
        std::process::exit(75);
    }
}

#[test]
#[ignore = "spawned by the authorized supervisor revocation regression"]
fn authorized_launch_long_running_child_helper() {
    std::thread::sleep(Duration::from_mins(1));
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
        let cases = [
            (
                ExecutionPolicyEvidence {
                    artifact_trust: b"different trust evidence",
                    ..policy_evidence()
                },
                ExecutionAuthorizationError::ArtifactTrustEvidenceMismatch,
            ),
            (
                ExecutionPolicyEvidence {
                    provenance: b"different provenance evidence",
                    ..policy_evidence()
                },
                ExecutionAuthorizationError::ProvenanceEvidenceMismatch,
            ),
            (
                ExecutionPolicyEvidence {
                    capability_policy: b"different capability policy",
                    ..policy_evidence()
                },
                ExecutionAuthorizationError::CapabilityPolicyMismatch,
            ),
            (
                ExecutionPolicyEvidence {
                    state_policy: b"different state policy",
                    ..policy_evidence()
                },
                ExecutionAuthorizationError::StatePolicyMismatch,
            ),
            (
                ExecutionPolicyEvidence {
                    user_policy: b"different user policy",
                    ..policy_evidence()
                },
                ExecutionAuthorizationError::UserPolicyMismatch,
            ),
        ];
        for (tampered, expected) in cases {
            let Err(actual) = authorize_snapshot!(
                snapshot,
                documents,
                "helper.exe",
                tampered,
                ExecutionAuthorizationLimits::new(1_024, 4_096)?
            ) else {
                return Err("tampered execution policy evidence was accepted".into());
            };
            assert_eq!(actual, expected);
        }

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
fn authorization_evidence_limits_cannot_disable_implementation_ceilings() {
    assert!(ExecutionAuthorizationLimits::new(usize::MAX, 4_096).is_err());
    assert!(ExecutionAuthorizationLimits::new(1_024, usize::MAX).is_err());
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
fn authorization_rejects_a_domain_valid_but_unrepresentable_windows_command_line()
-> Result<(), Box<dyn std::error::Error>> {
    with_snapshot_fixture(DimensionStatus::Satisfied, None, |snapshot, _documents| {
        let executable = snapshot.lock_executable("helper.exe", 64)?;
        let executable_digest = executable.digest();
        drop(executable);
        let expanding_argument = format!("{}\"", "\\".repeat(8_191));
        let documents = authorization_documents_with_arguments(
            *snapshot.package_tree_merkle(),
            executable_digest,
            DimensionStatus::Satisfied,
            vec![
                ExecutionArgument::new(expanding_argument.clone())?,
                ExecutionArgument::new(expanding_argument)?,
            ],
        )?;
        assert!(matches!(
            authorize_snapshot!(
                snapshot,
                documents,
                "helper.exe",
                policy_evidence(),
                ExecutionAuthorizationLimits::new(1_024, 4_096)?
            ),
            Err(ExecutionAuthorizationError::UnrepresentableLaunch)
        ));
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
fn current_user_policy_can_change_without_resigning_the_static_target()
-> Result<(), Box<dyn std::error::Error>> {
    with_snapshot_fixture(DimensionStatus::Satisfied, None, |snapshot, documents| {
        let static_contract_digest = documents.target_contract.canonical_document_digest()?;
        let original_authorization = authorize_snapshot!(
            snapshot,
            documents,
            "helper.exe",
            policy_evidence(),
            ExecutionAuthorizationLimits::new(1_024, 4_096)?
        )?;
        let original_context_digest = original_authorization.authorization_context_digest();
        let mut target_pins = documents.policy.target_pins().clone();
        target_pins.user_policy_digest = bytes_digest(UPDATED_USER_POLICY).into();
        let replacement = LocalExecutionPolicy::new(
            TrustMode::LocallyTrusted,
            authority_pins(&documents.authority),
            context_pins(documents.context),
            target_pins,
            digest(0x31),
        )?;
        documents.policy_store.replace_policy(replacement)?;

        let authorization = authorize_snapshot!(
            snapshot,
            documents,
            "helper.exe",
            ExecutionPolicyEvidence {
                user_policy: UPDATED_USER_POLICY,
                ..policy_evidence()
            },
            ExecutionAuthorizationLimits::new(1_024, 4_096)?
        )?;
        assert_eq!(
            documents.target_contract.canonical_document_digest()?,
            static_contract_digest
        );
        assert_ne!(
            authorization.authorization_context_digest(),
            original_context_digest
        );
        assert_eq!(
            original_authorization.verify_current_policy(),
            Err(ExecutionAuthorizationError::PolicyChanged)
        );
        authorization.verify_current_policy()?;
        Ok(())
    })
}

#[test]
fn compatibility_analysis_can_change_without_resigning_the_static_target()
-> Result<(), Box<dyn std::error::Error>> {
    with_snapshot_fixture(
        DimensionStatus::Satisfied,
        None,
        |snapshot, mut documents| {
            let static_contract_digest = documents.target_contract.canonical_document_digest()?;
            let compatibility = compatibility_analysis_with_evidence(
                documents.context,
                DimensionStatus::Satisfied,
                0x44,
            )?;
            let mut target_pins = documents.policy.target_pins().clone();
            target_pins.compatibility_analysis_digest = canonical_digest(&compatibility)?.into();
            let replacement = LocalExecutionPolicy::new(
                TrustMode::LocallyTrusted,
                authority_pins(&documents.authority),
                context_pins(documents.context),
                target_pins,
                digest(0x32),
            )?;
            documents.policy_store.replace_policy(replacement)?;
            documents.compatibility = compatibility;

            let authorization = authorize_snapshot!(
                snapshot,
                documents,
                "helper.exe",
                policy_evidence(),
                ExecutionAuthorizationLimits::new(1_024, 4_096)?
            )?;
            assert_eq!(
                documents.target_contract.canonical_document_digest()?,
                static_contract_digest
            );
            authorization.verify_current_policy()?;
            Ok(())
        },
    )
}

#[test]
fn policy_revocation_prevents_authorization_consumption() -> Result<(), Box<dyn std::error::Error>>
{
    with_snapshot_fixture(DimensionStatus::Satisfied, None, |snapshot, documents| {
        let authorization = authorize_snapshot!(
            snapshot,
            documents,
            "helper.exe",
            policy_evidence(),
            ExecutionAuthorizationLimits::new(1_024, 4_096)?
        )?;
        documents.policy_store.revoke(digest(0xfb))?;

        assert!(matches!(
            launch_authorized_execution(authorization),
            Err(SupervisedExecutionError::Authorization(
                ExecutionAuthorizationError::PolicyRevoked
            ))
        ));
        Ok(())
    })
}

#[test]
fn authorization_rejects_security_postures_that_the_windows_primitive_does_not_enforce()
-> Result<(), Box<dyn std::error::Error>> {
    with_snapshot_fixture(DimensionStatus::Satisfied, None, |snapshot, _documents| {
        let executable = snapshot.lock_executable("helper.exe", 64)?;
        let executable_digest = executable.digest();
        drop(executable);
        let documents = authorization_documents_with_launch(
            *snapshot.package_tree_merkle(),
            executable_digest,
            DimensionStatus::Satisfied,
            vec![ExecutionArgument::new("--serve")?],
            RequiredSecurityPosture::BrokerMediated,
            ExecutionStateMode::Disposable,
        )?;
        assert!(matches!(
            authorize_snapshot!(
                snapshot,
                documents,
                "helper.exe",
                policy_evidence(),
                ExecutionAuthorizationLimits::new(1_024, 4_096)?
            ),
            Err(ExecutionAuthorizationError::SecurityPostureMismatch)
        ));
        let stateful_documents = authorization_documents_with_launch(
            *snapshot.package_tree_merkle(),
            executable_digest,
            DimensionStatus::Satisfied,
            vec![ExecutionArgument::new("--serve")?],
            RequiredSecurityPosture::VendorEquivalentFullTrust,
            ExecutionStateMode::Disposable,
        )?;
        assert!(matches!(
            authorize_snapshot!(
                snapshot,
                stateful_documents,
                "helper.exe",
                policy_evidence(),
                ExecutionAuthorizationLimits::new(1_024, 4_096)?
            ),
            Err(ExecutionAuthorizationError::UnsupportedStateMode)
        ));
        let closed_dependency_documents =
            authorization_documents_for_locator(&AuthorizationDocumentOptions {
                locator: ExecutionArtifactLocator::package_snapshot("helper.exe")?,
                dependency_policy: ExecutionDependencyPolicy::ManifestClosed,
                artifact_source_digest: *snapshot.package_tree_merkle(),
                executable_digest,
                compatibility_status: DimensionStatus::Satisfied,
                arguments: vec![ExecutionArgument::new("--serve")?],
                required_security_posture: RequiredSecurityPosture::VendorEquivalentFullTrust,
                state_mode: ExecutionStateMode::VendorDefault,
            })?;
        assert!(matches!(
            authorize_snapshot!(
                snapshot,
                closed_dependency_documents,
                "helper.exe",
                policy_evidence(),
                ExecutionAuthorizationLimits::new(1_024, 4_096)?
            ),
            Err(ExecutionAuthorizationError::UnsupportedDependencyPolicy)
        ));
        Ok(())
    })
}

#[test]
fn non_executable_retained_bytes_fail_before_any_thread_can_resume()
-> Result<(), Box<dyn std::error::Error>> {
    with_snapshot_fixture(DimensionStatus::Satisfied, None, |snapshot, documents| {
        let authorization = authorize_snapshot!(
            snapshot,
            documents,
            "helper.exe",
            policy_evidence(),
            ExecutionAuthorizationLimits::new(1_024, 4_096)?
        )?;
        assert!(matches!(
            launch_authorized_execution(authorization),
            Err(SupervisedExecutionError::ProcessLaunch(_))
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
        assert!(matches!(
            LocalExecutionPolicy::new(
                TrustMode::ForensicOverride,
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
        let mut disposable_target = policy.target_pins().clone();
        disposable_target.state_mode = ExecutionStateMode::Disposable;
        assert!(
            LocalExecutionPolicy::new(
                TrustMode::Developer,
                policy.authority_pins().clone(),
                policy.context_pins(),
                disposable_target,
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
        let context = policy.context_pins();
        let mut wrong_source = context;
        wrong_source.source_build_fingerprint_digest = digest(0x53);
        let mut wrong_tree = context;
        wrong_tree.package_tree_merkle = digest(0x54);
        let mut wrong_environment = context;
        wrong_environment.execution_environment_digest = digest(0x55);
        let mut wrong_descriptor = context;
        wrong_descriptor.build_descriptor_digest = digest(0x56);
        let cases = [
            (
                wrong_source,
                ExecutionAuthorizationError::SourceBuildContextMismatch,
            ),
            (
                wrong_tree,
                ExecutionAuthorizationError::PackageTreeContextMismatch,
            ),
            (
                wrong_environment,
                ExecutionAuthorizationError::ExecutionEnvironmentContextMismatch,
            ),
            (
                wrong_descriptor,
                ExecutionAuthorizationError::BuildDescriptorContextMismatch,
            ),
        ];
        for (wrong_context, expected) in cases {
            documents
                .policy_store
                .replace_policy(LocalExecutionPolicy::new(
                    TrustMode::LocallyTrusted,
                    policy.authority_pins().clone(),
                    wrong_context,
                    policy.target_pins().clone(),
                    digest(0x57),
                )?)?;
            let Err(actual) = authorize_snapshot!(
                snapshot,
                documents,
                "helper.exe",
                policy_evidence(),
                ExecutionAuthorizationLimits::new(1_024, 4_096)?
            ) else {
                return Err("cross-context execution replay was accepted".into());
            };
            assert_eq!(actual, expected);
        }
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

struct AuthorizationDocumentOptions {
    locator: ExecutionArtifactLocator,
    dependency_policy: ExecutionDependencyPolicy,
    artifact_source_digest: Sha256Digest,
    executable_digest: Sha256Digest,
    compatibility_status: DimensionStatus,
    arguments: Vec<ExecutionArgument>,
    required_security_posture: RequiredSecurityPosture,
    state_mode: ExecutionStateMode,
}

impl AuthorizationDocumentOptions {
    fn target_contract(
        &self,
        target_id: &ExecutionTargetId,
    ) -> Result<ExecutionTargetContract, Box<dyn std::error::Error>> {
        Ok(ExecutionTargetContract::new(
            target_id.clone(),
            ExecutionTargetKind::VendorHelper,
            self.locator.clone(),
            ExecutionLaunchPolicy::new(
                self.arguments.clone(),
                self.dependency_policy,
                self.required_security_posture,
                self.state_mode,
                ExecutionResourceLimits::new(2, 64 * 1024 * 1024, 128 * 1024 * 1024)?,
                ExecutionPolicyRequirements {
                    capability_policy_digest: bytes_digest(CAPABILITY_POLICY).into(),
                    state_policy_digest: bytes_digest(STATE_POLICY).into(),
                },
            )?,
        ))
    }
}

fn authorization_documents(
    artifact_source_digest: Sha256Digest,
    executable_digest: Sha256Digest,
    compatibility_status: DimensionStatus,
) -> Result<AuthorizationDocuments, Box<dyn std::error::Error>> {
    authorization_documents_with_arguments(
        artifact_source_digest,
        executable_digest,
        compatibility_status,
        vec![ExecutionArgument::new("--serve")?],
    )
}

fn authorization_documents_with_arguments(
    artifact_source_digest: Sha256Digest,
    executable_digest: Sha256Digest,
    compatibility_status: DimensionStatus,
    arguments: Vec<ExecutionArgument>,
) -> Result<AuthorizationDocuments, Box<dyn std::error::Error>> {
    authorization_documents_with_launch(
        artifact_source_digest,
        executable_digest,
        compatibility_status,
        arguments,
        RequiredSecurityPosture::VendorEquivalentFullTrust,
        ExecutionStateMode::VendorDefault,
    )
}

fn authorization_documents_with_launch(
    artifact_source_digest: Sha256Digest,
    executable_digest: Sha256Digest,
    compatibility_status: DimensionStatus,
    arguments: Vec<ExecutionArgument>,
    required_security_posture: RequiredSecurityPosture,
    state_mode: ExecutionStateMode,
) -> Result<AuthorizationDocuments, Box<dyn std::error::Error>> {
    authorization_documents_for_locator(&AuthorizationDocumentOptions {
        locator: ExecutionArtifactLocator::package_snapshot("helper.exe")?,
        dependency_policy: ExecutionDependencyPolicy::VendorDefaultAmbient,
        artifact_source_digest,
        executable_digest,
        compatibility_status,
        arguments,
        required_security_posture,
        state_mode,
    })
}

fn authorization_documents_for_locator(
    options: &AuthorizationDocumentOptions,
) -> Result<AuthorizationDocuments, Box<dyn std::error::Error>> {
    let target_id = ExecutionTargetId::new("helper.allowed")?;
    let context = ExecutionOverlayContext {
        source_build_fingerprint_digest: digest(0x10),
        package_tree_merkle: options.artifact_source_digest,
        execution_environment_digest: digest(0x11),
        build_descriptor_digest: digest(0x12),
    };
    let compatibility = compatibility_analysis(context, options.compatibility_status)?;
    let compatibility_digest = canonical_digest(&compatibility)?;
    let artifact_source = options.locator.artifact_source();
    let target_contract = options.target_contract(&target_id)?;
    let target_contract_digest = target_contract.canonical_document_digest()?;
    let resolution = ExecutionResolutionEvidence::new(
        target_id.clone(),
        options.locator.clone(),
        ExecutionResolutionDigests {
            execution_contract_digest: target_contract_digest,
            artifact_source_digest: options.artifact_source_digest.into(),
            executable_digest: options.executable_digest.into(),
            artifact_trust_evidence_digest: bytes_digest(TRUST_EVIDENCE).into(),
            provenance_evidence_digest: bytes_digest(PROVENANCE_EVIDENCE).into(),
        },
    )?;
    let resolution_digest = resolution.canonical_document_digest()?;
    let authority = AdapterExecutionAuthority::new(
        AdapterId::new("local.test-adapter")?,
        ApplicationFamilyId::new("local.test-family")?,
        digest(0x20),
        BTreeMap::from([(
            target_id.clone(),
            AuthorizedExecutionTargetRef::new(
                ExecutionTargetKind::VendorHelper,
                artifact_source,
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
                artifact_source_digest: options.artifact_source_digest.into(),
                executable_digest: options.executable_digest.into(),
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
            artifact_trust_evidence_digest: bytes_digest(TRUST_EVIDENCE).into(),
            provenance_evidence_digest: bytes_digest(PROVENANCE_EVIDENCE).into(),
            compatibility_analysis_digest: compatibility_digest.into(),
            capability_policy_digest: bytes_digest(CAPABILITY_POLICY).into(),
            state_policy_digest: bytes_digest(STATE_POLICY).into(),
            user_policy_digest: bytes_digest(USER_POLICY).into(),
            security_posture: EffectiveSecurityPosture::VendorEquivalentFullTrust,
            state_mode: options.state_mode,
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

fn with_authorized_test_binary(
    child_test: &str,
    test: impl FnOnce(
        AuthorizedExecution<'_, '_>,
        &LocalExecutionPolicyStore,
    ) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let vendor = fixture.path().join("vendor");
    let store_root = fixture.path().join("store");
    fs::create_dir(&vendor)?;
    fs::create_dir(&store_root)?;
    fs::copy(std::env::current_exe()?, vendor.join("helper.exe"))?;
    let executable_bytes = fs::metadata(vendor.join("helper.exe"))?.len();
    let observation = observe_package_tree(
        &vendor,
        PackageTreeObservationLimits::new(1, 8, 4, executable_bytes, executable_bytes, 1_024)?,
    )?;
    let store = ManagedArtifactStore::open(&store_root, &vendor, ManagedStoreRootLimits::new(64)?)?;
    let snapshot = store.snapshot_package(
        &observation,
        PackageSnapshotWriteLimits::new(1, 8, executable_bytes, executable_bytes, 64)?,
    )?;
    let documents = authorization_documents_with_arguments(
        *snapshot.package_tree_merkle(),
        observation.manifest().files()[0].sha256,
        DimensionStatus::Satisfied,
        ["--ignored", "--exact", child_test, "--test-threads=1"]
            .into_iter()
            .map(ExecutionArgument::new)
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    let authorization = authorize_snapshot!(
        snapshot,
        documents,
        "helper.exe",
        policy_evidence(),
        ExecutionAuthorizationLimits::new(1_024, 4_096)?
    )?;
    test(authorization, &documents.policy_store)
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
    compatibility_analysis_with_evidence(context, status, 0x40)
}

fn compatibility_analysis_with_evidence(
    context: ExecutionOverlayContext,
    status: DimensionStatus,
    evidence_marker: u8,
) -> Result<CompatibilityAnalysis, Box<dyn std::error::Error>> {
    let evidence = CompatibilityEvidenceRef::new(
        CompatibilityEvidenceKind::StaticAnalysis,
        digest(evidence_marker),
    );
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
