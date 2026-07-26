//! Behavior tests for verified runner components and freshness-bound local publication.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    time::Duration,
};

use sha2::{Digest as _, Sha256};
use tempfile::tempdir;
use weregopher_domain::{
    CertificationArtifactDigest, CertificationArtifactKind, CertificationArtifactRef,
    CertificationCheckAssessment, CertificationCheckStatus, CertificationChecks,
    CertificationClass, CertificationControlPolicy, CertificationElectronRuntimeDigest,
    CertificationEvidence, CertificationExceptionProvenanceDigest, CertificationExpectedStatus,
    CertificationHostAgentDigest, CertificationHostImageDigest, CertificationHostPatchSetDigest,
    CertificationLanguageRuntimeSetDigest, CertificationPolicyRevisionDigest,
    CertificationPolicyRevocationDigest, CertificationProbeAssetSetDigest, CertificationProfile,
    CertificationProfileChecks, CertificationProfileClass, CertificationRunnerArtifactName,
    CertificationRunnerComponentArtifact, CertificationRunnerComponentDescriptor,
    CertificationRunnerComponentId, CertificationRunnerComponentProvenanceDigest,
    CertificationRunnerComponentRole, CertificationRunnerComponentVersion,
    CertificationRunnerEnvironmentIdentity, CertificationRunnerIdentity,
    CertificationRunnerImageDigest, CertificationRunnerPolicyRevisionDigest,
    CertificationRunnerPolicyRevocationDigest, CertificationRunnerProvenanceIdentity,
    CertificationRunnerToolingIdentity, CertificationSourceRevisionDigest, CertificationTarget,
    CertificationToolchainSetDigest, CertificationVerifierDigest, CompatibilityAnalysisDigest,
    ExecutableDigest, ExecutionArtifactSourceDigest, ExecutionContractDigest,
    ExecutionResolutionEvidenceDigest, FeatureId, MAX_LOCAL_CERTIFICATION_RUN_FRESHNESS_MILLIS,
    PublicationStatus, Sha256Digest,
};
use weregopher_transform::{
    AttestedCertificationPublicationError, AttestedLocalCertificationPublication,
    CertificationArtifactVerificationLimits, CertificationRunnerComponentVerificationError,
    CertificationRunnerComponentVerificationLimits, LocalAttestedCertificationPublicationStore,
    LocalCertificationLedger, LocalCertificationLedgerError, LocalCertificationPolicy,
    LocalCertificationPolicyStore, LocalCertificationRunnerPolicy,
    LocalCertificationRunnerPolicyStore, approve_local_certification_runner,
    assign_local_certification, begin_local_certification_run,
    prepare_attested_local_certification_publication, publish_attested_local_certification,
    verify_certification_artifacts, verify_certification_runner_components,
};

const REPORT_BYTES: &[u8] = b"semantic certification report";

#[test]
fn exact_runner_component_descriptors_and_artifacts_produce_a_current_opaque_proof()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RunnerFixture::new()?;
    let policy = LocalCertificationRunnerPolicy::new(
        fixture.identity.canonical_document_digest()?,
        CertificationRunnerPolicyRevisionDigest::new(digest(0x90)),
    );
    let store = LocalCertificationRunnerPolicyStore::new(policy);
    let approved = approve_local_certification_runner(fixture.identity.clone(), &store)?;
    let borrowed = fixture.borrowed_artifacts();

    let verified = verify_certification_runner_components(
        approved,
        &fixture.descriptors,
        &borrowed,
        CertificationRunnerComponentVerificationLimits::new(1024, 1024, 16 * 1024)?,
    )?;

    verified.verify_current_policy()?;
    assert_eq!(verified.descriptor_count(), 11);
    assert_eq!(verified.artifact_count(), 11);
    assert_eq!(verified.total_artifact_bytes(), 33);
    assert_eq!(
        verified.runner_identity_digest(),
        fixture.expected_identity_digest
    );
    assert_eq!(verified.runner_policy_generation(), 1);
    assert_ne!(
        verified.descriptor_set_digest().as_sha256(),
        &Sha256Digest::from_bytes([0; 32])
    );
    Ok(())
}

#[test]
fn runner_component_verification_rejects_missing_unexpected_mismatched_and_stale_inputs()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = RunnerFixture::new()?;
    let policy = LocalCertificationRunnerPolicy::new(
        fixture.identity.canonical_document_digest()?,
        CertificationRunnerPolicyRevisionDigest::new(digest(0x91)),
    );
    let store = LocalCertificationRunnerPolicyStore::new(policy.clone());
    let approved = approve_local_certification_runner(fixture.identity.clone(), &store)?;
    fixture
        .descriptors
        .remove(&CertificationRunnerComponentRole::Verifier);
    let borrowed = fixture.borrowed_artifacts();
    assert!(matches!(
        verify_certification_runner_components(
            approved,
            &fixture.descriptors,
            &borrowed,
            CertificationRunnerComponentVerificationLimits::new(1024, 1024, 16 * 1024)?,
        ),
        Err(
            CertificationRunnerComponentVerificationError::MissingDescriptor(
                CertificationRunnerComponentRole::Verifier
            )
        )
    ));

    let fixture = RunnerFixture::new()?;
    let approved = approve_local_certification_runner(fixture.identity.clone(), &store)?;
    let mut borrowed = fixture.borrowed_artifacts();
    borrowed
        .get_mut(&CertificationRunnerComponentRole::HostAgent)
        .ok_or("host-agent artifacts are missing")?
        .insert(
            CertificationRunnerArtifactName::new("unexpected.bin")?,
            b"unexpected".as_slice(),
        );
    assert!(matches!(
        verify_certification_runner_components(
            approved,
            &fixture.descriptors,
            &borrowed,
            CertificationRunnerComponentVerificationLimits::new(1024, 1024, 16 * 1024)?,
        ),
        Err(CertificationRunnerComponentVerificationError::UnexpectedArtifact { .. })
    ));

    let fixture = RunnerFixture::new()?;
    let approved = approve_local_certification_runner(fixture.identity.clone(), &store)?;
    let mut borrowed = fixture.borrowed_artifacts();
    let runner = borrowed
        .get_mut(&CertificationRunnerComponentRole::RunnerImage)
        .ok_or("runner-image artifacts are missing")?;
    let name = runner
        .keys()
        .next()
        .cloned()
        .ok_or("runner-image artifact is missing")?;
    runner.insert(name, b"tampered".as_slice());
    assert!(matches!(
        verify_certification_runner_components(
            approved,
            &fixture.descriptors,
            &borrowed,
            CertificationRunnerComponentVerificationLimits::new(1024, 1024, 16 * 1024)?,
        ),
        Err(
            CertificationRunnerComponentVerificationError::ArtifactLengthMismatch { .. }
                | CertificationRunnerComponentVerificationError::ArtifactDigestMismatch { .. }
        )
    ));

    let fixture = RunnerFixture::new()?;
    let approved = approve_local_certification_runner(fixture.identity.clone(), &store)?;
    let borrowed = fixture.borrowed_artifacts();
    let verified = verify_certification_runner_components(
        approved,
        &fixture.descriptors,
        &borrowed,
        CertificationRunnerComponentVerificationLimits::new(1024, 1024, 16 * 1024)?,
    )?;
    store.replace_policy(policy)?;
    assert!(verified.verify_current_policy().is_err());
    Ok(())
}

#[test]
fn fresh_run_attestation_binds_both_current_policies_and_the_exact_report()
-> Result<(), Box<dyn std::error::Error>> {
    let runner_fixture = RunnerFixture::new()?;
    let runner_policy = LocalCertificationRunnerPolicy::new(
        runner_fixture.identity.canonical_document_digest()?,
        CertificationRunnerPolicyRevisionDigest::new(digest(0xa0)),
    );
    let runner_store = LocalCertificationRunnerPolicyStore::new(runner_policy);
    let runner_approved =
        approve_local_certification_runner(runner_fixture.identity.clone(), &runner_store)?;
    let runner_artifacts = runner_fixture.borrowed_artifacts();
    let runner_verified = verify_certification_runner_components(
        runner_approved,
        &runner_fixture.descriptors,
        &runner_artifacts,
        CertificationRunnerComponentVerificationLimits::new(1024, 1024, 16 * 1024)?,
    )?;

    let certification = certification_fixture()?;
    let pending = begin_local_certification_run(
        runner_verified,
        certification.report_ref.clone(),
        Duration::from_secs(30),
    )?;
    let policy = LocalCertificationPolicy::new(
        certification.target.clone(),
        certification.profile_digest,
        certification.evidence_digest,
        CertificationClass::SmokeVerified,
        CertificationPolicyRevisionDigest::new(digest(0xa1)),
    )?;
    let certification_store = LocalCertificationPolicyStore::new(policy);
    let artifacts = BTreeMap::from([(certification.report_ref.clone(), REPORT_BYTES)]);
    let certified = assign_local_certification(
        verify_certification_artifacts(
            certification.structural,
            &artifacts,
            CertificationArtifactVerificationLimits::new(1024, 1024)?,
        )?,
        &certification_store,
    )?;
    let publication_store = LocalAttestedCertificationPublicationStore::new(8)?;
    let publication = publish_attested_local_certification(
        prepare_attested_local_certification_publication(pending, certified)?,
        &publication_store,
    )?;

    assert_eq!(publication_store.publication_count()?, 1);
    assert!(publication_store.contains(&publication)?);
    assert_eq!(
        publication.attestation().result().semantic_report(),
        &certification.report_ref
    );
    assert_eq!(publication.attestation().runner().policy_generation(), 1);
    assert_eq!(publication.attestation().result().policy_generation(), 1);
    assert_eq!(
        publication.receipt().publication_status(),
        PublicationStatus::LocalOnly
    );
    assert_eq!(
        publication.receipt().artifact_set_digest(),
        publication.attestation().result().artifact_set_digest()
    );
    assert!(
        publication.attestation().freshness().elapsed_millis()
            <= publication
                .attestation()
                .freshness()
                .maximum_elapsed_millis()
    );
    Ok(())
}

#[test]
fn pending_run_rejects_noncanonical_or_above_ceiling_freshness_durations()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RunnerFixture::new()?;
    let runner_policy = LocalCertificationRunnerPolicy::new(
        fixture.identity.canonical_document_digest()?,
        CertificationRunnerPolicyRevisionDigest::new(digest(0xa2)),
    );
    let runner_store = LocalCertificationRunnerPolicyStore::new(runner_policy);
    let approved = approve_local_certification_runner(fixture.identity.clone(), &runner_store)?;
    let runner_artifacts = fixture.borrowed_artifacts();
    let verified = verify_certification_runner_components(
        approved,
        &fixture.descriptors,
        &runner_artifacts,
        CertificationRunnerComponentVerificationLimits::new(1024, 1024, 16 * 1024)?,
    )?;
    let fractional_millisecond = Duration::from_secs(30) + Duration::from_nanos(1);
    assert!(matches!(
        begin_local_certification_run(
            verified,
            CertificationArtifactRef::new(
                CertificationArtifactKind::RuntimeProbe,
                CertificationArtifactDigest::new(digest(0xa3)),
            ),
            fractional_millisecond,
        ),
        Err(AttestedCertificationPublicationError::InvalidFreshnessLimit)
    ));

    let approved = approve_local_certification_runner(fixture.identity.clone(), &runner_store)?;
    let verified = verify_certification_runner_components(
        approved,
        &fixture.descriptors,
        &runner_artifacts,
        CertificationRunnerComponentVerificationLimits::new(1024, 1024, 16 * 1024)?,
    )?;
    let excessive = Duration::from_millis(MAX_LOCAL_CERTIFICATION_RUN_FRESHNESS_MILLIS)
        + Duration::from_nanos(1);

    assert!(matches!(
        begin_local_certification_run(
            verified,
            CertificationArtifactRef::new(
                CertificationArtifactKind::RuntimeProbe,
                CertificationArtifactDigest::new(digest(0xa3)),
            ),
            excessive,
        ),
        Err(AttestedCertificationPublicationError::InvalidFreshnessLimit)
    ));
    Ok(())
}

#[test]
fn attested_publication_fails_closed_after_runner_or_certification_revocation()
-> Result<(), Box<dyn std::error::Error>> {
    let runner_fixture = RunnerFixture::new()?;
    let runner_policy = LocalCertificationRunnerPolicy::new(
        runner_fixture.identity.canonical_document_digest()?,
        CertificationRunnerPolicyRevisionDigest::new(digest(0xb0)),
    );
    let runner_store = LocalCertificationRunnerPolicyStore::new(runner_policy);
    let approved =
        approve_local_certification_runner(runner_fixture.identity.clone(), &runner_store)?;
    let runner_artifacts = runner_fixture.borrowed_artifacts();
    let verified_runner = verify_certification_runner_components(
        approved,
        &runner_fixture.descriptors,
        &runner_artifacts,
        CertificationRunnerComponentVerificationLimits::new(1024, 1024, 16 * 1024)?,
    )?;
    let certification = certification_fixture()?;
    let pending = begin_local_certification_run(
        verified_runner,
        certification.report_ref.clone(),
        Duration::from_secs(30),
    )?;
    let policy = LocalCertificationPolicy::new(
        certification.target.clone(),
        certification.profile_digest,
        certification.evidence_digest,
        CertificationClass::SmokeVerified,
        CertificationPolicyRevisionDigest::new(digest(0xb1)),
    )?;
    let certification_store = LocalCertificationPolicyStore::new(policy);
    let artifacts = BTreeMap::from([(certification.report_ref.clone(), REPORT_BYTES)]);
    let certified = assign_local_certification(
        verify_certification_artifacts(
            certification.structural,
            &artifacts,
            CertificationArtifactVerificationLimits::new(1024, 1024)?,
        )?,
        &certification_store,
    )?;
    let prepared = prepare_attested_local_certification_publication(pending, certified)?;
    runner_store.revoke(CertificationRunnerPolicyRevocationDigest::new(digest(0xb2)))?;
    assert!(matches!(
        publish_attested_local_certification(
            prepared,
            &LocalAttestedCertificationPublicationStore::new(8)?,
        ),
        Err(AttestedCertificationPublicationError::RunnerPolicy(_))
    ));

    let runner_fixture = RunnerFixture::new()?;
    let runner_policy = LocalCertificationRunnerPolicy::new(
        runner_fixture.identity.canonical_document_digest()?,
        CertificationRunnerPolicyRevisionDigest::new(digest(0xc0)),
    );
    let runner_store = LocalCertificationRunnerPolicyStore::new(runner_policy);
    let approved =
        approve_local_certification_runner(runner_fixture.identity.clone(), &runner_store)?;
    let runner_artifacts = runner_fixture.borrowed_artifacts();
    let verified_runner = verify_certification_runner_components(
        approved,
        &runner_fixture.descriptors,
        &runner_artifacts,
        CertificationRunnerComponentVerificationLimits::new(1024, 1024, 16 * 1024)?,
    )?;
    let certification = certification_fixture()?;
    let pending = begin_local_certification_run(
        verified_runner,
        certification.report_ref.clone(),
        Duration::from_secs(30),
    )?;
    let policy = LocalCertificationPolicy::new(
        certification.target,
        certification.profile_digest,
        certification.evidence_digest,
        CertificationClass::SmokeVerified,
        CertificationPolicyRevisionDigest::new(digest(0xc1)),
    )?;
    let certification_store = LocalCertificationPolicyStore::new(policy);
    let artifacts = BTreeMap::from([(certification.report_ref.clone(), REPORT_BYTES)]);
    let certified = assign_local_certification(
        verify_certification_artifacts(
            certification.structural,
            &artifacts,
            CertificationArtifactVerificationLimits::new(1024, 1024)?,
        )?,
        &certification_store,
    )?;
    let prepared = prepare_attested_local_certification_publication(pending, certified)?;
    certification_store.revoke(CertificationPolicyRevocationDigest::new(digest(0xc2)))?;
    assert!(matches!(
        publish_attested_local_certification(
            prepared,
            &LocalAttestedCertificationPublicationStore::new(8)?,
        ),
        Err(AttestedCertificationPublicationError::CertificationPolicy(
            _
        ))
    ));
    Ok(())
}

#[test]
fn durable_ledger_reopens_from_an_independently_pinned_head_and_appends_a_fresh_run()
-> Result<(), Box<dyn std::error::Error>> {
    let first = attested_publication(0xd0, 0xd1)?;
    let root_parent = tempdir()?;
    let root = root_parent.path().join("ledger");
    let ledger = LocalCertificationLedger::create(&root, control_policy(&first)?, &first)?;
    let genesis_head = ledger.head_digest()?;
    assert_eq!(ledger.record_count()?, 1);

    let reopened = LocalCertificationLedger::open(&root, genesis_head)?;
    let second = attested_publication(0xd0, 0xd1)?;
    let appended = reopened.append_publication(&second)?;
    assert_eq!(appended.sequence(), 2);
    assert_eq!(reopened.record_count()?, 2);
    assert_eq!(reopened.head_digest()?, appended.record_digest());

    let reopened_again = LocalCertificationLedger::open(&root, appended.record_digest())?;
    assert_eq!(reopened_again.record_count()?, 2);
    assert!(matches!(
        reopened_again.append_publication(&second),
        Err(LocalCertificationLedgerError::FreshnessChallengeReplayed)
    ));
    assert!(matches!(
        LocalCertificationLedger::open(&root, genesis_head),
        Err(LocalCertificationLedgerError::HeadMismatch { .. })
    ));
    Ok(())
}

#[test]
fn durable_ledger_requires_exact_next_generations_before_replacement_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let first = attested_publication_at_generations(0xd2, 1, 0xd3, 1)?;
    let second = attested_publication_at_generations(0xd2, 2, 0xd3, 2)?;
    let parent = tempdir()?;
    let root = parent.path().join("ledger");
    let ledger = LocalCertificationLedger::create(&root, control_policy(&first)?, &first)?;

    let replacement = control_policy(&second)?;
    let replacement_receipt = ledger.replace_policy(replacement.clone())?;
    assert_eq!(replacement_receipt.sequence(), 2);
    let publication_receipt = ledger.append_publication(&second)?;
    assert_eq!(publication_receipt.sequence(), 3);
    assert!(matches!(
        ledger.replace_policy(replacement),
        Err(LocalCertificationLedgerError::NonMonotonicPolicyGeneration { .. })
    ));
    assert_eq!(
        LocalCertificationLedger::open(&root, publication_receipt.record_digest())?
            .record_count()?,
        3
    );
    Ok(())
}

#[test]
fn durable_ledger_rejects_noncanonical_corrupt_gapped_and_symbolic_link_state()
-> Result<(), Box<dyn std::error::Error>> {
    let publication = attested_publication(0xe0, 0xe1)?;
    let parent = tempdir()?;

    let noncanonical = parent.path().join("noncanonical");
    let ledger = LocalCertificationLedger::create(
        &noncanonical,
        control_policy(&publication)?,
        &publication,
    )?;
    let head = ledger.head_digest()?;
    let record_path = noncanonical.join("00000000000000000001.json");
    let mut bytes = fs::read(&record_path)?;
    bytes.push(b'\n');
    fs::write(&record_path, bytes)?;
    assert!(matches!(
        LocalCertificationLedger::open(&noncanonical, head),
        Err(LocalCertificationLedgerError::NonCanonicalRecord { sequence: 1 })
    ));

    let gapped = parent.path().join("gapped");
    let ledger =
        LocalCertificationLedger::create(&gapped, control_policy(&publication)?, &publication)?;
    let head = ledger.head_digest()?;
    fs::rename(
        gapped.join("00000000000000000001.json"),
        gapped.join("00000000000000000002.json"),
    )?;
    assert!(matches!(
        LocalCertificationLedger::open(&gapped, head),
        Err(LocalCertificationLedgerError::SequenceGap {
            expected: 1,
            actual: 2
        })
    ));

    let corrupt = parent.path().join("corrupt");
    let ledger =
        LocalCertificationLedger::create(&corrupt, control_policy(&publication)?, &publication)?;
    let head = ledger.head_digest()?;
    fs::write(corrupt.join("00000000000000000001.json"), b"{not-json")?;
    assert!(matches!(
        LocalCertificationLedger::open(&corrupt, head),
        Err(LocalCertificationLedgerError::InvalidRecord { sequence: 1, .. })
    ));

    #[cfg(unix)]
    {
        let symbolic = parent.path().join("symbolic");
        let ledger = LocalCertificationLedger::create(
            &symbolic,
            control_policy(&publication)?,
            &publication,
        )?;
        let head = ledger.head_digest()?;
        std::os::unix::fs::symlink(
            symbolic.join("00000000000000000001.json"),
            symbolic.join("00000000000000000002.json"),
        )?;
        assert!(matches!(
            LocalCertificationLedger::open(&symbolic, head),
            Err(LocalCertificationLedgerError::UnsafeLedgerEntry { .. })
        ));
    }
    #[cfg(windows)]
    {
        let junction_target = parent.path().join("junction-target");
        let ledger = LocalCertificationLedger::create(
            &junction_target,
            control_policy(&publication)?,
            &publication,
        )?;
        let head = ledger.head_digest()?;
        let junction_root = parent.path().join("junction-root");
        create_junction(&junction_root, &junction_target)?;
        assert!(matches!(
            LocalCertificationLedger::open(&junction_root, head),
            Err(LocalCertificationLedgerError::UnsafeLedgerRoot { .. })
        ));
    }
    Ok(())
}

#[test]
fn durable_ledger_fails_closed_on_revocation_replay_and_stale_concurrent_writers()
-> Result<(), Box<dyn std::error::Error>> {
    let first = attested_publication(0xf0, 0xf1)?;
    let second = attested_publication(0xf0, 0xf1)?;
    let third = attested_publication(0xf0, 0xf1)?;
    let parent = tempdir()?;
    let root = parent.path().join("ledger");
    let ledger = LocalCertificationLedger::create(&root, control_policy(&first)?, &first)?;
    let original_head = ledger.head_digest()?;
    let stale = LocalCertificationLedger::open(&root, original_head)?;
    ledger.append_publication(&second)?;
    assert!(matches!(
        stale.append_publication(&third),
        Err(LocalCertificationLedgerError::StaleWriter { .. }
            | LocalCertificationLedgerError::RecordAlreadyExists { sequence: 2 })
    ));

    let revoked_root = parent.path().join("revoked");
    let revoked = LocalCertificationLedger::create(&revoked_root, control_policy(&first)?, &first)?;
    revoked.revoke_runner(CertificationRunnerPolicyRevocationDigest::new(digest(0xf2)))?;
    assert!(matches!(
        revoked.append_publication(&second),
        Err(LocalCertificationLedgerError::RunnerPolicyRevoked)
    ));
    Ok(())
}

fn attested_publication(
    runner_policy_tag: u8,
    certification_policy_tag: u8,
) -> Result<AttestedLocalCertificationPublication, Box<dyn std::error::Error>> {
    attested_publication_at_generations(runner_policy_tag, 1, certification_policy_tag, 1)
}

fn attested_publication_at_generations(
    runner_policy_tag: u8,
    runner_generation: u64,
    certification_policy_tag: u8,
    certification_generation: u64,
) -> Result<AttestedLocalCertificationPublication, Box<dyn std::error::Error>> {
    if runner_generation == 0 || certification_generation == 0 {
        return Err("test policy generations must be nonzero".into());
    }
    let runner_fixture = RunnerFixture::new()?;
    let runner_policy = LocalCertificationRunnerPolicy::new(
        runner_fixture.identity.canonical_document_digest()?,
        CertificationRunnerPolicyRevisionDigest::new(digest(runner_policy_tag)),
    );
    let runner_store = LocalCertificationRunnerPolicyStore::new(runner_policy.clone());
    for _ in 1..runner_generation {
        runner_store.replace_policy(runner_policy.clone())?;
    }
    let approved =
        approve_local_certification_runner(runner_fixture.identity.clone(), &runner_store)?;
    let runner_artifacts = runner_fixture.borrowed_artifacts();
    let runner = verify_certification_runner_components(
        approved,
        &runner_fixture.descriptors,
        &runner_artifacts,
        CertificationRunnerComponentVerificationLimits::new(1024, 1024, 16 * 1024)?,
    )?;
    let certification = certification_fixture()?;
    let pending = begin_local_certification_run(
        runner,
        certification.report_ref.clone(),
        Duration::from_secs(30),
    )?;
    let policy = LocalCertificationPolicy::new(
        certification.target.clone(),
        certification.profile_digest,
        certification.evidence_digest,
        CertificationClass::SmokeVerified,
        CertificationPolicyRevisionDigest::new(digest(certification_policy_tag)),
    )?;
    let store = LocalCertificationPolicyStore::new(policy.clone());
    for _ in 1..certification_generation {
        store.replace_policy(policy.clone())?;
    }
    let artifacts = BTreeMap::from([(certification.report_ref, REPORT_BYTES)]);
    let certified = assign_local_certification(
        verify_certification_artifacts(
            certification.structural,
            &artifacts,
            CertificationArtifactVerificationLimits::new(1024, 1024)?,
        )?,
        &store,
    )?;
    Ok(publish_attested_local_certification(
        prepare_attested_local_certification_publication(pending, certified)?,
        &LocalAttestedCertificationPublicationStore::new(8)?,
    )?)
}

fn control_policy(
    publication: &AttestedLocalCertificationPublication,
) -> Result<CertificationControlPolicy, weregopher_domain::CertificationRunAttestationError> {
    let attestation = publication.attestation();
    let result = attestation.result();
    CertificationControlPolicy::new(
        attestation.runner().clone(),
        result.semantic_report().clone(),
        result.target().clone(),
        result.profile_digest(),
        result.evidence_digest(),
        result.artifact_set_digest(),
        result.class(),
        result.policy_revision_digest(),
        result.policy_generation(),
    )
}

struct RunnerFixture {
    identity: CertificationRunnerIdentity,
    expected_identity_digest: weregopher_domain::CertificationRunnerIdentityDigest,
    descriptors: BTreeMap<CertificationRunnerComponentRole, CertificationRunnerComponentDescriptor>,
    artifacts: BTreeMap<
        CertificationRunnerComponentRole,
        BTreeMap<CertificationRunnerArtifactName, Vec<u8>>,
    >,
}

impl RunnerFixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut descriptors = BTreeMap::new();
        let mut artifacts = BTreeMap::new();
        let mut descriptor_digests = BTreeMap::new();
        for (index, role) in runner_roles().into_iter().enumerate() {
            let tag = u8::try_from(index + 1)?;
            let bytes = vec![tag; 3];
            let name = CertificationRunnerArtifactName::new(format!("role/{tag:02}.bin"))?;
            let artifact = CertificationRunnerComponentArtifact::new(
                name.clone(),
                sha256(&bytes),
                u64::try_from(bytes.len())?,
            )?;
            let descriptor = CertificationRunnerComponentDescriptor::new(
                role,
                CertificationRunnerComponentId::new(format!("weregopher.test.{tag:02}"))?,
                CertificationRunnerComponentVersion::new(format!("1.0.{tag}"))?,
                CertificationRunnerComponentProvenanceDigest::new(digest(tag)),
                BTreeSet::from([artifact]),
            )?;
            descriptor_digests.insert(role, *descriptor.canonical_document_digest()?.as_sha256());
            descriptors.insert(role, descriptor);
            artifacts.insert(role, BTreeMap::from([(name, bytes)]));
        }
        let identity = CertificationRunnerIdentity::new(
            CertificationRunnerEnvironmentIdentity::windows_x86_64(
                CertificationRunnerImageDigest::new(descriptor_digest(
                    &descriptor_digests,
                    CertificationRunnerComponentRole::RunnerImage,
                )?),
                CertificationHostImageDigest::new(descriptor_digest(
                    &descriptor_digests,
                    CertificationRunnerComponentRole::HostImage,
                )?),
                CertificationHostPatchSetDigest::new(descriptor_digest(
                    &descriptor_digests,
                    CertificationRunnerComponentRole::HostPatchSet,
                )?),
                CertificationElectronRuntimeDigest::new(descriptor_digest(
                    &descriptor_digests,
                    CertificationRunnerComponentRole::ElectronRuntime,
                )?),
                CertificationLanguageRuntimeSetDigest::new(descriptor_digest(
                    &descriptor_digests,
                    CertificationRunnerComponentRole::LanguageRuntimeSet,
                )?),
            ),
            CertificationRunnerToolingIdentity::new(
                CertificationToolchainSetDigest::new(descriptor_digest(
                    &descriptor_digests,
                    CertificationRunnerComponentRole::ToolchainSet,
                )?),
                CertificationHostAgentDigest::new(descriptor_digest(
                    &descriptor_digests,
                    CertificationRunnerComponentRole::HostAgent,
                )?),
                CertificationVerifierDigest::new(descriptor_digest(
                    &descriptor_digests,
                    CertificationRunnerComponentRole::Verifier,
                )?),
                CertificationProbeAssetSetDigest::new(descriptor_digest(
                    &descriptor_digests,
                    CertificationRunnerComponentRole::ProbeAssetSet,
                )?),
            ),
            CertificationRunnerProvenanceIdentity::new(
                CertificationSourceRevisionDigest::new(descriptor_digest(
                    &descriptor_digests,
                    CertificationRunnerComponentRole::SourceRevision,
                )?),
                CertificationExceptionProvenanceDigest::new(descriptor_digest(
                    &descriptor_digests,
                    CertificationRunnerComponentRole::ExceptionProvenance,
                )?),
            ),
        );
        let expected_identity_digest = identity.canonical_document_digest()?;
        Ok(Self {
            identity,
            expected_identity_digest,
            descriptors,
            artifacts,
        })
    }

    fn borrowed_artifacts(
        &self,
    ) -> BTreeMap<CertificationRunnerComponentRole, BTreeMap<CertificationRunnerArtifactName, &[u8]>>
    {
        self.artifacts
            .iter()
            .map(|(role, artifacts)| {
                (
                    *role,
                    artifacts
                        .iter()
                        .map(|(name, bytes)| (name.clone(), bytes.as_slice()))
                        .collect(),
                )
            })
            .collect()
    }
}

struct CertificationFixture {
    structural: weregopher_domain::StructurallyValidatedCertificationEvidence,
    report_ref: CertificationArtifactRef,
    target: CertificationTarget,
    profile_digest: weregopher_domain::CertificationProfileDigest,
    evidence_digest: weregopher_domain::CertificationEvidenceDigest,
}

fn certification_fixture() -> Result<CertificationFixture, Box<dyn std::error::Error>> {
    let profile = CertificationProfile::new(
        CertificationProfileClass::SmokeVerified,
        profile_checks(CertificationExpectedStatus::Passed),
        BTreeSet::<FeatureId>::new(),
    )?;
    let profile_digest = profile.canonical_document_digest()?;
    let report_ref = CertificationArtifactRef::new(
        CertificationArtifactKind::RuntimeProbe,
        CertificationArtifactDigest::new(sha256(REPORT_BYTES)),
    );
    let assessment =
        CertificationCheckAssessment::new(CertificationCheckStatus::Passed, [report_ref.clone()])?;
    let target = target();
    let evidence = CertificationEvidence::new(
        target.clone(),
        profile_digest,
        checks(assessment),
        BTreeMap::new(),
    )?;
    let evidence_digest = evidence.canonical_document_digest()?;
    Ok(CertificationFixture {
        structural: evidence.validate_against_profile(profile)?,
        report_ref,
        target,
        profile_digest,
        evidence_digest,
    })
}

fn descriptor_digest(
    digests: &BTreeMap<CertificationRunnerComponentRole, Sha256Digest>,
    role: CertificationRunnerComponentRole,
) -> Result<Sha256Digest, Box<dyn std::error::Error>> {
    digests
        .get(&role)
        .copied()
        .ok_or_else(|| format!("missing descriptor digest for {role:?}").into())
}

const fn runner_roles() -> [CertificationRunnerComponentRole; 11] {
    [
        CertificationRunnerComponentRole::RunnerImage,
        CertificationRunnerComponentRole::HostImage,
        CertificationRunnerComponentRole::HostPatchSet,
        CertificationRunnerComponentRole::ElectronRuntime,
        CertificationRunnerComponentRole::LanguageRuntimeSet,
        CertificationRunnerComponentRole::ToolchainSet,
        CertificationRunnerComponentRole::HostAgent,
        CertificationRunnerComponentRole::Verifier,
        CertificationRunnerComponentRole::ProbeAssetSet,
        CertificationRunnerComponentRole::SourceRevision,
        CertificationRunnerComponentRole::ExceptionProvenance,
    ]
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

const fn profile_checks(expected: CertificationExpectedStatus) -> CertificationProfileChecks {
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

const fn target() -> CertificationTarget {
    CertificationTarget::new(
        CompatibilityAnalysisDigest::new(digest(0x10)),
        ExecutionContractDigest::new(digest(0x11)),
        ExecutionResolutionEvidenceDigest::new(digest(0x12)),
        ExecutionArtifactSourceDigest::new(digest(0x13)),
        ExecutableDigest::new(digest(0x14)),
    )
}

fn sha256(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

const fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

#[cfg(windows)]
fn create_junction(
    link: &std::path::Path,
    target: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let status = std::process::Command::new("cmd")
        .args(["/D", "/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err("mklink /J failed".into())
    }
}
