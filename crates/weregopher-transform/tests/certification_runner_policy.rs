//! Behavior tests for generation-current local approval of exact certification-runner identities.

use weregopher_domain::{
    CertificationElectronRuntimeDigest, CertificationExceptionProvenanceDigest,
    CertificationHostAgentDigest, CertificationHostImageDigest, CertificationHostPatchSetDigest,
    CertificationLanguageRuntimeSetDigest, CertificationProbeAssetSetDigest,
    CertificationRunnerEnvironmentIdentity, CertificationRunnerIdentity,
    CertificationRunnerImageDigest, CertificationRunnerProvenanceIdentity,
    CertificationRunnerToolingIdentity, CertificationSourceRevisionDigest,
    CertificationToolchainSetDigest, CertificationVerifierDigest, Sha256Digest,
};
use weregopher_transform::{
    CertificationRunnerPolicyError, CertificationRunnerPolicyRevisionDigest,
    CertificationRunnerPolicyRevocationDigest, LocalCertificationRunnerPolicy,
    LocalCertificationRunnerPolicyStore, approve_local_certification_runner,
};

#[test]
fn exact_runner_identity_receives_generation_current_local_approval()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = runner_identity(0x10);
    let expected_identity_digest = identity.canonical_document_digest()?;
    let policy = LocalCertificationRunnerPolicy::new(
        expected_identity_digest,
        CertificationRunnerPolicyRevisionDigest::new(digest(0x50)),
    );
    let store = LocalCertificationRunnerPolicyStore::new(policy);

    let approved = approve_local_certification_runner(identity, &store)?;

    approved.verify_current_policy()?;
    assert_eq!(approved.identity_digest(), expected_identity_digest);
    assert_eq!(approved.policy_generation(), 1);
    assert_eq!(
        approved.policy_revision_digest(),
        CertificationRunnerPolicyRevisionDigest::new(digest(0x50))
    );
    assert_eq!(
        approved.identity().canonical_document_digest()?,
        expected_identity_digest
    );
    let debug = format!("{approved:?}");
    assert!(debug.contains("identity_digest"));
    assert!(!debug.contains("runner_image_digest"));
    Ok(())
}

#[test]
fn runner_approval_requires_the_exact_policy_pinned_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let policy = LocalCertificationRunnerPolicy::new(
        runner_identity(0x20).canonical_document_digest()?,
        CertificationRunnerPolicyRevisionDigest::new(digest(0x51)),
    );
    let store = LocalCertificationRunnerPolicyStore::new(policy);

    assert!(matches!(
        approve_local_certification_runner(runner_identity(0x30), &store),
        Err(CertificationRunnerPolicyError::IdentityDigestMismatch)
    ));
    Ok(())
}

#[test]
fn runner_approval_fails_closed_after_replacement_revocation_or_store_loss()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = runner_identity(0x40);
    let policy = LocalCertificationRunnerPolicy::new(
        identity.canonical_document_digest()?,
        CertificationRunnerPolicyRevisionDigest::new(digest(0x60)),
    );
    let store = LocalCertificationRunnerPolicyStore::new(policy.clone());
    let approved = approve_local_certification_runner(identity, &store)?;
    store.replace_policy(policy)?;
    assert!(matches!(
        approved.verify_current_policy(),
        Err(CertificationRunnerPolicyError::PolicyChanged)
    ));

    let identity = runner_identity(0x41);
    let policy = LocalCertificationRunnerPolicy::new(
        identity.canonical_document_digest()?,
        CertificationRunnerPolicyRevisionDigest::new(digest(0x61)),
    );
    let store = LocalCertificationRunnerPolicyStore::new(policy);
    let approved = approve_local_certification_runner(identity, &store)?;
    store.revoke(CertificationRunnerPolicyRevocationDigest::new(digest(0x70)))?;
    assert!(matches!(
        approved.verify_current_policy(),
        Err(CertificationRunnerPolicyError::PolicyRevoked)
    ));
    assert!(matches!(
        approve_local_certification_runner(runner_identity(0x41), &store),
        Err(CertificationRunnerPolicyError::PolicyRevoked)
    ));

    let identity = runner_identity(0x42);
    let policy = LocalCertificationRunnerPolicy::new(
        identity.canonical_document_digest()?,
        CertificationRunnerPolicyRevisionDigest::new(digest(0x62)),
    );
    let store = LocalCertificationRunnerPolicyStore::new(policy);
    let approved = approve_local_certification_runner(identity, &store)?;
    drop(store);
    assert!(matches!(
        approved.verify_current_policy(),
        Err(CertificationRunnerPolicyError::PolicyStoreUnavailable)
    ));
    Ok(())
}

fn runner_identity(base: u8) -> CertificationRunnerIdentity {
    CertificationRunnerIdentity::new(
        CertificationRunnerEnvironmentIdentity::windows_x86_64(
            CertificationRunnerImageDigest::new(digest(base)),
            CertificationHostImageDigest::new(digest(base.wrapping_add(1))),
            CertificationHostPatchSetDigest::new(digest(base.wrapping_add(2))),
            CertificationElectronRuntimeDigest::new(digest(base.wrapping_add(3))),
            CertificationLanguageRuntimeSetDigest::new(digest(base.wrapping_add(4))),
        ),
        CertificationRunnerToolingIdentity::new(
            CertificationToolchainSetDigest::new(digest(base.wrapping_add(5))),
            CertificationHostAgentDigest::new(digest(base.wrapping_add(6))),
            CertificationVerifierDigest::new(digest(base.wrapping_add(7))),
            CertificationProbeAssetSetDigest::new(digest(base.wrapping_add(8))),
        ),
        CertificationRunnerProvenanceIdentity::new(
            CertificationSourceRevisionDigest::new(digest(base.wrapping_add(9))),
            CertificationExceptionProvenanceDigest::new(digest(base.wrapping_add(10))),
        ),
    )
}

const fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}
