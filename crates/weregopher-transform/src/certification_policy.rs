//! Generation-aware local trust resolution for exact certification artifacts.
//!
//! This module is the first boundary that may assign a trusted [`CertificationClass`]. It consumes
//! exact artifact-byte verification, matches every policy pin, and binds the result to a mutable
//! local-policy generation. The result does not grant publication, transformation, or execution
//! authority.

use std::{
    fmt,
    sync::{Arc, RwLock, Weak},
};

use thiserror::Error;
use weregopher_domain::{
    CertificationClass, CertificationEvidenceDigest, CertificationEvidenceDisposition,
    CertificationProfileClass, CertificationProfileDigest, CertificationTarget, Sha256Digest,
};

use crate::VerifiedCertificationArtifacts;

/// Role-specific identity of one local certification-policy revision.
///
/// Revision and revocation-evidence identities cannot be substituted:
///
/// ```compile_fail
/// use weregopher_domain::Sha256Digest;
/// use weregopher_transform::{
///     CertificationPolicyRevisionDigest, CertificationPolicyRevocationDigest,
/// };
///
/// let revision = CertificationPolicyRevisionDigest::new(Sha256Digest::from_bytes([0; 32]));
/// let revocation: CertificationPolicyRevocationDigest = revision;
/// # let _ = revocation;
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CertificationPolicyRevisionDigest(Sha256Digest);

impl CertificationPolicyRevisionDigest {
    /// Creates a policy-revision identity from a canonical SHA-256 digest.
    #[must_use]
    pub const fn new(digest: Sha256Digest) -> Self {
        Self(digest)
    }

    /// Returns the wire-compatible SHA-256 value at a hashing or transport boundary.
    #[must_use]
    pub const fn as_sha256(&self) -> &Sha256Digest {
        &self.0
    }
}

/// Role-specific identity of evidence that revokes a local certification policy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CertificationPolicyRevocationDigest(Sha256Digest);

impl CertificationPolicyRevocationDigest {
    /// Creates a revocation-evidence identity from a canonical SHA-256 digest.
    #[must_use]
    pub const fn new(digest: Sha256Digest) -> Self {
        Self(digest)
    }

    /// Returns the wire-compatible SHA-256 value at a hashing or transport boundary.
    #[must_use]
    pub const fn as_sha256(&self) -> &Sha256Digest {
        &self.0
    }
}

/// Exact immutable identities and trusted class approved by one local policy revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalCertificationPolicy {
    target: CertificationTarget,
    profile_digest: CertificationProfileDigest,
    evidence_digest: CertificationEvidenceDigest,
    approved_class: CertificationClass,
    revision_digest: CertificationPolicyRevisionDigest,
}

impl LocalCertificationPolicy {
    /// Constructs one exact local certification trust decision.
    ///
    /// `blocked` is represented by revocation and `provisional` does not satisfy this exact verified
    /// evidence boundary, so neither can be assigned by a current policy.
    ///
    /// # Errors
    ///
    /// Returns [`CertificationPolicyError::UnassignableClass`] for `blocked` or `provisional`.
    pub const fn new(
        target: CertificationTarget,
        profile_digest: CertificationProfileDigest,
        evidence_digest: CertificationEvidenceDigest,
        approved_class: CertificationClass,
        revision_digest: CertificationPolicyRevisionDigest,
    ) -> Result<Self, CertificationPolicyError> {
        if matches!(
            approved_class,
            CertificationClass::Blocked | CertificationClass::Provisional
        ) {
            return Err(CertificationPolicyError::UnassignableClass);
        }
        Ok(Self {
            target,
            profile_digest,
            evidence_digest,
            approved_class,
            revision_digest,
        })
    }

    /// Returns the exact target approved by this policy.
    #[must_use]
    pub const fn target(&self) -> &CertificationTarget {
        &self.target
    }

    /// Returns the exact profile identity approved by this policy.
    #[must_use]
    pub const fn profile_digest(&self) -> CertificationProfileDigest {
        self.profile_digest
    }

    /// Returns the exact evidence-document identity approved by this policy.
    #[must_use]
    pub const fn evidence_digest(&self) -> CertificationEvidenceDigest {
        self.evidence_digest
    }

    /// Returns the trusted class explicitly approved by this policy.
    #[must_use]
    pub const fn approved_class(&self) -> CertificationClass {
        self.approved_class
    }

    /// Returns this policy revision's role-specific identity.
    #[must_use]
    pub const fn revision_digest(&self) -> CertificationPolicyRevisionDigest {
        self.revision_digest
    }
}

#[derive(Clone, Debug)]
struct CertificationPolicyState {
    generation: u64,
    policy: LocalCertificationPolicy,
    revocation_evidence_digest: Option<CertificationPolicyRevocationDigest>,
}

/// Mutable local certification trust root.
///
/// Replacement and revocation monotonically advance the generation and invalidate all older local
/// certification decisions.
#[derive(Clone)]
pub struct LocalCertificationPolicyStore {
    inner: Arc<RwLock<CertificationPolicyState>>,
}

impl fmt::Debug for LocalCertificationPolicyStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalCertificationPolicyStore")
            .finish_non_exhaustive()
    }
}

impl LocalCertificationPolicyStore {
    /// Creates a current, non-revoked policy generation.
    #[must_use]
    pub fn new(policy: LocalCertificationPolicy) -> Self {
        Self {
            inner: Arc::new(RwLock::new(CertificationPolicyState {
                generation: 1,
                policy,
                revocation_evidence_digest: None,
            })),
        }
    }

    /// Atomically installs a replacement policy and invalidates every older decision.
    ///
    /// # Errors
    ///
    /// Returns a synchronization error or generation exhaustion. On exhaustion the previous policy
    /// remains current.
    pub fn replace_policy(
        &self,
        policy: LocalCertificationPolicy,
    ) -> Result<(), CertificationPolicyError> {
        let mut state = self
            .inner
            .write()
            .map_err(|_| CertificationPolicyError::PolicyStorePoisoned)?;
        let generation = state
            .generation
            .checked_add(1)
            .ok_or(CertificationPolicyError::PolicyGenerationExhausted)?;
        state.generation = generation;
        state.policy = policy;
        state.revocation_evidence_digest = None;
        Ok(())
    }

    /// Atomically records revocation evidence and invalidates every outstanding decision.
    ///
    /// # Errors
    ///
    /// Returns a synchronization error or generation exhaustion. On exhaustion the previous state
    /// remains current.
    pub fn revoke(
        &self,
        revocation_evidence_digest: CertificationPolicyRevocationDigest,
    ) -> Result<(), CertificationPolicyError> {
        let mut state = self
            .inner
            .write()
            .map_err(|_| CertificationPolicyError::PolicyStorePoisoned)?;
        let generation = state
            .generation
            .checked_add(1)
            .ok_or(CertificationPolicyError::PolicyGenerationExhausted)?;
        state.generation = generation;
        state.revocation_evidence_digest = Some(revocation_evidence_digest);
        Ok(())
    }

    fn snapshot(&self) -> Result<CertificationPolicyState, CertificationPolicyError> {
        self.inner
            .read()
            .map_err(|_| CertificationPolicyError::PolicyStorePoisoned)
            .map(|state| state.clone())
    }
}

/// Opaque generation-bound local certification decision over exact retained artifact bytes.
///
/// The value is deliberately non-serializable and non-cloneable. It retains the exact structural
/// proof and verified artifact-byte map. Its trusted class remains conditional on
/// [`Self::verify_current_policy`], and it does not grant publication, transformation, or execution
/// authority.
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<weregopher_transform::LocallyCertifiedArtifacts<'static, 'static>>();
/// ```
///
/// ```compile_fail
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<weregopher_transform::LocallyCertifiedArtifacts<'static, 'static>>();
/// ```
#[must_use = "a local certification decision remains conditional on current policy"]
pub struct LocallyCertifiedArtifacts<'artifacts, 'bytes> {
    verified_artifacts: VerifiedCertificationArtifacts<'artifacts, 'bytes>,
    policy: LocalCertificationPolicy,
    policy_generation: u64,
    policy_store: Weak<RwLock<CertificationPolicyState>>,
}

impl fmt::Debug for LocallyCertifiedArtifacts<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocallyCertifiedArtifacts")
            .field("class", &self.policy.approved_class)
            .field("target", &self.policy.target)
            .field("profile_digest", &self.policy.profile_digest)
            .field("evidence_digest", &self.policy.evidence_digest)
            .field("policy_revision_digest", &self.policy.revision_digest)
            .field("policy_generation", &self.policy_generation)
            .finish_non_exhaustive()
    }
}

impl<'artifacts, 'bytes> LocallyCertifiedArtifacts<'artifacts, 'bytes> {
    /// Returns the trusted class only after checking that the issuing policy remains current.
    ///
    /// This is still a point-in-time classification, not an authorization capability. Any
    /// policy-controlled effect must retain an appropriate policy guard through its own commit point;
    /// local publication does so by consuming this value into a prepared plan.
    ///
    /// # Errors
    ///
    /// Returns a currentness error if the store was dropped, replaced, revoked, or poisoned.
    pub fn current_class(&self) -> Result<CertificationClass, CertificationPolicyError> {
        self.verify_current_policy()?;
        Ok(self.policy.approved_class)
    }

    /// Returns the exact target bound by the local policy.
    #[must_use]
    pub const fn target(&self) -> &CertificationTarget {
        &self.policy.target
    }

    /// Returns the exact profile identity bound by the local policy.
    #[must_use]
    pub const fn profile_digest(&self) -> CertificationProfileDigest {
        self.policy.profile_digest
    }

    /// Returns the exact evidence-document identity bound by the local policy.
    #[must_use]
    pub const fn evidence_digest(&self) -> CertificationEvidenceDigest {
        self.policy.evidence_digest
    }

    /// Returns the issuing local policy revision identity.
    #[must_use]
    pub const fn policy_revision_digest(&self) -> CertificationPolicyRevisionDigest {
        self.policy.revision_digest
    }

    /// Returns the issuing policy generation.
    #[must_use]
    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    /// Returns the retained exact artifact verification proof.
    pub const fn verified_artifacts(&self) -> &VerifiedCertificationArtifacts<'artifacts, 'bytes> {
        &self.verified_artifacts
    }

    /// Fails closed unless the issuing policy remains current and non-revoked.
    ///
    /// This is a point-in-time check. Any policy-controlled effect must hold an appropriate policy
    /// guard through its own commit point rather than treating this method as a capability.
    ///
    /// # Errors
    ///
    /// Returns a currentness error if the store was dropped, replaced, revoked, or poisoned.
    pub fn verify_current_policy(&self) -> Result<(), CertificationPolicyError> {
        self.commit_while_policy_current(|| ())
    }

    pub(crate) fn commit_while_policy_current<T>(
        &self,
        commit: impl FnOnce() -> T,
    ) -> Result<T, CertificationPolicyError> {
        let store = self
            .policy_store
            .upgrade()
            .ok_or(CertificationPolicyError::PolicyStoreUnavailable)?;
        commit_if_policy_current(&store, &self.policy, self.policy_generation, commit)
    }
}

fn commit_if_policy_current<T>(
    store: &RwLock<CertificationPolicyState>,
    expected_policy: &LocalCertificationPolicy,
    expected_generation: u64,
    commit: impl FnOnce() -> T,
) -> Result<T, CertificationPolicyError> {
    let state = store
        .read()
        .map_err(|_| CertificationPolicyError::PolicyStorePoisoned)?;
    if state.revocation_evidence_digest.is_some() {
        return Err(CertificationPolicyError::PolicyRevoked);
    }
    if state.generation != expected_generation || state.policy != *expected_policy {
        return Err(CertificationPolicyError::PolicyChanged);
    }
    Ok(commit())
}

/// Assigns a trusted local class only when every exact policy pin matches verified evidence bytes.
///
/// This consumes the artifact-verification proof so the resulting decision retains the same exact
/// structural proof and borrowed byte map. Profile intent is converted to the shared trusted class
/// vocabulary only inside this policy-authenticated boundary.
///
/// # Errors
///
/// Returns [`CertificationPolicyError`] for revoked or changed policy, non-complete evidence, an
/// unavailable canonical identity, or any target, profile, evidence, or class mismatch.
pub fn assign_local_certification<'artifacts, 'bytes>(
    verified_artifacts: VerifiedCertificationArtifacts<'artifacts, 'bytes>,
    policy_store: &LocalCertificationPolicyStore,
) -> Result<LocallyCertifiedArtifacts<'artifacts, 'bytes>, CertificationPolicyError> {
    let snapshot = policy_store.snapshot()?;
    if snapshot.revocation_evidence_digest.is_some() {
        return Err(CertificationPolicyError::PolicyRevoked);
    }

    let structural = verified_artifacts.structural_validation();
    let profile = structural.profile();
    let evidence = structural.evidence();
    if evidence.disposition() != CertificationEvidenceDisposition::Complete {
        return Err(CertificationPolicyError::EvidenceNotComplete);
    }

    let profile_digest = profile
        .canonical_document_digest()
        .map_err(CertificationPolicyError::ProfileDigestUnavailable)?;
    if profile_digest != snapshot.policy.profile_digest {
        return Err(CertificationPolicyError::ProfileDigestMismatch);
    }
    if evidence.profile_digest() != &profile_digest {
        return Err(CertificationPolicyError::ProfileDigestMismatch);
    }
    if evidence.target() != &snapshot.policy.target {
        return Err(CertificationPolicyError::TargetMismatch);
    }

    let evidence_digest = evidence
        .canonical_document_digest()
        .map_err(CertificationPolicyError::EvidenceDigestUnavailable)?;
    if evidence_digest != snapshot.policy.evidence_digest {
        return Err(CertificationPolicyError::EvidenceDigestMismatch);
    }

    let declared_class = trusted_class_for_profile(profile.class());
    if declared_class != snapshot.policy.approved_class {
        return Err(CertificationPolicyError::ClassMismatch);
    }

    let certified = LocallyCertifiedArtifacts {
        verified_artifacts,
        policy: snapshot.policy,
        policy_generation: snapshot.generation,
        policy_store: Arc::downgrade(&policy_store.inner),
    };
    certified.verify_current_policy()?;
    Ok(certified)
}

const fn trusted_class_for_profile(profile_class: CertificationProfileClass) -> CertificationClass {
    match profile_class {
        CertificationProfileClass::StructuralVerified => CertificationClass::StructuralVerified,
        CertificationProfileClass::SmokeVerified => CertificationClass::SmokeVerified,
        CertificationProfileClass::ContractVerified => CertificationClass::ContractVerified,
        CertificationProfileClass::ExactCertified => CertificationClass::ExactCertified,
    }
}

/// Failure to construct, resolve, or recheck a local certification trust decision.
#[derive(Debug, Error)]
pub enum CertificationPolicyError {
    /// `blocked` and `provisional` cannot be assigned from exact verified evidence at this boundary.
    #[error("local certification policy class is not assignable from exact verified evidence")]
    UnassignableClass,
    /// The policy store synchronization primitive was poisoned.
    #[error("local certification policy store is poisoned")]
    PolicyStorePoisoned,
    /// The monotonic policy generation cannot advance safely.
    #[error("local certification policy generation is exhausted")]
    PolicyGenerationExhausted,
    /// The issuing policy store no longer exists.
    #[error("local certification policy store is no longer available")]
    PolicyStoreUnavailable,
    /// Current policy revokes the certification decision.
    #[error("local certification policy is revoked")]
    PolicyRevoked,
    /// Current policy differs from the issuing generation.
    #[error("local certification policy changed after class assignment")]
    PolicyChanged,
    /// Structurally validated evidence was not complete.
    #[error("certification evidence is not complete")]
    EvidenceNotComplete,
    /// Canonical profile identity could not be produced.
    #[error("canonical certification profile identity is unavailable")]
    ProfileDigestUnavailable(#[source] serde_json::Error),
    /// Canonical evidence identity could not be produced.
    #[error("canonical certification evidence identity is unavailable")]
    EvidenceDigestUnavailable(#[source] serde_json::Error),
    /// Exact target did not match local policy.
    #[error("certification target does not match local policy")]
    TargetMismatch,
    /// Exact profile identity did not match local policy.
    #[error("certification profile identity does not match local policy")]
    ProfileDigestMismatch,
    /// Exact evidence-document identity did not match local policy.
    #[error("certification evidence identity does not match local policy")]
    EvidenceDigestMismatch,
    /// The profile's declared class did not match the class explicitly approved by local policy.
    #[error("certification profile class does not match local policy")]
    ClassMismatch,
}

#[cfg(test)]
mod tests {
    use weregopher_domain::{
        CertificationClass, CertificationEvidenceDigest, CertificationProfileDigest,
        CertificationTarget, CompatibilityAnalysisDigest, ExecutableDigest,
        ExecutionArtifactSourceDigest, ExecutionContractDigest, ExecutionResolutionEvidenceDigest,
        Sha256Digest,
    };

    use super::{
        CertificationPolicyRevisionDigest, LocalCertificationPolicy, LocalCertificationPolicyStore,
        commit_if_policy_current,
    };

    #[test]
    fn current_policy_guard_is_held_through_the_commit_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        let policy = LocalCertificationPolicy::new(
            CertificationTarget::new(
                CompatibilityAnalysisDigest::new(digest(0x10)),
                ExecutionContractDigest::new(digest(0x11)),
                ExecutionResolutionEvidenceDigest::new(digest(0x12)),
                ExecutionArtifactSourceDigest::new(digest(0x13)),
                ExecutableDigest::new(digest(0x14)),
            ),
            CertificationProfileDigest::new(digest(0x20)),
            CertificationEvidenceDigest::new(digest(0x21)),
            CertificationClass::ContractVerified,
            CertificationPolicyRevisionDigest::new(digest(0x22)),
        )?;
        let store = LocalCertificationPolicyStore::new(policy.clone());

        let write_was_blocked = commit_if_policy_current(&store.inner, &policy, 1, || {
            store.inner.try_write().is_err()
        })?;

        assert!(write_was_blocked);
        Ok(())
    }

    const fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }
}
