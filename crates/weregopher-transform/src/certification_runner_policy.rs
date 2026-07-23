//! Generation-aware local approval for exact certification-runner identity manifests.
//!
//! This boundary allows trusted local configuration to approve one exact canonical runner identity.
//! It does not verify the component descriptors named by that manifest, prove that a run occurred,
//! establish freshness, validate semantic reports, assign a certification class, or authorize an
//! effect. Any later effect must recheck currentness through its own commit point.

use std::{
    fmt,
    sync::{Arc, RwLock, Weak},
};

use thiserror::Error;
use weregopher_domain::{
    CertificationRunnerIdentity, CertificationRunnerIdentityDigest, Sha256Digest,
};

/// Role-specific identity of one local runner-policy revision.
///
/// Revision and revocation-evidence identities cannot be substituted:
///
/// ```compile_fail
/// use weregopher_domain::Sha256Digest;
/// use weregopher_transform::{
///     CertificationRunnerPolicyRevisionDigest, CertificationRunnerPolicyRevocationDigest,
/// };
///
/// let revision =
///     CertificationRunnerPolicyRevisionDigest::new(Sha256Digest::from_bytes([0; 32]));
/// let revocation: CertificationRunnerPolicyRevocationDigest = revision;
/// # let _ = revocation;
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CertificationRunnerPolicyRevisionDigest(Sha256Digest);

impl CertificationRunnerPolicyRevisionDigest {
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

/// Role-specific identity of evidence that revokes a local runner policy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CertificationRunnerPolicyRevocationDigest(Sha256Digest);

impl CertificationRunnerPolicyRevocationDigest {
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

/// Exact certification-runner identity approved by one trusted local policy revision.
///
/// Construction is a trusted in-process configuration operation, not a parser or an authentication
/// result. Approval of the manifest identity does not independently authenticate its component
/// descriptor preimages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalCertificationRunnerPolicy {
    identity_digest: CertificationRunnerIdentityDigest,
    revision_digest: CertificationRunnerPolicyRevisionDigest,
}

impl LocalCertificationRunnerPolicy {
    /// Constructs one exact local runner-identity approval.
    #[must_use]
    pub const fn new(
        identity_digest: CertificationRunnerIdentityDigest,
        revision_digest: CertificationRunnerPolicyRevisionDigest,
    ) -> Self {
        Self {
            identity_digest,
            revision_digest,
        }
    }

    /// Returns the exact canonical runner identity approved by this policy.
    #[must_use]
    pub const fn identity_digest(&self) -> CertificationRunnerIdentityDigest {
        self.identity_digest
    }

    /// Returns this policy revision's role-specific identity.
    #[must_use]
    pub const fn revision_digest(&self) -> CertificationRunnerPolicyRevisionDigest {
        self.revision_digest
    }
}

#[derive(Clone, Debug)]
struct CertificationRunnerPolicyState {
    generation: u64,
    policy: LocalCertificationRunnerPolicy,
    revocation_evidence_digest: Option<CertificationRunnerPolicyRevocationDigest>,
}

/// Mutable local trust root for exact certification-runner identities.
///
/// Replacement and revocation monotonically advance the generation and invalidate all older local
/// approvals, including approvals issued from a byte-equal replacement policy.
#[derive(Clone)]
pub struct LocalCertificationRunnerPolicyStore {
    inner: Arc<RwLock<CertificationRunnerPolicyState>>,
}

impl fmt::Debug for LocalCertificationRunnerPolicyStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalCertificationRunnerPolicyStore")
            .finish_non_exhaustive()
    }
}

impl LocalCertificationRunnerPolicyStore {
    /// Creates a current, non-revoked runner policy at generation one.
    #[must_use]
    pub fn new(policy: LocalCertificationRunnerPolicy) -> Self {
        Self {
            inner: Arc::new(RwLock::new(CertificationRunnerPolicyState {
                generation: 1,
                policy,
                revocation_evidence_digest: None,
            })),
        }
    }

    /// Atomically installs a replacement policy and invalidates every older approval.
    ///
    /// # Errors
    ///
    /// Returns a synchronization error or generation exhaustion. On exhaustion the previous policy
    /// remains current.
    pub fn replace_policy(
        &self,
        policy: LocalCertificationRunnerPolicy,
    ) -> Result<(), CertificationRunnerPolicyError> {
        let mut state = self
            .inner
            .write()
            .map_err(|_| CertificationRunnerPolicyError::PolicyStorePoisoned)?;
        let generation = state
            .generation
            .checked_add(1)
            .ok_or(CertificationRunnerPolicyError::PolicyGenerationExhausted)?;
        state.generation = generation;
        state.policy = policy;
        state.revocation_evidence_digest = None;
        Ok(())
    }

    /// Atomically records revocation evidence and invalidates every outstanding approval.
    ///
    /// # Errors
    ///
    /// Returns a synchronization error or generation exhaustion. On exhaustion the previous state
    /// remains current.
    pub fn revoke(
        &self,
        revocation_evidence_digest: CertificationRunnerPolicyRevocationDigest,
    ) -> Result<(), CertificationRunnerPolicyError> {
        let mut state = self
            .inner
            .write()
            .map_err(|_| CertificationRunnerPolicyError::PolicyStorePoisoned)?;
        let generation = state
            .generation
            .checked_add(1)
            .ok_or(CertificationRunnerPolicyError::PolicyGenerationExhausted)?;
        state.generation = generation;
        state.revocation_evidence_digest = Some(revocation_evidence_digest);
        Ok(())
    }

    fn snapshot(&self) -> Result<CertificationRunnerPolicyState, CertificationRunnerPolicyError> {
        self.inner
            .read()
            .map_err(|_| CertificationRunnerPolicyError::PolicyStorePoisoned)
            .map(|state| state.clone())
    }
}

/// Opaque generation-bound local approval of one exact runner identity manifest.
///
/// The value is deliberately non-serializable and non-cloneable. It retains the exact identity
/// document, but does not prove component-descriptor authenticity, execution, freshness, report
/// meaning, certification class, or effect authority.
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<weregopher_transform::LocallyApprovedCertificationRunner>();
/// ```
///
/// ```compile_fail
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<weregopher_transform::LocallyApprovedCertificationRunner>();
/// ```
#[must_use = "a local runner approval remains conditional on current policy"]
pub struct LocallyApprovedCertificationRunner {
    identity: CertificationRunnerIdentity,
    identity_digest: CertificationRunnerIdentityDigest,
    policy: LocalCertificationRunnerPolicy,
    policy_generation: u64,
    policy_store: Weak<RwLock<CertificationRunnerPolicyState>>,
}

impl fmt::Debug for LocallyApprovedCertificationRunner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocallyApprovedCertificationRunner")
            .field("identity_digest", &self.identity_digest)
            .field("policy_revision_digest", &self.policy.revision_digest)
            .field("policy_generation", &self.policy_generation)
            .finish_non_exhaustive()
    }
}

impl LocallyApprovedCertificationRunner {
    /// Returns the retained exact runner identity manifest.
    #[must_use]
    pub const fn identity(&self) -> &CertificationRunnerIdentity {
        &self.identity
    }

    /// Returns the exact canonical identity approved by local policy.
    #[must_use]
    pub const fn identity_digest(&self) -> CertificationRunnerIdentityDigest {
        self.identity_digest
    }

    /// Returns the issuing local policy revision identity.
    #[must_use]
    pub const fn policy_revision_digest(&self) -> CertificationRunnerPolicyRevisionDigest {
        self.policy.revision_digest
    }

    /// Returns the issuing policy generation.
    #[must_use]
    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    /// Fails closed unless the issuing policy remains current and non-revoked.
    ///
    /// This is a point-in-time check, not run-attestation or effect authority. A later effect must hold
    /// an appropriate policy guard through its own commit point.
    ///
    /// # Errors
    ///
    /// Returns a currentness error if the store was dropped, replaced, revoked, or poisoned.
    pub fn verify_current_policy(&self) -> Result<(), CertificationRunnerPolicyError> {
        let store = self
            .policy_store
            .upgrade()
            .ok_or(CertificationRunnerPolicyError::PolicyStoreUnavailable)?;
        let state = store
            .read()
            .map_err(|_| CertificationRunnerPolicyError::PolicyStorePoisoned)?;
        if state.revocation_evidence_digest.is_some() {
            return Err(CertificationRunnerPolicyError::PolicyRevoked);
        }
        if state.generation != self.policy_generation || state.policy != self.policy {
            return Err(CertificationRunnerPolicyError::PolicyChanged);
        }
        Ok(())
    }
}

/// Approves one exact canonical runner identity under current trusted local policy.
///
/// This consumes the identity document so downstream layers cannot substitute another manifest while
/// retaining the approval. It does not verify opaque component-descriptor preimages or attest a run.
///
/// # Errors
///
/// Returns [`CertificationRunnerPolicyError`] for unavailable canonical identity, revoked or changed
/// policy, or an exact identity mismatch.
pub fn approve_local_certification_runner(
    identity: CertificationRunnerIdentity,
    policy_store: &LocalCertificationRunnerPolicyStore,
) -> Result<LocallyApprovedCertificationRunner, CertificationRunnerPolicyError> {
    let snapshot = policy_store.snapshot()?;
    if snapshot.revocation_evidence_digest.is_some() {
        return Err(CertificationRunnerPolicyError::PolicyRevoked);
    }
    let identity_digest = identity
        .canonical_document_digest()
        .map_err(CertificationRunnerPolicyError::IdentityDigestUnavailable)?;
    if identity_digest != snapshot.policy.identity_digest {
        return Err(CertificationRunnerPolicyError::IdentityDigestMismatch);
    }

    let approved = LocallyApprovedCertificationRunner {
        identity,
        identity_digest,
        policy: snapshot.policy,
        policy_generation: snapshot.generation,
        policy_store: Arc::downgrade(&policy_store.inner),
    };
    approved.verify_current_policy()?;
    Ok(approved)
}

/// Failure to construct, resolve, or recheck local runner-identity approval.
#[derive(Debug, Error)]
pub enum CertificationRunnerPolicyError {
    /// The runner-policy store synchronization primitive was poisoned.
    #[error("local certification-runner policy store is poisoned")]
    PolicyStorePoisoned,
    /// The monotonic runner-policy generation cannot advance safely.
    #[error("local certification-runner policy generation is exhausted")]
    PolicyGenerationExhausted,
    /// The issuing runner-policy store no longer exists.
    #[error("local certification-runner policy store is no longer available")]
    PolicyStoreUnavailable,
    /// Current runner policy revokes the approval.
    #[error("local certification-runner policy is revoked")]
    PolicyRevoked,
    /// Current runner policy differs from the issuing generation.
    #[error("local certification-runner policy changed after approval")]
    PolicyChanged,
    /// Canonical runner identity could not be produced.
    #[error("canonical certification-runner identity is unavailable")]
    IdentityDigestUnavailable(#[source] serde_json::Error),
    /// Exact runner identity did not match local policy.
    #[error("certification-runner identity does not match local policy")]
    IdentityDigestMismatch,
}
