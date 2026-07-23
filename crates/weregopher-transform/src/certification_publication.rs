//! Atomic, generation-current publication of exact local certification receipts.

use std::{fmt, sync::RwLock};

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use weregopher_domain::{
    CertificationArtifactKind, CertificationClass, CertificationEvidenceDigest,
    CertificationProfileDigest, CertificationTarget, PublicationStatus, Sha256Digest,
};

use crate::{
    CertificationPolicyError, CertificationPolicyRevisionDigest, LocallyCertifiedArtifacts,
};

const ARTIFACT_SET_DIGEST_DOMAIN: &[u8] = b"weregopher.certification.artifact-set.v1\0";

/// Hard ceiling for receipts retained by one in-memory local publication store.
pub const MAX_LOCAL_CERTIFICATION_PUBLICATIONS: usize = 4_096;

/// Role-specific identity of the exact artifact-reference set whose bytes were verified.
///
/// Artifact-set identities cannot be substituted for evidence-document identities:
///
/// ```compile_fail
/// use weregopher_domain::{CertificationEvidenceDigest, Sha256Digest};
/// use weregopher_transform::CertificationArtifactSetDigest;
///
/// let artifacts = CertificationArtifactSetDigest::new(Sha256Digest::from_bytes([0; 32]));
/// let evidence: CertificationEvidenceDigest = artifacts;
/// # let _ = evidence;
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CertificationArtifactSetDigest(Sha256Digest);

impl CertificationArtifactSetDigest {
    /// Creates an artifact-set identity from a canonical SHA-256 digest.
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

impl fmt::Display for CertificationArtifactSetDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Historical receipt for one exact local-only certification publication commit.
///
/// A receipt records the policy that was current through the in-memory commit point. It is not a
/// claim that the policy remains current, a durable registry record, a signature, or authority to
/// transform, publish externally, or execute anything.
///
/// ```compile_fail
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<weregopher_transform::LocalCertificationPublicationReceipt>();
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalCertificationPublicationReceipt {
    target: CertificationTarget,
    profile_digest: CertificationProfileDigest,
    evidence_digest: CertificationEvidenceDigest,
    artifact_set_digest: CertificationArtifactSetDigest,
    class: CertificationClass,
    policy_revision_digest: CertificationPolicyRevisionDigest,
    policy_generation: u64,
    artifact_count: usize,
    total_artifact_bytes: usize,
    publication_status: PublicationStatus,
}

impl LocalCertificationPublicationReceipt {
    /// Returns the exact compatibility, execution, and artifact target.
    #[must_use]
    pub const fn target(&self) -> &CertificationTarget {
        &self.target
    }

    /// Returns the exact canonical certification-profile identity.
    #[must_use]
    pub const fn profile_digest(&self) -> CertificationProfileDigest {
        self.profile_digest
    }

    /// Returns the exact canonical certification-evidence identity.
    #[must_use]
    pub const fn evidence_digest(&self) -> CertificationEvidenceDigest {
        self.evidence_digest
    }

    /// Returns the exact verified artifact-reference-set identity.
    #[must_use]
    pub const fn artifact_set_digest(&self) -> CertificationArtifactSetDigest {
        self.artifact_set_digest
    }

    /// Returns the trusted class assigned by the committing local policy.
    #[must_use]
    pub const fn class(&self) -> CertificationClass {
        self.class
    }

    /// Returns the committing local policy revision identity.
    #[must_use]
    pub const fn policy_revision_digest(&self) -> CertificationPolicyRevisionDigest {
        self.policy_revision_digest
    }

    /// Returns the committing local policy generation.
    #[must_use]
    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    /// Returns the number of unique exact artifact references covered by the receipt.
    #[must_use]
    pub const fn artifact_count(&self) -> usize {
        self.artifact_count
    }

    /// Returns the checked aggregate byte length of the verified artifacts.
    #[must_use]
    pub const fn total_artifact_bytes(&self) -> usize {
        self.total_artifact_bytes
    }

    /// Returns `local_only`; registry publication is a separate authenticated boundary.
    #[must_use]
    pub const fn publication_status(&self) -> PublicationStatus {
        self.publication_status
    }
}

/// Non-cloneable plan that retains the exact local certification decision until publication.
///
/// Preparing a plan performs a point-in-time currentness check. Publication consumes the plan and
/// rechecks policy while holding the policy read guard through the receipt-store commit.
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<weregopher_transform::PreparedLocalCertificationPublication<'static, 'static>>();
/// ```
#[must_use = "a prepared local certification publication has not been committed"]
pub struct PreparedLocalCertificationPublication<'artifacts, 'bytes> {
    certified: LocallyCertifiedArtifacts<'artifacts, 'bytes>,
    receipt: LocalCertificationPublicationReceipt,
}

impl fmt::Debug for PreparedLocalCertificationPublication<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedLocalCertificationPublication")
            .field("receipt", &self.receipt)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct PublicationState {
    receipts: Vec<LocalCertificationPublicationReceipt>,
}

/// Bounded in-memory destination for local-only certification publication receipts.
///
/// Exact duplicate receipts converge without consuming another slot. This store is deliberately not
/// durable and does not represent an authenticated registry.
pub struct LocalCertificationPublicationStore {
    max_publications: usize,
    inner: RwLock<PublicationState>,
}

impl fmt::Debug for LocalCertificationPublicationStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalCertificationPublicationStore")
            .field("max_publications", &self.max_publications)
            .finish_non_exhaustive()
    }
}

impl LocalCertificationPublicationStore {
    /// Creates an empty local publication store with a caller-tightened hard bound.
    ///
    /// # Errors
    ///
    /// Returns [`CertificationPublicationError::InvalidLimits`] for zero or
    /// [`CertificationPublicationError::LimitsExceedImplementationMaximum`] above the hard ceiling.
    pub fn new(max_publications: usize) -> Result<Self, CertificationPublicationError> {
        if max_publications == 0 {
            return Err(CertificationPublicationError::InvalidLimits);
        }
        if max_publications > MAX_LOCAL_CERTIFICATION_PUBLICATIONS {
            return Err(CertificationPublicationError::LimitsExceedImplementationMaximum);
        }
        Ok(Self {
            max_publications,
            inner: RwLock::new(PublicationState {
                receipts: Vec::new(),
            }),
        })
    }

    /// Returns the number of distinct committed local receipts.
    ///
    /// # Errors
    ///
    /// Returns [`CertificationPublicationError::StorePoisoned`] after synchronization failure.
    pub fn publication_count(&self) -> Result<usize, CertificationPublicationError> {
        self.inner
            .read()
            .map_err(|_| CertificationPublicationError::StorePoisoned)
            .map(|state| state.receipts.len())
    }

    /// Reports whether this exact historical receipt is committed in the local store.
    ///
    /// # Errors
    ///
    /// Returns [`CertificationPublicationError::StorePoisoned`] after synchronization failure.
    pub fn contains(
        &self,
        receipt: &LocalCertificationPublicationReceipt,
    ) -> Result<bool, CertificationPublicationError> {
        self.inner
            .read()
            .map_err(|_| CertificationPublicationError::StorePoisoned)
            .map(|state| state.receipts.contains(receipt))
    }

    fn commit(
        &self,
        receipt: LocalCertificationPublicationReceipt,
    ) -> Result<LocalCertificationPublicationReceipt, CertificationPublicationError> {
        let mut state = self
            .inner
            .write()
            .map_err(|_| CertificationPublicationError::StorePoisoned)?;
        if let Some(existing) = state.receipts.iter().find(|existing| **existing == receipt) {
            return Ok(existing.clone());
        }
        if state.receipts.len() >= self.max_publications {
            return Err(CertificationPublicationError::StoreFull);
        }
        state
            .receipts
            .try_reserve(1)
            .map_err(|_| CertificationPublicationError::ReceiptAllocationFailed)?;
        state.receipts.push(receipt.clone());
        Ok(receipt)
    }
}

/// Prepares one exact local certification receipt without committing publication.
///
/// The returned plan consumes and retains the non-cloneable local certification decision. The
/// artifact-set digest is canonical SHA-256 over the domain tag
/// `weregopher.certification.artifact-set.v1\0`, a little-endian `u64` reference count, and each
/// `BTreeMap`-ordered reference encoded as its fixed one-byte kind tag followed by its 32 digest
/// bytes. Kind tags follow the declared `CertificationArtifactKind` order from zero through nine.
///
/// # Errors
///
/// Returns a policy currentness error or rejects an unrepresentable artifact count.
pub fn prepare_local_certification_publication<'artifacts, 'bytes>(
    certified: LocallyCertifiedArtifacts<'artifacts, 'bytes>,
) -> Result<PreparedLocalCertificationPublication<'artifacts, 'bytes>, CertificationPublicationError>
{
    let class = certified.current_class()?;
    let verified = certified.verified_artifacts();
    let artifact_count = verified.artifact_count();
    let encoded_count = u64::try_from(artifact_count)
        .map_err(|_| CertificationPublicationError::ArtifactCountUnrepresentable)?;
    let mut hasher = Sha256::new();
    hasher.update(ARTIFACT_SET_DIGEST_DOMAIN);
    hasher.update(encoded_count.to_le_bytes());
    for reference in verified.artifacts().keys() {
        hasher.update([artifact_kind_tag(reference.kind)]);
        hasher.update(reference.digest.as_sha256().as_bytes());
    }
    let artifact_set_digest =
        CertificationArtifactSetDigest::new(Sha256Digest::from_bytes(hasher.finalize().into()));
    let receipt = LocalCertificationPublicationReceipt {
        target: certified.target().clone(),
        profile_digest: certified.profile_digest(),
        evidence_digest: certified.evidence_digest(),
        artifact_set_digest,
        class,
        policy_revision_digest: certified.policy_revision_digest(),
        policy_generation: certified.policy_generation(),
        artifact_count,
        total_artifact_bytes: verified.total_bytes(),
        publication_status: PublicationStatus::LocalOnly,
    };
    Ok(PreparedLocalCertificationPublication { certified, receipt })
}

/// Atomically commits one local-only receipt while its issuing policy remains current.
///
/// The policy read guard is acquired before the destination-store write lock and retained through
/// duplicate verification or receipt insertion. Replacement and revocation therefore cannot commit
/// between final currentness verification and local publication visibility.
///
/// # Errors
///
/// Returns [`CertificationPublicationError`] when policy is unavailable, changed, or revoked, or
/// when the bounded destination cannot commit the receipt.
pub fn publish_local_certification(
    prepared: PreparedLocalCertificationPublication<'_, '_>,
    publication_store: &LocalCertificationPublicationStore,
) -> Result<LocalCertificationPublicationReceipt, CertificationPublicationError> {
    let PreparedLocalCertificationPublication { certified, receipt } = prepared;
    certified
        .commit_while_policy_current(|| publication_store.commit(receipt))
        .map_err(CertificationPublicationError::Policy)?
}

const fn artifact_kind_tag(kind: CertificationArtifactKind) -> u8 {
    match kind {
        CertificationArtifactKind::PackageIdentity => 0,
        CertificationArtifactKind::StaticAnalysis => 1,
        CertificationArtifactKind::RuntimeProbe => 2,
        CertificationArtifactKind::RendererProbe => 3,
        CertificationArtifactKind::StateProbe => 4,
        CertificationArtifactKind::SecurityProbe => 5,
        CertificationArtifactKind::WorkflowProbe => 6,
        CertificationArtifactKind::ResourceProbe => 7,
        CertificationArtifactKind::HelperProbe => 8,
        CertificationArtifactKind::ExceptionVerification => 9,
    }
}

/// Failure to prepare or atomically commit a local certification publication.
#[derive(Debug, Error)]
pub enum CertificationPublicationError {
    /// The caller selected a zero publication-store bound.
    #[error("local certification publication limit must be nonzero")]
    InvalidLimits,
    /// The caller attempted to raise the fixed implementation ceiling.
    #[error("local certification publication limit exceeds the implementation ceiling")]
    LimitsExceedImplementationMaximum,
    /// The exact artifact count cannot be represented by the canonical framing.
    #[error("certification artifact count cannot be represented canonically")]
    ArtifactCountUnrepresentable,
    /// The issuing local policy was not current through the publication commit.
    #[error(transparent)]
    Policy(#[from] CertificationPolicyError),
    /// The local publication store synchronization primitive was poisoned.
    #[error("local certification publication store is poisoned")]
    StorePoisoned,
    /// The bounded local publication store has no slot for another distinct receipt.
    #[error("local certification publication store is full")]
    StoreFull,
    /// Memory for one additional bounded receipt could not be reserved.
    #[error("local certification publication receipt allocation failed")]
    ReceiptAllocationFailed,
}
