//! Freshness-bound atomic publication under current runner and certification policies.

use std::{
    fmt,
    sync::RwLock,
    time::{Duration, Instant},
};

use thiserror::Error;
use uuid::Uuid;
use weregopher_domain::{
    CertificationArtifactRef, CertificationRunAttestationError, CertificationRunFreshness,
    CertificationRunResultIdentity, CertificationRunRunnerIdentity,
    LocalCertificationRunAttestation, MAX_LOCAL_CERTIFICATION_RUN_FRESHNESS_MILLIS,
};

use crate::certification_publication::local_certification_receipt;
use crate::{
    CertificationPolicyError, CertificationPublicationError, CertificationRunnerPolicyError,
    LocalCertificationPublicationReceipt, LocallyCertifiedArtifacts,
    VerifiedCertificationRunnerComponents,
};

/// Non-cloneable single-use capability created immediately before one local certification run.
///
/// This value retains a cryptographically random challenge, the monotonic start instant, the exact
/// semantic report reference, and the consumed component-verification proof. It cannot be
/// reconstructed from serialized bytes.
#[must_use = "a pending local certification run has not been attested"]
pub struct PendingLocalCertificationRun<'descriptors, 'runner_artifacts, 'runner_bytes> {
    runner: VerifiedCertificationRunnerComponents<'descriptors, 'runner_artifacts, 'runner_bytes>,
    semantic_report: CertificationArtifactRef,
    challenge: Uuid,
    started_at: Instant,
    maximum_elapsed: Duration,
    maximum_elapsed_millis: u64,
}

impl fmt::Debug for PendingLocalCertificationRun<'_, '_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingLocalCertificationRun")
            .field(
                "runner_identity_digest",
                &self.runner.runner_identity_digest(),
            )
            .field(
                "descriptor_set_digest",
                &self.runner.descriptor_set_digest(),
            )
            .field("semantic_report", &self.semantic_report)
            .field("challenge", &self.challenge)
            .field("maximum_elapsed", &self.maximum_elapsed)
            .finish_non_exhaustive()
    }
}

/// Begins one single-use local certification run after exact runner verification.
///
/// The random challenge and monotonic start instant are created only after the issuing runner
/// policy is checked. The returned capability must be consumed by attested publication.
///
/// # Errors
///
/// Rejects a zero, non-whole-millisecond, or greater-than-ten-minute freshness window and fails
/// closed if the runner policy is no longer current.
pub fn begin_local_certification_run<'descriptors, 'runner_artifacts, 'runner_bytes>(
    runner: VerifiedCertificationRunnerComponents<'descriptors, 'runner_artifacts, 'runner_bytes>,
    semantic_report: CertificationArtifactRef,
    maximum_elapsed: Duration,
) -> Result<
    PendingLocalCertificationRun<'descriptors, 'runner_artifacts, 'runner_bytes>,
    AttestedCertificationPublicationError,
> {
    let implementation_maximum =
        Duration::from_millis(MAX_LOCAL_CERTIFICATION_RUN_FRESHNESS_MILLIS);
    let maximum_elapsed_millis = u64::try_from(maximum_elapsed.as_millis())
        .map_err(|_| AttestedCertificationPublicationError::InvalidFreshnessLimit)?;
    if maximum_elapsed.is_zero()
        || maximum_elapsed_millis == 0
        || maximum_elapsed != Duration::from_millis(maximum_elapsed_millis)
        || maximum_elapsed > implementation_maximum
    {
        return Err(AttestedCertificationPublicationError::InvalidFreshnessLimit);
    }
    runner
        .verify_current_policy()
        .map_err(AttestedCertificationPublicationError::RunnerPolicy)?;
    Ok(PendingLocalCertificationRun {
        runner,
        semantic_report,
        challenge: Uuid::new_v4(),
        started_at: Instant::now(),
        maximum_elapsed,
        maximum_elapsed_millis,
    })
}

/// Non-cloneable plan retaining both conditional policy proofs until atomic publication.
#[must_use = "an attested local certification publication has not been committed"]
pub struct PreparedAttestedLocalCertificationPublication<
    'descriptors,
    'runner_artifacts,
    'runner_bytes,
    'certification_artifacts,
    'certification_bytes,
> {
    pending: PendingLocalCertificationRun<'descriptors, 'runner_artifacts, 'runner_bytes>,
    certified: LocallyCertifiedArtifacts<'certification_artifacts, 'certification_bytes>,
    receipt: LocalCertificationPublicationReceipt,
}

impl fmt::Debug for PreparedAttestedLocalCertificationPublication<'_, '_, '_, '_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedAttestedLocalCertificationPublication")
            .field("pending", &self.pending)
            .field("receipt", &self.receipt)
            .finish_non_exhaustive()
    }
}

/// One atomically committed attestation and matching historical local receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestedLocalCertificationPublication {
    attestation: LocalCertificationRunAttestation,
    receipt: LocalCertificationPublicationReceipt,
}

impl AttestedLocalCertificationPublication {
    /// Returns the exact serialized historical run attestation.
    #[must_use]
    pub const fn attestation(&self) -> &LocalCertificationRunAttestation {
        &self.attestation
    }

    /// Returns the matching local-only in-memory receipt.
    #[must_use]
    pub const fn receipt(&self) -> &LocalCertificationPublicationReceipt {
        &self.receipt
    }
}

#[derive(Debug)]
struct AttestedPublicationState {
    publications: Vec<AttestedLocalCertificationPublication>,
}

/// Hard-bounded atomic in-memory destination for paired attestations and local receipts.
pub struct LocalAttestedCertificationPublicationStore {
    max_publications: usize,
    inner: RwLock<AttestedPublicationState>,
}

impl fmt::Debug for LocalAttestedCertificationPublicationStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalAttestedCertificationPublicationStore")
            .field("max_publications", &self.max_publications)
            .finish_non_exhaustive()
    }
}

impl LocalAttestedCertificationPublicationStore {
    /// Creates an empty bounded destination.
    ///
    /// # Errors
    ///
    /// Rejects zero or above-ceiling publication limits.
    pub fn new(max_publications: usize) -> Result<Self, AttestedCertificationPublicationError> {
        if max_publications == 0 {
            return Err(AttestedCertificationPublicationError::InvalidLimits);
        }
        if max_publications > crate::MAX_LOCAL_CERTIFICATION_PUBLICATIONS {
            return Err(AttestedCertificationPublicationError::LimitsExceedImplementationMaximum);
        }
        Ok(Self {
            max_publications,
            inner: RwLock::new(AttestedPublicationState {
                publications: Vec::new(),
            }),
        })
    }

    /// Returns the number of distinct committed pairs.
    ///
    /// # Errors
    ///
    /// Returns an error if the store synchronization primitive was poisoned.
    pub fn publication_count(&self) -> Result<usize, AttestedCertificationPublicationError> {
        self.inner
            .read()
            .map_err(|_| AttestedCertificationPublicationError::StorePoisoned)
            .map(|state| state.publications.len())
    }

    /// Reports whether this exact attestation and receipt pair has committed.
    ///
    /// # Errors
    ///
    /// Returns an error if the store synchronization primitive was poisoned.
    pub fn contains(
        &self,
        publication: &AttestedLocalCertificationPublication,
    ) -> Result<bool, AttestedCertificationPublicationError> {
        self.inner
            .read()
            .map_err(|_| AttestedCertificationPublicationError::StorePoisoned)
            .map(|state| state.publications.contains(publication))
    }

    fn commit(
        &self,
        publication: AttestedLocalCertificationPublication,
    ) -> Result<AttestedLocalCertificationPublication, AttestedCertificationPublicationError> {
        let mut state = self
            .inner
            .write()
            .map_err(|_| AttestedCertificationPublicationError::StorePoisoned)?;
        if let Some(existing) = state
            .publications
            .iter()
            .find(|existing| **existing == publication)
        {
            return Ok(existing.clone());
        }
        if state.publications.len() >= self.max_publications {
            return Err(AttestedCertificationPublicationError::StoreFull);
        }
        state
            .publications
            .try_reserve(1)
            .map_err(|_| AttestedCertificationPublicationError::PublicationAllocationFailed)?;
        state.publications.push(publication.clone());
        Ok(publication)
    }
}

/// Joins a pending pre-run capability to one exact local certification decision.
///
/// Preparation checks that the preselected semantic-report reference occurs in the exact verified
/// artifact set and computes the matching historical receipt. Both opaque values are consumed and
/// retained for final atomic publication.
///
/// # Errors
///
/// Fails closed for stale policy, a missing semantic report, or receipt preparation failure.
pub fn prepare_attested_local_certification_publication<
    'descriptors,
    'runner_artifacts,
    'runner_bytes,
    'certification_artifacts,
    'certification_bytes,
>(
    pending: PendingLocalCertificationRun<'descriptors, 'runner_artifacts, 'runner_bytes>,
    certified: LocallyCertifiedArtifacts<'certification_artifacts, 'certification_bytes>,
) -> Result<
    PreparedAttestedLocalCertificationPublication<
        'descriptors,
        'runner_artifacts,
        'runner_bytes,
        'certification_artifacts,
        'certification_bytes,
    >,
    AttestedCertificationPublicationError,
> {
    pending
        .runner
        .verify_current_policy()
        .map_err(AttestedCertificationPublicationError::RunnerPolicy)?;
    if !certified
        .verified_artifacts()
        .artifacts()
        .contains_key(&pending.semantic_report)
    {
        return Err(AttestedCertificationPublicationError::SemanticReportMissing);
    }
    let receipt = local_certification_receipt(&certified)
        .map_err(AttestedCertificationPublicationError::Publication)?;
    Ok(PreparedAttestedLocalCertificationPublication {
        pending,
        certified,
        receipt,
    })
}

/// Atomically commits one freshness-bound attestation and receipt under both current policies.
///
/// Lock order is runner policy, certification policy, then destination store. Both policy read
/// guards remain held until the exact pair is visible or the bounded commit fails.
///
/// # Errors
///
/// Fails closed for expired freshness, unrepresentable canonical fields, either non-current policy,
/// invalid attestation fields, or a bounded destination failure.
pub fn publish_attested_local_certification(
    prepared: PreparedAttestedLocalCertificationPublication<'_, '_, '_, '_, '_>,
    publication_store: &LocalAttestedCertificationPublicationStore,
) -> Result<AttestedLocalCertificationPublication, AttestedCertificationPublicationError> {
    let PreparedAttestedLocalCertificationPublication {
        pending,
        certified,
        receipt,
    } = prepared;
    let PendingLocalCertificationRun {
        runner,
        semantic_report,
        challenge,
        started_at,
        maximum_elapsed,
        maximum_elapsed_millis,
    } = pending;

    let under_runner = runner
        .commit_while_policy_current(|| {
            certified.commit_while_policy_current(|| {
                let elapsed = started_at.elapsed();
                if elapsed > maximum_elapsed {
                    return Err(AttestedCertificationPublicationError::FreshnessExpired);
                }
                let elapsed_millis = u64::try_from(elapsed.as_millis()).map_err(|_| {
                    AttestedCertificationPublicationError::ElapsedDurationUnrepresentable
                })?;
                let freshness = CertificationRunFreshness::new(
                    challenge,
                    maximum_elapsed_millis,
                    elapsed_millis,
                )
                .map_err(AttestedCertificationPublicationError::Attestation)?;
                let runner_identity = CertificationRunRunnerIdentity::new(
                    runner.runner_identity_digest(),
                    runner.descriptor_set_digest(),
                    runner.runner_policy_revision_digest(),
                    runner.runner_policy_generation(),
                )
                .map_err(AttestedCertificationPublicationError::Attestation)?;
                let artifact_count = u32::try_from(receipt.artifact_count()).map_err(|_| {
                    AttestedCertificationPublicationError::ArtifactCountUnrepresentable
                })?;
                let total_artifact_bytes =
                    u64::try_from(receipt.total_artifact_bytes()).map_err(|_| {
                        AttestedCertificationPublicationError::ArtifactBytesUnrepresentable
                    })?;
                let result = CertificationRunResultIdentity::new(
                    semantic_report,
                    receipt.target().clone(),
                    receipt.profile_digest(),
                    receipt.evidence_digest(),
                    receipt.artifact_set_digest(),
                    receipt.class(),
                    receipt.policy_revision_digest(),
                    receipt.policy_generation(),
                    artifact_count,
                    total_artifact_bytes,
                )
                .map_err(AttestedCertificationPublicationError::Attestation)?;
                publication_store.commit(AttestedLocalCertificationPublication {
                    attestation: LocalCertificationRunAttestation::new(
                        freshness,
                        runner_identity,
                        result,
                    ),
                    receipt,
                })
            })
        })
        .map_err(AttestedCertificationPublicationError::RunnerPolicy)?;
    under_runner.map_err(AttestedCertificationPublicationError::CertificationPolicy)?
}

/// Failure to prepare or atomically publish a local run attestation.
#[derive(Debug, Error)]
pub enum AttestedCertificationPublicationError {
    /// Store limit was zero.
    #[error("attested local certification publication limit must be nonzero")]
    InvalidLimits,
    /// Store limit exceeded its fixed implementation maximum.
    #[error("attested local certification publication limit exceeds the implementation ceiling")]
    LimitsExceedImplementationMaximum,
    /// Freshness duration was zero, non-whole-millisecond, excessive, or unrepresentable.
    #[error("local certification-run freshness limit is invalid")]
    InvalidFreshnessLimit,
    /// Monotonic elapsed time exceeded the pre-run maximum.
    #[error("local certification-run freshness window expired")]
    FreshnessExpired,
    /// Monotonic elapsed milliseconds cannot be represented canonically.
    #[error("local certification-run elapsed duration is unrepresentable")]
    ElapsedDurationUnrepresentable,
    /// Selected semantic report was absent from the verified evidence artifacts.
    #[error("selected semantic report is absent from verified certification artifacts")]
    SemanticReportMissing,
    /// Verified artifact count cannot be represented in the attestation.
    #[error("verified certification artifact count is unrepresentable")]
    ArtifactCountUnrepresentable,
    /// Verified artifact bytes cannot be represented in the attestation.
    #[error("verified certification artifact bytes are unrepresentable")]
    ArtifactBytesUnrepresentable,
    /// Runner policy was not current through the shared commit.
    #[error("runner policy rejected attested certification publication")]
    RunnerPolicy(#[source] CertificationRunnerPolicyError),
    /// Certification policy was not current through the shared commit.
    #[error("certification policy rejected attested certification publication")]
    CertificationPolicy(#[source] CertificationPolicyError),
    /// Existing receipt preparation failed.
    #[error("local certification receipt preparation failed")]
    Publication(#[source] CertificationPublicationError),
    /// Canonical attestation construction failed.
    #[error("local certification-run attestation construction failed")]
    Attestation(#[source] CertificationRunAttestationError),
    /// Destination synchronization failed.
    #[error("attested local certification publication store is poisoned")]
    StorePoisoned,
    /// Destination has no room for another exact pair.
    #[error("attested local certification publication store is full")]
    StoreFull,
    /// Memory could not be reserved for another bounded pair.
    #[error("attested local certification publication allocation failed")]
    PublicationAllocationFailed,
}
