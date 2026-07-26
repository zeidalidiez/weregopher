//! Exact bounded verification of every certification-runner component preimage.

use std::{collections::BTreeMap, fmt};

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use weregopher_domain::{
    CertificationRunnerArtifactName, CertificationRunnerComponentDescriptor,
    CertificationRunnerComponentRole, CertificationRunnerDescriptorSetDigest,
    CertificationRunnerIdentity, CertificationRunnerIdentityDigest,
    CertificationRunnerPolicyRevisionDigest, MAX_CERTIFICATION_RUNNER_COMPONENT_ARTIFACTS,
    MAX_CERTIFICATION_RUNNER_COMPONENT_DESCRIPTOR_BYTES, Sha256Digest,
};

use crate::{CertificationRunnerPolicyError, LocallyApprovedCertificationRunner};

const DESCRIPTOR_SET_DIGEST_DOMAIN: &[u8] = b"weregopher.certification.runner-descriptor-set.v1\0";
const RUNNER_COMPONENT_ROLE_COUNT: usize = 11;
const MAX_RUNNER_COMPONENT_ARTIFACT_BYTES: usize = 512 * 1024 * 1024;

/// Hard aggregate byte ceiling for one runner-component verification.
pub const MAX_TOTAL_CERTIFICATION_RUNNER_COMPONENT_ARTIFACT_BYTES: usize = 2 * 1024 * 1024 * 1024;
/// Hard ceiling for artifacts across the complete fixed runner-component role set.
pub const MAX_CERTIFICATION_RUNNER_COMPONENT_ARTIFACT_COUNT: usize =
    RUNNER_COMPONENT_ROLE_COUNT * MAX_CERTIFICATION_RUNNER_COMPONENT_ARTIFACTS;

/// Caller-tightened bounds for exact runner-component verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificationRunnerComponentVerificationLimits {
    descriptor: usize,
    artifact: usize,
    aggregate: usize,
}

impl CertificationRunnerComponentVerificationLimits {
    /// Constructs nonzero limits beneath the fixed implementation ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`CertificationRunnerComponentVerificationError::InvalidLimits`] for a zero limit
    /// and `LimitsExceedImplementationMaximum` when a caller attempts to raise a hard ceiling.
    pub const fn new(
        max_descriptor_bytes: usize,
        max_artifact_bytes: usize,
        max_total_artifact_bytes: usize,
    ) -> Result<Self, CertificationRunnerComponentVerificationError> {
        if max_descriptor_bytes == 0 || max_artifact_bytes == 0 || max_total_artifact_bytes == 0 {
            return Err(CertificationRunnerComponentVerificationError::InvalidLimits);
        }
        if max_descriptor_bytes > MAX_CERTIFICATION_RUNNER_COMPONENT_DESCRIPTOR_BYTES
            || max_artifact_bytes > MAX_RUNNER_COMPONENT_ARTIFACT_BYTES
            || max_total_artifact_bytes > MAX_TOTAL_CERTIFICATION_RUNNER_COMPONENT_ARTIFACT_BYTES
        {
            return Err(
                CertificationRunnerComponentVerificationError::LimitsExceedImplementationMaximum,
            );
        }
        Ok(Self {
            descriptor: max_descriptor_bytes,
            artifact: max_artifact_bytes,
            aggregate: max_total_artifact_bytes,
        })
    }
}

/// Opaque proof retaining every exact descriptor and borrowed component artifact byte.
///
/// This value consumes the runner approval and is deliberately non-cloneable and
/// non-serializable. It proves bounded byte-for-digest conformance under one conditional local
/// policy generation; it does not prove that a run occurred or authorize execution.
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<weregopher_transform::VerifiedCertificationRunnerComponents<'static, 'static, 'static>>();
/// ```
#[must_use = "verified runner components remain conditional on current runner policy"]
pub struct VerifiedCertificationRunnerComponents<'descriptors, 'artifacts, 'bytes> {
    approved: LocallyApprovedCertificationRunner,
    descriptors: &'descriptors BTreeMap<
        CertificationRunnerComponentRole,
        CertificationRunnerComponentDescriptor,
    >,
    artifacts: &'artifacts BTreeMap<
        CertificationRunnerComponentRole,
        BTreeMap<CertificationRunnerArtifactName, &'bytes [u8]>,
    >,
    descriptor_set_digest: CertificationRunnerDescriptorSetDigest,
    artifact_count: usize,
    total_artifact_bytes: usize,
}

impl fmt::Debug for VerifiedCertificationRunnerComponents<'_, '_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedCertificationRunnerComponents")
            .field("runner_identity_digest", &self.approved.identity_digest())
            .field("descriptor_set_digest", &self.descriptor_set_digest)
            .field("descriptor_count", &self.descriptors.len())
            .field("artifact_count", &self.artifact_count)
            .field("total_artifact_bytes", &self.total_artifact_bytes)
            .field(
                "runner_policy_generation",
                &self.approved.policy_generation(),
            )
            .finish_non_exhaustive()
    }
}

impl<'descriptors, 'artifacts, 'bytes>
    VerifiedCertificationRunnerComponents<'descriptors, 'artifacts, 'bytes>
{
    /// Fails closed unless the runner policy issuing this proof remains current.
    ///
    /// # Errors
    ///
    /// Returns a currentness error if the policy store disappeared, changed, was revoked, or was
    /// poisoned.
    pub fn verify_current_policy(&self) -> Result<(), CertificationRunnerPolicyError> {
        self.approved.verify_current_policy()
    }

    /// Returns the retained canonical runner identity.
    #[must_use]
    pub const fn runner_identity(&self) -> &CertificationRunnerIdentity {
        self.approved.identity()
    }

    /// Returns the exact canonical runner-identity digest.
    #[must_use]
    pub const fn runner_identity_digest(&self) -> CertificationRunnerIdentityDigest {
        self.approved.identity_digest()
    }

    /// Returns the exact runner-policy revision.
    #[must_use]
    pub const fn runner_policy_revision_digest(&self) -> CertificationRunnerPolicyRevisionDigest {
        self.approved.policy_revision_digest()
    }

    /// Returns the issuing runner-policy generation.
    #[must_use]
    pub const fn runner_policy_generation(&self) -> u64 {
        self.approved.policy_generation()
    }

    /// Returns the canonical identity of all fixed-role descriptor preimages.
    #[must_use]
    pub const fn descriptor_set_digest(&self) -> CertificationRunnerDescriptorSetDigest {
        self.descriptor_set_digest
    }

    /// Returns the exact descriptor count.
    #[must_use]
    pub fn descriptor_count(&self) -> usize {
        self.descriptors.len()
    }

    /// Returns the exact component artifact count.
    #[must_use]
    pub const fn artifact_count(&self) -> usize {
        self.artifact_count
    }

    /// Returns the checked aggregate component artifact bytes.
    #[must_use]
    pub const fn total_artifact_bytes(&self) -> usize {
        self.total_artifact_bytes
    }

    /// Returns every retained exact descriptor in fixed role order.
    #[must_use]
    pub const fn descriptors(
        &self,
    ) -> &'descriptors BTreeMap<
        CertificationRunnerComponentRole,
        CertificationRunnerComponentDescriptor,
    > {
        self.descriptors
    }

    /// Returns every retained borrowed component artifact byte map.
    #[must_use]
    pub const fn artifacts(
        &self,
    ) -> &'artifacts BTreeMap<
        CertificationRunnerComponentRole,
        BTreeMap<CertificationRunnerArtifactName, &'bytes [u8]>,
    > {
        self.artifacts
    }

    pub(crate) fn commit_while_policy_current<T>(
        &self,
        commit: impl FnOnce() -> T,
    ) -> Result<T, CertificationRunnerPolicyError> {
        self.approved.commit_while_policy_current(commit)
    }
}

struct VerificationSummary {
    descriptor_set_digest: CertificationRunnerDescriptorSetDigest,
    artifact_count: usize,
    total_artifact_bytes: usize,
}

/// Verifies the descriptor preimage and every exact artifact for all runner identity roles.
///
/// Coverage and selected limits are checked before hashing artifact bytes. The runner-policy read
/// guard remains held throughout verification, and the returned proof retains the consumed approval
/// plus every descriptor and borrowed byte map.
///
/// # Errors
///
/// Rejects missing or unexpected roles/artifacts, role or digest mismatch, invalid bounds, size
/// overflow, and exact byte digest mismatch.
pub fn verify_certification_runner_components<'descriptors, 'artifacts, 'bytes>(
    approved: LocallyApprovedCertificationRunner,
    descriptors: &'descriptors BTreeMap<
        CertificationRunnerComponentRole,
        CertificationRunnerComponentDescriptor,
    >,
    artifacts: &'artifacts BTreeMap<
        CertificationRunnerComponentRole,
        BTreeMap<CertificationRunnerArtifactName, &'bytes [u8]>,
    >,
    limits: CertificationRunnerComponentVerificationLimits,
) -> Result<
    VerifiedCertificationRunnerComponents<'descriptors, 'artifacts, 'bytes>,
    CertificationRunnerComponentVerificationError,
> {
    let summary = approved
        .commit_while_policy_current(|| {
            verify_component_inputs(approved.identity(), descriptors, artifacts, limits)
        })
        .map_err(CertificationRunnerComponentVerificationError::Policy)??;

    Ok(VerifiedCertificationRunnerComponents {
        approved,
        descriptors,
        artifacts,
        descriptor_set_digest: summary.descriptor_set_digest,
        artifact_count: summary.artifact_count,
        total_artifact_bytes: summary.total_artifact_bytes,
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "fixed-role coverage, bounds, length, and digest phases remain visibly linear"
)]
fn verify_component_inputs(
    identity: &CertificationRunnerIdentity,
    descriptors: &BTreeMap<
        CertificationRunnerComponentRole,
        CertificationRunnerComponentDescriptor,
    >,
    artifacts: &BTreeMap<
        CertificationRunnerComponentRole,
        BTreeMap<CertificationRunnerArtifactName, &[u8]>,
    >,
    limits: CertificationRunnerComponentVerificationLimits,
) -> Result<VerificationSummary, CertificationRunnerComponentVerificationError> {
    for role in runner_roles() {
        if !descriptors.contains_key(&role) {
            return Err(CertificationRunnerComponentVerificationError::MissingDescriptor(role));
        }
        if !artifacts.contains_key(&role) {
            return Err(CertificationRunnerComponentVerificationError::MissingArtifactSet(role));
        }
    }
    if descriptors.len() != RUNNER_COMPONENT_ROLE_COUNT {
        let role = descriptors
            .keys()
            .find(|role| !runner_roles().contains(role))
            .copied()
            .ok_or(CertificationRunnerComponentVerificationError::UnexpectedDescriptorCount)?;
        return Err(CertificationRunnerComponentVerificationError::UnexpectedDescriptor(role));
    }
    if artifacts.len() != RUNNER_COMPONENT_ROLE_COUNT {
        let role = artifacts
            .keys()
            .find(|role| !runner_roles().contains(role))
            .copied()
            .ok_or(CertificationRunnerComponentVerificationError::UnexpectedArtifactSetCount)?;
        return Err(CertificationRunnerComponentVerificationError::UnexpectedArtifactSet(role));
    }

    let mut descriptor_hasher = Sha256::new();
    descriptor_hasher.update(DESCRIPTOR_SET_DIGEST_DOMAIN);
    descriptor_hasher.update((RUNNER_COMPONENT_ROLE_COUNT as u64).to_le_bytes());
    let mut artifact_count = 0_usize;
    let mut total_artifact_bytes = 0_usize;

    for role in runner_roles() {
        let descriptor = descriptors
            .get(&role)
            .ok_or(CertificationRunnerComponentVerificationError::MissingDescriptor(role))?;
        if descriptor.role() != role {
            return Err(
                CertificationRunnerComponentVerificationError::DescriptorRoleMismatch {
                    expected: role,
                    actual: descriptor.role(),
                },
            );
        }
        let descriptor_bytes = descriptor.canonical_json_bytes().map_err(
            CertificationRunnerComponentVerificationError::CanonicalDescriptorUnavailable,
        )?;
        if descriptor_bytes.len() > limits.descriptor {
            return Err(
                CertificationRunnerComponentVerificationError::DescriptorTooLarge {
                    role,
                    actual_bytes: descriptor_bytes.len(),
                    max_bytes: limits.descriptor,
                },
            );
        }
        let descriptor_digest = descriptor.canonical_document_digest().map_err(
            CertificationRunnerComponentVerificationError::CanonicalDescriptorUnavailable,
        )?;
        let expected_digest = identity_descriptor_digest(identity, role);
        if descriptor_digest.as_sha256() != &expected_digest {
            return Err(
                CertificationRunnerComponentVerificationError::DescriptorDigestMismatch(role),
            );
        }
        descriptor_hasher.update([runner_role_tag(role)]);
        descriptor_hasher.update(descriptor_digest.as_sha256().as_bytes());

        let supplied = artifacts
            .get(&role)
            .ok_or(CertificationRunnerComponentVerificationError::MissingArtifactSet(role))?;
        for expected in descriptor.artifacts() {
            if !supplied.contains_key(expected.name()) {
                return Err(
                    CertificationRunnerComponentVerificationError::MissingArtifact {
                        role,
                        name: expected.name().clone(),
                    },
                );
            }
        }
        for name in supplied.keys() {
            if !descriptor
                .artifacts()
                .iter()
                .any(|artifact| artifact.name() == name)
            {
                return Err(
                    CertificationRunnerComponentVerificationError::UnexpectedArtifact {
                        role,
                        name: name.clone(),
                    },
                );
            }
        }
        artifact_count = artifact_count
            .checked_add(supplied.len())
            .ok_or(CertificationRunnerComponentVerificationError::ArtifactCountExceeded)?;
        if artifact_count > MAX_CERTIFICATION_RUNNER_COMPONENT_ARTIFACT_COUNT {
            return Err(CertificationRunnerComponentVerificationError::ArtifactCountExceeded);
        }
        for expected in descriptor.artifacts() {
            let bytes = supplied.get(expected.name()).ok_or_else(|| {
                CertificationRunnerComponentVerificationError::MissingArtifact {
                    role,
                    name: expected.name().clone(),
                }
            })?;
            if bytes.len() > limits.artifact {
                return Err(
                    CertificationRunnerComponentVerificationError::ArtifactTooLarge {
                        role,
                        name: expected.name().clone(),
                        actual_bytes: bytes.len(),
                        max_bytes: limits.artifact,
                    },
                );
            }
            let expected_length = usize::try_from(expected.size_bytes()).map_err(|_| {
                CertificationRunnerComponentVerificationError::ArtifactLengthUnrepresentable {
                    role,
                    name: expected.name().clone(),
                }
            })?;
            if bytes.len() != expected_length {
                return Err(
                    CertificationRunnerComponentVerificationError::ArtifactLengthMismatch {
                        role,
                        name: expected.name().clone(),
                        expected_bytes: expected_length,
                        actual_bytes: bytes.len(),
                    },
                );
            }
            total_artifact_bytes = total_artifact_bytes.checked_add(bytes.len()).ok_or(
                CertificationRunnerComponentVerificationError::TotalArtifactBytesExceeded {
                    actual_bytes: usize::MAX,
                    max_bytes: limits.aggregate,
                },
            )?;
            if total_artifact_bytes > limits.aggregate {
                return Err(
                    CertificationRunnerComponentVerificationError::TotalArtifactBytesExceeded {
                        actual_bytes: total_artifact_bytes,
                        max_bytes: limits.aggregate,
                    },
                );
            }
        }
    }

    for role in runner_roles() {
        let descriptor = descriptors
            .get(&role)
            .ok_or(CertificationRunnerComponentVerificationError::MissingDescriptor(role))?;
        let supplied = artifacts
            .get(&role)
            .ok_or(CertificationRunnerComponentVerificationError::MissingArtifactSet(role))?;
        for expected in descriptor.artifacts() {
            let bytes = supplied.get(expected.name()).ok_or_else(|| {
                CertificationRunnerComponentVerificationError::MissingArtifact {
                    role,
                    name: expected.name().clone(),
                }
            })?;
            let actual = Sha256Digest::from_bytes(Sha256::digest(bytes).into());
            if actual != expected.digest() {
                return Err(
                    CertificationRunnerComponentVerificationError::ArtifactDigestMismatch {
                        role,
                        name: expected.name().clone(),
                    },
                );
            }
        }
    }

    Ok(VerificationSummary {
        descriptor_set_digest: CertificationRunnerDescriptorSetDigest::new(
            Sha256Digest::from_bytes(descriptor_hasher.finalize().into()),
        ),
        artifact_count,
        total_artifact_bytes,
    })
}

const fn runner_roles() -> [CertificationRunnerComponentRole; RUNNER_COMPONENT_ROLE_COUNT] {
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

const fn runner_role_tag(role: CertificationRunnerComponentRole) -> u8 {
    match role {
        CertificationRunnerComponentRole::RunnerImage => 0,
        CertificationRunnerComponentRole::HostImage => 1,
        CertificationRunnerComponentRole::HostPatchSet => 2,
        CertificationRunnerComponentRole::ElectronRuntime => 3,
        CertificationRunnerComponentRole::LanguageRuntimeSet => 4,
        CertificationRunnerComponentRole::ToolchainSet => 5,
        CertificationRunnerComponentRole::HostAgent => 6,
        CertificationRunnerComponentRole::Verifier => 7,
        CertificationRunnerComponentRole::ProbeAssetSet => 8,
        CertificationRunnerComponentRole::SourceRevision => 9,
        CertificationRunnerComponentRole::ExceptionProvenance => 10,
    }
}

const fn identity_descriptor_digest(
    identity: &CertificationRunnerIdentity,
    role: CertificationRunnerComponentRole,
) -> Sha256Digest {
    match role {
        CertificationRunnerComponentRole::RunnerImage => {
            *identity.runner_image_digest().as_sha256()
        }
        CertificationRunnerComponentRole::HostImage => *identity.host_image_digest().as_sha256(),
        CertificationRunnerComponentRole::HostPatchSet => {
            *identity.host_patch_set_digest().as_sha256()
        }
        CertificationRunnerComponentRole::ElectronRuntime => {
            *identity.electron_runtime_digest().as_sha256()
        }
        CertificationRunnerComponentRole::LanguageRuntimeSet => {
            *identity.language_runtime_set_digest().as_sha256()
        }
        CertificationRunnerComponentRole::ToolchainSet => {
            *identity.toolchain_set_digest().as_sha256()
        }
        CertificationRunnerComponentRole::HostAgent => *identity.host_agent_digest().as_sha256(),
        CertificationRunnerComponentRole::Verifier => *identity.verifier_digest().as_sha256(),
        CertificationRunnerComponentRole::ProbeAssetSet => {
            *identity.probe_asset_set_digest().as_sha256()
        }
        CertificationRunnerComponentRole::SourceRevision => {
            *identity.source_revision_digest().as_sha256()
        }
        CertificationRunnerComponentRole::ExceptionProvenance => {
            *identity.exception_provenance_digest().as_sha256()
        }
    }
}

/// Failure to authenticate exact runner component descriptors and bytes.
#[derive(Debug, Error)]
pub enum CertificationRunnerComponentVerificationError {
    /// At least one caller-selected limit was zero.
    #[error("runner-component verification limits must be nonzero")]
    InvalidLimits,
    /// A caller-selected limit exceeded a hard implementation ceiling.
    #[error("runner-component verification limits exceed implementation ceilings")]
    LimitsExceedImplementationMaximum,
    /// One fixed-role descriptor was absent.
    #[error("missing runner-component descriptor for {0:?}")]
    MissingDescriptor(CertificationRunnerComponentRole),
    /// A descriptor occupied a role outside the fixed role set.
    #[error("unexpected runner-component descriptor for {0:?}")]
    UnexpectedDescriptor(CertificationRunnerComponentRole),
    /// Descriptor count differed from the fixed closed role set.
    #[error("runner-component descriptor count does not match the fixed role set")]
    UnexpectedDescriptorCount,
    /// One fixed-role artifact set was absent.
    #[error("missing runner-component artifact set for {0:?}")]
    MissingArtifactSet(CertificationRunnerComponentRole),
    /// An artifact set occupied a role outside the fixed role set.
    #[error("unexpected runner-component artifact set for {0:?}")]
    UnexpectedArtifactSet(CertificationRunnerComponentRole),
    /// Artifact-set count differed from the fixed closed role set.
    #[error("runner-component artifact-set count does not match the fixed role set")]
    UnexpectedArtifactSetCount,
    /// A descriptor's declared role differed from its manifest slot.
    #[error("runner-component descriptor role mismatch: expected {expected:?}, found {actual:?}")]
    DescriptorRoleMismatch {
        /// Manifest slot.
        expected: CertificationRunnerComponentRole,
        /// Descriptor declaration.
        actual: CertificationRunnerComponentRole,
    },
    /// Canonical descriptor bytes could not be produced.
    #[error("canonical runner-component descriptor is unavailable")]
    CanonicalDescriptorUnavailable(#[source] serde_json::Error),
    /// A canonical descriptor exceeded the caller-selected byte ceiling.
    #[error("runner-component descriptor {role:?} is {actual_bytes} bytes; limit is {max_bytes}")]
    DescriptorTooLarge {
        /// Exact descriptor role.
        role: CertificationRunnerComponentRole,
        /// Actual canonical bytes.
        actual_bytes: usize,
        /// Caller-selected maximum.
        max_bytes: usize,
    },
    /// A descriptor preimage did not match its identity manifest role digest.
    #[error("runner-component descriptor digest mismatch for {0:?}")]
    DescriptorDigestMismatch(CertificationRunnerComponentRole),
    /// One descriptor-named artifact was absent.
    #[error("missing runner-component artifact {name} for {role:?}")]
    MissingArtifact {
        /// Exact role.
        role: CertificationRunnerComponentRole,
        /// Logical name.
        name: CertificationRunnerArtifactName,
    },
    /// Supplied bytes were not named by the role descriptor.
    #[error("unexpected runner-component artifact {name} for {role:?}")]
    UnexpectedArtifact {
        /// Exact role.
        role: CertificationRunnerComponentRole,
        /// Logical name.
        name: CertificationRunnerArtifactName,
    },
    /// Total component artifact count exceeded its fixed maximum.
    #[error("runner-component artifact count exceeds the implementation ceiling")]
    ArtifactCountExceeded,
    /// One artifact exceeded its caller-selected ceiling.
    #[error(
        "runner-component artifact {name} for {role:?} is {actual_bytes} bytes; limit is {max_bytes}"
    )]
    ArtifactTooLarge {
        /// Exact role.
        role: CertificationRunnerComponentRole,
        /// Logical name.
        name: CertificationRunnerArtifactName,
        /// Actual bytes.
        actual_bytes: usize,
        /// Caller-selected maximum.
        max_bytes: usize,
    },
    /// Descriptor byte length cannot be represented on this target.
    #[error("runner-component artifact length is unrepresentable for {name} in {role:?}")]
    ArtifactLengthUnrepresentable {
        /// Exact role.
        role: CertificationRunnerComponentRole,
        /// Logical name.
        name: CertificationRunnerArtifactName,
    },
    /// Supplied bytes differed from the descriptor's exact length.
    #[error(
        "runner-component artifact {name} for {role:?} is {actual_bytes} bytes; expected {expected_bytes}"
    )]
    ArtifactLengthMismatch {
        /// Exact role.
        role: CertificationRunnerComponentRole,
        /// Logical name.
        name: CertificationRunnerArtifactName,
        /// Descriptor length.
        expected_bytes: usize,
        /// Supplied length.
        actual_bytes: usize,
    },
    /// Aggregate bytes overflowed or exceeded the selected limit.
    #[error("runner-component artifacts total {actual_bytes} bytes; limit is {max_bytes}")]
    TotalArtifactBytesExceeded {
        /// Aggregate bytes, or `usize::MAX` on overflow.
        actual_bytes: usize,
        /// Caller-selected maximum.
        max_bytes: usize,
    },
    /// Exact artifact digest verification failed.
    #[error("runner-component artifact digest mismatch for {name} in {role:?}")]
    ArtifactDigestMismatch {
        /// Exact role.
        role: CertificationRunnerComponentRole,
        /// Logical name.
        name: CertificationRunnerArtifactName,
    },
    /// Runner policy was not current throughout verification.
    #[error(transparent)]
    Policy(#[from] CertificationRunnerPolicyError),
}
