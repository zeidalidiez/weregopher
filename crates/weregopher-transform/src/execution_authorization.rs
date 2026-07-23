//! Live authorization over exact execution contracts and retained executable capabilities.
//!
//! The local policy store is the trust and revocation root for this initial implementation. An
//! authorization capability remains conditional on the exact store generation and must be consumed
//! by a supervisor operation that rechecks that generation while launching. This module never opens
//! an executable from an untrusted path.

use std::{
    ffi::OsString,
    fmt, io,
    sync::{Arc, RwLock, Weak},
    time::Duration,
};

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use weregopher_domain::{
    AdapterId, AnalysisDisposition, ApplicationFamilyId, ArtifactTrustEvidenceDigest,
    AuthorizationContextDigest, CapabilityPolicyDigest, CompatibilityAnalysis,
    CompatibilityAnalysisDigest, EffectiveSecurityPosture, ExecutableDigest, ExecutionArgument,
    ExecutionArtifactLocator, ExecutionArtifactSource, ExecutionArtifactSourceDigest,
    ExecutionConsolePolicy, ExecutionContractDigest, ExecutionDependencyPolicy,
    ExecutionEnvironmentPolicy, ExecutionInheritedHandlePolicy, ExecutionLaunchPolicy,
    ExecutionResolutionEvidence, ExecutionResolutionEvidenceDigest, ExecutionResourceLimits,
    ExecutionStateMode, ExecutionTargetContract, ExecutionTargetId,
    ExecutionWorkingDirectoryPolicy, GeneratedExecutionOverlay, MAX_EXECUTION_ARGUMENTS,
    ProvenanceEvidenceDigest, Sha256Digest, StatePolicyDigest,
    StructurallyValidatedExecutionOverlay, TrustMode, UserPolicyDigest,
};
use weregopher_windows::{
    JobLimits, KillOnCloseJob, LockedExecutable, OwnedJobProcess, PreparedProcessLaunch,
    ProcessLaunchLimits,
};

use crate::{
    ManagedArtifactExecutable, ManagedArtifactLease, PackageSnapshotExecutable,
    PackageSnapshotLease,
};

const WINDOWS_MAX_COMMAND_LINE_UNITS: usize = 32_767;
const WINDOWS_MAX_SINGLE_VALUE_UNITS: usize = 32_766;

/// Role-named immutable identities authenticated by one local execution policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionAuthorityPins {
    /// Durable adapter identity.
    pub adapter_id: AdapterId,
    /// Application-family identity.
    pub family: ApplicationFamilyId,
    /// Exact adapter artifact identity.
    pub adapter_content_digest: Sha256Digest,
    /// Exact canonical execution-authority document identity.
    pub authority_document_digest: Sha256Digest,
}

/// Role-named immutable build and environment identities approved by local policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionContextPins {
    /// Exact source build-fingerprint identity.
    pub source_build_fingerprint_digest: Sha256Digest,
    /// Exact source package-tree identity.
    pub package_tree_merkle: Sha256Digest,
    /// Exact execution-environment descriptor identity.
    pub execution_environment_digest: Sha256Digest,
    /// Exact generated build-descriptor identity.
    pub build_descriptor_digest: Sha256Digest,
}

/// Role-named target and evidence identities approved by one local execution policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionTargetPins {
    /// Exact target identifier.
    pub target_id: ExecutionTargetId,
    /// Exact static target-contract identity.
    pub target_contract_digest: ExecutionContractDigest,
    /// Exact generated resolution-evidence identity.
    pub resolution_evidence_digest: ExecutionResolutionEvidenceDigest,
    /// Exact artifact-trust evidence identity.
    pub artifact_trust_evidence_digest: ArtifactTrustEvidenceDigest,
    /// Exact provenance evidence identity.
    pub provenance_evidence_digest: ProvenanceEvidenceDigest,
    /// Exact complete compatibility-analysis identity.
    pub compatibility_analysis_digest: CompatibilityAnalysisDigest,
    /// Exact resolved capability-policy identity.
    pub capability_policy_digest: CapabilityPolicyDigest,
    /// Exact resolved state-policy identity.
    pub state_policy_digest: StatePolicyDigest,
    /// Exact current user-policy identity.
    pub user_policy_digest: UserPolicyDigest,
    /// Explicitly approved effective security posture.
    pub security_posture: EffectiveSecurityPosture,
    /// Explicitly approved state namespace mode.
    pub state_mode: ExecutionStateMode,
}

/// Exact locally authenticated policy for one execution target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalExecutionPolicy {
    trust_mode: TrustMode,
    authority: ExecutionAuthorityPins,
    context: ExecutionContextPins,
    target: ExecutionTargetPins,
    revision_digest: Sha256Digest,
}

impl LocalExecutionPolicy {
    /// Constructs an exact local trust decision.
    ///
    /// Registry and forensic modes require trust engines not implemented by this local-policy
    /// boundary. Developer mode is restricted to disposable state.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionAuthorizationError::UnsupportedTrustMode`] for registry or forensic trust,
    /// or [`ExecutionAuthorizationError::DeveloperModeRequiresDisposableState`] when an unsigned
    /// developer target requests production state.
    pub fn new(
        trust_mode: TrustMode,
        authority: ExecutionAuthorityPins,
        context: ExecutionContextPins,
        target: ExecutionTargetPins,
        revision_digest: Sha256Digest,
    ) -> Result<Self, ExecutionAuthorizationError> {
        if target.security_posture != EffectiveSecurityPosture::VendorEquivalentFullTrust {
            return Err(ExecutionAuthorizationError::UnsupportedSecurityPosture);
        }
        match trust_mode {
            TrustMode::LocallyTrusted => {}
            TrustMode::Developer if target.state_mode == ExecutionStateMode::Disposable => {}
            TrustMode::Developer => {
                return Err(ExecutionAuthorizationError::DeveloperModeRequiresDisposableState);
            }
            TrustMode::RegistryTrusted | TrustMode::ForensicOverride => {
                return Err(ExecutionAuthorizationError::UnsupportedTrustMode);
            }
        }
        Ok(Self {
            trust_mode,
            authority,
            context,
            target,
            revision_digest,
        })
    }

    /// Returns the exact authority identities authenticated by this policy.
    #[must_use]
    pub const fn authority_pins(&self) -> &ExecutionAuthorityPins {
        &self.authority
    }

    /// Returns the exact build and environment identities authenticated by this policy.
    #[must_use]
    pub const fn context_pins(&self) -> ExecutionContextPins {
        self.context
    }

    /// Returns the exact target and evidence identities authenticated by this policy.
    #[must_use]
    pub const fn target_pins(&self) -> &ExecutionTargetPins {
        &self.target
    }

    /// Returns the local policy revision identity.
    #[must_use]
    pub const fn revision_digest(&self) -> Sha256Digest {
        self.revision_digest
    }
}

#[derive(Clone, Debug)]
struct ExecutionPolicyState {
    generation: u64,
    policy: LocalExecutionPolicy,
    revocation_evidence_digest: Option<Sha256Digest>,
}

/// Mutable local trust root whose generation invalidates previously issued authorization values.
#[derive(Clone)]
pub struct LocalExecutionPolicyStore {
    inner: Arc<RwLock<ExecutionPolicyState>>,
}

impl fmt::Debug for LocalExecutionPolicyStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalExecutionPolicyStore")
            .finish_non_exhaustive()
    }
}

impl LocalExecutionPolicyStore {
    /// Creates a current, non-revoked policy generation.
    #[must_use]
    pub fn new(policy: LocalExecutionPolicy) -> Self {
        Self {
            inner: Arc::new(RwLock::new(ExecutionPolicyState {
                generation: 1,
                policy,
                revocation_evidence_digest: None,
            })),
        }
    }

    /// Atomically installs a replacement policy and invalidates every older authorization.
    ///
    /// # Errors
    ///
    /// Returns a policy-store error if synchronization is poisoned or the monotonic generation is
    /// exhausted. The previous state remains active on generation exhaustion.
    pub fn replace_policy(
        &self,
        policy: LocalExecutionPolicy,
    ) -> Result<(), ExecutionAuthorizationError> {
        let mut state = self
            .inner
            .write()
            .map_err(|_| ExecutionAuthorizationError::PolicyStorePoisoned)?;
        let generation = state
            .generation
            .checked_add(1)
            .ok_or(ExecutionAuthorizationError::PolicyGenerationExhausted)?;
        state.generation = generation;
        state.policy = policy;
        state.revocation_evidence_digest = None;
        Ok(())
    }

    /// Atomically records revocation evidence and invalidates every outstanding authorization.
    ///
    /// # Errors
    ///
    /// Returns a policy-store error if synchronization is poisoned or the monotonic generation is
    /// exhausted. The previous state remains active on generation exhaustion.
    pub fn revoke(
        &self,
        revocation_evidence_digest: Sha256Digest,
    ) -> Result<(), ExecutionAuthorizationError> {
        let mut state = self
            .inner
            .write()
            .map_err(|_| ExecutionAuthorizationError::PolicyStorePoisoned)?;
        let generation = state
            .generation
            .checked_add(1)
            .ok_or(ExecutionAuthorizationError::PolicyGenerationExhausted)?;
        state.generation = generation;
        state.revocation_evidence_digest = Some(revocation_evidence_digest);
        Ok(())
    }

    fn snapshot(&self) -> Result<ExecutionPolicyState, ExecutionAuthorizationError> {
        self.inner
            .read()
            .map_err(|_| ExecutionAuthorizationError::PolicyStorePoisoned)
            .map(|state| state.clone())
    }
}

/// Hard per-document ceiling for policy evidence hashed by live authorization.
pub const MAX_EXECUTION_POLICY_EVIDENCE_BYTES: usize = 1024 * 1024;
/// Hard aggregate ceiling for all policy evidence hashed by one live authorization.
pub const MAX_TOTAL_EXECUTION_POLICY_EVIDENCE_BYTES: usize = 4 * 1024 * 1024;

/// Caller-selected bounds for evidence hashed by one live authorization decision.
///
/// Callers may tighten these limits but cannot raise the implementation ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionAuthorizationLimits {
    max_evidence_bytes: usize,
    max_total_evidence_bytes: usize,
}

impl ExecutionAuthorizationLimits {
    /// Constructs nonzero per-evidence and aggregate byte limits.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionAuthorizationError::InvalidLimits`] when either limit is zero, or
    /// [`ExecutionAuthorizationError::EvidenceLimitsExceedImplementationMaximum`] when either
    /// caller-selected limit exceeds its hard implementation ceiling.
    pub const fn new(
        max_evidence_bytes: usize,
        max_total_evidence_bytes: usize,
    ) -> Result<Self, ExecutionAuthorizationError> {
        if max_evidence_bytes == 0 || max_total_evidence_bytes == 0 {
            return Err(ExecutionAuthorizationError::InvalidLimits);
        }
        if max_evidence_bytes > MAX_EXECUTION_POLICY_EVIDENCE_BYTES
            || max_total_evidence_bytes > MAX_TOTAL_EXECUTION_POLICY_EVIDENCE_BYTES
        {
            return Err(ExecutionAuthorizationError::EvidenceLimitsExceedImplementationMaximum);
        }
        Ok(Self {
            max_evidence_bytes,
            max_total_evidence_bytes,
        })
    }
}

/// Exact immutable policy and trust evidence bytes supplied to live authorization.
#[derive(Clone, Copy)]
pub struct ExecutionPolicyEvidence<'evidence> {
    /// Artifact signer, local-build trust, or equivalent trust evidence.
    pub artifact_trust: &'evidence [u8],
    /// Artifact provenance evidence.
    pub provenance: &'evidence [u8],
    /// Resolved capability-policy bytes.
    pub capability_policy: &'evidence [u8],
    /// Resolved state-policy bytes.
    pub state_policy: &'evidence [u8],
    /// Current user-policy or consent bytes.
    pub user_policy: &'evidence [u8],
}

impl fmt::Debug for ExecutionPolicyEvidence<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionPolicyEvidence")
            .field("artifact_trust_bytes", &self.artifact_trust.len())
            .field("provenance_bytes", &self.provenance.len())
            .field("capability_policy_bytes", &self.capability_policy.len())
            .field("state_policy_bytes", &self.state_policy.len())
            .field("user_policy_bytes", &self.user_policy.len())
            .finish_non_exhaustive()
    }
}

/// Exact retained executable source consumed by live authorization.
#[must_use = "a retained executable is not authorized until authorize_execution consumes it"]
pub enum RetainedExecutionArtifact<'lease, 'store> {
    /// Manifest-allowlisted executable from an exact package snapshot.
    PackageSnapshot(PackageSnapshotExecutable<'lease, 'store>),
    /// Exact content-addressed executable from a managed materialization manifest.
    ManagedArtifact(ManagedArtifactExecutable<'lease, 'store>),
}

impl fmt::Debug for RetainedExecutionArtifact<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PackageSnapshot(executable) => executable.fmt(formatter),
            Self::ManagedArtifact(executable) => executable.fmt(formatter),
        }
    }
}

impl RetainedExecutionArtifact<'_, '_> {
    fn source(&self) -> ExecutionArtifactSource {
        match self {
            Self::PackageSnapshot(_) => ExecutionArtifactSource::PackageSnapshot,
            Self::ManagedArtifact(_) => ExecutionArtifactSource::ManagedArtifact,
        }
    }

    fn source_digest(&self) -> Sha256Digest {
        match self {
            Self::PackageSnapshot(executable) => executable.package_tree_merkle(),
            Self::ManagedArtifact(executable) => executable.manifest_digest(),
        }
    }

    fn executable_digest(&self) -> Sha256Digest {
        match self {
            Self::PackageSnapshot(executable) => executable.digest(),
            Self::ManagedArtifact(executable) => executable.digest(),
        }
    }

    fn matches_locator(&self, locator: &ExecutionArtifactLocator) -> bool {
        match (self, locator) {
            (
                Self::PackageSnapshot(executable),
                ExecutionArtifactLocator::PackageSnapshot { .. },
            ) => locator
                .package_path()
                .is_some_and(|path| path == executable.normalized_path()),
            (
                Self::ManagedArtifact(executable),
                ExecutionArtifactLocator::ManagedArtifact { .. },
            ) => locator
                .managed_digest()
                .is_some_and(|digest| digest.as_sha256() == &executable.digest()),
            _ => false,
        }
    }

    fn verify_current(&self) -> Result<(), ExecutionAuthorizationError> {
        match self {
            Self::PackageSnapshot(executable) => executable
                .verify_current_view()
                .map_err(|_| ExecutionAuthorizationError::RetainedArtifactCurrentViewInvalid),
            Self::ManagedArtifact(executable) => executable
                .verify_current()
                .map_err(|_| ExecutionAuthorizationError::RetainedArtifactCurrentViewInvalid),
        }
    }

    fn prepare_launch(
        &self,
        arguments: &[OsString],
        limits: ProcessLaunchLimits,
    ) -> io::Result<PreparedProcessLaunch> {
        match self {
            Self::PackageSnapshot(executable) => {
                executable.locked().prepare_launch(arguments, limits)
            }
            Self::ManagedArtifact(executable) => {
                executable.locked().prepare_launch(arguments, limits)
            }
        }
    }
}

enum RetainedExecutionLease<'lease, 'store> {
    PackageSnapshot {
        _lease: &'lease PackageSnapshotLease<'store>,
    },
    ManagedArtifact {
        _lease: &'lease ManagedArtifactLease<'store>,
    },
}

impl RetainedExecutionLease<'_, '_> {
    const fn source(&self) -> ExecutionArtifactSource {
        match self {
            Self::PackageSnapshot { .. } => ExecutionArtifactSource::PackageSnapshot,
            Self::ManagedArtifact { .. } => ExecutionArtifactSource::ManagedArtifact,
        }
    }
}

impl<'lease, 'store> RetainedExecutionArtifact<'lease, 'store> {
    fn into_launch_parts(self) -> (RetainedExecutionLease<'lease, 'store>, LockedExecutable) {
        match self {
            Self::PackageSnapshot(executable) => {
                let (lease, locked) = executable.into_launch_parts();
                (
                    RetainedExecutionLease::PackageSnapshot { _lease: lease },
                    locked,
                )
            }
            Self::ManagedArtifact(executable) => {
                let (lease, locked) = executable.into_launch_parts();
                (
                    RetainedExecutionLease::ManagedArtifact { _lease: lease },
                    locked,
                )
            }
        }
    }
}

/// Named inputs required for one live authorization decision.
pub struct ExecutionAuthorizationRequest<'input, 'overlay, 'authority, 'lease, 'store> {
    /// Structural proof over the exact generated overlay and authority object.
    pub structural_overlay: &'input StructurallyValidatedExecutionOverlay<'overlay, 'authority>,
    /// Exact parsed static target contract.
    pub target_contract: &'input ExecutionTargetContract,
    /// Exact parsed generated resolution evidence.
    pub resolution_evidence: &'input ExecutionResolutionEvidence,
    /// Exact complete compatibility analysis.
    pub compatibility_analysis: &'input CompatibilityAnalysis,
    /// Current mutable local trust and revocation root.
    pub policy_store: &'input LocalExecutionPolicyStore,
    /// Exact policy/trust evidence bytes.
    pub policy_evidence: ExecutionPolicyEvidence<'input>,
    /// Identity-bound retained executable capability.
    pub retained_artifact: RetainedExecutionArtifact<'lease, 'store>,
    /// Evidence hashing limits.
    pub limits: ExecutionAuthorizationLimits,
}

struct PreparedAuthorizedLaunch {
    job_limits: JobLimits,
    process: PreparedProcessLaunch,
}

/// One-shot, non-cloneable, non-serializable live execution authorization capability.
///
/// The compiler rejects attempts to duplicate the capability:
///
/// ```compile_fail
/// use weregopher_transform::AuthorizedExecution;
///
/// fn require_clone<T: Clone>() {}
/// fn check<'policy, 'artifact>() {
///     require_clone::<AuthorizedExecution<'policy, 'artifact>>();
/// }
/// ```
///
/// This value retains the exact executable and its parent lease. It is conditional on the policy
/// generation that issued it; the launch boundary must recheck that generation while consuming it.
#[must_use = "authorization must be consumed by the supervised launch boundary"]
pub struct AuthorizedExecution<'lease, 'store> {
    target_id: ExecutionTargetId,
    trust_mode: TrustMode,
    effective_security_posture: EffectiveSecurityPosture,
    launch_policy: ExecutionLaunchPolicy,
    authorization_context_digest: AuthorizationContextDigest,
    policy_store: Weak<RwLock<ExecutionPolicyState>>,
    policy_generation: u64,
    prepared_launch: PreparedAuthorizedLaunch,
    retained_artifact: RetainedExecutionArtifact<'lease, 'store>,
}

impl fmt::Debug for AuthorizedExecution<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedExecution")
            .field("target_id", &self.target_id)
            .field("trust_mode", &self.trust_mode)
            .field(
                "effective_security_posture",
                &self.effective_security_posture,
            )
            .field("argument_count", &self.launch_policy.arguments().len())
            .field(
                "argument_utf8_bytes",
                &self
                    .launch_policy
                    .arguments()
                    .iter()
                    .map(|argument| argument.as_str().len())
                    .sum::<usize>(),
            )
            .field(
                "required_security_posture",
                &self.launch_policy.required_security_posture(),
            )
            .field("state_mode", &self.launch_policy.state_mode())
            .field("resource_limits", &self.launch_policy.resource_limits())
            .field(
                "authorization_context_digest",
                &self.authorization_context_digest,
            )
            .field("artifact_source", &self.retained_artifact.source())
            .finish_non_exhaustive()
    }
}

impl AuthorizedExecution<'_, '_> {
    /// Returns the exact statically authorized target identifier.
    #[must_use]
    pub const fn target_id(&self) -> &ExecutionTargetId {
        &self.target_id
    }

    /// Returns how the local policy authenticated this execution target.
    #[must_use]
    pub const fn trust_mode(&self) -> TrustMode {
        self.trust_mode
    }

    /// Returns fixed command-line arguments in declared order.
    #[must_use]
    pub fn arguments(&self) -> &[ExecutionArgument] {
        self.launch_policy.arguments()
    }

    /// Returns every exact launch parameter covered by this authorization.
    #[must_use]
    pub const fn launch_policy(&self) -> &ExecutionLaunchPolicy {
        &self.launch_policy
    }

    /// Returns the approved effective security posture.
    #[must_use]
    pub const fn security_posture(&self) -> EffectiveSecurityPosture {
        self.effective_security_posture
    }

    /// Returns the approved state namespace mode.
    #[must_use]
    pub const fn state_mode(&self) -> ExecutionStateMode {
        self.launch_policy.state_mode()
    }

    /// Returns exact process-tree resource limits.
    #[must_use]
    pub const fn resource_limits(&self) -> ExecutionResourceLimits {
        self.launch_policy.resource_limits()
    }

    /// Returns the decision identity binding every authenticated and retained input.
    #[must_use]
    pub const fn authorization_context_digest(&self) -> AuthorizationContextDigest {
        self.authorization_context_digest
    }

    /// Confirms that the issuing policy store still exists, is current, and is not revoked.
    ///
    /// This point-in-time diagnostic check is not a launch operation. The supervised launch boundary
    /// must hold the same policy read lock through final retained-view verification and process setup.
    ///
    /// # Errors
    ///
    /// Returns a policy-currentness error when the store was dropped, replaced, revoked, or poisoned.
    pub fn verify_current_policy(&self) -> Result<(), ExecutionAuthorizationError> {
        let store = self
            .policy_store
            .upgrade()
            .ok_or(ExecutionAuthorizationError::PolicyStoreUnavailable)?;
        let state = store
            .read()
            .map_err(|_| ExecutionAuthorizationError::PolicyStorePoisoned)?;
        verify_policy_state(&state, self.policy_generation)
    }
}

fn verify_policy_state(
    state: &ExecutionPolicyState,
    expected_generation: u64,
) -> Result<(), ExecutionAuthorizationError> {
    if state.revocation_evidence_digest.is_some() {
        return Err(ExecutionAuthorizationError::PolicyRevoked);
    }
    if state.generation != expected_generation {
        return Err(ExecutionAuthorizationError::PolicyChanged);
    }
    Ok(())
}

/// One resumed process tree created by consuming an exact live authorization.
///
/// The complete containing-artifact lease remains borrowed for this owner's lifetime. Dropping the
/// owner closes the kill-on-close Job Object and terminates any surviving process tree.
#[must_use = "dropping the owner terminates its Job-contained process tree"]
pub struct SupervisedExecution<'lease, 'store> {
    process: OwnedJobProcess,
    target_id: ExecutionTargetId,
    trust_mode: TrustMode,
    effective_security_posture: EffectiveSecurityPosture,
    launch_policy: ExecutionLaunchPolicy,
    authorization_context_digest: AuthorizationContextDigest,
    retained_source: RetainedExecutionLease<'lease, 'store>,
    policy_store: Weak<RwLock<ExecutionPolicyState>>,
    policy_generation: u64,
}

impl fmt::Debug for SupervisedExecution<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SupervisedExecution")
            .field("process_id", &self.process.id())
            .field("target_id", &self.target_id)
            .field("trust_mode", &self.trust_mode)
            .field(
                "effective_security_posture",
                &self.effective_security_posture,
            )
            .field("argument_count", &self.launch_policy.arguments().len())
            .field(
                "authorization_context_digest",
                &self.authorization_context_digest,
            )
            .field("artifact_source", &self.retained_source.source())
            .field("job_limits", &self.process.job_limits())
            .finish_non_exhaustive()
    }
}

impl SupervisedExecution<'_, '_> {
    /// Returns the Windows process identifier captured during suspended creation.
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.process.id()
    }

    /// Returns the exact target identifier whose authorization was consumed.
    #[must_use]
    pub const fn target_id(&self) -> &ExecutionTargetId {
        &self.target_id
    }

    /// Returns the authenticated trust mode under which this process was authorized.
    #[must_use]
    pub const fn trust_mode(&self) -> TrustMode {
        self.trust_mode
    }

    /// Returns the effective posture actually implemented by the launch boundary.
    #[must_use]
    pub const fn security_posture(&self) -> EffectiveSecurityPosture {
        self.effective_security_posture
    }

    /// Returns the complete exact launch policy consumed to create this process.
    #[must_use]
    pub const fn launch_policy(&self) -> &ExecutionLaunchPolicy {
        &self.launch_policy
    }

    /// Returns the decision identity bound to this process tree.
    #[must_use]
    pub const fn authorization_context_digest(&self) -> AuthorizationContextDigest {
        self.authorization_context_digest
    }

    /// Returns the exact limits enforced by the owned Job Object.
    #[must_use]
    pub const fn job_limits(&self) -> JobLimits {
        self.process.job_limits()
    }

    /// Rechecks whether the trust and revocation root still permits this running process tree.
    ///
    /// This method does not terminate the process itself. A supervisor must treat every error as a
    /// revocation signal and call [`Self::terminate`] before permitting further privileged effects.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed policy error after revocation, replacement, store loss, or lock poison.
    pub fn verify_current_policy(&self) -> Result<(), ExecutionAuthorizationError> {
        let store = self
            .policy_store
            .upgrade()
            .ok_or(ExecutionAuthorizationError::PolicyStoreUnavailable)?;
        let state = store
            .read()
            .map_err(|_| ExecutionAuthorizationError::PolicyStorePoisoned)?;
        verify_policy_state(&state, self.policy_generation)
    }

    /// Reports whether Windows still associates the primary process with its owned Job Object.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error when membership cannot be queried.
    pub fn is_in_job(&self) -> io::Result<bool> {
        self.process.is_in_job()
    }

    /// Waits for at most `timeout` and returns the primary-process exit code when available.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error when the duration exceeds the Windows timeout range, or the
    /// operating-system error from waiting or querying the process.
    pub fn wait_for(&self, timeout: Duration) -> io::Result<Option<u32>> {
        self.process.wait_for(timeout)
    }

    /// Terminates the complete owned process tree with the supplied exit code.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error when Windows cannot terminate the Job Object.
    pub fn terminate(&self, exit_code: u32) -> io::Result<()> {
        self.process.terminate(exit_code)
    }
}

/// Consumes one current authorization into atomically Job-owned suspended process creation.
///
/// The issuing policy generation is held under a read lock from the final currentness check through
/// retained-view verification, Job creation, process creation, membership verification, and primary
/// thread resume. Format-v2 empty-environment/no-inheritance/no-console/current-directory semantics
/// are implemented by the Windows launch primitive. This initial consumer accepts only
/// [`EffectiveSecurityPosture::VendorEquivalentFullTrust`]; brokered or OS-contained targets require
/// a different enforcing launch boundary.
///
/// The retained executable is moved directly into process creation and is never reopened from an
/// untrusted path. Package directory retention still does not prevent a same-user process from
/// inserting a new child after manifest verification and is not an OS sandbox claim.
///
/// # Errors
///
/// Returns [`SupervisedExecutionError`] without resuming a process when policy, current-view,
/// security-posture, resource-limit, Job creation, or suspended-launch validation fails.
pub fn launch_authorized_execution<'lease, 'store>(
    authorization: AuthorizedExecution<'lease, 'store>,
) -> Result<SupervisedExecution<'lease, 'store>, SupervisedExecutionError> {
    let policy_store = authorization
        .policy_store
        .upgrade()
        .ok_or(ExecutionAuthorizationError::PolicyStoreUnavailable)?;
    let policy_state = policy_store
        .read()
        .map_err(|_| ExecutionAuthorizationError::PolicyStorePoisoned)?;
    verify_policy_state(&policy_state, authorization.policy_generation)?;
    authorization.retained_artifact.verify_current()?;

    let job = KillOnCloseJob::create(authorization.prepared_launch.job_limits)
        .map_err(SupervisedExecutionError::JobCreation)?;
    let AuthorizedExecution {
        target_id,
        trust_mode,
        effective_security_posture,
        launch_policy,
        authorization_context_digest,
        policy_store,
        policy_generation,
        prepared_launch,
        retained_artifact,
    } = authorization;
    let (retained_source, executable) = retained_artifact.into_launch_parts();
    let process = job
        .launch_prepared(executable, prepared_launch.process)
        .map_err(SupervisedExecutionError::ProcessLaunch)?;
    drop(policy_state);

    Ok(SupervisedExecution {
        process,
        target_id,
        trust_mode,
        effective_security_posture,
        launch_policy,
        authorization_context_digest,
        retained_source,
        policy_store,
        policy_generation,
    })
}

/// Failure to consume a live authorization into atomically contained process creation.
#[derive(Debug, Error)]
pub enum SupervisedExecutionError {
    /// The authorization is no longer current or its retained view failed final verification.
    #[error(transparent)]
    Authorization(#[from] ExecutionAuthorizationError),

    /// Windows could not create or configure the required kill-on-close Job Object.
    #[error("authorized Job Object creation failed")]
    JobCreation(#[source] io::Error),
    /// Suspended process creation, atomic Job assignment, verification, or resume failed.
    #[error("authorized suspended process launch failed")]
    ProcessLaunch(#[source] io::Error),
}

/// Authenticates and resolves one exact retained executable into a conditional authorization.
///
/// The returned value is not serializable or cloneable and owns the retained executable capability.
/// It still cannot launch by itself: the supervisor must consume it while holding the issuing policy
/// generation stable through final current-view verification, containment, and suspended creation.
///
/// # Errors
///
/// Returns [`ExecutionAuthorizationError`] on any authority, contract, evidence, compatibility,
/// policy, retained-artifact, revocation, or bounded-input mismatch.
pub fn authorize_execution<'lease, 'store>(
    request: ExecutionAuthorizationRequest<'_, '_, '_, 'lease, 'store>,
) -> Result<AuthorizedExecution<'lease, 'store>, ExecutionAuthorizationError> {
    let snapshot = request.policy_store.snapshot()?;
    if snapshot.revocation_evidence_digest.is_some() {
        return Err(ExecutionAuthorizationError::PolicyRevoked);
    }
    let policy = &snapshot.policy;
    let proof = request.structural_overlay;
    let overlay = proof.overlay();
    let bindings = validate_execution_bindings(
        policy,
        proof,
        request.target_contract,
        request.resolution_evidence,
    )?;

    let launch_policy = request.target_contract.launch_policy();
    let (evidence_digests, compatibility_digest) = validate_policy_evidence(
        policy,
        overlay,
        request.resolution_evidence,
        request.compatibility_analysis,
        launch_policy,
        request.policy_evidence,
        request.limits,
    )?;

    let artifact = request.retained_artifact;
    if artifact.source() != bindings.artifact_source {
        return Err(ExecutionAuthorizationError::RetainedArtifactSourceMismatch);
    }
    if !artifact.matches_locator(request.target_contract.artifact_locator()) {
        return Err(ExecutionAuthorizationError::RetainedArtifactLocatorMismatch);
    }
    let artifact_source_digest = artifact.source_digest();
    if &artifact_source_digest != bindings.artifact_source_digest.as_sha256() {
        return Err(ExecutionAuthorizationError::RetainedArtifactSourceDigestMismatch);
    }
    let executable_digest = artifact.executable_digest();
    if &executable_digest != bindings.executable_digest.as_sha256() {
        return Err(ExecutionAuthorizationError::RetainedExecutableDigestMismatch);
    }

    let prepared_launch = prepare_authorized_launch(&artifact, launch_policy)?;

    artifact.verify_current()?;
    verify_policy_generation(request.policy_store, snapshot.generation)?;

    let authorization_context_digest = authorization_context_digest(
        &bindings.target_id,
        &AuthorizationContextDigests {
            authority_document: bindings.authority_digest,
            target_contract: bindings.contract_digest,
            resolution_evidence: bindings.resolution_digest,
            artifact_source: artifact_source_digest.into(),
            executable: executable_digest.into(),
            compatibility_analysis: compatibility_digest,
            policy_evidence: evidence_digests,
        },
        policy,
        snapshot.generation,
    )?;
    Ok(AuthorizedExecution {
        target_id: bindings.target_id,
        trust_mode: policy.trust_mode,
        effective_security_posture: policy.target.security_posture,
        launch_policy: launch_policy.clone(),
        authorization_context_digest,
        policy_store: Arc::downgrade(&request.policy_store.inner),
        policy_generation: snapshot.generation,
        prepared_launch,
        retained_artifact: artifact,
    })
}

fn prepare_authorized_launch(
    artifact: &RetainedExecutionArtifact<'_, '_>,
    launch_policy: &ExecutionLaunchPolicy,
) -> Result<PreparedAuthorizedLaunch, ExecutionAuthorizationError> {
    if launch_policy.dependency_policy() != ExecutionDependencyPolicy::VendorDefaultAmbient {
        return Err(ExecutionAuthorizationError::UnsupportedDependencyPolicy);
    }
    if launch_policy.state_mode() != ExecutionStateMode::VendorDefault {
        return Err(ExecutionAuthorizationError::UnsupportedStateMode);
    }
    if launch_policy.environment() != ExecutionEnvironmentPolicy::Empty
        || launch_policy.inherited_handles() != ExecutionInheritedHandlePolicy::None
        || launch_policy.console() != ExecutionConsolePolicy::None
        || launch_policy.working_directory() != ExecutionWorkingDirectoryPolicy::ExecutableParent
    {
        return Err(ExecutionAuthorizationError::UnsupportedLaunchSemantics);
    }

    let mut arguments = Vec::new();
    arguments
        .try_reserve_exact(launch_policy.arguments().len())
        .map_err(|_| ExecutionAuthorizationError::UnrepresentableLaunch)?;
    arguments.extend(
        launch_policy
            .arguments()
            .iter()
            .map(|argument| OsString::from(argument.as_str())),
    );
    let process_limits = ProcessLaunchLimits::new(
        MAX_EXECUTION_ARGUMENTS,
        WINDOWS_MAX_SINGLE_VALUE_UNITS,
        WINDOWS_MAX_COMMAND_LINE_UNITS,
    )
    .map_err(|_| ExecutionAuthorizationError::UnrepresentableLaunch)?;
    let process = artifact
        .prepare_launch(&arguments, process_limits)
        .map_err(|_| ExecutionAuthorizationError::UnrepresentableLaunch)?;

    let resources = launch_policy.resource_limits();
    let job_limits = JobLimits::new(
        resources.active_process_limit(),
        resources.process_memory_limit_bytes(),
        resources.job_memory_limit_bytes(),
    )
    .map_err(|_| ExecutionAuthorizationError::UnrepresentableResourceLimits)?;
    Ok(PreparedAuthorizedLaunch {
        job_limits,
        process,
    })
}

struct ValidatedExecutionBindings {
    authority_digest: Sha256Digest,
    target_id: ExecutionTargetId,
    contract_digest: ExecutionContractDigest,
    resolution_digest: ExecutionResolutionEvidenceDigest,
    artifact_source: ExecutionArtifactSource,
    artifact_source_digest: ExecutionArtifactSourceDigest,
    executable_digest: ExecutableDigest,
}

fn validate_execution_bindings(
    policy: &LocalExecutionPolicy,
    proof: &StructurallyValidatedExecutionOverlay<'_, '_>,
    target_contract: &ExecutionTargetContract,
    resolution: &ExecutionResolutionEvidence,
) -> Result<ValidatedExecutionBindings, ExecutionAuthorizationError> {
    let authority = proof.authority();
    if authority.adapter_id() != &policy.authority.adapter_id
        || authority.family() != &policy.authority.family
        || authority.adapter_content_digest() != &policy.authority.adapter_content_digest
    {
        return Err(ExecutionAuthorizationError::AuthorityIdentityMismatch);
    }
    let authority_digest = authority.canonical_document_digest();
    if authority_digest != policy.authority.authority_document_digest {
        return Err(ExecutionAuthorizationError::AuthorityDigestMismatch);
    }
    let overlay_context = proof.overlay().binding();
    if overlay_context.source_build_fingerprint_digest()
        != &policy.context.source_build_fingerprint_digest
    {
        return Err(ExecutionAuthorizationError::SourceBuildContextMismatch);
    }
    if overlay_context.package_tree_merkle() != &policy.context.package_tree_merkle {
        return Err(ExecutionAuthorizationError::PackageTreeContextMismatch);
    }
    if overlay_context.execution_environment_digest()
        != &policy.context.execution_environment_digest
    {
        return Err(ExecutionAuthorizationError::ExecutionEnvironmentContextMismatch);
    }
    if overlay_context.build_descriptor_digest() != &policy.context.build_descriptor_digest {
        return Err(ExecutionAuthorizationError::BuildDescriptorContextMismatch);
    }

    let target_id = target_contract.target_id();
    if target_id != &policy.target.target_id {
        return Err(ExecutionAuthorizationError::TargetPolicyMismatch);
    }
    let static_target = authority
        .targets()
        .get(target_id)
        .ok_or(ExecutionAuthorizationError::UnknownTarget)?;
    let generated_binding = proof
        .overlay()
        .bindings()
        .get(target_id)
        .ok_or(ExecutionAuthorizationError::UnknownTarget)?;
    let contract_digest = target_contract
        .canonical_document_digest()
        .map_err(|_| ExecutionAuthorizationError::CanonicalSerializationFailed)?;
    if contract_digest != policy.target.target_contract_digest
        || static_target.execution_contract_digest() != &contract_digest
        || generated_binding.execution_contract_digest() != &contract_digest
    {
        return Err(ExecutionAuthorizationError::TargetContractDigestMismatch);
    }
    if target_contract.kind() != static_target.kind() {
        return Err(ExecutionAuthorizationError::TargetKindMismatch);
    }
    let locator = target_contract.artifact_locator();
    if locator.artifact_source() != static_target.artifact_source() {
        return Err(ExecutionAuthorizationError::ArtifactSourceMismatch);
    }

    let resolution_digest = resolution
        .canonical_document_digest()
        .map_err(|_| ExecutionAuthorizationError::CanonicalSerializationFailed)?;
    if resolution_digest != policy.target.resolution_evidence_digest
        || generated_binding.resolution_evidence_digest() != &resolution_digest
    {
        return Err(ExecutionAuthorizationError::ResolutionEvidenceDigestMismatch);
    }
    if resolution.target_id() != target_id {
        return Err(ExecutionAuthorizationError::ResolutionTargetMismatch);
    }
    if resolution.artifact_locator() != locator {
        return Err(ExecutionAuthorizationError::ResolutionLocatorMismatch);
    }
    let resolution_digests = resolution.digests();
    if resolution_digests.execution_contract_digest != contract_digest {
        return Err(ExecutionAuthorizationError::ResolutionContractMismatch);
    }
    if generated_binding.artifact_source_digest() != &resolution_digests.artifact_source_digest {
        return Err(ExecutionAuthorizationError::ResolutionArtifactSourceMismatch);
    }
    if generated_binding.executable_digest() != &resolution_digests.executable_digest {
        return Err(ExecutionAuthorizationError::ResolutionExecutableMismatch);
    }
    Ok(ValidatedExecutionBindings {
        authority_digest,
        target_id: target_id.clone(),
        contract_digest,
        resolution_digest,
        artifact_source: static_target.artifact_source(),
        artifact_source_digest: resolution_digests.artifact_source_digest,
        executable_digest: resolution_digests.executable_digest,
    })
}

fn validate_policy_evidence(
    policy: &LocalExecutionPolicy,
    overlay: &GeneratedExecutionOverlay,
    resolution: &ExecutionResolutionEvidence,
    compatibility: &CompatibilityAnalysis,
    launch_policy: &ExecutionLaunchPolicy,
    evidence: ExecutionPolicyEvidence<'_>,
    limits: ExecutionAuthorizationLimits,
) -> Result<(PolicyEvidenceDigests, CompatibilityAnalysisDigest), ExecutionAuthorizationError> {
    let evidence_digests = hash_policy_evidence(evidence, limits)?;
    let resolution_digests = resolution.digests();
    if evidence_digests.artifact_trust != resolution_digests.artifact_trust_evidence_digest
        || evidence_digests.artifact_trust != policy.target.artifact_trust_evidence_digest
    {
        return Err(ExecutionAuthorizationError::ArtifactTrustEvidenceMismatch);
    }
    if evidence_digests.provenance != resolution_digests.provenance_evidence_digest
        || evidence_digests.provenance != policy.target.provenance_evidence_digest
    {
        return Err(ExecutionAuthorizationError::ProvenanceEvidenceMismatch);
    }

    let required = launch_policy.policy_requirements();
    let compatibility_digest = CompatibilityAnalysisDigest::new(canonical_digest(compatibility)?);
    if compatibility_digest != policy.target.compatibility_analysis_digest {
        return Err(ExecutionAuthorizationError::CompatibilityDigestMismatch);
    }
    if compatibility.disposition() != AnalysisDisposition::Complete {
        return Err(ExecutionAuthorizationError::CompatibilityDenied);
    }
    if compatibility.source_build_fingerprint_digest()
        != overlay.binding().source_build_fingerprint_digest()
    {
        return Err(ExecutionAuthorizationError::CompatibilitySourceMismatch);
    }
    if compatibility.target().execution_environment_digest()
        != overlay.binding().execution_environment_digest()
    {
        return Err(ExecutionAuthorizationError::CompatibilityEnvironmentMismatch);
    }
    if evidence_digests.capability_policy != required.capability_policy_digest
        || evidence_digests.capability_policy != policy.target.capability_policy_digest
    {
        return Err(ExecutionAuthorizationError::CapabilityPolicyMismatch);
    }
    if evidence_digests.state_policy != required.state_policy_digest
        || evidence_digests.state_policy != policy.target.state_policy_digest
    {
        return Err(ExecutionAuthorizationError::StatePolicyMismatch);
    }
    if evidence_digests.user_policy != policy.target.user_policy_digest {
        return Err(ExecutionAuthorizationError::UserPolicyMismatch);
    }
    if !launch_policy
        .required_security_posture()
        .is_satisfied_by(policy.target.security_posture)
    {
        return Err(ExecutionAuthorizationError::SecurityPostureMismatch);
    }
    if launch_policy.state_mode() != policy.target.state_mode {
        return Err(ExecutionAuthorizationError::StateModeMismatch);
    }
    Ok((evidence_digests, compatibility_digest))
}

#[derive(Clone, Copy)]
struct PolicyEvidenceDigests {
    artifact_trust: ArtifactTrustEvidenceDigest,
    provenance: ProvenanceEvidenceDigest,
    capability_policy: CapabilityPolicyDigest,
    state_policy: StatePolicyDigest,
    user_policy: UserPolicyDigest,
}

impl PolicyEvidenceDigests {
    fn into_sha256_array(self) -> [Sha256Digest; 5] {
        [
            self.artifact_trust.into_sha256(),
            self.provenance.into_sha256(),
            self.capability_policy.into_sha256(),
            self.state_policy.into_sha256(),
            self.user_policy.into_sha256(),
        ]
    }
}

fn hash_policy_evidence(
    evidence: ExecutionPolicyEvidence<'_>,
    limits: ExecutionAuthorizationLimits,
) -> Result<PolicyEvidenceDigests, ExecutionAuthorizationError> {
    let values = [
        evidence.artifact_trust,
        evidence.provenance,
        evidence.capability_policy,
        evidence.state_policy,
        evidence.user_policy,
    ];
    let mut total = 0_usize;
    for value in values {
        if value.len() > limits.max_evidence_bytes {
            return Err(ExecutionAuthorizationError::EvidenceByteLimitExceeded);
        }
        total = total
            .checked_add(value.len())
            .ok_or(ExecutionAuthorizationError::EvidenceByteCountOverflow)?;
        if total > limits.max_total_evidence_bytes {
            return Err(ExecutionAuthorizationError::AggregateEvidenceByteLimitExceeded);
        }
    }
    Ok(PolicyEvidenceDigests {
        artifact_trust: digest(evidence.artifact_trust).into(),
        provenance: digest(evidence.provenance).into(),
        capability_policy: digest(evidence.capability_policy).into(),
        state_policy: digest(evidence.state_policy).into(),
        user_policy: digest(evidence.user_policy).into(),
    })
}

fn canonical_digest<T: serde::Serialize>(
    value: &T,
) -> Result<Sha256Digest, ExecutionAuthorizationError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| ExecutionAuthorizationError::CanonicalSerializationFailed)?;
    Ok(digest(&bytes))
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn verify_policy_generation(
    store: &LocalExecutionPolicyStore,
    generation: u64,
) -> Result<(), ExecutionAuthorizationError> {
    let state = store
        .inner
        .read()
        .map_err(|_| ExecutionAuthorizationError::PolicyStorePoisoned)?;
    if state.revocation_evidence_digest.is_some() {
        return Err(ExecutionAuthorizationError::PolicyRevoked);
    }
    if state.generation != generation {
        return Err(ExecutionAuthorizationError::PolicyChanged);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct AuthorizationContextDigests {
    authority_document: Sha256Digest,
    target_contract: ExecutionContractDigest,
    resolution_evidence: ExecutionResolutionEvidenceDigest,
    artifact_source: ExecutionArtifactSourceDigest,
    executable: ExecutableDigest,
    compatibility_analysis: CompatibilityAnalysisDigest,
    policy_evidence: PolicyEvidenceDigests,
}

fn authorization_context_digest(
    target_id: &ExecutionTargetId,
    digests: &AuthorizationContextDigests,
    policy: &LocalExecutionPolicy,
    generation: u64,
) -> Result<AuthorizationContextDigest, ExecutionAuthorizationError> {
    let target_length = u64::try_from(target_id.as_str().len())
        .map_err(|_| ExecutionAuthorizationError::AuthorizationContextEncodingFailed)?;
    let mut hasher = Sha256::new();
    hasher.update(b"weregopher-live-execution-authorization-v1\0");
    hasher.update(target_length.to_le_bytes());
    hasher.update(target_id.as_str().as_bytes());
    for value in [
        digests.authority_document,
        policy.context.source_build_fingerprint_digest,
        policy.context.package_tree_merkle,
        policy.context.execution_environment_digest,
        policy.context.build_descriptor_digest,
    ] {
        hasher.update(value.as_bytes());
    }
    for value in [
        digests.target_contract.as_sha256(),
        digests.resolution_evidence.as_sha256(),
        digests.artifact_source.as_sha256(),
        digests.executable.as_sha256(),
        digests.compatibility_analysis.as_sha256(),
    ] {
        hasher.update(value.as_bytes());
    }
    for value in digests.policy_evidence.into_sha256_array() {
        hasher.update(value.as_bytes());
    }
    hasher.update(policy.revision_digest.as_bytes());
    hasher.update(generation.to_le_bytes());
    hasher.update([match policy.trust_mode {
        TrustMode::RegistryTrusted => 0,
        TrustMode::LocallyTrusted => 1,
        TrustMode::Developer => 2,
        TrustMode::ForensicOverride => 3,
    }]);
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()).into())
}

/// Failure constructing policy state or issuing/rechecking a live execution authorization.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ExecutionAuthorizationError {
    /// Caller-selected evidence limits were zero.
    #[error("execution authorization evidence limits must be nonzero")]
    InvalidLimits,
    /// Caller-selected evidence limits attempted to exceed a hard implementation ceiling.
    #[error("execution authorization evidence limits exceed the implementation maximum")]
    EvidenceLimitsExceedImplementationMaximum,
    /// One evidence artifact exceeded its byte limit.
    #[error("execution authorization evidence exceeds its per-artifact byte limit")]
    EvidenceByteLimitExceeded,
    /// Evidence byte accounting overflowed.
    #[error("execution authorization evidence byte count overflowed")]
    EvidenceByteCountOverflow,
    /// Aggregate evidence bytes exceeded their limit.
    #[error("execution authorization evidence exceeds its aggregate byte limit")]
    AggregateEvidenceByteLimitExceeded,
    /// The selected trust mode requires a trust engine outside this local-policy boundary.
    #[error("execution authorization trust mode is not supported by local policy")]
    UnsupportedTrustMode,
    /// The local authorizer has no launch mechanism that can establish the approved posture.
    #[error("execution security posture is not supported by the local launch boundary")]
    UnsupportedSecurityPosture,
    /// Fixed launch semantics cannot be implemented by the local Windows launch boundary.
    #[error("execution target requires unsupported launch semantics")]
    UnsupportedLaunchSemantics,
    /// The target requires a state namespace that this low-level launch boundary does not retain.
    #[error("execution target requires an unsupported state namespace mode")]
    UnsupportedStateMode,
    /// The target requires a closed dependency namespace that this launch boundary cannot seal.
    #[error("execution target requires an unsupported dependency namespace policy")]
    UnsupportedDependencyPolicy,
    /// The exact executable path and quoted arguments cannot be represented by `CreateProcessW`.
    #[error("execution target cannot be represented as a bounded Windows process launch")]
    UnrepresentableLaunch,
    /// Exact resource limits cannot be represented by the Windows Job primitive.
    #[error("execution target resource limits cannot be represented by the Windows Job primitive")]
    UnrepresentableResourceLimits,
    /// Unsigned developer execution requested production state.
    #[error("developer execution requires disposable state")]
    DeveloperModeRequiresDisposableState,
    /// The policy store synchronization primitive was poisoned.
    #[error("execution authorization policy store is poisoned")]
    PolicyStorePoisoned,
    /// The policy generation counter cannot advance safely.
    #[error("execution authorization policy generation is exhausted")]
    PolicyGenerationExhausted,
    /// The issuing policy store no longer exists.
    #[error("execution authorization policy store is no longer available")]
    PolicyStoreUnavailable,
    /// Current policy revokes the target.
    #[error("execution authorization policy is revoked")]
    PolicyRevoked,
    /// Policy changed after this authorization was issued.
    #[error("execution authorization policy generation changed")]
    PolicyChanged,
    /// Adapter, family, or adapter-content identity did not match local trust pins.
    #[error("execution authority identity does not match local policy")]
    AuthorityIdentityMismatch,
    /// The canonical authority document did not match the authenticated local pin.
    #[error("execution authority document does not match local policy")]
    AuthorityDigestMismatch,
    /// The generated evidence covered a different source build than local policy.
    #[error("execution source-build context does not match local policy")]
    SourceBuildContextMismatch,
    /// The generated evidence covered a different source package tree than local policy.
    #[error("execution package-tree context does not match local policy")]
    PackageTreeContextMismatch,
    /// The generated evidence covered a different environment than local policy.
    #[error("execution environment context does not match local policy")]
    ExecutionEnvironmentContextMismatch,
    /// The generated evidence covered a different build descriptor than local policy.
    #[error("execution build-descriptor context does not match local policy")]
    BuildDescriptorContextMismatch,
    /// The target selected a different local-policy entry.
    #[error("execution target does not match local policy")]
    TargetPolicyMismatch,
    /// The exact target is absent from authority or generated bindings.
    #[error("execution target is not present in exact authority and generated evidence")]
    UnknownTarget,
    /// Static, generated, resolved, or locally pinned target-contract identity differed.
    #[error("execution target contract identity mismatch")]
    TargetContractDigestMismatch,
    /// The parsed target kind differed from static authority.
    #[error("execution target kind mismatch")]
    TargetKindMismatch,
    /// The parsed locator source differed from static authority.
    #[error("execution artifact source mismatch")]
    ArtifactSourceMismatch,
    /// Generated resolution-evidence bytes differed from generated or locally pinned identity.
    #[error("execution resolution evidence identity mismatch")]
    ResolutionEvidenceDigestMismatch,
    /// Resolution evidence selected a different target.
    #[error("execution resolution target mismatch")]
    ResolutionTargetMismatch,
    /// Resolution evidence selected a different locator.
    #[error("execution resolution locator mismatch")]
    ResolutionLocatorMismatch,
    /// Resolution evidence selected a different static contract.
    #[error("execution resolution contract mismatch")]
    ResolutionContractMismatch,
    /// Resolution and generated evidence selected different containing artifacts.
    #[error("execution resolution artifact-source identity mismatch")]
    ResolutionArtifactSourceMismatch,
    /// Resolution and generated evidence selected different executable bytes.
    #[error("execution resolution executable identity mismatch")]
    ResolutionExecutableMismatch,
    /// Supplied artifact trust evidence did not match resolution and local policy.
    #[error("execution artifact trust evidence mismatch")]
    ArtifactTrustEvidenceMismatch,
    /// Supplied artifact provenance did not match resolution and local policy.
    #[error("execution artifact provenance evidence mismatch")]
    ProvenanceEvidenceMismatch,
    /// Complete compatibility analysis did not match target and local policy.
    #[error("execution compatibility-analysis identity mismatch")]
    CompatibilityDigestMismatch,
    /// Compatibility analysis was incomplete or blocked.
    #[error("execution compatibility analysis does not permit execution")]
    CompatibilityDenied,
    /// Compatibility analysis covered a different source build.
    #[error("execution compatibility analysis references a different source build")]
    CompatibilitySourceMismatch,
    /// Compatibility analysis covered a different execution environment.
    #[error("execution compatibility analysis references a different environment")]
    CompatibilityEnvironmentMismatch,
    /// Supplied capability policy differed from target and local policy.
    #[error("execution capability policy mismatch")]
    CapabilityPolicyMismatch,
    /// Supplied state policy differed from target and local policy.
    #[error("execution state policy mismatch")]
    StatePolicyMismatch,
    /// Supplied user policy differed from target and local policy.
    #[error("execution user policy mismatch")]
    UserPolicyMismatch,
    /// Effective security posture differed from local policy.
    #[error("execution security posture mismatch")]
    SecurityPostureMismatch,
    /// State namespace mode differed from local policy.
    #[error("execution state mode mismatch")]
    StateModeMismatch,
    /// Retained executable capability came from a different source kind.
    #[error("retained executable source does not match authority")]
    RetainedArtifactSourceMismatch,
    /// Retained executable capability did not match the exact locator.
    #[error("retained executable locator mismatch")]
    RetainedArtifactLocatorMismatch,
    /// Retained executable capability came from a different package tree or manifest.
    #[error("retained executable containing-artifact identity mismatch")]
    RetainedArtifactSourceDigestMismatch,
    /// Retained executable bytes had a different digest.
    #[error("retained executable byte identity mismatch")]
    RetainedExecutableDigestMismatch,
    /// Immediate current-view verification failed.
    #[error("retained executable current-view verification failed")]
    RetainedArtifactCurrentViewInvalid,
    /// Canonical serialization failed.
    #[error("execution authorization canonical serialization failed")]
    CanonicalSerializationFailed,
    /// A bounded identity could not be encoded into the authorization context.
    #[error("execution authorization context encoding failed")]
    AuthorizationContextEncodingFailed,
}
