//! Canonical platform-neutral Weregopher contracts.
//!
//! Public serialized types are defined here and generate the external schemas.

#![forbid(unsafe_code)]

mod build;
mod candidate;
mod certification;
mod certification_evidence;
mod certification_runner;
mod compatibility;
mod digest;
mod discovery;
mod execution;
mod execution_digest;
mod execution_target;
mod ids;
mod protocol;
mod security;
mod transformation;

pub use build::{Architecture, BuildFingerprint, InstallationKind, PackageIdentity};
pub use candidate::{
    CandidateChannelHint, CandidateProfile, CandidateTarget, initial_candidate_profiles,
};
pub use certification::{CertificationClass, PublicationStatus, TrustMode};
pub use certification_evidence::{
    CERTIFICATION_EVIDENCE_FORMAT_VERSION, CERTIFICATION_FIXED_CHECK_COUNT,
    CERTIFICATION_PROFILE_FORMAT_VERSION, CertificationArtifactDigest, CertificationArtifactKind,
    CertificationArtifactRef, CertificationCheckAssessment, CertificationCheckDimension,
    CertificationCheckStatus, CertificationChecks, CertificationContractError,
    CertificationDocumentError, CertificationEvidence, CertificationEvidenceDigest,
    CertificationEvidenceDisposition, CertificationExpectedStatus, CertificationProfile,
    CertificationProfileChecks, CertificationProfileClass, CertificationProfileDigest,
    CertificationProfileValidationError, CertificationTarget, MAX_CERTIFICATION_DOCUMENT_BYTES,
    MAX_CERTIFICATION_EVIDENCE_REFS, MAX_CERTIFICATION_PROFILE_DOCUMENT_BYTES,
    MAX_CERTIFICATION_WORKFLOWS, StructurallyValidatedCertificationEvidence,
};
pub use certification_runner::{
    CERTIFICATION_RUNNER_IDENTITY_FORMAT_VERSION, CertificationElectronRuntimeDigest,
    CertificationExceptionProvenanceDigest, CertificationHostAgentDigest,
    CertificationHostImageDigest, CertificationHostPatchSetDigest,
    CertificationLanguageRuntimeSetDigest, CertificationProbeAssetSetDigest,
    CertificationRunnerArchitecture, CertificationRunnerDocumentError,
    CertificationRunnerEnvironmentIdentity, CertificationRunnerIdentity,
    CertificationRunnerIdentityDigest, CertificationRunnerImageDigest, CertificationRunnerPlatform,
    CertificationRunnerProvenanceIdentity, CertificationRunnerToolingIdentity,
    CertificationSourceRevisionDigest, CertificationToolchainSetDigest,
    CertificationVerifierDigest, MAX_CERTIFICATION_RUNNER_IDENTITY_DOCUMENT_BYTES,
};
pub use compatibility::{
    AnalysisDisposition, COMPATIBILITY_ANALYSIS_FORMAT_VERSION, CompatibilityAnalysis,
    CompatibilityArchitecture, CompatibilityContractError, CompatibilityDimensions,
    CompatibilityEvidenceKind, CompatibilityEvidenceRef, CompatibilityPlatform,
    CompatibilityTarget, DimensionAssessment, DimensionStatus, MAX_COMPATIBILITY_EVIDENCE_REFS,
    MAX_COMPATIBILITY_WORKFLOWS,
};
pub use digest::{Sha256Digest, Sha256DigestError};
pub use discovery::{
    CandidateInstallationEvidence, DerivedValue, DiscoveryConfidence, DiscoverySource,
};
pub use execution::{
    AdapterExecutionAuthority, AuthorizedExecutionTargetRef, EXECUTION_REBINDING_FORMAT_VERSION,
    ExecutionArchitecture, ExecutionArtifactBinding, ExecutionArtifactDigests,
    ExecutionArtifactSource, ExecutionAuthorityBinding, ExecutionContractError,
    ExecutionOverlayBinding, ExecutionOverlayContext, ExecutionPlatform, ExecutionTargetKind,
    GeneratedExecutionOverlay, MAX_AUTHORIZED_EXECUTION_TARGETS, MAX_GENERATED_EXECUTION_BINDINGS,
    StructurallyValidatedExecutionOverlay,
};
pub use execution_digest::{
    ArtifactTrustEvidenceDigest, AuthorizationContextDigest, CapabilityPolicyDigest,
    CompatibilityAnalysisDigest, ExecutableDigest, ExecutionArtifactSourceDigest,
    ExecutionContractDigest, ExecutionResolutionEvidenceDigest, ProvenanceEvidenceDigest,
    StatePolicyDigest, UserPolicyDigest,
};
pub use execution_target::{
    EXECUTION_RESOLUTION_FORMAT_VERSION, EXECUTION_TARGET_CONTRACT_FORMAT_VERSION,
    ExecutionArgument, ExecutionArtifactLocator, ExecutionConsolePolicy,
    ExecutionContractParseError, ExecutionDependencyPolicy, ExecutionEnvironmentPolicy,
    ExecutionInheritedHandlePolicy, ExecutionLaunchPolicy, ExecutionPackagePath,
    ExecutionPolicyRequirements, ExecutionResolutionDigests, ExecutionResolutionEvidence,
    ExecutionResourceLimits, ExecutionStateMode, ExecutionTargetContract,
    ExecutionTargetContractError, ExecutionWorkingDirectoryPolicy,
    MAX_EXECUTION_ARGUMENT_AGGREGATE_BYTES, MAX_EXECUTION_ARGUMENT_BYTES, MAX_EXECUTION_ARGUMENTS,
    MAX_EXECUTION_PACKAGE_PATH_BYTES, MAX_EXECUTION_PACKAGE_PATH_COMPONENTS,
    MAX_EXECUTION_RESOLUTION_DOCUMENT_BYTES, MAX_EXECUTION_TARGET_DOCUMENT_BYTES,
    RequiredSecurityPosture,
};
pub use ids::{
    AdapterId, AppInstanceId, ApplicationFamilyId, BuildId, CapabilityGrantId, ExecutionTargetId,
    FeatureId, IdentifierError, ObjectId, ProfileId, ProtocolSessionId, RendererId, RuntimeId,
    ScenarioId, SourceUnitId, TraceId, TransformRuleId, UserActivationId, WindowId,
};
pub use protocol::{
    BufferStorage, CallAuthority, CallContext, ContentBlobId, FRAME_HEADER_LEN, FrameHeader,
    FrameHeaderError, FrameIdentity, MessageKind, MessagePortHandle, ObjectHandle, ObjectKind,
    OpaqueHandle, OriginIdentity, ProtocolLimitError, ProtocolLimits, RemoteFunctionHandle,
    RemotePromiseHandle, ScriptWorldKind, SharedBufferHandle, StreamHandle, TypedArrayKind,
    WireError, WireObjectEntry, WireValue, WorldIdentity,
};
pub use security::EffectiveSecurityPosture;
pub use transformation::{
    AdapterTransformAuthority, AuthorizedTransformRuleRef, GeneratedTransformOverlay,
    MAX_AUTHORIZED_TRANSFORM_RULES, MAX_GENERATED_TRANSFORM_REBINDINGS, SourceUnitRef,
    StructurallyValidatedTransformOverlay, TRANSFORM_REBINDING_FORMAT_VERSION,
    TransformArchitecture, TransformContractError, TransformOverlayBinding, TransformPlatform,
    TransformRebinding,
};
