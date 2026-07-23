//! Canonical platform-neutral Weregopher contracts.
//!
//! Public serialized types are defined here and generate the external schemas.

#![forbid(unsafe_code)]

mod build;
mod candidate;
mod certification;
mod compatibility;
mod digest;
mod discovery;
mod execution;
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
pub use execution_target::{
    EXECUTION_RESOLUTION_FORMAT_VERSION, EXECUTION_TARGET_CONTRACT_FORMAT_VERSION,
    ExecutionArgument, ExecutionArtifactLocator, ExecutionConsolePolicy,
    ExecutionEnvironmentPolicy, ExecutionInheritedHandlePolicy, ExecutionLaunchPolicy,
    ExecutionPolicyDigests, ExecutionResolutionDigests, ExecutionResolutionEvidence,
    ExecutionResourceLimits, ExecutionStateMode, ExecutionTargetContract,
    ExecutionTargetContractError, ExecutionWorkingDirectoryPolicy,
    MAX_EXECUTION_ARGUMENT_AGGREGATE_BYTES, MAX_EXECUTION_ARGUMENT_BYTES, MAX_EXECUTION_ARGUMENTS,
    MAX_EXECUTION_PACKAGE_PATH_BYTES, MAX_EXECUTION_PACKAGE_PATH_COMPONENTS,
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
