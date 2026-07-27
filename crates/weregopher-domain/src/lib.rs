//! Canonical platform-neutral Weregopher contracts.
//!
//! Public serialized types are defined here and generate the external schemas.

#![forbid(unsafe_code)]

mod build;
mod candidate;
mod certification;
mod certification_control_plane;
mod certification_evidence;
mod certification_runner;
mod certification_scenario;
mod compatibility;
mod digest;
mod discovery;
mod execution;
mod execution_digest;
mod execution_target;
mod g2;
mod ids;
mod protocol;
mod renderer;
mod runtime_protocol;
mod security;
mod transformation;

pub use build::{Architecture, BuildFingerprint, InstallationKind, PackageIdentity};
pub use candidate::{
    CandidateChannelHint, CandidateProfile, CandidateTarget, initial_candidate_profiles,
};
pub use certification::{CertificationClass, PublicationStatus, TrustMode};
pub use certification_control_plane::{
    BoundedDocumentReadError, CERTIFICATION_RUNNER_COMPONENT_DESCRIPTOR_FORMAT_VERSION,
    CertificationArtifactSetDigest, CertificationControlPolicy, CertificationPolicyRevisionDigest,
    CertificationPolicyRevocationDigest, CertificationRunAttestationDocumentError,
    CertificationRunAttestationError, CertificationRunFreshness, CertificationRunResultIdentity,
    CertificationRunRunnerIdentity, CertificationRunnerArtifactName,
    CertificationRunnerComponentArtifact, CertificationRunnerComponentDescriptor,
    CertificationRunnerComponentDescriptorDigest, CertificationRunnerComponentDescriptorError,
    CertificationRunnerComponentDocumentError, CertificationRunnerComponentId,
    CertificationRunnerComponentProvenanceDigest, CertificationRunnerComponentRole,
    CertificationRunnerComponentTextError, CertificationRunnerComponentVersion,
    CertificationRunnerDescriptorSetDigest, CertificationRunnerPolicyRevisionDigest,
    CertificationRunnerPolicyRevocationDigest, LOCAL_CERTIFICATION_LEDGER_RECORD_FORMAT_VERSION,
    LOCAL_CERTIFICATION_RUN_ATTESTATION_FORMAT_VERSION,
    LocalCertificationLedgerCertificationRevocation, LocalCertificationLedgerContractError,
    LocalCertificationLedgerDocumentError, LocalCertificationLedgerEvent,
    LocalCertificationLedgerGenesis, LocalCertificationLedgerPolicyReplacement,
    LocalCertificationLedgerPublication, LocalCertificationLedgerReceipt,
    LocalCertificationLedgerRecord, LocalCertificationLedgerRecordDigest,
    LocalCertificationLedgerRunnerRevocation, LocalCertificationRunAttestation,
    LocalCertificationRunAttestationDigest, MAX_CERTIFICATION_RUNNER_COMPONENT_ARTIFACT_BYTES,
    MAX_CERTIFICATION_RUNNER_COMPONENT_ARTIFACT_NAME_BYTES,
    MAX_CERTIFICATION_RUNNER_COMPONENT_ARTIFACTS,
    MAX_CERTIFICATION_RUNNER_COMPONENT_DESCRIPTOR_BYTES,
    MAX_CERTIFICATION_RUNNER_COMPONENT_TEXT_BYTES, MAX_LOCAL_CERTIFICATION_LEDGER_BYTES,
    MAX_LOCAL_CERTIFICATION_LEDGER_RECORD_BYTES, MAX_LOCAL_CERTIFICATION_LEDGER_RECORDS,
    MAX_LOCAL_CERTIFICATION_RUN_ATTESTATION_BYTES, MAX_LOCAL_CERTIFICATION_RUN_FRESHNESS_MILLIS,
};
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
pub use certification_scenario::{
    DISPOSABLE_CERTIFICATION_SCENARIO_FORMAT_VERSION,
    DISPOSABLE_CERTIFICATION_SCENARIO_REPORT_FORMAT_VERSION, DisposableCertificationScenario,
    DisposableCertificationScenarioDigest, DisposableCertificationScenarioDocumentError,
    DisposableCertificationScenarioError, DisposableCertificationScenarioReport,
    DisposableCertificationScenarioReportDigest,
    DisposableCertificationScenarioReportDocumentError, DisposableCertificationScenarioReportError,
    DisposableScenarioArgument, DisposableScenarioExecution,
    DisposableScenarioExecutionObservation, DisposableScenarioLimits,
    DisposableScenarioPackageObservation, DisposableScenarioStateRoot,
    DisposableScenarioStateRootKind, DisposableScenarioSuccessFileObservation,
    MAX_DISPOSABLE_CERTIFICATION_SCENARIO_BYTES,
    MAX_DISPOSABLE_CERTIFICATION_SCENARIO_REPORT_BYTES, MAX_DISPOSABLE_SCENARIO_ARGUMENTS,
    MAX_DISPOSABLE_SCENARIO_COMMAND_LINE_UTF16_UNITS, MAX_DISPOSABLE_SCENARIO_LAUNCH_ARGUMENTS,
    MAX_DISPOSABLE_SCENARIO_POLL_MILLIS, MAX_DISPOSABLE_SCENARIO_SHUTDOWN_MILLIS,
    MAX_DISPOSABLE_SCENARIO_STATE_ROOTS, MAX_DISPOSABLE_SCENARIO_SUCCESS_FILE_BYTES,
    MAX_DISPOSABLE_SCENARIO_TIMEOUT_MILLIS,
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
pub use g2::{
    AppServerProbeChecks, AppServerProbeReport, G2_FEASIBILITY_FORMAT_VERSION, G2ComponentEvidence,
    G2ComponentSource, G2ContractError, G2FeasibilityDisposition, G2FeasibilityReport,
    G2GateEvidence, G2GateStatus, G2PackagePath, G2ProbeScope, G2Target,
    MAX_G2_BACKEND_VERSION_BYTES, MAX_G2_PACKAGE_PATH_BYTES, MAX_G2_PACKAGE_PATH_COMPONENTS,
    MAX_G2_PRELOAD_ENTRIES, MAX_G2_RENDERER_ENTRIES, OpenAiPackageInventory, PreloadBridgeChecks,
    PreloadBridgeProbeReport,
};
pub use ids::{
    AdapterId, AppInstanceId, ApplicationFamilyId, BuildId, CapabilityGrantId, ExecutionTargetId,
    FeatureId, IdentifierError, ObjectId, ProfileId, ProtocolSessionId, RendererId,
    RuntimeBackendId, RuntimeId, ScenarioId, ScenarioStateRootId, SourceUnitId, TraceId,
    TransformRuleId, UserActivationId, WindowId,
};
pub use protocol::{
    BufferStorage, CallAuthority, CallContext, ContentBlobId, FRAME_HEADER_LEN, FrameHeader,
    FrameHeaderError, FrameIdentity, MessageKind, MessagePortHandle, ObjectHandle, ObjectKind,
    OpaqueHandle, OriginIdentity, ProtocolLimitError, ProtocolLimits, RemoteFunctionHandle,
    RemotePromiseHandle, ScriptWorldKind, SharedBufferHandle, StreamHandle, TypedArrayKind,
    WireError, WireObjectEntry, WireValue, WorldIdentity,
};
pub use renderer::{
    MAX_RENDERER_BRIDGE_ERROR_BYTES, MAX_RENDERER_BRIDGE_NAME_BYTES, RENDERER_BRIDGE_NONCE_BYTES,
    RendererBridgeFailure, RendererBridgeInvocation, RendererBridgeNonce, RendererBridgeReply,
    RendererContractError, RendererEnvelope,
};
pub use runtime_protocol::{
    CallTarget, G1_PROTOCOL_MAJOR, G1_PROTOCOL_MINOR, HeartbeatPolicy,
    MAX_PROTOCOL_BACKEND_VERSION_BYTES, MAX_PROTOCOL_REJECT_DETAIL_BYTES, ProtocolFeatures,
    ProtocolReject, ProtocolRejectCode, ProtocolVersion, ProtocolVersionRange,
    RuntimeBackendIdentity, RuntimeCall, RuntimeCallError, RuntimeCallResult, RuntimeCancel,
    RuntimeEvent, RuntimeHello, RuntimeProtocolContractError, RuntimeShutdown,
    RuntimeShutdownReason, RuntimeStreamData, RuntimeStreamOpen, RuntimeStreamWindow,
    RuntimeWelcome, WireValueBudget, validate_wire_value_graph, validate_wire_value_graph_for_app,
};
pub use security::EffectiveSecurityPosture;
pub use transformation::{
    AdapterTransformAuthority, AuthorizedTransformRuleRef, GeneratedTransformOverlay,
    MAX_AUTHORIZED_TRANSFORM_RULES, MAX_GENERATED_TRANSFORM_REBINDINGS, SourceUnitRef,
    StructurallyValidatedTransformOverlay, TRANSFORM_REBINDING_FORMAT_VERSION,
    TransformArchitecture, TransformContractError, TransformOverlayBinding, TransformPlatform,
    TransformRebinding,
};
