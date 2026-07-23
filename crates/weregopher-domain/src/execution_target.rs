//! Canonical execution-target and generated resolution-evidence contracts.
//!
//! These content-addressed contracts are inputs to live authorization. Parsing and hashing them does
//! not authenticate an adapter, establish current revocation state, retain an executable, or authorize
//! process launch. Callers parsing hostile bytes must impose an outer byte/read limit before Serde.

use std::{borrow::Cow, fmt};

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, IgnoredAny, SeqAccess, Visitor},
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    EffectiveSecurityPosture, ExecutionArtifactSource, ExecutionTargetId, ExecutionTargetKind,
    Sha256Digest,
};

/// Current serialized execution-target contract version.
pub const EXECUTION_TARGET_CONTRACT_FORMAT_VERSION: &str = "1";
/// Current serialized execution-resolution evidence version.
pub const EXECUTION_RESOLUTION_FORMAT_VERSION: &str = "1";
/// Maximum fixed arguments in one execution launch policy.
pub const MAX_EXECUTION_ARGUMENTS: usize = 64;
/// Maximum UTF-8 bytes in one fixed execution argument.
pub const MAX_EXECUTION_ARGUMENT_BYTES: usize = 8 * 1024;
/// Maximum aggregate UTF-8 bytes across fixed execution arguments.
pub const MAX_EXECUTION_ARGUMENT_AGGREGATE_BYTES: usize = 16 * 1024;
/// Maximum UTF-8 bytes in one normalized package-relative executable path.
pub const MAX_EXECUTION_PACKAGE_PATH_BYTES: usize = 4 * 1024;
/// Maximum components in one normalized package-relative executable path.
pub const MAX_EXECUTION_PACKAGE_PATH_COMPONENTS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
enum ExecutionTargetContractFormatVersion {
    #[serde(rename = "1")]
    V1,
}

#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
enum ExecutionResolutionFormatVersion {
    #[serde(rename = "1")]
    V1,
}

/// One bounded fixed command-line argument from a static execution target contract.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ExecutionArgument(String);

impl JsonSchema for ExecutionArgument {
    fn schema_name() -> Cow<'static, str> {
        "ExecutionArgument".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::ExecutionArgument").into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "One bounded fixed command-line argument.",
            "type": "string",
            "maxLength": 8192
        })
    }
}

impl ExecutionArgument {
    /// Validates one fixed UTF-8 command-line argument.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionTargetContractError`] when the argument exceeds its byte bound or contains
    /// an embedded NUL, which Windows command lines cannot represent.
    pub fn new(value: impl Into<String>) -> Result<Self, ExecutionTargetContractError> {
        let value = value.into();
        if value.len() > MAX_EXECUTION_ARGUMENT_BYTES {
            return Err(ExecutionTargetContractError::ArgumentTooLong);
        }
        if value.contains('\0') {
            return Err(ExecutionTargetContractError::ArgumentContainsNul);
        }
        Ok(Self(value))
    }

    /// Returns the fixed argument text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ExecutionArgument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionArgument")
            .field("utf8_bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl TryFrom<String> for ExecutionArgument {
    type Error = ExecutionTargetContractError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ExecutionArgument> for String {
    fn from(value: ExecutionArgument) -> Self {
        value.0
    }
}

/// Exact artifact locator interpreted only within the source declared by one target contract.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(
    tag = "artifact_source",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ExecutionArtifactLocator {
    /// Exact manifest-allowlisted package-relative path.
    PackageSnapshot {
        /// Canonical forward-slash package-relative path.
        #[schemars(length(min = 1, max = 4096))]
        normalized_path: String,
    },
    /// Exact blob in a retained managed-artifact manifest.
    ManagedArtifact {
        /// Content identity of the executable blob.
        digest: Sha256Digest,
    },
}

#[derive(Deserialize)]
#[serde(
    tag = "artifact_source",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum ExecutionArtifactLocatorTransport {
    PackageSnapshot { normalized_path: String },
    ManagedArtifact { digest: Sha256Digest },
}

impl<'de> Deserialize<'de> for ExecutionArtifactLocator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match ExecutionArtifactLocatorTransport::deserialize(deserializer)? {
            ExecutionArtifactLocatorTransport::PackageSnapshot { normalized_path } => {
                Self::package_snapshot(normalized_path).map_err(D::Error::custom)
            }
            ExecutionArtifactLocatorTransport::ManagedArtifact { digest } => {
                Ok(Self::managed_artifact(digest))
            }
        }
    }
}

impl ExecutionArtifactLocator {
    /// Constructs a bounded canonical package-relative locator.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionTargetContractError`] when the path is empty, absolute-like, contains a
    /// non-canonical component, exceeds its bounds, or uses a Windows separator/drive prefix.
    pub fn package_snapshot(
        normalized_path: impl Into<String>,
    ) -> Result<Self, ExecutionTargetContractError> {
        let normalized_path = normalized_path.into();
        validate_package_path(&normalized_path)?;
        Ok(Self::PackageSnapshot { normalized_path })
    }

    /// Constructs one exact managed-artifact digest locator.
    #[must_use]
    pub const fn managed_artifact(digest: Sha256Digest) -> Self {
        Self::ManagedArtifact { digest }
    }

    /// Returns the artifact source encoded by this locator.
    #[must_use]
    pub const fn artifact_source(&self) -> ExecutionArtifactSource {
        match self {
            Self::PackageSnapshot { .. } => ExecutionArtifactSource::PackageSnapshot,
            Self::ManagedArtifact { .. } => ExecutionArtifactSource::ManagedArtifact,
        }
    }

    /// Returns the package-relative path when this is a package-snapshot locator.
    #[must_use]
    pub fn package_path(&self) -> Option<&str> {
        match self {
            Self::PackageSnapshot { normalized_path } => Some(normalized_path),
            Self::ManagedArtifact { .. } => None,
        }
    }

    /// Returns the managed executable digest when this is a managed-artifact locator.
    #[must_use]
    pub const fn managed_digest(&self) -> Option<&Sha256Digest> {
        match self {
            Self::ManagedArtifact { digest } => Some(digest),
            Self::PackageSnapshot { .. } => None,
        }
    }
}

fn validate_package_path(path: &str) -> Result<(), ExecutionTargetContractError> {
    if path.is_empty() || path.len() > MAX_EXECUTION_PACKAGE_PATH_BYTES {
        return Err(ExecutionTargetContractError::InvalidPackagePath);
    }
    if path.contains(['\\', '\0', ':']) || path.starts_with('/') || path.ends_with('/') {
        return Err(ExecutionTargetContractError::InvalidPackagePath);
    }
    let mut component_count = 0_usize;
    for component in path.split('/') {
        component_count = component_count
            .checked_add(1)
            .ok_or(ExecutionTargetContractError::InvalidPackagePath)?;
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.ends_with(['.', ' '])
        {
            return Err(ExecutionTargetContractError::InvalidPackagePath);
        }
    }
    if component_count > MAX_EXECUTION_PACKAGE_PATH_COMPONENTS {
        return Err(ExecutionTargetContractError::InvalidPackagePath);
    }
    Ok(())
}

/// State namespace selected by one exact execution target contract.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStateMode {
    /// Candidate validation uses isolated disposable state.
    Disposable,
    /// A separately approved production-state policy is required.
    Production,
}

/// Fixed empty-environment policy for execution-target format version 1.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionEnvironmentPolicy {
    /// Launch with an explicit empty Unicode environment block.
    Empty,
}

/// Fixed inherited-handle policy for execution-target format version 1.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionInheritedHandlePolicy {
    /// Inherit no process handles.
    None,
}

/// Fixed console policy for execution-target format version 1.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionConsolePolicy {
    /// Create no console window.
    None,
}

/// Fixed current-directory policy for execution-target format version 1.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionWorkingDirectoryPolicy {
    /// Use the retained executable's direct parent directory.
    ExecutableParent,
}

/// Exact bounded Job Object and process-memory requirements for one target.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionResourceLimits {
    #[schemars(range(min = 1))]
    active_process_limit: u32,
    #[schemars(range(min = 1))]
    process_memory_limit_bytes: u64,
    #[schemars(range(min = 1))]
    job_memory_limit_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionResourceLimitsTransport {
    active_process_limit: u32,
    process_memory_limit_bytes: u64,
    job_memory_limit_bytes: u64,
}

impl<'de> Deserialize<'de> for ExecutionResourceLimits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let transport = ExecutionResourceLimitsTransport::deserialize(deserializer)?;
        Self::new(
            transport.active_process_limit,
            transport.process_memory_limit_bytes,
            transport.job_memory_limit_bytes,
        )
        .map_err(D::Error::custom)
    }
}

impl ExecutionResourceLimits {
    /// Constructs nonzero coherent Job Object resource limits.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionTargetContractError`] for zero values or a per-process memory limit above
    /// the aggregate Job memory limit.
    pub const fn new(
        active_process_limit: u32,
        process_memory_limit_bytes: u64,
        job_memory_limit_bytes: u64,
    ) -> Result<Self, ExecutionTargetContractError> {
        if active_process_limit == 0
            || process_memory_limit_bytes == 0
            || job_memory_limit_bytes == 0
        {
            return Err(ExecutionTargetContractError::ZeroResourceLimit);
        }
        if process_memory_limit_bytes > job_memory_limit_bytes {
            return Err(ExecutionTargetContractError::IncoherentMemoryLimits);
        }
        Ok(Self {
            active_process_limit,
            process_memory_limit_bytes,
            job_memory_limit_bytes,
        })
    }

    /// Returns the maximum simultaneously active process count.
    #[must_use]
    pub const fn active_process_limit(self) -> u32 {
        self.active_process_limit
    }

    /// Returns the per-process memory ceiling in bytes.
    #[must_use]
    pub const fn process_memory_limit_bytes(self) -> u64 {
        self.process_memory_limit_bytes
    }

    /// Returns the aggregate Job memory ceiling in bytes.
    #[must_use]
    pub const fn job_memory_limit_bytes(self) -> u64 {
        self.job_memory_limit_bytes
    }
}

/// Role-named policy artifact identities referenced by one exact launch policy.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPolicyDigests {
    /// Complete compatibility-analysis document identity.
    pub compatibility_analysis_digest: Sha256Digest,
    /// Resolved capability-manifest/policy identity.
    pub capability_policy_digest: Sha256Digest,
    /// Resolved state policy identity.
    pub state_policy_digest: Sha256Digest,
    /// Current user-policy/consent identity.
    pub user_policy_digest: Sha256Digest,
}

/// Fixed bounded launch and policy requirements from one static target contract.
#[derive(Clone, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionLaunchPolicy {
    #[schemars(length(max = 64))]
    arguments: Vec<ExecutionArgument>,
    environment: ExecutionEnvironmentPolicy,
    inherited_handles: ExecutionInheritedHandlePolicy,
    console: ExecutionConsolePolicy,
    working_directory: ExecutionWorkingDirectoryPolicy,
    security_posture: EffectiveSecurityPosture,
    state_mode: ExecutionStateMode,
    resource_limits: ExecutionResourceLimits,
    policy_digests: ExecutionPolicyDigests,
}

impl fmt::Debug for ExecutionLaunchPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionLaunchPolicy")
            .field("argument_count", &self.arguments.len())
            .field("argument_utf8_bytes", &self.argument_bytes())
            .field("environment", &self.environment)
            .field("inherited_handles", &self.inherited_handles)
            .field("console", &self.console)
            .field("working_directory", &self.working_directory)
            .field("security_posture", &self.security_posture)
            .field("state_mode", &self.state_mode)
            .field("resource_limits", &self.resource_limits)
            .field("policy_digests", &self.policy_digests)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionLaunchPolicyTransport {
    #[serde(deserialize_with = "deserialize_execution_arguments")]
    arguments: Vec<ExecutionArgument>,
    environment: ExecutionEnvironmentPolicy,
    inherited_handles: ExecutionInheritedHandlePolicy,
    console: ExecutionConsolePolicy,
    working_directory: ExecutionWorkingDirectoryPolicy,
    security_posture: EffectiveSecurityPosture,
    state_mode: ExecutionStateMode,
    resource_limits: ExecutionResourceLimits,
    policy_digests: ExecutionPolicyDigests,
}

fn deserialize_execution_arguments<'de, D>(
    deserializer: D,
) -> Result<Vec<ExecutionArgument>, D::Error>
where
    D: Deserializer<'de>,
{
    struct ArgumentsVisitor;

    impl<'de> Visitor<'de> for ArgumentsVisitor {
        type Value = Vec<ExecutionArgument>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded sequence of fixed execution arguments")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence
                .size_hint()
                .is_some_and(|length| length > MAX_EXECUTION_ARGUMENTS)
            {
                return Err(A::Error::custom(
                    ExecutionTargetContractError::TooManyArguments,
                ));
            }
            let mut arguments = Vec::new();
            while arguments.len() < MAX_EXECUTION_ARGUMENTS {
                let Some(argument) = sequence.next_element()? else {
                    return Ok(arguments);
                };
                arguments.push(argument);
            }
            if sequence.next_element::<IgnoredAny>()?.is_some() {
                return Err(A::Error::custom(
                    ExecutionTargetContractError::TooManyArguments,
                ));
            }
            Ok(arguments)
        }
    }

    deserializer.deserialize_seq(ArgumentsVisitor)
}

impl<'de> Deserialize<'de> for ExecutionLaunchPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let transport = ExecutionLaunchPolicyTransport::deserialize(deserializer)?;
        let policy = Self::new(
            transport.arguments,
            transport.security_posture,
            transport.state_mode,
            transport.resource_limits,
            transport.policy_digests,
        )
        .map_err(D::Error::custom)?;
        if policy.environment != transport.environment
            || policy.inherited_handles != transport.inherited_handles
            || policy.console != transport.console
            || policy.working_directory != transport.working_directory
        {
            return Err(D::Error::custom(
                "execution launch policy contains unsupported fixed launch semantics",
            ));
        }
        Ok(policy)
    }
}

impl ExecutionLaunchPolicy {
    /// Constructs one format-v1 fixed launch policy.
    ///
    /// Format version 1 always uses an empty environment, inherits no handles, creates no console,
    /// and uses the retained executable's parent as current directory.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionTargetContractError`] when argument count or aggregate bytes exceed their
    /// bounds.
    pub fn new(
        arguments: Vec<ExecutionArgument>,
        security_posture: EffectiveSecurityPosture,
        state_mode: ExecutionStateMode,
        resource_limits: ExecutionResourceLimits,
        policy_digests: ExecutionPolicyDigests,
    ) -> Result<Self, ExecutionTargetContractError> {
        if arguments.len() > MAX_EXECUTION_ARGUMENTS {
            return Err(ExecutionTargetContractError::TooManyArguments);
        }
        let mut aggregate = 0_usize;
        for argument in &arguments {
            aggregate = aggregate
                .checked_add(argument.0.len())
                .ok_or(ExecutionTargetContractError::TooManyArgumentBytes)?;
            if aggregate > MAX_EXECUTION_ARGUMENT_AGGREGATE_BYTES {
                return Err(ExecutionTargetContractError::TooManyArgumentBytes);
            }
        }
        Ok(Self {
            arguments,
            environment: ExecutionEnvironmentPolicy::Empty,
            inherited_handles: ExecutionInheritedHandlePolicy::None,
            console: ExecutionConsolePolicy::None,
            working_directory: ExecutionWorkingDirectoryPolicy::ExecutableParent,
            security_posture,
            state_mode,
            resource_limits,
            policy_digests,
        })
    }

    /// Returns fixed command-line arguments in declared order.
    #[must_use]
    pub fn arguments(&self) -> &[ExecutionArgument] {
        &self.arguments
    }

    /// Returns aggregate UTF-8 argument bytes.
    #[must_use]
    pub fn argument_bytes(&self) -> usize {
        self.arguments.iter().map(|argument| argument.0.len()).sum()
    }

    /// Returns the fixed environment policy.
    #[must_use]
    pub const fn environment(&self) -> ExecutionEnvironmentPolicy {
        self.environment
    }

    /// Returns the fixed inherited-handle policy.
    #[must_use]
    pub const fn inherited_handles(&self) -> ExecutionInheritedHandlePolicy {
        self.inherited_handles
    }

    /// Returns the fixed console policy.
    #[must_use]
    pub const fn console(&self) -> ExecutionConsolePolicy {
        self.console
    }

    /// Returns the fixed current-directory policy.
    #[must_use]
    pub const fn working_directory(&self) -> ExecutionWorkingDirectoryPolicy {
        self.working_directory
    }

    /// Returns the declared effective security posture.
    #[must_use]
    pub const fn security_posture(&self) -> EffectiveSecurityPosture {
        self.security_posture
    }

    /// Returns the state namespace mode.
    #[must_use]
    pub const fn state_mode(&self) -> ExecutionStateMode {
        self.state_mode
    }

    /// Returns exact process-tree resource limits.
    #[must_use]
    pub const fn resource_limits(&self) -> ExecutionResourceLimits {
        self.resource_limits
    }

    /// Returns exact external policy evidence identities.
    #[must_use]
    pub const fn policy_digests(&self) -> &ExecutionPolicyDigests {
        &self.policy_digests
    }
}

/// Complete static target contract referenced by an adapter execution authority.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionTargetContract {
    format_version: ExecutionTargetContractFormatVersion,
    target_id: ExecutionTargetId,
    kind: ExecutionTargetKind,
    artifact_locator: ExecutionArtifactLocator,
    launch_policy: ExecutionLaunchPolicy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionTargetContractTransport {
    format_version: ExecutionTargetContractFormatVersion,
    target_id: ExecutionTargetId,
    kind: ExecutionTargetKind,
    artifact_locator: ExecutionArtifactLocator,
    launch_policy: ExecutionLaunchPolicy,
}

impl<'de> Deserialize<'de> for ExecutionTargetContract {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let transport = ExecutionTargetContractTransport::deserialize(deserializer)?;
        match transport.format_version {
            ExecutionTargetContractFormatVersion::V1 => Ok(Self::new(
                transport.target_id,
                transport.kind,
                transport.artifact_locator,
                transport.launch_policy,
            )),
        }
    }
}

impl ExecutionTargetContract {
    /// Constructs one validated format-v1 execution target contract.
    #[must_use]
    pub const fn new(
        target_id: ExecutionTargetId,
        kind: ExecutionTargetKind,
        artifact_locator: ExecutionArtifactLocator,
        launch_policy: ExecutionLaunchPolicy,
    ) -> Self {
        Self {
            format_version: ExecutionTargetContractFormatVersion::V1,
            target_id,
            kind,
            artifact_locator,
            launch_policy,
        }
    }

    /// Returns the exact target identifier.
    #[must_use]
    pub const fn target_id(&self) -> &ExecutionTargetId {
        &self.target_id
    }

    /// Returns the supervisor-visible target kind.
    #[must_use]
    pub const fn kind(&self) -> ExecutionTargetKind {
        self.kind
    }

    /// Returns the exact artifact locator.
    #[must_use]
    pub const fn artifact_locator(&self) -> &ExecutionArtifactLocator {
        &self.artifact_locator
    }

    /// Returns fixed launch and policy requirements.
    #[must_use]
    pub const fn launch_policy(&self) -> &ExecutionLaunchPolicy {
        &self.launch_policy
    }

    /// Returns deterministic canonical JSON bytes for content addressing.
    ///
    /// # Errors
    ///
    /// Returns a Serde JSON error if canonical serialization cannot complete.
    pub fn canonical_json_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

    /// Computes the SHA-256 identity of canonical JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns a Serde JSON error if canonical serialization cannot complete.
    pub fn canonical_document_digest(&self) -> serde_json::Result<Sha256Digest> {
        let bytes = self.canonical_json_bytes()?;
        Ok(Sha256Digest::from_bytes(Sha256::digest(bytes).into()))
    }
}

/// Role-named generated resolution-evidence identities.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionResolutionDigests {
    /// Exact static target-contract identity.
    pub execution_contract_digest: Sha256Digest,
    /// Exact package-tree or managed-manifest identity.
    pub artifact_source_digest: Sha256Digest,
    /// Exact executable byte identity.
    pub executable_digest: Sha256Digest,
    /// Exact signer, local-build trust, or equivalent artifact trust evidence identity.
    pub artifact_trust_evidence_digest: Sha256Digest,
    /// Exact artifact provenance evidence identity.
    pub provenance_evidence_digest: Sha256Digest,
}

/// Generated exact resolution evidence for one static execution target.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionResolutionEvidence {
    format_version: ExecutionResolutionFormatVersion,
    target_id: ExecutionTargetId,
    artifact_locator: ExecutionArtifactLocator,
    digests: ExecutionResolutionDigests,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionResolutionEvidenceTransport {
    format_version: ExecutionResolutionFormatVersion,
    target_id: ExecutionTargetId,
    artifact_locator: ExecutionArtifactLocator,
    digests: ExecutionResolutionDigests,
}

impl<'de> Deserialize<'de> for ExecutionResolutionEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let transport = ExecutionResolutionEvidenceTransport::deserialize(deserializer)?;
        match transport.format_version {
            ExecutionResolutionFormatVersion::V1 => Ok(Self::new(
                transport.target_id,
                transport.artifact_locator,
                transport.digests,
            )),
        }
    }
}

impl ExecutionResolutionEvidence {
    /// Constructs format-v1 generated target-resolution evidence.
    #[must_use]
    pub const fn new(
        target_id: ExecutionTargetId,
        artifact_locator: ExecutionArtifactLocator,
        digests: ExecutionResolutionDigests,
    ) -> Self {
        Self {
            format_version: ExecutionResolutionFormatVersion::V1,
            target_id,
            artifact_locator,
            digests,
        }
    }

    /// Returns the exact static target identifier.
    #[must_use]
    pub const fn target_id(&self) -> &ExecutionTargetId {
        &self.target_id
    }

    /// Returns the resolved exact artifact locator.
    #[must_use]
    pub const fn artifact_locator(&self) -> &ExecutionArtifactLocator {
        &self.artifact_locator
    }

    /// Returns all role-named resolution identities.
    #[must_use]
    pub const fn digests(&self) -> &ExecutionResolutionDigests {
        &self.digests
    }

    /// Returns deterministic canonical JSON bytes for content addressing.
    ///
    /// # Errors
    ///
    /// Returns a Serde JSON error if canonical serialization cannot complete.
    pub fn canonical_json_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

    /// Computes the SHA-256 identity of canonical JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns a Serde JSON error if canonical serialization cannot complete.
    pub fn canonical_document_digest(&self) -> serde_json::Result<Sha256Digest> {
        let bytes = self.canonical_json_bytes()?;
        Ok(Sha256Digest::from_bytes(Sha256::digest(bytes).into()))
    }
}

/// Invalid execution-target or resolution-evidence contract.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ExecutionTargetContractError {
    /// One fixed argument exceeded its byte bound.
    #[error("execution argument exceeds its byte limit")]
    ArgumentTooLong,
    /// One fixed argument contained a NUL.
    #[error("execution argument contains an embedded NUL")]
    ArgumentContainsNul,
    /// The launch policy exceeded its argument count.
    #[error("execution argument count exceeds its limit")]
    TooManyArguments,
    /// Fixed arguments exceeded their aggregate byte bound.
    #[error("execution arguments exceed their aggregate byte limit")]
    TooManyArgumentBytes,
    /// A package-relative locator was not bounded and canonical.
    #[error("execution package path is not bounded and canonical")]
    InvalidPackagePath,
    /// One process-tree resource limit was zero.
    #[error("execution resource limits must be nonzero")]
    ZeroResourceLimit,
    /// Per-process memory exceeded aggregate Job memory.
    #[error("process memory limit exceeds aggregate job memory limit")]
    IncoherentMemoryLimits,
}
