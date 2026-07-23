//! Canonical execution-target and generated resolution-evidence contracts.
//!
//! These content-addressed contracts are inputs to live authorization. Parsing and hashing them does
//! not authenticate an adapter, establish current revocation state, retain an executable, or authorize
//! process launch. Hostile bytes must enter through the bounded `from_json_*` APIs; generic Serde
//! deserialization is provided for composition only and assumes its caller already bounded transport
//! bytes.

use std::{
    borrow::Cow,
    fmt,
    io::{self, Read},
};

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, IgnoredAny, SeqAccess, Visitor},
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    ArtifactTrustEvidenceDigest, CapabilityPolicyDigest, EffectiveSecurityPosture,
    ExecutableDigest, ExecutionArtifactSource, ExecutionArtifactSourceDigest,
    ExecutionContractDigest, ExecutionResolutionEvidenceDigest, ExecutionTargetId,
    ExecutionTargetKind, ProvenanceEvidenceDigest, Sha256Digest, StatePolicyDigest,
};

/// Current serialized execution-target contract version.
pub const EXECUTION_TARGET_CONTRACT_FORMAT_VERSION: &str = "2";
/// Current serialized execution-resolution evidence version.
pub const EXECUTION_RESOLUTION_FORMAT_VERSION: &str = "2";
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
/// Maximum serialized bytes accepted by the bounded target-contract parser.
pub const MAX_EXECUTION_TARGET_DOCUMENT_BYTES: usize = 256 * 1024;
/// Maximum serialized bytes accepted by the bounded resolution-evidence parser.
pub const MAX_EXECUTION_RESOLUTION_DOCUMENT_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
enum ExecutionTargetContractFormatVersion {
    #[serde(rename = "2")]
    V2,
}

#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
enum ExecutionResolutionFormatVersion {
    #[serde(rename = "2")]
    V2,
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
            "maxLength": 8192,
            "pattern": "^[^\\u0000]*$",
            "x-weregopher-maxUtf8Bytes": 8192
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

/// Canonical, bounded package-relative Windows executable path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ExecutionPackagePath(String);

impl ExecutionPackagePath {
    /// Constructs one path after canonical Windows component validation.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionTargetContractError::InvalidPackagePath`] for an empty, oversized,
    /// ambiguous, device-aliased, absolute-like, or non-canonical path.
    pub fn new(value: impl Into<String>) -> Result<Self, ExecutionTargetContractError> {
        Self::try_from(value.into())
    }

    /// Returns the canonical forward-slash path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl JsonSchema for ExecutionPackagePath {
    fn schema_name() -> Cow<'static, str> {
        "ExecutionPackagePath".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::ExecutionPackagePath").into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "Canonical package-relative Windows path. Rust validation also rejects DOS device aliases in every component.",
            "type": "string",
            "minLength": 1,
            "maxLength": 4096,
            "pattern": "^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[<>:\"\\\\|?*\\u0000-\\u001f])(?!.*[. ](?:/|$)).+$",
            "x-weregopher-maxUtf8Bytes": 4096,
            "x-weregopher-maxPathComponents": 256,
            "x-weregopher-windowsDeviceAliasesRejected": true
        })
    }
}

impl TryFrom<String> for ExecutionPackagePath {
    type Error = ExecutionTargetContractError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_package_path(&value)?;
        Ok(Self(value))
    }
}

impl From<ExecutionPackagePath> for String {
    fn from(value: ExecutionPackagePath) -> Self {
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
        normalized_path: ExecutionPackagePath,
    },
    /// Exact blob in a retained managed-artifact manifest.
    ManagedArtifact {
        /// Content identity of the executable blob.
        digest: ExecutableDigest,
    },
}

#[derive(Deserialize)]
#[serde(
    tag = "artifact_source",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum ExecutionArtifactLocatorTransport {
    PackageSnapshot {
        normalized_path: ExecutionPackagePath,
    },
    ManagedArtifact {
        digest: ExecutableDigest,
    },
}

impl<'de> Deserialize<'de> for ExecutionArtifactLocator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match ExecutionArtifactLocatorTransport::deserialize(deserializer)? {
            ExecutionArtifactLocatorTransport::PackageSnapshot { normalized_path } => {
                Ok(Self::PackageSnapshot { normalized_path })
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
        let normalized_path = ExecutionPackagePath::try_from(normalized_path.into())?;
        Ok(Self::PackageSnapshot { normalized_path })
    }

    /// Constructs one exact managed-artifact digest locator.
    #[must_use]
    pub const fn managed_artifact(digest: ExecutableDigest) -> Self {
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
            Self::PackageSnapshot { normalized_path } => Some(&normalized_path.0),
            Self::ManagedArtifact { .. } => None,
        }
    }

    /// Returns the managed executable digest when this is a managed-artifact locator.
    #[must_use]
    pub const fn managed_digest(&self) -> Option<&ExecutableDigest> {
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
    if path.starts_with('/') || path.ends_with('/') {
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
            || component.chars().any(is_invalid_windows_path_character)
            || is_reserved_windows_component(component)
        {
            return Err(ExecutionTargetContractError::InvalidPackagePath);
        }
    }
    if component_count > MAX_EXECUTION_PACKAGE_PATH_COMPONENTS {
        return Err(ExecutionTargetContractError::InvalidPackagePath);
    }
    Ok(())
}

fn is_invalid_windows_path_character(character: char) -> bool {
    character <= '\u{001f}' || matches!(character, '<' | '>' | ':' | '"' | '\\' | '|' | '?' | '*')
}

fn is_reserved_windows_component(component: &str) -> bool {
    let stem = component
        .split_once('.')
        .map_or(component, |(stem, _extension)| stem)
        .trim_end_matches([' ', '.']);
    let uppercase = stem.to_ascii_uppercase();
    if matches!(
        uppercase.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$"
    ) {
        return true;
    }
    ["COM", "LPT"].iter().any(|prefix| {
        uppercase.strip_prefix(prefix).is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    })
}

/// State namespace selected by one exact execution target contract.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStateMode {
    /// Candidate validation uses isolated disposable state.
    Disposable,
    /// A separately approved production-state policy is required.
    Production,
    /// The target intentionally uses the vendor's ambient process-default state behavior.
    ///
    /// This mode provides no state isolation or retained namespace capability. It exists so the
    /// initial full-trust process primitive does not misrepresent ambient state as disposable or
    /// production-state mediation.
    VendorDefault,
}

/// Minimum security mechanism required by one static execution target.
///
/// This is a durable requirement, not evidence that a launcher actually established the posture.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredSecurityPosture {
    /// The complete vendor-equivalent application executes as an unrestricted same-user process.
    VendorEquivalentFullTrust,
    /// Privileged effects require mediation by a separately authenticated broker policy.
    BrokerMediated,
    /// A separately tested operating-system containment mechanism is required.
    OsContained,
}

impl RequiredSecurityPosture {
    /// Reports whether live mechanism evidence establishes exactly this required posture.
    #[must_use]
    pub const fn is_satisfied_by(self, effective: EffectiveSecurityPosture) -> bool {
        matches!(
            (self, effective),
            (
                Self::VendorEquivalentFullTrust,
                EffectiveSecurityPosture::VendorEquivalentFullTrust
            ) | (
                Self::BrokerMediated,
                EffectiveSecurityPosture::BrokerMediated
            ) | (Self::OsContained, EffectiveSecurityPosture::OsContained)
        )
    }
}

/// Fixed empty-environment policy for execution-target format version 2.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionEnvironmentPolicy {
    /// Launch with an explicit empty Unicode environment block.
    Empty,
}

/// Fixed inherited-handle policy for execution-target format version 2.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionInheritedHandlePolicy {
    /// Inherit no process handles.
    None,
}

/// Fixed console policy for execution-target format version 2.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionConsolePolicy {
    /// Create no console window.
    None,
}

/// Fixed current-directory policy for execution-target format version 2.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionWorkingDirectoryPolicy {
    /// Use the retained executable's direct parent directory.
    ExecutableParent,
}

/// Required loader dependency-namespace behavior for one execution target.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionDependencyPolicy {
    /// Permit unsealed ambient Windows loader resolution from the executable directory and system.
    ///
    /// This mode does not claim that package-relative DLLs or resources form a closed immutable set,
    /// or that a relocated executable preserves its original package-relative dependency behavior.
    VendorDefaultAmbient,
    /// Require every load-bearing dependency to come from an immutable manifest-closed namespace.
    ManifestClosed,
}

/// Exact bounded Job Object and process-memory requirements for one target.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionResourceLimits {
    active_process_limit: u32,
    process_memory_limit_bytes: u64,
    job_memory_limit_bytes: u64,
}

impl JsonSchema for ExecutionResourceLimits {
    fn schema_name() -> Cow<'static, str> {
        "ExecutionResourceLimits".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::ExecutionResourceLimits").into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "Nonzero Windows Job limits. Rust validation additionally requires process_memory_limit_bytes <= job_memory_limit_bytes.",
            "type": "object",
            "properties": {
                "active_process_limit": {
                    "type": "integer",
                    "format": "uint32",
                    "minimum": 1,
                    "maximum": 4_294_967_295_u64
                },
                "process_memory_limit_bytes": {
                    "type": "integer",
                    "format": "uint64",
                    "minimum": 1,
                    "maximum": 18_446_744_073_709_551_615_u64
                },
                "job_memory_limit_bytes": {
                    "type": "integer",
                    "format": "uint64",
                    "minimum": 1,
                    "maximum": 18_446_744_073_709_551_615_u64
                }
            },
            "required": [
                "active_process_limit",
                "process_memory_limit_bytes",
                "job_memory_limit_bytes"
            ],
            "additionalProperties": false,
            "x-weregopher-processMemoryAtMostJobMemory": true
        })
    }
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

/// Durable policy requirements referenced by one exact static launch policy.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPolicyRequirements {
    /// Capability policy identity whose exact authority the static adapter requires.
    pub capability_policy_digest: CapabilityPolicyDigest,
    /// State policy identity whose exact namespace rules the static adapter requires.
    pub state_policy_digest: StatePolicyDigest,
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
    dependency_policy: ExecutionDependencyPolicy,
    required_security_posture: RequiredSecurityPosture,
    state_mode: ExecutionStateMode,
    resource_limits: ExecutionResourceLimits,
    policy_requirements: ExecutionPolicyRequirements,
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
            .field("dependency_policy", &self.dependency_policy)
            .field("required_security_posture", &self.required_security_posture)
            .field("state_mode", &self.state_mode)
            .field("resource_limits", &self.resource_limits)
            .field("policy_requirements", &self.policy_requirements)
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
    dependency_policy: ExecutionDependencyPolicy,
    required_security_posture: RequiredSecurityPosture,
    state_mode: ExecutionStateMode,
    resource_limits: ExecutionResourceLimits,
    policy_requirements: ExecutionPolicyRequirements,
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
            transport.dependency_policy,
            transport.required_security_posture,
            transport.state_mode,
            transport.resource_limits,
            transport.policy_requirements,
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
    /// Constructs one format-v2 fixed launch policy.
    ///
    /// Format version 2 always uses an empty environment, inherits no handles, creates no console,
    /// and uses the retained executable's parent as current directory.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionTargetContractError`] when argument count or aggregate bytes exceed their
    /// bounds.
    pub fn new(
        arguments: Vec<ExecutionArgument>,
        dependency_policy: ExecutionDependencyPolicy,
        required_security_posture: RequiredSecurityPosture,
        state_mode: ExecutionStateMode,
        resource_limits: ExecutionResourceLimits,
        policy_requirements: ExecutionPolicyRequirements,
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
            dependency_policy,
            required_security_posture,
            state_mode,
            resource_limits,
            policy_requirements,
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

    /// Returns the required loader dependency-namespace behavior.
    #[must_use]
    pub const fn dependency_policy(&self) -> ExecutionDependencyPolicy {
        self.dependency_policy
    }

    /// Returns the static minimum security mechanism requirement.
    #[must_use]
    pub const fn required_security_posture(&self) -> RequiredSecurityPosture {
        self.required_security_posture
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

    /// Returns exact durable policy requirements.
    #[must_use]
    pub const fn policy_requirements(&self) -> &ExecutionPolicyRequirements {
        &self.policy_requirements
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
            ExecutionTargetContractFormatVersion::V2 => Ok(Self::new(
                transport.target_id,
                transport.kind,
                transport.artifact_locator,
                transport.launch_policy,
            )),
        }
    }
}

impl ExecutionTargetContract {
    /// Constructs one validated format-v2 execution target contract.
    #[must_use]
    pub const fn new(
        target_id: ExecutionTargetId,
        kind: ExecutionTargetKind,
        artifact_locator: ExecutionArtifactLocator,
        launch_policy: ExecutionLaunchPolicy,
    ) -> Self {
        Self {
            format_version: ExecutionTargetContractFormatVersion::V2,
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

    /// Parses one target contract only after enforcing the complete transport byte bound.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionContractParseError`] when the document exceeds its byte limit or is not a
    /// valid format-v2 target contract.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, ExecutionContractParseError> {
        parse_bounded_slice(bytes, MAX_EXECUTION_TARGET_DOCUMENT_BYTES)
    }

    /// Reads and parses one target contract while retaining at most the document byte limit plus one
    /// sentinel byte.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionContractParseError`] for reader failures, an oversized document, or an
    /// invalid format-v2 target contract.
    pub fn from_json_reader(reader: impl Read) -> Result<Self, ExecutionContractParseError> {
        parse_bounded_reader(reader, MAX_EXECUTION_TARGET_DOCUMENT_BYTES)
    }

    /// Returns deterministic canonical JSON bytes for content addressing.
    ///
    /// # Errors
    ///
    /// Returns a Serde JSON error if canonical serialization cannot complete.
    pub fn canonical_json_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

    /// Computes the role-typed SHA-256 identity of canonical JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns a Serde JSON error if canonical serialization cannot complete.
    pub fn canonical_document_digest(&self) -> serde_json::Result<ExecutionContractDigest> {
        let bytes = self.canonical_json_bytes()?;
        Ok(ExecutionContractDigest::new(Sha256Digest::from_bytes(
            Sha256::digest(bytes).into(),
        )))
    }
}

/// Role-named generated resolution-evidence identities.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionResolutionDigests {
    /// Exact static target-contract identity.
    pub execution_contract_digest: ExecutionContractDigest,
    /// Exact package-tree or managed-manifest identity.
    pub artifact_source_digest: ExecutionArtifactSourceDigest,
    /// Exact executable byte identity.
    pub executable_digest: ExecutableDigest,
    /// Exact signer, local-build trust, or equivalent artifact trust evidence identity.
    pub artifact_trust_evidence_digest: ArtifactTrustEvidenceDigest,
    /// Exact artifact provenance evidence identity.
    pub provenance_evidence_digest: ProvenanceEvidenceDigest,
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
            ExecutionResolutionFormatVersion::V2 => Self::new(
                transport.target_id,
                transport.artifact_locator,
                transport.digests,
            )
            .map_err(D::Error::custom),
        }
    }
}

impl ExecutionResolutionEvidence {
    /// Constructs format-v2 generated target-resolution evidence.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionTargetContractError::ManagedExecutableDigestMismatch`] when a managed
    /// locator and the role-named executable digest contradict one another.
    pub fn new(
        target_id: ExecutionTargetId,
        artifact_locator: ExecutionArtifactLocator,
        digests: ExecutionResolutionDigests,
    ) -> Result<Self, ExecutionTargetContractError> {
        if artifact_locator
            .managed_digest()
            .is_some_and(|digest| digest != &digests.executable_digest)
        {
            return Err(ExecutionTargetContractError::ManagedExecutableDigestMismatch);
        }
        Ok(Self {
            format_version: ExecutionResolutionFormatVersion::V2,
            target_id,
            artifact_locator,
            digests,
        })
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

    /// Parses one resolution document only after enforcing the complete transport byte bound.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionContractParseError`] when the document exceeds its byte limit or is not
    /// valid format-v2 resolution evidence.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, ExecutionContractParseError> {
        parse_bounded_slice(bytes, MAX_EXECUTION_RESOLUTION_DOCUMENT_BYTES)
    }

    /// Reads and parses one resolution document while retaining at most the document byte limit plus
    /// one sentinel byte.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionContractParseError`] for reader failures, an oversized document, or invalid
    /// format-v2 resolution evidence.
    pub fn from_json_reader(reader: impl Read) -> Result<Self, ExecutionContractParseError> {
        parse_bounded_reader(reader, MAX_EXECUTION_RESOLUTION_DOCUMENT_BYTES)
    }

    /// Returns deterministic canonical JSON bytes for content addressing.
    ///
    /// # Errors
    ///
    /// Returns a Serde JSON error if canonical serialization cannot complete.
    pub fn canonical_json_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

    /// Computes the role-typed SHA-256 identity of canonical JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns a Serde JSON error if canonical serialization cannot complete.
    pub fn canonical_document_digest(
        &self,
    ) -> serde_json::Result<ExecutionResolutionEvidenceDigest> {
        let bytes = self.canonical_json_bytes()?;
        Ok(ExecutionResolutionEvidenceDigest::new(
            Sha256Digest::from_bytes(Sha256::digest(bytes).into()),
        ))
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
    /// A managed locator contradicted the role-named executable byte identity.
    #[error("managed artifact locator digest does not match the resolved executable digest")]
    ManagedExecutableDigestMismatch,
    /// One process-tree resource limit was zero.
    #[error("execution resource limits must be nonzero")]
    ZeroResourceLimit,
    /// Per-process memory exceeded aggregate Job memory.
    #[error("process memory limit exceeds aggregate job memory limit")]
    IncoherentMemoryLimits,
}

/// Failure to read or parse one byte-bounded execution contract document.
#[derive(Debug, Error)]
pub enum ExecutionContractParseError {
    /// The serialized document exceeded its root-specific transport bound.
    #[error("execution contract document exceeds its {maximum}-byte transport limit")]
    DocumentTooLarge {
        /// Maximum accepted serialized bytes for this document root.
        maximum: usize,
    },
    /// Reading a bounded document failed.
    #[error("execution contract document could not be read")]
    Read(#[source] io::Error),
    /// Bounded bytes were not a valid canonical contract shape.
    #[error("execution contract document is invalid")]
    Json(#[source] serde_json::Error),
}

fn parse_bounded_slice<T>(bytes: &[u8], maximum: usize) -> Result<T, ExecutionContractParseError>
where
    T: for<'de> Deserialize<'de>,
{
    if bytes.len() > maximum {
        return Err(ExecutionContractParseError::DocumentTooLarge { maximum });
    }
    serde_json::from_slice(bytes).map_err(ExecutionContractParseError::Json)
}

fn parse_bounded_reader<T>(
    reader: impl Read,
    maximum: usize,
) -> Result<T, ExecutionContractParseError>
where
    T: for<'de> Deserialize<'de>,
{
    let Some(sentinel_limit) = maximum.checked_add(1) else {
        return Err(ExecutionContractParseError::DocumentTooLarge { maximum });
    };
    let Ok(sentinel_limit) = u64::try_from(sentinel_limit) else {
        return Err(ExecutionContractParseError::DocumentTooLarge { maximum });
    };
    let mut bytes = Vec::new();
    reader
        .take(sentinel_limit)
        .read_to_end(&mut bytes)
        .map_err(ExecutionContractParseError::Read)?;
    parse_bounded_slice(&bytes, maximum)
}
