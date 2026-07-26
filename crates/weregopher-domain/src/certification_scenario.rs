//! Canonical contracts for closed disposable-state certification scenarios and results.
//!
//! These documents describe one exact diagnostic scenario and its successful observation. They do
//! not authenticate a runner, authorize execution, establish an operating-system sandbox, or assign
//! a certification class. Higher layers must retrieve scenario bytes from an independently approved
//! runner component and retain the applicable package and policy capabilities.

use std::{collections::BTreeSet, fmt, io::Read, time::Duration};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    AdapterId, ApplicationFamilyId, EffectiveSecurityPosture, ExecutionArgument,
    ExecutionDependencyPolicy, ExecutionPackagePath, ExecutionResourceLimits, ExecutionStateMode,
    FeatureId, MAX_EXECUTION_ARGUMENT_AGGREGATE_BYTES, ScenarioId, ScenarioStateRootId,
    Sha256Digest,
};

/// Current serialized disposable certification-scenario format.
pub const DISPOSABLE_CERTIFICATION_SCENARIO_FORMAT_VERSION: &str = "1";
/// Maximum serialized bytes accepted for one disposable certification scenario.
pub const MAX_DISPOSABLE_CERTIFICATION_SCENARIO_BYTES: usize = 64 * 1024;
/// Maximum logical state roots declared by one disposable scenario.
pub const MAX_DISPOSABLE_SCENARIO_STATE_ROOTS: usize = 16;
/// Maximum fixed or state-path arguments declared by one disposable scenario.
pub const MAX_DISPOSABLE_SCENARIO_ARGUMENTS: usize = 32;
/// Maximum success-file bytes accepted by the initial scenario runner.
pub const MAX_DISPOSABLE_SCENARIO_SUCCESS_FILE_BYTES: u64 = 1024 * 1024;
/// Maximum scenario deadline accepted by the initial runner.
pub const MAX_DISPOSABLE_SCENARIO_TIMEOUT_MILLIS: u64 = 10 * 60 * 1_000;
/// Maximum polling interval accepted by the initial runner.
pub const MAX_DISPOSABLE_SCENARIO_POLL_MILLIS: u64 = 60 * 1_000;
/// Maximum graceful observation/termination interval accepted by the initial runner.
pub const MAX_DISPOSABLE_SCENARIO_SHUTDOWN_MILLIS: u64 = 60 * 1_000;
/// Maximum Windows arguments accepted by the scenario contract.
pub const MAX_DISPOSABLE_SCENARIO_LAUNCH_ARGUMENTS: u32 = 64;
/// Windows `CreateProcessW` command-line ceiling, including its terminating NUL.
pub const MAX_DISPOSABLE_SCENARIO_COMMAND_LINE_UTF16_UNITS: u32 = 32_767;

/// Current serialized successful disposable certification-scenario report format.
pub const DISPOSABLE_CERTIFICATION_SCENARIO_REPORT_FORMAT_VERSION: &str = "1";
/// Maximum serialized bytes accepted for one successful disposable scenario report.
pub const MAX_DISPOSABLE_CERTIFICATION_SCENARIO_REPORT_BYTES: usize = 128 * 1024;

macro_rules! scenario_digest_role {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Clone,
            Copy,
            Debug,
            Deserialize,
            Eq,
            Hash,
            JsonSchema,
            Ord,
            PartialEq,
            PartialOrd,
            Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(Sha256Digest);

        impl $name {
            /// Creates this role-specific identity from canonical SHA-256 bytes.
            #[must_use]
            pub const fn new(digest: Sha256Digest) -> Self {
                Self(digest)
            }

            /// Returns the wire-compatible SHA-256 value.
            #[must_use]
            pub const fn as_sha256(&self) -> &Sha256Digest {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

scenario_digest_role!(
    /// Identity of one canonical disposable certification-scenario definition.
    DisposableCertificationScenarioDigest
);
scenario_digest_role!(
    /// Identity of one canonical successful disposable certification-scenario report.
    DisposableCertificationScenarioReportDigest
);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
enum DisposableCertificationScenarioFormatVersion {
    #[serde(rename = "1")]
    V1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
enum DisposableCertificationScenarioReportFormatVersion {
    #[serde(rename = "1")]
    V1,
}

/// Preparation and observation semantics for one logical disposable-state root.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DisposableScenarioStateRootKind {
    /// The runner creates a new empty directory before process creation.
    EmptyDirectory,
    /// The process must create one exact bounded success file.
    SuccessFile {
        /// Exact required success-file byte identity.
        sha256: Sha256Digest,
        /// Exact required success-file byte length.
        #[schemars(range(max = 1_048_576))]
        size_bytes: u64,
        /// Maximum bytes the runner may read from this file.
        #[schemars(range(min = 1, max = 1_048_576))]
        maximum_bytes: u64,
    },
}

/// One logical state root whose absolute path is supplied separately at run time.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DisposableScenarioStateRoot {
    id: ScenarioStateRootId,
    definition: DisposableScenarioStateRootKind,
}

impl DisposableScenarioStateRoot {
    /// Declares one new empty directory.
    #[must_use]
    pub const fn empty_directory(id: ScenarioStateRootId) -> Self {
        Self {
            id,
            definition: DisposableScenarioStateRootKind::EmptyDirectory,
        }
    }

    /// Declares the exact success file created by a scenario.
    ///
    /// # Errors
    ///
    /// Rejects a maximum above the fixed runner ceiling, a zero maximum, or an expected length above
    /// the selected maximum.
    pub fn success_file(
        id: ScenarioStateRootId,
        sha256: Sha256Digest,
        size_bytes: u64,
        maximum_bytes: u64,
    ) -> Result<Self, DisposableCertificationScenarioError> {
        validate_success_file(size_bytes, maximum_bytes)?;
        Ok(Self {
            id,
            definition: DisposableScenarioStateRootKind::SuccessFile {
                sha256,
                size_bytes,
                maximum_bytes,
            },
        })
    }

    /// Returns the logical state-root identity.
    #[must_use]
    pub const fn id(&self) -> &ScenarioStateRootId {
        &self.id
    }

    /// Returns the exact preparation and observation semantics.
    #[must_use]
    pub const fn definition(&self) -> &DisposableScenarioStateRootKind {
        &self.definition
    }
}

/// One ordered argument in a disposable certification scenario.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DisposableScenarioArgument {
    /// One exact fixed argument.
    Literal {
        /// Exact fixed argument value.
        value: ExecutionArgument,
    },
    /// One argument composed from an exact prefix and a separately supplied state-root path.
    StatePath {
        /// Logical disposable-state root.
        state_root: ScenarioStateRootId,
        /// Exact argument prefix placed before the absolute state path.
        prefix: ExecutionArgument,
    },
}

impl DisposableScenarioArgument {
    /// Constructs one fixed argument.
    #[must_use]
    pub const fn literal(value: ExecutionArgument) -> Self {
        Self::Literal { value }
    }

    /// Constructs one state-path argument.
    #[must_use]
    pub const fn state_path(state_root: ScenarioStateRootId, prefix: ExecutionArgument) -> Self {
        Self::StatePath { state_root, prefix }
    }

    /// Returns the referenced state root, if any.
    #[must_use]
    pub const fn state_root(&self) -> Option<&ScenarioStateRootId> {
        match self {
            Self::Literal { .. } => None,
            Self::StatePath { state_root, .. } => Some(state_root),
        }
    }

    /// Returns the fixed value or state-path prefix.
    #[must_use]
    pub const fn value_or_prefix(&self) -> &ExecutionArgument {
        match self {
            Self::Literal { value } => value,
            Self::StatePath { prefix, .. } => prefix,
        }
    }
}

/// Exact time, launch, and Job Object limits for one disposable scenario.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DisposableScenarioLimits {
    #[schemars(range(min = 1, max = 600_000))]
    maximum_timeout_millis: u64,
    #[schemars(range(min = 1, max = 60000))]
    poll_interval_millis: u64,
    #[schemars(range(min = 1, max = 60000))]
    shutdown_timeout_millis: u64,
    #[schemars(range(min = 1, max = 64))]
    maximum_arguments: u32,
    #[schemars(range(min = 1, max = 32766))]
    maximum_argument_utf16_units: u32,
    #[schemars(range(min = 2, max = 32767))]
    maximum_command_line_utf16_units: u32,
    resource_limits: ExecutionResourceLimits,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedDisposableScenarioLimits {
    maximum_timeout_millis: u64,
    poll_interval_millis: u64,
    shutdown_timeout_millis: u64,
    maximum_arguments: u32,
    maximum_argument_utf16_units: u32,
    maximum_command_line_utf16_units: u32,
    resource_limits: ExecutionResourceLimits,
}

impl<'de> Deserialize<'de> for DisposableScenarioLimits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedDisposableScenarioLimits::deserialize(deserializer)?;
        Self::from_millis(
            unchecked.maximum_timeout_millis,
            unchecked.poll_interval_millis,
            unchecked.shutdown_timeout_millis,
            unchecked.maximum_arguments,
            unchecked.maximum_argument_utf16_units,
            unchecked.maximum_command_line_utf16_units,
            unchecked.resource_limits,
        )
        .map_err(D::Error::custom)
    }
}

impl DisposableScenarioLimits {
    /// Constructs bounded whole-millisecond scenario and Windows launch limits.
    ///
    /// # Errors
    ///
    /// Rejects zero, sub-millisecond, excessive, inverted, or unrepresentable durations and launch
    /// limits.
    pub fn new(
        maximum_timeout: Duration,
        poll_interval: Duration,
        shutdown_timeout: Duration,
        maximum_arguments: u32,
        maximum_argument_utf16_units: u32,
        maximum_command_line_utf16_units: u32,
        resource_limits: ExecutionResourceLimits,
    ) -> Result<Self, DisposableCertificationScenarioError> {
        Self::from_millis(
            exact_millis(maximum_timeout)?,
            exact_millis(poll_interval)?,
            exact_millis(shutdown_timeout)?,
            maximum_arguments,
            maximum_argument_utf16_units,
            maximum_command_line_utf16_units,
            resource_limits,
        )
    }

    fn from_millis(
        maximum_timeout_millis: u64,
        poll_interval_millis: u64,
        shutdown_timeout_millis: u64,
        maximum_arguments: u32,
        maximum_argument_utf16_units: u32,
        maximum_command_line_utf16_units: u32,
        resource_limits: ExecutionResourceLimits,
    ) -> Result<Self, DisposableCertificationScenarioError> {
        if maximum_timeout_millis == 0
            || maximum_timeout_millis > MAX_DISPOSABLE_SCENARIO_TIMEOUT_MILLIS
            || poll_interval_millis == 0
            || poll_interval_millis > MAX_DISPOSABLE_SCENARIO_POLL_MILLIS
            || poll_interval_millis > maximum_timeout_millis
            || shutdown_timeout_millis == 0
            || shutdown_timeout_millis > MAX_DISPOSABLE_SCENARIO_SHUTDOWN_MILLIS
        {
            return Err(DisposableCertificationScenarioError::InvalidDurationLimits);
        }
        if maximum_arguments == 0
            || maximum_arguments > MAX_DISPOSABLE_SCENARIO_LAUNCH_ARGUMENTS
            || maximum_argument_utf16_units == 0
            || maximum_argument_utf16_units >= maximum_command_line_utf16_units
            || maximum_command_line_utf16_units == 0
            || maximum_command_line_utf16_units > MAX_DISPOSABLE_SCENARIO_COMMAND_LINE_UTF16_UNITS
        {
            return Err(DisposableCertificationScenarioError::InvalidLaunchLimits);
        }
        Ok(Self {
            maximum_timeout_millis,
            poll_interval_millis,
            shutdown_timeout_millis,
            maximum_arguments,
            maximum_argument_utf16_units,
            maximum_command_line_utf16_units,
            resource_limits,
        })
    }

    /// Returns the maximum selected scenario duration.
    #[must_use]
    pub const fn maximum_timeout_millis(self) -> u64 {
        self.maximum_timeout_millis
    }

    /// Returns the process/success-file polling interval.
    #[must_use]
    pub const fn poll_interval_millis(self) -> u64 {
        self.poll_interval_millis
    }

    /// Returns the maximum wait for confirmed primary-process termination after success.
    #[must_use]
    pub const fn shutdown_timeout_millis(self) -> u64 {
        self.shutdown_timeout_millis
    }

    /// Returns the maximum caller-supplied argument count.
    #[must_use]
    pub const fn maximum_arguments(self) -> u32 {
        self.maximum_arguments
    }

    /// Returns the maximum UTF-16 units in one argument before quoting.
    #[must_use]
    pub const fn maximum_argument_utf16_units(self) -> u32 {
        self.maximum_argument_utf16_units
    }

    /// Returns the maximum UTF-16 units in the complete Windows command line.
    #[must_use]
    pub const fn maximum_command_line_utf16_units(self) -> u32 {
        self.maximum_command_line_utf16_units
    }

    /// Returns the exact Job Object resource limits.
    #[must_use]
    pub const fn resource_limits(self) -> ExecutionResourceLimits {
        self.resource_limits
    }
}

/// Fixed process posture and limits for disposable scenario format 1.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DisposableScenarioExecution {
    state_mode: ExecutionStateMode,
    security_posture: EffectiveSecurityPosture,
    dependency_policy: ExecutionDependencyPolicy,
    limits: DisposableScenarioLimits,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedDisposableScenarioExecution {
    state_mode: ExecutionStateMode,
    security_posture: EffectiveSecurityPosture,
    dependency_policy: ExecutionDependencyPolicy,
    limits: DisposableScenarioLimits,
}

impl<'de> Deserialize<'de> for DisposableScenarioExecution {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedDisposableScenarioExecution::deserialize(deserializer)?;
        if unchecked.state_mode != ExecutionStateMode::Disposable
            || unchecked.security_posture != EffectiveSecurityPosture::VendorEquivalentFullTrust
            || unchecked.dependency_policy != ExecutionDependencyPolicy::VendorDefaultAmbient
        {
            return Err(D::Error::custom(
                DisposableCertificationScenarioError::UnsupportedExecutionPosture,
            ));
        }
        Ok(Self::new(unchecked.limits))
    }
}

impl DisposableScenarioExecution {
    const fn new(limits: DisposableScenarioLimits) -> Self {
        Self {
            state_mode: ExecutionStateMode::Disposable,
            security_posture: EffectiveSecurityPosture::VendorEquivalentFullTrust,
            dependency_policy: ExecutionDependencyPolicy::VendorDefaultAmbient,
            limits,
        }
    }

    /// Returns the fixed disposable-state mode.
    #[must_use]
    pub const fn state_mode(self) -> ExecutionStateMode {
        self.state_mode
    }

    /// Returns the honest unrestricted same-user security posture.
    #[must_use]
    pub const fn security_posture(self) -> EffectiveSecurityPosture {
        self.security_posture
    }

    /// Returns the unsealed ambient dependency posture.
    #[must_use]
    pub const fn dependency_policy(self) -> ExecutionDependencyPolicy {
        self.dependency_policy
    }

    /// Returns the exact scenario limits.
    #[must_use]
    pub const fn limits(self) -> DisposableScenarioLimits {
        self.limits
    }
}

/// Canonical bounded description of one exact disposable-state diagnostic scenario.
///
/// Parsing and content addressing do not authenticate these bytes or authorize their launch.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DisposableCertificationScenario {
    format_version: DisposableCertificationScenarioFormatVersion,
    id: ScenarioId,
    application_family: ApplicationFamilyId,
    adapter_id: AdapterId,
    workflow: FeatureId,
    executable: ExecutionPackagePath,
    #[schemars(length(min = 1, max = 16))]
    state_roots: BTreeSet<DisposableScenarioStateRoot>,
    #[schemars(length(min = 1, max = 32))]
    arguments: Vec<DisposableScenarioArgument>,
    execution: DisposableScenarioExecution,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedDisposableCertificationScenario {
    format_version: DisposableCertificationScenarioFormatVersion,
    id: ScenarioId,
    application_family: ApplicationFamilyId,
    adapter_id: AdapterId,
    workflow: FeatureId,
    executable: ExecutionPackagePath,
    state_roots: Vec<DisposableScenarioStateRoot>,
    arguments: Vec<DisposableScenarioArgument>,
    execution: DisposableScenarioExecution,
}

impl<'de> Deserialize<'de> for DisposableCertificationScenario {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let UncheckedDisposableCertificationScenario {
            format_version: DisposableCertificationScenarioFormatVersion::V1,
            id,
            application_family,
            adapter_id,
            workflow,
            executable,
            state_roots,
            arguments,
            execution,
        } = UncheckedDisposableCertificationScenario::deserialize(deserializer)?;
        Self::new(
            id,
            application_family,
            adapter_id,
            workflow,
            executable,
            state_roots,
            arguments,
            execution.limits(),
        )
        .map_err(D::Error::custom)
    }
}

impl DisposableCertificationScenario {
    /// Constructs one closed, bounded, fixed-posture scenario.
    ///
    /// # Errors
    ///
    /// Rejects missing, excessive, duplicate, invalid, multiply bound, or unbound state roots;
    /// excessive arguments; and argument limits that cannot contain the declared argument list.
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor keeps every scenario identity and capability-bearing input explicit"
    )]
    pub fn new(
        id: ScenarioId,
        application_family: ApplicationFamilyId,
        adapter_id: AdapterId,
        workflow: FeatureId,
        executable: ExecutionPackagePath,
        state_roots: Vec<DisposableScenarioStateRoot>,
        arguments: Vec<DisposableScenarioArgument>,
        limits: DisposableScenarioLimits,
    ) -> Result<Self, DisposableCertificationScenarioError> {
        if state_roots.is_empty() || state_roots.len() > MAX_DISPOSABLE_SCENARIO_STATE_ROOTS {
            return Err(DisposableCertificationScenarioError::InvalidStateRootCount);
        }
        let mut roots = BTreeSet::new();
        let mut root_ids = BTreeSet::new();
        let mut success_files = 0_usize;
        for root in state_roots {
            if !root_ids.insert(root.id.clone()) {
                return Err(DisposableCertificationScenarioError::DuplicateStateRoot);
            }
            if let DisposableScenarioStateRootKind::SuccessFile {
                size_bytes,
                maximum_bytes,
                ..
            } = root.definition
            {
                validate_success_file(size_bytes, maximum_bytes)?;
                success_files = success_files
                    .checked_add(1)
                    .ok_or(DisposableCertificationScenarioError::InvalidSuccessFileCount)?;
            }
            roots.insert(root);
        }
        if success_files != 1 {
            return Err(DisposableCertificationScenarioError::InvalidSuccessFileCount);
        }
        if arguments.is_empty()
            || arguments.len() > MAX_DISPOSABLE_SCENARIO_ARGUMENTS
            || arguments.len()
                > usize::try_from(limits.maximum_arguments)
                    .map_err(|_| DisposableCertificationScenarioError::InvalidLaunchLimits)?
        {
            return Err(DisposableCertificationScenarioError::InvalidArgumentCount);
        }
        let mut bound_roots = BTreeSet::new();
        let mut aggregate_argument_bytes = 0_usize;
        for argument in &arguments {
            aggregate_argument_bytes = aggregate_argument_bytes
                .checked_add(argument.value_or_prefix().as_str().len())
                .ok_or(DisposableCertificationScenarioError::ArgumentBytesExceeded)?;
            if aggregate_argument_bytes > MAX_EXECUTION_ARGUMENT_AGGREGATE_BYTES {
                return Err(DisposableCertificationScenarioError::ArgumentBytesExceeded);
            }
            if let Some(root) = argument.state_root() {
                if !root_ids.contains(root) {
                    return Err(DisposableCertificationScenarioError::UnknownStateRoot);
                }
                if !bound_roots.insert(root.clone()) {
                    return Err(DisposableCertificationScenarioError::DuplicateStateRootArgument);
                }
            }
        }
        if bound_roots != root_ids {
            return Err(DisposableCertificationScenarioError::UnboundStateRoot);
        }
        Ok(Self {
            format_version: DisposableCertificationScenarioFormatVersion::V1,
            id,
            application_family,
            adapter_id,
            workflow,
            executable,
            state_roots: roots,
            arguments,
            execution: DisposableScenarioExecution::new(limits),
        })
    }

    /// Parses one scenario after enforcing its serialized-byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns a closed document or contract error for oversized, malformed, unsupported, or
    /// semantically invalid input.
    pub fn from_json_slice(
        bytes: &[u8],
    ) -> Result<Self, DisposableCertificationScenarioDocumentError> {
        if bytes.len() > MAX_DISPOSABLE_CERTIFICATION_SCENARIO_BYTES {
            return Err(DisposableCertificationScenarioDocumentError::DocumentTooLarge);
        }
        let UncheckedDisposableCertificationScenario {
            format_version: DisposableCertificationScenarioFormatVersion::V1,
            id,
            application_family,
            adapter_id,
            workflow,
            executable,
            state_roots,
            arguments,
            execution,
        } = serde_json::from_slice(bytes)
            .map_err(DisposableCertificationScenarioDocumentError::InvalidDocument)?;
        Self::new(
            id,
            application_family,
            adapter_id,
            workflow,
            executable,
            state_roots,
            arguments,
            execution.limits(),
        )
        .map_err(DisposableCertificationScenarioDocumentError::InvalidContract)
    }

    /// Reads one scenario through its fixed byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns a bounded read, document, or contract error.
    pub fn from_json_reader(
        mut reader: impl Read,
    ) -> Result<Self, DisposableCertificationScenarioDocumentError> {
        let mut bytes = Vec::new();
        reader
            .by_ref()
            .take(
                u64::try_from(MAX_DISPOSABLE_CERTIFICATION_SCENARIO_BYTES)
                    .map_err(|_| DisposableCertificationScenarioDocumentError::DocumentTooLarge)?
                    + 1,
            )
            .read_to_end(&mut bytes)
            .map_err(DisposableCertificationScenarioDocumentError::Read)?;
        Self::from_json_slice(&bytes)
    }

    /// Returns canonical compact JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns a serialization error when canonical bytes cannot be produced.
    pub fn canonical_json_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

    /// Returns the exact canonical scenario identity.
    ///
    /// # Errors
    ///
    /// Returns a serialization error when canonical bytes cannot be produced.
    pub fn canonical_document_digest(
        &self,
    ) -> serde_json::Result<DisposableCertificationScenarioDigest> {
        Ok(DisposableCertificationScenarioDigest::new(
            canonical_digest(self)?,
        ))
    }

    /// Returns the exact format version.
    #[must_use]
    pub const fn format_version(&self) -> &'static str {
        DISPOSABLE_CERTIFICATION_SCENARIO_FORMAT_VERSION
    }

    /// Returns the scenario identity.
    #[must_use]
    pub const fn id(&self) -> &ScenarioId {
        &self.id
    }

    /// Returns the selected application family.
    #[must_use]
    pub const fn application_family(&self) -> &ApplicationFamilyId {
        &self.application_family
    }

    /// Returns the selected adapter.
    #[must_use]
    pub const fn adapter_id(&self) -> &AdapterId {
        &self.adapter_id
    }

    /// Returns the exact workflow.
    #[must_use]
    pub const fn workflow(&self) -> &FeatureId {
        &self.workflow
    }

    /// Returns the manifest-relative executable.
    #[must_use]
    pub const fn executable(&self) -> &ExecutionPackagePath {
        &self.executable
    }

    /// Returns disposable state roots in canonical identity order.
    #[must_use]
    pub const fn state_roots(&self) -> &BTreeSet<DisposableScenarioStateRoot> {
        &self.state_roots
    }

    /// Returns arguments in exact launch order.
    #[must_use]
    pub fn arguments(&self) -> &[DisposableScenarioArgument] {
        &self.arguments
    }

    /// Returns the fixed execution contract.
    #[must_use]
    pub const fn execution(&self) -> DisposableScenarioExecution {
        self.execution
    }

    /// Returns the fixed disposable state mode.
    #[must_use]
    pub const fn state_mode(&self) -> ExecutionStateMode {
        self.execution.state_mode()
    }

    /// Returns the honest unrestricted same-user security posture.
    #[must_use]
    pub const fn security_posture(&self) -> EffectiveSecurityPosture {
        self.execution.security_posture()
    }

    /// Returns the ambient dependency-resolution posture.
    #[must_use]
    pub const fn dependency_policy(&self) -> ExecutionDependencyPolicy {
        self.execution.dependency_policy()
    }

    /// Returns the maximum selected timeout.
    #[must_use]
    pub const fn maximum_timeout(&self) -> Duration {
        Duration::from_millis(self.execution.limits.maximum_timeout_millis)
    }

    /// Returns the poll interval.
    #[must_use]
    pub const fn poll_interval(&self) -> Duration {
        Duration::from_millis(self.execution.limits.poll_interval_millis)
    }

    /// Returns the primary-process shutdown interval.
    #[must_use]
    pub const fn shutdown_timeout(&self) -> Duration {
        Duration::from_millis(self.execution.limits.shutdown_timeout_millis)
    }

    /// Returns the unique success-file root.
    #[must_use]
    pub fn success_file_root(&self) -> Option<&DisposableScenarioStateRoot> {
        self.state_roots.iter().find(|root| {
            matches!(
                root.definition,
                DisposableScenarioStateRootKind::SuccessFile { .. }
            )
        })
    }
}

fn validate_success_file(
    size_bytes: u64,
    maximum_bytes: u64,
) -> Result<(), DisposableCertificationScenarioError> {
    if maximum_bytes == 0
        || maximum_bytes > MAX_DISPOSABLE_SCENARIO_SUCCESS_FILE_BYTES
        || size_bytes > maximum_bytes
    {
        return Err(DisposableCertificationScenarioError::InvalidSuccessFileLimits);
    }
    Ok(())
}

fn exact_millis(duration: Duration) -> Result<u64, DisposableCertificationScenarioError> {
    let millis = u64::try_from(duration.as_millis())
        .map_err(|_| DisposableCertificationScenarioError::InvalidDurationLimits)?;
    if millis == 0 || duration != Duration::from_millis(millis) {
        return Err(DisposableCertificationScenarioError::InvalidDurationLimits);
    }
    Ok(millis)
}

/// Invalid disposable certification-scenario construction.
#[derive(Debug, Error)]
pub enum DisposableCertificationScenarioError {
    /// State-root count was zero or exceeded the fixed ceiling.
    #[error("disposable scenario state-root count is invalid")]
    InvalidStateRootCount,
    /// Two roots used the same logical identity.
    #[error("disposable scenario contains a duplicate state-root identity")]
    DuplicateStateRoot,
    /// The scenario did not contain exactly one success file.
    #[error("disposable scenario must contain exactly one success file")]
    InvalidSuccessFileCount,
    /// Success-file length or read ceiling was invalid.
    #[error("disposable scenario success-file limits are invalid")]
    InvalidSuccessFileLimits,
    /// Duration fields were zero, sub-millisecond, inverted, excessive, or unrepresentable.
    #[error("disposable scenario duration limits are invalid")]
    InvalidDurationLimits,
    /// Windows process-launch limits were zero, inverted, or excessive.
    #[error("disposable scenario launch limits are invalid")]
    InvalidLaunchLimits,
    /// Argument count was zero, excessive, or above the scenario's selected launch bound.
    #[error("disposable scenario argument count is invalid")]
    InvalidArgumentCount,
    /// Fixed argument and prefix bytes exceeded their aggregate ceiling.
    #[error("disposable scenario argument bytes exceed their aggregate ceiling")]
    ArgumentBytesExceeded,
    /// An argument referenced an undeclared logical root.
    #[error("disposable scenario argument references an unknown state root")]
    UnknownStateRoot,
    /// More than one argument referenced the same state root.
    #[error("disposable scenario state root is bound by more than one argument")]
    DuplicateStateRootArgument,
    /// A declared state root was not used by the exact argument list.
    #[error("disposable scenario state root is not bound by an argument")]
    UnboundStateRoot,
    /// Serialized execution posture differed from the fixed format-1 semantics.
    #[error("disposable scenario execution posture is unsupported")]
    UnsupportedExecutionPosture,
}

/// Failure to read or parse one bounded disposable certification scenario.
#[derive(Debug, Error)]
pub enum DisposableCertificationScenarioDocumentError {
    /// Serialized input exceeded the fixed ceiling.
    #[error("disposable certification scenario exceeds its byte ceiling")]
    DocumentTooLarge,
    /// Bounded input could not be read.
    #[error("failed to read disposable certification scenario")]
    Read(#[source] std::io::Error),
    /// JSON syntax, the closed transport shape, or domain semantics were invalid.
    #[error("disposable certification scenario document is invalid")]
    InvalidDocument(#[source] serde_json::Error),
    /// Parsed fields violated the scenario contract.
    #[error("disposable certification scenario contract is invalid")]
    InvalidContract(#[source] DisposableCertificationScenarioError),
}

/// Exact retained package facts used by one scenario run.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DisposableScenarioPackageObservation {
    package_tree_merkle: Sha256Digest,
    executable_sha256: Sha256Digest,
    #[schemars(range(min = 1))]
    package_files: u32,
    #[schemars(range(min = 1))]
    package_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedDisposableScenarioPackageObservation {
    package_tree_merkle: Sha256Digest,
    executable_sha256: Sha256Digest,
    package_files: u32,
    package_bytes: u64,
}

impl<'de> Deserialize<'de> for DisposableScenarioPackageObservation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedDisposableScenarioPackageObservation::deserialize(deserializer)?;
        Self::from_wire(
            unchecked.package_tree_merkle,
            unchecked.executable_sha256,
            unchecked.package_files,
            unchecked.package_bytes,
        )
        .map_err(D::Error::custom)
    }
}

impl DisposableScenarioPackageObservation {
    /// Constructs nonempty, representable package facts.
    ///
    /// # Errors
    ///
    /// Rejects a zero or unrepresentable file count and zero aggregate package bytes.
    pub fn new(
        package_tree_merkle: Sha256Digest,
        executable_sha256: Sha256Digest,
        package_files: usize,
        package_bytes: u64,
    ) -> Result<Self, DisposableCertificationScenarioReportError> {
        let package_files = u32::try_from(package_files)
            .map_err(|_| DisposableCertificationScenarioReportError::InvalidPackageFileCount)?;
        Self::from_wire(
            package_tree_merkle,
            executable_sha256,
            package_files,
            package_bytes,
        )
    }

    fn from_wire(
        package_tree_merkle: Sha256Digest,
        executable_sha256: Sha256Digest,
        package_files: u32,
        package_bytes: u64,
    ) -> Result<Self, DisposableCertificationScenarioReportError> {
        if package_files == 0 {
            return Err(DisposableCertificationScenarioReportError::InvalidPackageFileCount);
        }
        if package_bytes == 0 {
            return Err(DisposableCertificationScenarioReportError::InvalidPackageByteCount);
        }
        Ok(Self {
            package_tree_merkle,
            executable_sha256,
            package_files,
            package_bytes,
        })
    }

    /// Returns the exact package-tree identity.
    #[must_use]
    pub const fn package_tree_merkle(&self) -> Sha256Digest {
        self.package_tree_merkle
    }

    /// Returns the exact executable-byte identity.
    #[must_use]
    pub const fn executable_sha256(&self) -> Sha256Digest {
        self.executable_sha256
    }

    /// Returns the retained package file count.
    #[must_use]
    pub const fn package_files(&self) -> u32 {
        self.package_files
    }

    /// Returns aggregate retained package bytes.
    #[must_use]
    pub const fn package_bytes(&self) -> u64 {
        self.package_bytes
    }
}

/// Exact successful file observation from one disposable scenario.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DisposableScenarioSuccessFileObservation {
    state_root: ScenarioStateRootId,
    sha256: Sha256Digest,
    #[schemars(range(max = 1_048_576))]
    size_bytes: u64,
}

impl DisposableScenarioSuccessFileObservation {
    /// Returns the logical success-file root.
    #[must_use]
    pub const fn state_root(&self) -> &ScenarioStateRootId {
        &self.state_root
    }

    /// Returns the exact observed byte identity.
    #[must_use]
    pub const fn sha256(&self) -> Sha256Digest {
        self.sha256
    }

    /// Returns the exact observed byte length.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DisposableScenarioPassedCheck {
    Passed,
}

/// Deterministic successful process and state observations.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DisposableScenarioExecutionObservation {
    #[schemars(range(min = 1, max = 600_000))]
    selected_timeout_millis: u64,
    job_membership: DisposableScenarioPassedCheck,
    job_tree_termination: DisposableScenarioPassedCheck,
    primary_process_exit: DisposableScenarioPassedCheck,
    snapshot_revalidation: DisposableScenarioPassedCheck,
    success_file: DisposableScenarioSuccessFileObservation,
}

impl DisposableScenarioExecutionObservation {
    /// Returns the selected timeout as exact whole milliseconds.
    #[must_use]
    pub const fn selected_timeout_millis(&self) -> u64 {
        self.selected_timeout_millis
    }

    /// Returns the selected timeout.
    #[must_use]
    pub const fn selected_timeout(&self) -> Duration {
        Duration::from_millis(self.selected_timeout_millis)
    }

    /// Reports the fixed successful Job-membership check.
    #[must_use]
    pub const fn job_membership_confirmed(&self) -> bool {
        matches!(self.job_membership, DisposableScenarioPassedCheck::Passed)
    }

    /// Reports the fixed successful whole-Job process-tree termination check.
    #[must_use]
    pub const fn job_tree_termination_confirmed(&self) -> bool {
        matches!(
            self.job_tree_termination,
            DisposableScenarioPassedCheck::Passed
        )
    }

    /// Reports the fixed successful primary-process exit check.
    #[must_use]
    pub const fn primary_process_exit_confirmed(&self) -> bool {
        matches!(
            self.primary_process_exit,
            DisposableScenarioPassedCheck::Passed
        )
    }

    /// Reports the fixed successful point-in-time snapshot revalidation.
    #[must_use]
    pub const fn snapshot_revalidated(&self) -> bool {
        matches!(
            self.snapshot_revalidation,
            DisposableScenarioPassedCheck::Passed
        )
    }

    /// Returns the exact success-file observation.
    #[must_use]
    pub const fn success_file(&self) -> &DisposableScenarioSuccessFileObservation {
        &self.success_file
    }
}

/// Canonical non-authorizing report from one successful disposable-state scenario.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DisposableCertificationScenarioReport {
    format_version: DisposableCertificationScenarioReportFormatVersion,
    scenario: DisposableCertificationScenario,
    package: DisposableScenarioPackageObservation,
    execution: DisposableScenarioExecutionObservation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedDisposableCertificationScenarioReport {
    format_version: DisposableCertificationScenarioReportFormatVersion,
    scenario: DisposableCertificationScenario,
    package: DisposableScenarioPackageObservation,
    execution: DisposableScenarioExecutionObservation,
}

impl<'de> Deserialize<'de> for DisposableCertificationScenarioReport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let UncheckedDisposableCertificationScenarioReport {
            format_version: DisposableCertificationScenarioReportFormatVersion::V1,
            scenario,
            package,
            execution,
        } = UncheckedDisposableCertificationScenarioReport::deserialize(deserializer)?;
        Self::from_observations(scenario, package, execution).map_err(D::Error::custom)
    }
}

impl DisposableCertificationScenarioReport {
    /// Constructs one successful report from exact observed success-file bytes.
    ///
    /// # Errors
    ///
    /// Rejects a selected timeout outside the scenario contract or observed success bytes that do
    /// not match the unique declared success file.
    pub fn successful(
        scenario: DisposableCertificationScenario,
        package: DisposableScenarioPackageObservation,
        selected_timeout: Duration,
        success_file_bytes: &[u8],
    ) -> Result<Self, DisposableCertificationScenarioReportError> {
        let selected_timeout_millis = exact_report_millis(selected_timeout)?;
        let success_root = scenario
            .success_file_root()
            .ok_or(DisposableCertificationScenarioReportError::MissingSuccessFile)?;
        let success_size = u64::try_from(success_file_bytes.len())
            .map_err(|_| DisposableCertificationScenarioReportError::SuccessFileMismatch)?;
        let success_file = DisposableScenarioSuccessFileObservation {
            state_root: success_root.id.clone(),
            sha256: digest(success_file_bytes),
            size_bytes: success_size,
        };
        Self::from_observations(
            scenario,
            package,
            DisposableScenarioExecutionObservation {
                selected_timeout_millis,
                job_membership: DisposableScenarioPassedCheck::Passed,
                job_tree_termination: DisposableScenarioPassedCheck::Passed,
                primary_process_exit: DisposableScenarioPassedCheck::Passed,
                snapshot_revalidation: DisposableScenarioPassedCheck::Passed,
                success_file,
            },
        )
    }

    fn from_observations(
        scenario: DisposableCertificationScenario,
        package: DisposableScenarioPackageObservation,
        execution: DisposableScenarioExecutionObservation,
    ) -> Result<Self, DisposableCertificationScenarioReportError> {
        if execution.selected_timeout_millis == 0
            || execution.selected_timeout_millis > scenario.execution.limits.maximum_timeout_millis
        {
            return Err(DisposableCertificationScenarioReportError::InvalidSelectedTimeout);
        }
        let success_root = scenario
            .success_file_root()
            .ok_or(DisposableCertificationScenarioReportError::MissingSuccessFile)?;
        let DisposableScenarioStateRootKind::SuccessFile {
            sha256,
            size_bytes,
            maximum_bytes,
        } = &success_root.definition
        else {
            return Err(DisposableCertificationScenarioReportError::MissingSuccessFile);
        };
        if execution.success_file.state_root != success_root.id
            || execution.success_file.sha256 != *sha256
            || execution.success_file.size_bytes != *size_bytes
            || execution.success_file.size_bytes > *maximum_bytes
        {
            return Err(DisposableCertificationScenarioReportError::SuccessFileMismatch);
        }
        Ok(Self {
            format_version: DisposableCertificationScenarioReportFormatVersion::V1,
            scenario,
            package,
            execution,
        })
    }

    /// Parses one report after enforcing its serialized-byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns a document or contract error for oversized, malformed, unsupported, or semantically
    /// inconsistent input.
    pub fn from_json_slice(
        bytes: &[u8],
    ) -> Result<Self, DisposableCertificationScenarioReportDocumentError> {
        if bytes.len() > MAX_DISPOSABLE_CERTIFICATION_SCENARIO_REPORT_BYTES {
            return Err(DisposableCertificationScenarioReportDocumentError::DocumentTooLarge);
        }
        let UncheckedDisposableCertificationScenarioReport {
            format_version: DisposableCertificationScenarioReportFormatVersion::V1,
            scenario,
            package,
            execution,
        } = serde_json::from_slice(bytes)
            .map_err(DisposableCertificationScenarioReportDocumentError::InvalidDocument)?;
        Self::from_observations(scenario, package, execution)
            .map_err(DisposableCertificationScenarioReportDocumentError::InvalidContract)
    }

    /// Reads one report through its fixed byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns a bounded read, document, or contract error.
    pub fn from_json_reader(
        mut reader: impl Read,
    ) -> Result<Self, DisposableCertificationScenarioReportDocumentError> {
        let mut bytes = Vec::new();
        reader
            .by_ref()
            .take(
                u64::try_from(MAX_DISPOSABLE_CERTIFICATION_SCENARIO_REPORT_BYTES).map_err(
                    |_| DisposableCertificationScenarioReportDocumentError::DocumentTooLarge,
                )? + 1,
            )
            .read_to_end(&mut bytes)
            .map_err(DisposableCertificationScenarioReportDocumentError::Read)?;
        Self::from_json_slice(&bytes)
    }

    /// Returns canonical compact JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns a serialization error when canonical bytes cannot be produced.
    pub fn canonical_json_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

    /// Returns the exact canonical report identity.
    ///
    /// # Errors
    ///
    /// Returns a serialization error when canonical bytes cannot be produced.
    pub fn canonical_document_digest(
        &self,
    ) -> serde_json::Result<DisposableCertificationScenarioReportDigest> {
        Ok(DisposableCertificationScenarioReportDigest::new(
            canonical_digest(self)?,
        ))
    }

    /// Returns the exact report format version.
    #[must_use]
    pub const fn format_version(&self) -> &'static str {
        DISPOSABLE_CERTIFICATION_SCENARIO_REPORT_FORMAT_VERSION
    }

    /// Returns the exact executed scenario.
    #[must_use]
    pub const fn scenario(&self) -> &DisposableCertificationScenario {
        &self.scenario
    }

    /// Returns exact retained package facts.
    #[must_use]
    pub const fn package(&self) -> &DisposableScenarioPackageObservation {
        &self.package
    }

    /// Returns deterministic successful execution observations.
    #[must_use]
    pub const fn execution(&self) -> &DisposableScenarioExecutionObservation {
        &self.execution
    }
}

fn exact_report_millis(
    duration: Duration,
) -> Result<u64, DisposableCertificationScenarioReportError> {
    let millis = u64::try_from(duration.as_millis())
        .map_err(|_| DisposableCertificationScenarioReportError::InvalidSelectedTimeout)?;
    if millis == 0 || duration != Duration::from_millis(millis) {
        return Err(DisposableCertificationScenarioReportError::InvalidSelectedTimeout);
    }
    Ok(millis)
}

/// Invalid successful disposable certification-scenario report.
#[derive(Debug, Error)]
pub enum DisposableCertificationScenarioReportError {
    /// Package file count was zero or unrepresentable.
    #[error("disposable scenario package file count is invalid")]
    InvalidPackageFileCount,
    /// Aggregate package bytes were zero.
    #[error("disposable scenario package byte count is invalid")]
    InvalidPackageByteCount,
    /// Selected timeout was zero, sub-millisecond, excessive, or unrepresentable.
    #[error("disposable scenario selected timeout is invalid")]
    InvalidSelectedTimeout,
    /// The scenario did not expose its required unique success file.
    #[error("disposable scenario success file is missing")]
    MissingSuccessFile,
    /// Observed success-file identity, root, or length did not match the scenario.
    #[error("disposable scenario success-file observation does not match its contract")]
    SuccessFileMismatch,
}

/// Failure to read or parse one bounded successful scenario report.
#[derive(Debug, Error)]
pub enum DisposableCertificationScenarioReportDocumentError {
    /// Serialized input exceeded the fixed ceiling.
    #[error("disposable certification scenario report exceeds its byte ceiling")]
    DocumentTooLarge,
    /// Bounded input could not be read.
    #[error("failed to read disposable certification scenario report")]
    Read(#[source] std::io::Error),
    /// JSON syntax or the closed transport shape was invalid.
    #[error("disposable certification scenario report document is invalid")]
    InvalidDocument(#[source] serde_json::Error),
    /// Parsed fields violated the report contract.
    #[error("disposable certification scenario report contract is invalid")]
    InvalidContract(#[source] DisposableCertificationScenarioReportError),
}

fn canonical_digest(value: &impl Serialize) -> serde_json::Result<Sha256Digest> {
    serde_json::to_vec(value).map(|bytes| digest(&bytes))
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}
