//! Canonical semantic report for the exact Discord disposable-state smoke workflow.

use std::{fmt, time::Duration};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use weregopher_domain::{
    AdapterId, ApplicationFamilyId, DisposableCertificationScenario,
    DisposableCertificationScenarioDigest, DisposableCertificationScenarioError,
    DisposableCertificationScenarioReport, DisposableScenarioArgument, DisposableScenarioLimits,
    DisposableScenarioStateRoot, ExecutionArgument, ExecutionPackagePath, ExecutionResourceLimits,
    ExecutionTargetContractError, FeatureId, IdentifierError, ScenarioId, ScenarioStateRootId,
    Sha256Digest,
};

use crate::{
    DISCORD_MAIN_ENTRY, DiscordAdapterError, SMOKE_ADAPTER_ID, SMOKE_MARKER_ARGUMENT_PREFIX,
    SMOKE_MARKER_CONTENT, SMOKE_PREFIX, transform_smoke_source,
};

/// Current Discord smoke-certification report format.
pub const DISCORD_SMOKE_CERTIFICATION_REPORT_FORMAT_VERSION: &str = "2";
/// Maximum serialized report bytes accepted by the canonical parser.
pub const MAX_DISCORD_SMOKE_CERTIFICATION_REPORT_BYTES: usize = 64 * 1024;
/// Exact workflow certified by this deliberately narrow profile.
pub const DISCORD_SMOKE_WORKFLOW_ID: &str = "discord.smoke-marker";
/// Exact probe-asset name containing the canonical Discord smoke scenario.
pub const DISCORD_SMOKE_SCENARIO_ARTIFACT_NAME: &str =
    "scenarios/discord.smoke-marker.scenario.json";
/// Durable Discord application-family identity used by the smoke scenario.
pub const DISCORD_APPLICATION_FAMILY_ID: &str = "discord";
/// Manifest-relative executable selected by the Discord smoke scenario.
pub const DISCORD_EXECUTABLE_PATH: &str = "Discord.exe";
/// Logical success-file root selected by the Discord smoke scenario.
pub const DISCORD_SMOKE_MARKER_STATE_ROOT_ID: &str = "marker";
/// Logical empty user-data root selected by the Discord smoke scenario.
pub const DISCORD_SMOKE_USER_DATA_STATE_ROOT_ID: &str = "user-data";
/// Exact reviewed mutable file omitted from the managed smoke package.
pub const SMOKE_MUTABLE_DISPATCH_LOG_PATH: &str =
    "modules/discord_dispatch-1/discord_dispatch/dispatch.log";
/// Exact reviewed empty mutable directory omitted from the managed smoke package.
pub const SMOKE_MUTABLE_KRISP_LOG_DIRECTORY_PATH: &str =
    "modules/discord_krisp-1/discord_krisp/KMS/logs";
/// Maximum launch duration accepted by the smoke-report contract.
pub const SMOKE_TIMEOUT_MAX_SECONDS: u64 = 60;
/// Job active-process ceiling used by the smoke workflow.
pub const SMOKE_ACTIVE_PROCESS_LIMIT: u32 = 16;
/// Per-process memory ceiling used by the smoke workflow.
pub const SMOKE_PER_PROCESS_MEMORY_LIMIT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Aggregate Job memory ceiling used by the smoke workflow.
pub const SMOKE_JOB_MEMORY_LIMIT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Maximum explicit launch arguments used by the smoke workflow.
pub const SMOKE_LAUNCH_ARGUMENT_LIMIT: usize = 8;
/// Maximum aggregate argument bytes used by the smoke workflow.
pub const SMOKE_LAUNCH_ARGUMENT_BYTES: usize = 8_192;
/// Maximum complete Windows command-line UTF-16 units used by the smoke workflow.
pub const SMOKE_COMMAND_LINE_UTF16_LIMIT: usize = 32_767;

const ADAPTER_CONTRACT_DOMAIN: &[u8] = b"weregopher.discord.smoke-adapter-contract.v1\0";
const SOURCE_BUILD_DOMAIN: &[u8] = b"weregopher.discord.smoke-source-build.v1\0";
const MAIN_RUNTIME_DOMAIN: &[u8] = b"weregopher.discord.smoke-main-runtime.v1\0";
const RENDERER_SCOPE_DOMAIN: &[u8] = b"weregopher.discord.smoke-renderer-scope.v1\0";
const EXECUTION_ENVIRONMENT_DOMAIN: &[u8] = b"weregopher.discord.smoke-execution-environment.v1\0";
const EXECUTION_CONTRACT_DOMAIN: &[u8] = b"weregopher.discord.smoke-execution-contract.v1\0";
const RESOLUTION_EVIDENCE_DOMAIN: &[u8] = b"weregopher.discord.smoke-resolution-evidence.v1\0";
const ARTIFACT_SOURCE_DOMAIN: &[u8] = b"weregopher.discord.smoke-artifact-source.v1\0";

/// Constructs the exact canonical scenario accepted by the Discord marker adapter.
///
/// The matching compact JSON bytes must be present under
/// [`DISCORD_SMOKE_SCENARIO_ARTIFACT_NAME`] in the verified runner's probe-asset component.
///
/// # Errors
///
/// Returns a closed construction error if a compiled-in identifier, path, argument, duration, or
/// resource limit no longer satisfies the canonical domain contract.
pub fn discord_smoke_scenario() -> Result<DisposableCertificationScenario, DiscordSmokeScenarioError>
{
    let marker = ScenarioStateRootId::new(DISCORD_SMOKE_MARKER_STATE_ROOT_ID)?;
    let user_data = ScenarioStateRootId::new(DISCORD_SMOKE_USER_DATA_STATE_ROOT_ID)?;
    let marker_size = u64::try_from(SMOKE_MARKER_CONTENT.len())
        .map_err(|_| DiscordSmokeScenarioError::MarkerLengthUnrepresentable)?;
    let resources = ExecutionResourceLimits::new(
        SMOKE_ACTIVE_PROCESS_LIMIT,
        SMOKE_PER_PROCESS_MEMORY_LIMIT_BYTES,
        SMOKE_JOB_MEMORY_LIMIT_BYTES,
    )?;
    let limits = DisposableScenarioLimits::new(
        Duration::from_secs(SMOKE_TIMEOUT_MAX_SECONDS),
        Duration::from_millis(100),
        Duration::from_secs(5),
        u32::try_from(SMOKE_LAUNCH_ARGUMENT_LIMIT)
            .map_err(|_| DiscordSmokeScenarioError::LaunchLimitUnrepresentable)?,
        u32::try_from(SMOKE_LAUNCH_ARGUMENT_BYTES)
            .map_err(|_| DiscordSmokeScenarioError::LaunchLimitUnrepresentable)?,
        u32::try_from(SMOKE_COMMAND_LINE_UTF16_LIMIT)
            .map_err(|_| DiscordSmokeScenarioError::LaunchLimitUnrepresentable)?,
        resources,
    )?;
    Ok(DisposableCertificationScenario::new(
        ScenarioId::new(DISCORD_SMOKE_WORKFLOW_ID)?,
        ApplicationFamilyId::new(DISCORD_APPLICATION_FAMILY_ID)?,
        AdapterId::new(SMOKE_ADAPTER_ID)?,
        FeatureId::new(DISCORD_SMOKE_WORKFLOW_ID)?,
        ExecutionPackagePath::new(DISCORD_EXECUTABLE_PATH)?,
        vec![
            DisposableScenarioStateRoot::success_file(
                marker.clone(),
                digest(SMOKE_MARKER_CONTENT.as_bytes()),
                marker_size,
                256,
            )?,
            DisposableScenarioStateRoot::empty_directory(user_data.clone()),
        ],
        vec![
            DisposableScenarioArgument::state_path(
                marker,
                ExecutionArgument::new(SMOKE_MARKER_ARGUMENT_PREFIX)?,
            ),
            DisposableScenarioArgument::state_path(
                user_data,
                ExecutionArgument::new("--user-data-dir=")?,
            ),
        ],
        limits,
    )?)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
enum DiscordSmokeCertificationReportFormatVersion {
    #[serde(rename = "2")]
    V2,
}

/// Role-specific identity of one canonical Discord smoke-certification report.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(transparent)]
pub struct DiscordSmokeCertificationReportDigest(Sha256Digest);

impl DiscordSmokeCertificationReportDigest {
    /// Constructs the role-specific identity from an already computed SHA-256 value.
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

impl fmt::Display for DiscordSmokeCertificationReportDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Exact static input and output identities accepted by the Discord smoke adapter.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscordSmokeStaticObservation {
    adapter_contract_digest: Sha256Digest,
    source_app_asar_sha256: Sha256Digest,
    transformed_app_asar_sha256: Sha256Digest,
    package_manifest_sha256: Sha256Digest,
    source_main_entry_sha256: Sha256Digest,
    transformed_main_entry_sha256: Sha256Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedDiscordSmokeStaticObservation {
    adapter_contract_digest: Sha256Digest,
    source_app_asar_sha256: Sha256Digest,
    transformed_app_asar_sha256: Sha256Digest,
    package_manifest_sha256: Sha256Digest,
    source_main_entry_sha256: Sha256Digest,
    transformed_main_entry_sha256: Sha256Digest,
}

impl DiscordSmokeStaticObservation {
    /// Verifies the exact adapter output and records its immutable input/output identities.
    ///
    /// # Errors
    ///
    /// Returns [`DiscordSmokeCertificationReportError`] when the package is unsupported, the
    /// supplied transformed source is not the exact adapter output, or the source and transformed
    /// archive identities are equal.
    pub fn from_transform(
        source_app_asar_sha256: Sha256Digest,
        transformed_app_asar_sha256: Sha256Digest,
        package_manifest: &[u8],
        source_main_entry: &[u8],
        transformed_main_entry: &[u8],
    ) -> Result<Self, DiscordSmokeCertificationReportError> {
        let expected = transform_smoke_source(package_manifest, source_main_entry)?;
        if expected != transformed_main_entry {
            return Err(DiscordSmokeCertificationReportError::TransformOutputMismatch);
        }
        let value = Self {
            adapter_contract_digest: adapter_contract_digest(),
            source_app_asar_sha256,
            transformed_app_asar_sha256,
            package_manifest_sha256: digest(package_manifest),
            source_main_entry_sha256: digest(source_main_entry),
            transformed_main_entry_sha256: digest(transformed_main_entry),
        };
        value.validate()?;
        Ok(value)
    }

    fn from_unchecked(
        unchecked: &UncheckedDiscordSmokeStaticObservation,
    ) -> Result<Self, DiscordSmokeCertificationReportError> {
        let value = Self {
            adapter_contract_digest: unchecked.adapter_contract_digest,
            source_app_asar_sha256: unchecked.source_app_asar_sha256,
            transformed_app_asar_sha256: unchecked.transformed_app_asar_sha256,
            package_manifest_sha256: unchecked.package_manifest_sha256,
            source_main_entry_sha256: unchecked.source_main_entry_sha256,
            transformed_main_entry_sha256: unchecked.transformed_main_entry_sha256,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), DiscordSmokeCertificationReportError> {
        if self.adapter_contract_digest != adapter_contract_digest() {
            return Err(DiscordSmokeCertificationReportError::AdapterContractMismatch);
        }
        if self.source_app_asar_sha256 == self.transformed_app_asar_sha256 {
            return Err(DiscordSmokeCertificationReportError::ArchiveNotTransformed);
        }
        if self.source_main_entry_sha256 == self.transformed_main_entry_sha256 {
            return Err(DiscordSmokeCertificationReportError::SourceNotTransformed);
        }
        Ok(())
    }

    /// Returns the exact static adapter-contract identity.
    #[must_use]
    pub const fn adapter_contract_digest(&self) -> &Sha256Digest {
        &self.adapter_contract_digest
    }

    /// Returns the source `app.asar` identity.
    #[must_use]
    pub const fn source_app_asar_sha256(&self) -> &Sha256Digest {
        &self.source_app_asar_sha256
    }

    /// Returns the transformed `app.asar` identity.
    #[must_use]
    pub const fn transformed_app_asar_sha256(&self) -> &Sha256Digest {
        &self.transformed_app_asar_sha256
    }

    /// Returns the exact package-manifest identity analyzed by the adapter.
    #[must_use]
    pub const fn package_manifest_sha256(&self) -> &Sha256Digest {
        &self.package_manifest_sha256
    }

    /// Returns the exact source main-entry identity analyzed by the adapter.
    #[must_use]
    pub const fn source_main_entry_sha256(&self) -> &Sha256Digest {
        &self.source_main_entry_sha256
    }

    /// Returns the exact transformed main-entry identity emitted by the adapter.
    #[must_use]
    pub const fn transformed_main_entry_sha256(&self) -> &Sha256Digest {
        &self.transformed_main_entry_sha256
    }
}

/// Deterministic outcome of one successful disposable-state Job-owned smoke probe.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscordSmokeRuntimeObservation {
    scenario_sha256: DisposableCertificationScenarioDigest,
    scenario_report: DisposableCertificationScenarioReport,
    source_app_asar_after_sha256: Sha256Digest,
    omitted_mutable_paths: [String; 2],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedDiscordSmokeRuntimeObservation {
    scenario_sha256: DisposableCertificationScenarioDigest,
    scenario_report: DisposableCertificationScenarioReport,
    source_app_asar_after_sha256: Sha256Digest,
    omitted_mutable_paths: [String; 2],
}

impl DiscordSmokeRuntimeObservation {
    /// Wraps one completed shared scenario report with Discord-specific source-stability facts.
    ///
    /// # Errors
    ///
    /// Rejects any scenario other than the exact adapter-owned Discord marker definition.
    pub fn successful(
        scenario_report: DisposableCertificationScenarioReport,
        source_app_asar_after_sha256: Sha256Digest,
    ) -> Result<Self, DiscordSmokeCertificationReportError> {
        let scenario_sha256 = scenario_report.scenario().canonical_document_digest()?;
        let value = Self {
            scenario_sha256,
            scenario_report,
            source_app_asar_after_sha256,
            omitted_mutable_paths: [
                SMOKE_MUTABLE_DISPATCH_LOG_PATH.to_owned(),
                SMOKE_MUTABLE_KRISP_LOG_DIRECTORY_PATH.to_owned(),
            ],
        };
        value.validate()?;
        Ok(value)
    }

    fn from_unchecked(
        unchecked: UncheckedDiscordSmokeRuntimeObservation,
    ) -> Result<Self, DiscordSmokeCertificationReportError> {
        let value = Self {
            scenario_sha256: unchecked.scenario_sha256,
            scenario_report: unchecked.scenario_report,
            source_app_asar_after_sha256: unchecked.source_app_asar_after_sha256,
            omitted_mutable_paths: unchecked.omitted_mutable_paths,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), DiscordSmokeCertificationReportError> {
        let expected = discord_smoke_scenario()?;
        if self.scenario_report.scenario() != &expected {
            return Err(DiscordSmokeCertificationReportError::ScenarioMismatch);
        }
        let actual_scenario = self
            .scenario_report
            .scenario()
            .canonical_document_digest()?;
        if actual_scenario != self.scenario_sha256 {
            return Err(DiscordSmokeCertificationReportError::ScenarioIdentityMismatch);
        }
        let expected_paths = [
            SMOKE_MUTABLE_DISPATCH_LOG_PATH.to_owned(),
            SMOKE_MUTABLE_KRISP_LOG_DIRECTORY_PATH.to_owned(),
        ];
        if self.omitted_mutable_paths != expected_paths {
            return Err(DiscordSmokeCertificationReportError::MutablePathScopeMismatch);
        }
        Ok(())
    }

    /// Returns the exact managed package-tree identity.
    #[must_use]
    pub const fn managed_package_tree_merkle(&self) -> Sha256Digest {
        self.scenario_report.package().package_tree_merkle()
    }

    /// Returns the exact managed executable-byte identity.
    #[must_use]
    pub const fn managed_executable_sha256(&self) -> Sha256Digest {
        self.scenario_report.package().executable_sha256()
    }

    /// Returns the number of files bound by the managed package manifest.
    #[must_use]
    pub const fn package_files(&self) -> u32 {
        self.scenario_report.package().package_files()
    }

    /// Returns aggregate bytes bound by the managed package manifest.
    #[must_use]
    pub const fn package_bytes(&self) -> u64 {
        self.scenario_report.package().package_bytes()
    }

    /// Returns the post-probe vendor `app.asar` identity.
    #[must_use]
    pub const fn source_app_asar_after_sha256(&self) -> &Sha256Digest {
        &self.source_app_asar_after_sha256
    }

    /// Returns the observed marker-byte identity.
    #[must_use]
    pub const fn marker_sha256(&self) -> Sha256Digest {
        self.scenario_report.execution().success_file().sha256()
    }

    /// Returns the exact verified scenario identity.
    #[must_use]
    pub const fn scenario_sha256(&self) -> DisposableCertificationScenarioDigest {
        self.scenario_sha256
    }

    /// Returns the successful shared scenario report.
    #[must_use]
    pub const fn scenario_report(&self) -> &DisposableCertificationScenarioReport {
        &self.scenario_report
    }

    /// Returns the selected probe timeout.
    #[must_use]
    pub const fn selected_timeout(&self) -> Duration {
        self.scenario_report.execution().selected_timeout()
    }
}

/// Canonical non-authorizing semantic report for one exact Discord smoke probe.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscordSmokeCertificationReport {
    format_version: DiscordSmokeCertificationReportFormatVersion,
    static_observation: DiscordSmokeStaticObservation,
    runtime_observation: DiscordSmokeRuntimeObservation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedDiscordSmokeCertificationReport {
    format_version: DiscordSmokeCertificationReportFormatVersion,
    static_observation: UncheckedDiscordSmokeStaticObservation,
    runtime_observation: UncheckedDiscordSmokeRuntimeObservation,
}

impl DiscordSmokeCertificationReport {
    /// Constructs one cross-checked static and runtime smoke report.
    ///
    /// # Errors
    ///
    /// Returns [`DiscordSmokeCertificationReportError::VendorSourceChanged`] when the vendor source
    /// archive identity observed after the probe differs from the pre-transform source identity.
    pub fn new(
        static_observation: DiscordSmokeStaticObservation,
        runtime_observation: DiscordSmokeRuntimeObservation,
    ) -> Result<Self, DiscordSmokeCertificationReportError> {
        static_observation.validate()?;
        runtime_observation.validate()?;
        if static_observation.source_app_asar_sha256
            != runtime_observation.source_app_asar_after_sha256
        {
            return Err(DiscordSmokeCertificationReportError::VendorSourceChanged);
        }
        Ok(Self {
            format_version: DiscordSmokeCertificationReportFormatVersion::V2,
            static_observation,
            runtime_observation,
        })
    }

    /// Parses one report only after enforcing its non-configurable byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`DiscordSmokeCertificationReportError`] for oversized, malformed, unsupported, or
    /// semantically inconsistent report bytes.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, DiscordSmokeCertificationReportError> {
        if bytes.len() > MAX_DISCORD_SMOKE_CERTIFICATION_REPORT_BYTES {
            return Err(DiscordSmokeCertificationReportError::DocumentTooLarge);
        }
        let UncheckedDiscordSmokeCertificationReport {
            format_version: DiscordSmokeCertificationReportFormatVersion::V2,
            static_observation,
            runtime_observation,
        } = serde_json::from_slice(bytes)
            .map_err(DiscordSmokeCertificationReportError::InvalidDocument)?;
        let static_observation =
            DiscordSmokeStaticObservation::from_unchecked(&static_observation)?;
        let runtime_observation =
            DiscordSmokeRuntimeObservation::from_unchecked(runtime_observation)?;
        Self::new(static_observation, runtime_observation)
    }

    /// Returns canonical compact JSON bytes.
    ///
    /// Format v2 uses declaration-order object members, canonical digest spellings, no
    /// insignificant whitespace, and no trailing newline. The checked-in golden byte and SHA-256
    /// vectors freeze this encoding; changing it requires a new report format.
    ///
    /// # Errors
    ///
    /// Returns a serialization error when the in-memory report cannot be encoded.
    pub fn canonical_json_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

    /// Returns the role-specific canonical report identity.
    ///
    /// # Errors
    ///
    /// Returns a serialization error when canonical bytes cannot be produced.
    pub fn canonical_document_digest(
        &self,
    ) -> serde_json::Result<DiscordSmokeCertificationReportDigest> {
        let bytes = self.canonical_json_bytes()?;
        Ok(DiscordSmokeCertificationReportDigest::new(digest(&bytes)))
    }

    /// Returns the exact report format version.
    #[must_use]
    pub const fn format_version(&self) -> &'static str {
        DISCORD_SMOKE_CERTIFICATION_REPORT_FORMAT_VERSION
    }

    /// Returns the static transform observation.
    #[must_use]
    pub const fn static_observation(&self) -> &DiscordSmokeStaticObservation {
        &self.static_observation
    }

    /// Returns the successful disposable-state runtime observation.
    #[must_use]
    pub const fn runtime_observation(&self) -> &DiscordSmokeRuntimeObservation {
        &self.runtime_observation
    }

    /// Derives the exact adapter-scoped source-build identity.
    #[must_use]
    pub fn source_build_fingerprint_digest(&self) -> Sha256Digest {
        let package_tree = self.runtime_observation.managed_package_tree_merkle();
        let executable = self.runtime_observation.managed_executable_sha256();
        domain_digest(
            SOURCE_BUILD_DOMAIN,
            &[
                self.static_observation.source_app_asar_sha256.as_bytes(),
                self.static_observation.package_manifest_sha256.as_bytes(),
                self.static_observation.source_main_entry_sha256.as_bytes(),
                package_tree.as_bytes(),
                executable.as_bytes(),
            ],
        )
    }

    /// Derives the exact main-runtime contract identity for this smoke scope.
    #[must_use]
    pub fn main_runtime_contract_digest(&self) -> Sha256Digest {
        let executable = self.runtime_observation.managed_executable_sha256();
        let package_tree = self.runtime_observation.managed_package_tree_merkle();
        domain_digest(
            MAIN_RUNTIME_DOMAIN,
            &[
                executable.as_bytes(),
                package_tree.as_bytes(),
                SMOKE_MARKER_ARGUMENT_PREFIX.as_bytes(),
                SMOKE_MARKER_CONTENT.as_bytes(),
                self.runtime_observation
                    .scenario_sha256
                    .as_sha256()
                    .as_bytes(),
            ],
        )
    }

    /// Derives the explicit no-renderer smoke-scope contract identity.
    #[must_use]
    pub fn renderer_scope_contract_digest(&self) -> Sha256Digest {
        domain_digest(
            RENDERER_SCOPE_DOMAIN,
            &[
                self.static_observation.adapter_contract_digest.as_bytes(),
                DISCORD_SMOKE_WORKFLOW_ID.as_bytes(),
            ],
        )
    }

    /// Derives the disposable-state, Job-bounded execution-environment identity.
    #[must_use]
    pub fn execution_environment_digest(&self) -> Sha256Digest {
        let timeout = self
            .runtime_observation
            .scenario_report
            .execution()
            .selected_timeout_millis()
            .to_le_bytes();
        domain_digest(
            EXECUTION_ENVIRONMENT_DOMAIN,
            &[
                self.runtime_observation
                    .scenario_sha256
                    .as_sha256()
                    .as_bytes(),
                &timeout,
            ],
        )
    }

    /// Derives the exact app-specific smoke execution-contract identity.
    #[must_use]
    pub fn execution_contract_digest(&self) -> Sha256Digest {
        let environment = self.execution_environment_digest();
        domain_digest(
            EXECUTION_CONTRACT_DOMAIN,
            &[
                self.static_observation.adapter_contract_digest.as_bytes(),
                environment.as_bytes(),
                DISCORD_SMOKE_WORKFLOW_ID.as_bytes(),
            ],
        )
    }

    /// Derives exact managed package and executable resolution evidence.
    #[must_use]
    pub fn execution_resolution_evidence_digest(&self) -> Sha256Digest {
        let package_tree = self.runtime_observation.managed_package_tree_merkle();
        let executable = self.runtime_observation.managed_executable_sha256();
        domain_digest(
            RESOLUTION_EVIDENCE_DOMAIN,
            &[
                package_tree.as_bytes(),
                executable.as_bytes(),
                self.static_observation
                    .transformed_app_asar_sha256
                    .as_bytes(),
                self.runtime_observation
                    .scenario_sha256
                    .as_sha256()
                    .as_bytes(),
            ],
        )
    }

    /// Derives the exact transformed managed-package source identity.
    #[must_use]
    pub fn execution_artifact_source_digest(&self) -> Sha256Digest {
        let package_tree = self.runtime_observation.managed_package_tree_merkle();
        domain_digest(
            ARTIFACT_SOURCE_DOMAIN,
            &[
                self.static_observation.source_app_asar_sha256.as_bytes(),
                self.static_observation
                    .transformed_app_asar_sha256
                    .as_bytes(),
                package_tree.as_bytes(),
            ],
        )
    }
}

/// Failure to construct the exact built-in Discord smoke scenario.
#[derive(Debug, Error)]
pub enum DiscordSmokeScenarioError {
    /// A built-in stable identifier no longer satisfies the canonical grammar.
    #[error("Discord smoke scenario contains an invalid built-in identifier")]
    Identifier(#[from] IdentifierError),
    /// A built-in argument, path, or Job limit no longer satisfies the execution contract.
    #[error("Discord smoke scenario contains an invalid execution value")]
    Execution(#[from] ExecutionTargetContractError),
    /// The assembled scenario violates the disposable-scenario contract.
    #[error("Discord smoke scenario contract is invalid")]
    Scenario(#[from] DisposableCertificationScenarioError),
    /// Marker length cannot be represented by the scenario format.
    #[error("Discord smoke marker length is unrepresentable")]
    MarkerLengthUnrepresentable,
    /// A built-in platform launch limit cannot be represented by the scenario format.
    #[error("Discord smoke launch limit is unrepresentable")]
    LaunchLimitUnrepresentable,
}

/// Rejection produced while constructing or parsing Discord smoke-certification evidence.
#[derive(Debug, Error)]
pub enum DiscordSmokeCertificationReportError {
    /// Serialized input exceeded the fixed report ceiling.
    #[error("Discord smoke certification report exceeds the byte limit")]
    DocumentTooLarge,
    /// Serialized input did not match the closed format-v2 transport.
    #[error("invalid Discord smoke certification report")]
    InvalidDocument(#[source] serde_json::Error),
    /// Canonical nested scenario bytes could not be produced.
    #[error("failed to serialize the canonical Discord smoke scenario")]
    Serialization(#[from] serde_json::Error),
    /// The exact built-in Discord scenario could not be constructed.
    #[error(transparent)]
    Scenario(#[from] DiscordSmokeScenarioError),
    /// The package or main source did not satisfy the adapter contract.
    #[error(transparent)]
    Adapter(#[from] DiscordAdapterError),
    /// Supplied transformed source differed from the exact adapter output.
    #[error("Discord smoke transformed source does not match the adapter output")]
    TransformOutputMismatch,
    /// Source and transformed archive identities were equal.
    #[error("Discord smoke transform did not change the application archive identity")]
    ArchiveNotTransformed,
    /// Source and transformed main-entry identities were equal.
    #[error("Discord smoke transform did not change the main-entry identity")]
    SourceNotTransformed,
    /// Report bytes did not bind the fixed adapter contract.
    #[error("Discord smoke report adapter-contract identity mismatch")]
    AdapterContractMismatch,
    /// The nested shared scenario differed from the exact adapter-owned definition.
    #[error("Discord smoke scenario does not match the adapter contract")]
    ScenarioMismatch,
    /// The explicit scenario identity differed from the nested canonical definition.
    #[error("Discord smoke scenario identity mismatch")]
    ScenarioIdentityMismatch,
    /// Mutable-path omissions differed from the fixed reviewed adapter contract.
    #[error("Discord smoke mutable-path scope mismatch")]
    MutablePathScopeMismatch,
    /// Vendor source archive identity changed between transform input and probe completion.
    #[error("Discord vendor source changed during the smoke probe")]
    VendorSourceChanged,
}

fn adapter_contract_digest() -> Sha256Digest {
    domain_digest(
        ADAPTER_CONTRACT_DOMAIN,
        &[
            SMOKE_ADAPTER_ID.as_bytes(),
            SMOKE_PREFIX,
            DISCORD_MAIN_ENTRY.as_bytes(),
            DISCORD_EXECUTABLE_PATH.as_bytes(),
            DISCORD_SMOKE_SCENARIO_ARTIFACT_NAME.as_bytes(),
            DISCORD_SMOKE_MARKER_STATE_ROOT_ID.as_bytes(),
            DISCORD_SMOKE_USER_DATA_STATE_ROOT_ID.as_bytes(),
            SMOKE_MARKER_ARGUMENT_PREFIX.as_bytes(),
            SMOKE_MARKER_CONTENT.as_bytes(),
            SMOKE_MUTABLE_DISPATCH_LOG_PATH.as_bytes(),
            SMOKE_MUTABLE_KRISP_LOG_DIRECTORY_PATH.as_bytes(),
        ],
    )
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn domain_digest(domain: &[u8], values: &[&[u8]]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((values.len() as u64).to_le_bytes());
    for value in values {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value);
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}
