//! Canonical semantic report for the exact Discord disposable-state smoke workflow.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use weregopher_domain::Sha256Digest;

use crate::{
    DISCORD_MAIN_ENTRY, DiscordAdapterError, SMOKE_ADAPTER_ID, SMOKE_MARKER_ARGUMENT_PREFIX,
    SMOKE_MARKER_CONTENT, SMOKE_PREFIX, transform_smoke_source,
};

/// Current Discord smoke-certification report format.
pub const DISCORD_SMOKE_CERTIFICATION_REPORT_FORMAT_VERSION: &str = "1";
/// Maximum serialized report bytes accepted by the canonical parser.
pub const MAX_DISCORD_SMOKE_CERTIFICATION_REPORT_BYTES: usize = 64 * 1024;
/// Exact workflow certified by this deliberately narrow profile.
pub const DISCORD_SMOKE_WORKFLOW_ID: &str = "discord.smoke-marker";
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
enum DiscordSmokeCertificationReportFormatVersion {
    #[serde(rename = "1")]
    V1,
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
    managed_package_tree_merkle: Sha256Digest,
    managed_executable_sha256: Sha256Digest,
    package_files: u32,
    package_bytes: u64,
    source_app_asar_after_sha256: Sha256Digest,
    marker_sha256: Sha256Digest,
    timeout_seconds: u64,
    active_process_limit: u32,
    per_process_memory_limit_bytes: u64,
    job_memory_limit_bytes: u64,
    launch_argument_limit: u32,
    launch_argument_bytes: u32,
    command_line_utf16_limit: u32,
    omitted_mutable_paths: [String; 2],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedDiscordSmokeRuntimeObservation {
    managed_package_tree_merkle: Sha256Digest,
    managed_executable_sha256: Sha256Digest,
    package_files: u32,
    package_bytes: u64,
    source_app_asar_after_sha256: Sha256Digest,
    marker_sha256: Sha256Digest,
    timeout_seconds: u64,
    active_process_limit: u32,
    per_process_memory_limit_bytes: u64,
    job_memory_limit_bytes: u64,
    launch_argument_limit: u32,
    launch_argument_bytes: u32,
    command_line_utf16_limit: u32,
    omitted_mutable_paths: [String; 2],
}

impl DiscordSmokeRuntimeObservation {
    /// Records a probe only after the caller has verified Job membership, marker semantics,
    /// disposable state, vendor-source stability, and primary-process termination. The caller must
    /// retain kill-on-close ownership of the complete Job through the reporting boundary.
    ///
    /// # Errors
    ///
    /// Returns [`DiscordSmokeCertificationReportError`] when marker bytes, package bounds, timeout,
    /// or numeric execution-profile fields cannot fit the fixed report contract.
    pub fn successful(
        managed_package_tree_merkle: Sha256Digest,
        managed_executable_sha256: Sha256Digest,
        package_files: usize,
        package_bytes: u64,
        source_app_asar_after_sha256: Sha256Digest,
        marker_bytes: &[u8],
        timeout_seconds: u64,
    ) -> Result<Self, DiscordSmokeCertificationReportError> {
        let value = Self {
            managed_package_tree_merkle,
            managed_executable_sha256,
            package_files: u32::try_from(package_files)
                .map_err(|_| DiscordSmokeCertificationReportError::PackageFileCountInvalid)?,
            package_bytes,
            source_app_asar_after_sha256,
            marker_sha256: digest(marker_bytes),
            timeout_seconds,
            active_process_limit: SMOKE_ACTIVE_PROCESS_LIMIT,
            per_process_memory_limit_bytes: SMOKE_PER_PROCESS_MEMORY_LIMIT_BYTES,
            job_memory_limit_bytes: SMOKE_JOB_MEMORY_LIMIT_BYTES,
            launch_argument_limit: u32::try_from(SMOKE_LAUNCH_ARGUMENT_LIMIT)
                .map_err(|_| DiscordSmokeCertificationReportError::ExecutionProfileMismatch)?,
            launch_argument_bytes: u32::try_from(SMOKE_LAUNCH_ARGUMENT_BYTES)
                .map_err(|_| DiscordSmokeCertificationReportError::ExecutionProfileMismatch)?,
            command_line_utf16_limit: u32::try_from(SMOKE_COMMAND_LINE_UTF16_LIMIT)
                .map_err(|_| DiscordSmokeCertificationReportError::ExecutionProfileMismatch)?,
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
            managed_package_tree_merkle: unchecked.managed_package_tree_merkle,
            managed_executable_sha256: unchecked.managed_executable_sha256,
            package_files: unchecked.package_files,
            package_bytes: unchecked.package_bytes,
            source_app_asar_after_sha256: unchecked.source_app_asar_after_sha256,
            marker_sha256: unchecked.marker_sha256,
            timeout_seconds: unchecked.timeout_seconds,
            active_process_limit: unchecked.active_process_limit,
            per_process_memory_limit_bytes: unchecked.per_process_memory_limit_bytes,
            job_memory_limit_bytes: unchecked.job_memory_limit_bytes,
            launch_argument_limit: unchecked.launch_argument_limit,
            launch_argument_bytes: unchecked.launch_argument_bytes,
            command_line_utf16_limit: unchecked.command_line_utf16_limit,
            omitted_mutable_paths: unchecked.omitted_mutable_paths,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), DiscordSmokeCertificationReportError> {
        if self.marker_sha256 != digest(SMOKE_MARKER_CONTENT.as_bytes()) {
            return Err(DiscordSmokeCertificationReportError::MarkerMismatch);
        }
        if self.package_files == 0 {
            return Err(DiscordSmokeCertificationReportError::PackageFileCountInvalid);
        }
        if self.package_bytes == 0 {
            return Err(DiscordSmokeCertificationReportError::PackageByteCountInvalid);
        }
        if self.timeout_seconds == 0 || self.timeout_seconds > SMOKE_TIMEOUT_MAX_SECONDS {
            return Err(DiscordSmokeCertificationReportError::TimeoutInvalid);
        }
        let expected_argument_limit = u32::try_from(SMOKE_LAUNCH_ARGUMENT_LIMIT)
            .map_err(|_| DiscordSmokeCertificationReportError::ExecutionProfileMismatch)?;
        let expected_argument_bytes = u32::try_from(SMOKE_LAUNCH_ARGUMENT_BYTES)
            .map_err(|_| DiscordSmokeCertificationReportError::ExecutionProfileMismatch)?;
        let expected_command_line = u32::try_from(SMOKE_COMMAND_LINE_UTF16_LIMIT)
            .map_err(|_| DiscordSmokeCertificationReportError::ExecutionProfileMismatch)?;
        if self.active_process_limit != SMOKE_ACTIVE_PROCESS_LIMIT
            || self.per_process_memory_limit_bytes != SMOKE_PER_PROCESS_MEMORY_LIMIT_BYTES
            || self.job_memory_limit_bytes != SMOKE_JOB_MEMORY_LIMIT_BYTES
            || self.launch_argument_limit != expected_argument_limit
            || self.launch_argument_bytes != expected_argument_bytes
            || self.command_line_utf16_limit != expected_command_line
        {
            return Err(DiscordSmokeCertificationReportError::ExecutionProfileMismatch);
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
    pub const fn managed_package_tree_merkle(&self) -> &Sha256Digest {
        &self.managed_package_tree_merkle
    }

    /// Returns the exact managed executable-byte identity.
    #[must_use]
    pub const fn managed_executable_sha256(&self) -> &Sha256Digest {
        &self.managed_executable_sha256
    }

    /// Returns the number of files bound by the managed package manifest.
    #[must_use]
    pub const fn package_files(&self) -> u32 {
        self.package_files
    }

    /// Returns aggregate bytes bound by the managed package manifest.
    #[must_use]
    pub const fn package_bytes(&self) -> u64 {
        self.package_bytes
    }

    /// Returns the post-probe vendor `app.asar` identity.
    #[must_use]
    pub const fn source_app_asar_after_sha256(&self) -> &Sha256Digest {
        &self.source_app_asar_after_sha256
    }

    /// Returns the observed marker-byte identity.
    #[must_use]
    pub const fn marker_sha256(&self) -> &Sha256Digest {
        &self.marker_sha256
    }

    /// Returns the fixed probe deadline in seconds.
    #[must_use]
    pub const fn timeout_seconds(&self) -> u64 {
        self.timeout_seconds
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
            format_version: DiscordSmokeCertificationReportFormatVersion::V1,
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
            format_version: DiscordSmokeCertificationReportFormatVersion::V1,
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
    /// Format v1 uses declaration-order object members, canonical digest spellings, no
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
        domain_digest(
            SOURCE_BUILD_DOMAIN,
            &[
                self.static_observation.source_app_asar_sha256.as_bytes(),
                self.static_observation.package_manifest_sha256.as_bytes(),
                self.static_observation.source_main_entry_sha256.as_bytes(),
                self.runtime_observation
                    .managed_package_tree_merkle
                    .as_bytes(),
                self.runtime_observation
                    .managed_executable_sha256
                    .as_bytes(),
            ],
        )
    }

    /// Derives the exact main-runtime contract identity for this smoke scope.
    #[must_use]
    pub fn main_runtime_contract_digest(&self) -> Sha256Digest {
        domain_digest(
            MAIN_RUNTIME_DOMAIN,
            &[
                self.runtime_observation
                    .managed_executable_sha256
                    .as_bytes(),
                self.runtime_observation
                    .managed_package_tree_merkle
                    .as_bytes(),
                SMOKE_MARKER_ARGUMENT_PREFIX.as_bytes(),
                SMOKE_MARKER_CONTENT.as_bytes(),
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
        let timeout = self.runtime_observation.timeout_seconds.to_le_bytes();
        domain_digest(
            EXECUTION_ENVIRONMENT_DOMAIN,
            &[
                &timeout,
                &self.runtime_observation.active_process_limit.to_le_bytes(),
                &self
                    .runtime_observation
                    .per_process_memory_limit_bytes
                    .to_le_bytes(),
                &self
                    .runtime_observation
                    .job_memory_limit_bytes
                    .to_le_bytes(),
                &self.runtime_observation.launch_argument_limit.to_le_bytes(),
                &self.runtime_observation.launch_argument_bytes.to_le_bytes(),
                &self
                    .runtime_observation
                    .command_line_utf16_limit
                    .to_le_bytes(),
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
        domain_digest(
            RESOLUTION_EVIDENCE_DOMAIN,
            &[
                self.runtime_observation
                    .managed_package_tree_merkle
                    .as_bytes(),
                self.runtime_observation
                    .managed_executable_sha256
                    .as_bytes(),
                self.static_observation
                    .transformed_app_asar_sha256
                    .as_bytes(),
            ],
        )
    }

    /// Derives the exact transformed managed-package source identity.
    #[must_use]
    pub fn execution_artifact_source_digest(&self) -> Sha256Digest {
        domain_digest(
            ARTIFACT_SOURCE_DOMAIN,
            &[
                self.static_observation.source_app_asar_sha256.as_bytes(),
                self.static_observation
                    .transformed_app_asar_sha256
                    .as_bytes(),
                self.runtime_observation
                    .managed_package_tree_merkle
                    .as_bytes(),
            ],
        )
    }
}

/// Rejection produced while constructing or parsing Discord smoke-certification evidence.
#[derive(Debug, Error)]
pub enum DiscordSmokeCertificationReportError {
    /// Serialized input exceeded the fixed report ceiling.
    #[error("Discord smoke certification report exceeds the byte limit")]
    DocumentTooLarge,
    /// Serialized input did not match the closed format-v1 transport.
    #[error("invalid Discord smoke certification report")]
    InvalidDocument(#[source] serde_json::Error),
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
    /// Managed package file count was zero or unrepresentable.
    #[error("Discord smoke managed package file count is invalid")]
    PackageFileCountInvalid,
    /// Managed package byte count was zero.
    #[error("Discord smoke managed package byte count is invalid")]
    PackageByteCountInvalid,
    /// Probe timeout was zero or exceeded the fixed smoke ceiling.
    #[error("Discord smoke probe timeout is invalid")]
    TimeoutInvalid,
    /// Probe marker bytes did not match the exact adapter marker.
    #[error("Discord smoke probe marker mismatch")]
    MarkerMismatch,
    /// Numeric Job or launch limits differed from the fixed smoke execution profile.
    #[error("Discord smoke execution profile mismatch")]
    ExecutionProfileMismatch,
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
