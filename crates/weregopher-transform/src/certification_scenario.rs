//! Verified probe-asset selection and Windows execution for disposable certification scenarios.

use std::{fmt, time::Duration};

#[cfg(windows)]
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Read as _,
    os::windows::{
        ffi::{OsStrExt as _, OsStringExt as _},
        fs::{MetadataExt as _, OpenOptionsExt as _},
    },
    path::{Path, PathBuf},
    time::Instant,
};

#[cfg(windows)]
use sha2::Digest as _;
use thiserror::Error;
use weregopher_domain::{
    CertificationArtifactRef, CertificationRunnerArtifactName, CertificationRunnerComponentRole,
    DisposableCertificationScenario, DisposableCertificationScenarioDigest,
    DisposableCertificationScenarioDocumentError,
};

#[cfg(windows)]
use weregopher_domain::{
    DisposableCertificationScenarioReport, DisposableCertificationScenarioReportError,
    DisposableScenarioArgument, DisposableScenarioPackageObservation,
    DisposableScenarioStateRootKind, ExecutionPackagePath, ScenarioStateRootId,
};

use crate::VerifiedCertificationRunnerComponents;

#[cfg(windows)]
use crate::{
    AttestedCertificationPublicationError, CertificationRunnerPolicyError, PackageSnapshotError,
    PackageSnapshotExecutable, PendingLocalCertificationRun, begin_local_certification_run,
};

#[cfg(windows)]
use weregopher_windows::{
    JobLimits, KillOnCloseJob, ProcessLaunchLimits, windows_ordinal_case_key,
};

/// Opaque proof that one canonical scenario is an exact verified probe-asset component artifact.
///
/// This value consumes the complete runner-component proof and is deliberately non-cloneable and
/// non-serializable. It authenticates the scenario only under the exact local runner policy already
/// represented by that proof; it does not authorize process launch.
#[must_use = "a verified scenario has not been executed or consumed"]
pub struct VerifiedDisposableCertificationScenario<'descriptors, 'artifacts, 'bytes> {
    runner: VerifiedCertificationRunnerComponents<'descriptors, 'artifacts, 'bytes>,
    artifact_name: CertificationRunnerArtifactName,
    scenario: DisposableCertificationScenario,
    scenario_digest: DisposableCertificationScenarioDigest,
}

impl fmt::Debug for VerifiedDisposableCertificationScenario<'_, '_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedDisposableCertificationScenario")
            .field("artifact_name", &self.artifact_name)
            .field("scenario_digest", &self.scenario_digest)
            .field("scenario_id", self.scenario.id())
            .field(
                "runner_identity_digest",
                &self.runner.runner_identity_digest(),
            )
            .field(
                "runner_policy_generation",
                &self.runner.runner_policy_generation(),
            )
            .finish_non_exhaustive()
    }
}

impl VerifiedDisposableCertificationScenario<'_, '_, '_> {
    /// Returns the exact logical probe-asset artifact name.
    #[must_use]
    pub const fn artifact_name(&self) -> &CertificationRunnerArtifactName {
        &self.artifact_name
    }

    /// Returns the parsed canonical scenario.
    #[must_use]
    pub const fn scenario(&self) -> &DisposableCertificationScenario {
        &self.scenario
    }

    /// Returns the exact canonical scenario identity.
    #[must_use]
    pub const fn scenario_digest(&self) -> DisposableCertificationScenarioDigest {
        self.scenario_digest
    }

    /// Returns the exact approved runner identity.
    #[must_use]
    pub const fn runner_identity_digest(
        &self,
    ) -> weregopher_domain::CertificationRunnerIdentityDigest {
        self.runner.runner_identity_digest()
    }

    /// Returns the complete verified descriptor-set identity.
    #[must_use]
    pub const fn runner_descriptor_set_digest(
        &self,
    ) -> weregopher_domain::CertificationRunnerDescriptorSetDigest {
        self.runner.descriptor_set_digest()
    }

    /// Returns the trusted local runner-policy revision.
    #[must_use]
    pub const fn runner_policy_revision_digest(
        &self,
    ) -> weregopher_domain::CertificationRunnerPolicyRevisionDigest {
        self.runner.runner_policy_revision_digest()
    }

    /// Returns the issuing runner-policy generation.
    #[must_use]
    pub const fn runner_policy_generation(&self) -> u64 {
        self.runner.runner_policy_generation()
    }
}

/// Selects one canonical scenario from the exact verified `probe_asset_set`.
///
/// # Errors
///
/// Rejects an absent named artifact, malformed or oversized scenario bytes, a noncanonical stored
/// encoding, or an unavailable canonical identity.
pub fn verify_disposable_certification_scenario<'descriptors, 'artifacts, 'bytes>(
    runner: VerifiedCertificationRunnerComponents<'descriptors, 'artifacts, 'bytes>,
    artifact_name: CertificationRunnerArtifactName,
) -> Result<
    VerifiedDisposableCertificationScenario<'descriptors, 'artifacts, 'bytes>,
    DisposableCertificationScenarioVerificationError,
> {
    let bytes = runner
        .artifacts()
        .get(&CertificationRunnerComponentRole::ProbeAssetSet)
        .and_then(|artifacts| artifacts.get(&artifact_name))
        .copied()
        .ok_or_else(|| {
            DisposableCertificationScenarioVerificationError::MissingProbeAsset(
                artifact_name.clone(),
            )
        })?;
    let scenario = DisposableCertificationScenario::from_json_slice(bytes)
        .map_err(DisposableCertificationScenarioVerificationError::ScenarioDocument)?;
    let canonical = scenario
        .canonical_json_bytes()
        .map_err(DisposableCertificationScenarioVerificationError::CanonicalScenarioUnavailable)?;
    if canonical != bytes {
        return Err(DisposableCertificationScenarioVerificationError::NonCanonicalScenarioArtifact);
    }
    let scenario_digest = scenario
        .canonical_document_digest()
        .map_err(DisposableCertificationScenarioVerificationError::CanonicalScenarioUnavailable)?;
    Ok(VerifiedDisposableCertificationScenario {
        runner,
        artifact_name,
        scenario,
        scenario_digest,
    })
}

/// Whether one verified scenario is a candidate-only diagnostic or begins a freshness capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DisposableCertificationScenarioRunMode {
    /// Run under a current verified runner without assigning or publishing a certification class.
    Candidate,
    /// Generate a single-use challenge immediately before launch for one pinned semantic report.
    Attested {
        /// Exact semantic report reference expected after the run.
        semantic_report: CertificationArtifactRef,
        /// Maximum monotonic elapsed duration through final attested publication.
        maximum_elapsed: Duration,
    },
}

#[cfg(windows)]
enum ScenarioRunControl<'descriptors, 'artifacts, 'bytes> {
    Candidate(VerifiedCertificationRunnerComponents<'descriptors, 'artifacts, 'bytes>),
    Attested(PendingLocalCertificationRun<'descriptors, 'artifacts, 'bytes>),
}

#[cfg(windows)]
impl fmt::Debug for ScenarioRunControl<'_, '_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Candidate(_) => formatter.write_str("ScenarioRunControl::Candidate(..)"),
            Self::Attested(_) => formatter.write_str("ScenarioRunControl::Attested(..)"),
        }
    }
}

/// Noncanonical diagnostics from one completed scenario run.
///
/// These values intentionally do not contribute to scenario or certification evidence identity.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisposableCertificationScenarioDiagnostics {
    process_id: u32,
    process_exit_code: u32,
    success_file_path: PathBuf,
}

#[cfg(windows)]
impl DisposableCertificationScenarioDiagnostics {
    /// Returns the diagnostic Windows process identifier.
    #[must_use]
    pub const fn process_id(&self) -> u32 {
        self.process_id
    }

    /// Returns the confirmed primary-process exit code.
    #[must_use]
    pub const fn process_exit_code(&self) -> u32 {
        self.process_exit_code
    }

    /// Returns the caller-selected success-file path.
    #[must_use]
    pub fn success_file_path(&self) -> &Path {
        &self.success_file_path
    }
}

/// One completed shared scenario result plus an optional single-use attestation capability.
#[cfg(windows)]
#[must_use = "a completed scenario result has not been mapped into adapter evidence"]
pub struct CompletedDisposableCertificationScenario<'descriptors, 'artifacts, 'bytes> {
    report: DisposableCertificationScenarioReport,
    pending: Option<PendingLocalCertificationRun<'descriptors, 'artifacts, 'bytes>>,
    diagnostics: DisposableCertificationScenarioDiagnostics,
}

#[cfg(windows)]
impl fmt::Debug for CompletedDisposableCertificationScenario<'_, '_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletedDisposableCertificationScenario")
            .field("report", &self.report)
            .field("has_pending_attestation", &self.pending.is_some())
            .field("diagnostics", &self.diagnostics)
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl<'descriptors, 'artifacts, 'bytes>
    CompletedDisposableCertificationScenario<'descriptors, 'artifacts, 'bytes>
{
    /// Returns the canonical successful shared scenario report.
    #[must_use]
    pub const fn report(&self) -> &DisposableCertificationScenarioReport {
        &self.report
    }

    /// Returns noncanonical process and path diagnostics.
    #[must_use]
    pub const fn diagnostics(&self) -> &DisposableCertificationScenarioDiagnostics {
        &self.diagnostics
    }

    /// Consumes the result into its report, optional pending attestation, and diagnostics.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        DisposableCertificationScenarioReport,
        Option<PendingLocalCertificationRun<'descriptors, 'artifacts, 'bytes>>,
        DisposableCertificationScenarioDiagnostics,
    ) {
        (self.report, self.pending, self.diagnostics)
    }
}

/// Runs one verified scenario against an exact retained package-snapshot executable on Windows.
///
/// The runner resolves only caller-supplied absolute paths for the scenario's closed logical root
/// set. Every root must have an unambiguous Windows leaf, be new, remain mutually disjoint under
/// Windows ordinal case semantics, and stay outside the package snapshot. Direct empty directories
/// are created before the single-use challenge. The process is created atomically inside a
/// kill-on-close Job Object with an empty environment and no inherited handles. Success requires
/// completing the exact direct-file read before the selected deadline, complete Job termination,
/// confirmed primary exit, and a final complete snapshot revalidation.
///
/// This remains an unrestricted same-user diagnostic process and is not execution authorization or
/// an operating-system sandbox.
///
/// # Errors
///
/// Rejects path-set, timeout, executable, launch, process, success-file, policy, and snapshot
/// failures without producing a successful report or attestation.
#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the trust-sensitive launch, observation, termination, and revalidation order remains linear"
)]
pub fn execute_disposable_certification_scenario<'descriptors, 'artifacts, 'bytes>(
    verified: VerifiedDisposableCertificationScenario<'descriptors, 'artifacts, 'bytes>,
    mode: DisposableCertificationScenarioRunMode,
    package_executable: PackageSnapshotExecutable<'_, '_>,
    state_paths: &BTreeMap<ScenarioStateRootId, PathBuf>,
    selected_timeout: Duration,
) -> Result<
    CompletedDisposableCertificationScenario<'descriptors, 'artifacts, 'bytes>,
    DisposableCertificationScenarioExecutionError,
> {
    let scenario = verified.scenario.clone();
    validate_selected_timeout(&scenario, selected_timeout)?;
    if package_executable.normalized_path() != scenario.executable().as_str() {
        return Err(DisposableCertificationScenarioExecutionError::ExecutablePathMismatch);
    }
    package_executable
        .verify_current_view()
        .map_err(DisposableCertificationScenarioExecutionError::Snapshot)?;
    let executable_digest = package_executable.digest();
    let (snapshot, locked_executable) = package_executable.into_launch_parts();
    let resolved_state = resolve_state_paths(
        &scenario,
        state_paths,
        snapshot.unrestricted_physical_root(),
    )?;
    prepare_state_roots(&scenario, &resolved_state)?;
    let arguments = resolve_arguments(&scenario, &resolved_state)?;
    let limits = scenario.execution().limits();
    let process_limits = ProcessLaunchLimits::new(
        usize::try_from(limits.maximum_arguments())
            .map_err(|_| DisposableCertificationScenarioExecutionError::InvalidLaunchLimits)?,
        usize::try_from(limits.maximum_argument_utf16_units())
            .map_err(|_| DisposableCertificationScenarioExecutionError::InvalidLaunchLimits)?,
        usize::try_from(limits.maximum_command_line_utf16_units())
            .map_err(|_| DisposableCertificationScenarioExecutionError::InvalidLaunchLimits)?,
    )
    .map_err(DisposableCertificationScenarioExecutionError::Process)?;
    let prepared_launch = locked_executable
        .prepare_launch(&arguments, process_limits)
        .map_err(DisposableCertificationScenarioExecutionError::Process)?;
    let resource_limits = limits.resource_limits();
    let job_limits = JobLimits::new(
        resource_limits.active_process_limit(),
        resource_limits.process_memory_limit_bytes(),
        resource_limits.job_memory_limit_bytes(),
    )
    .map_err(DisposableCertificationScenarioExecutionError::Process)?;
    let job = KillOnCloseJob::create(job_limits)
        .map_err(DisposableCertificationScenarioExecutionError::Process)?;

    let VerifiedDisposableCertificationScenario { runner, .. } = verified;
    let control = match mode {
        DisposableCertificationScenarioRunMode::Candidate => {
            runner
                .verify_current_policy()
                .map_err(DisposableCertificationScenarioExecutionError::RunnerPolicy)?;
            ScenarioRunControl::Candidate(runner)
        }
        DisposableCertificationScenarioRunMode::Attested {
            semantic_report,
            maximum_elapsed,
        } => ScenarioRunControl::Attested(
            begin_local_certification_run(runner, semantic_report, maximum_elapsed)
                .map_err(DisposableCertificationScenarioExecutionError::Attestation)?,
        ),
    };

    let process = job
        .launch_prepared(locked_executable, prepared_launch)
        .map_err(DisposableCertificationScenarioExecutionError::Process)?;
    if !process
        .is_in_job()
        .map_err(DisposableCertificationScenarioExecutionError::Process)?
    {
        return Err(DisposableCertificationScenarioExecutionError::JobMembershipMissing);
    }
    let process_id = process.id();
    let success_root = scenario
        .success_file_root()
        .ok_or(DisposableCertificationScenarioExecutionError::SuccessFileMissing)?;
    let success_path = resolved_state
        .get(success_root.id())
        .cloned()
        .ok_or(DisposableCertificationScenarioExecutionError::SuccessFileMissing)?;
    let deadline = Instant::now()
        .checked_add(selected_timeout)
        .ok_or(DisposableCertificationScenarioExecutionError::DeadlineOverflow)?;
    let poll_interval = scenario.poll_interval();
    let mut process_exit_code = None;
    let mut success_bytes = None;
    let mut last_success_file_error = None;
    loop {
        if !observation_precedes_deadline(Instant::now(), deadline) {
            break;
        }
        if success_path.is_file() {
            match read_success_file(&success_path, success_root.definition()) {
                Ok(observed) => {
                    if observation_precedes_deadline(Instant::now(), deadline) {
                        success_bytes = Some(observed);
                    }
                    break;
                }
                Err(error) => match error {
                    error @ (DisposableCertificationScenarioExecutionError::SuccessFileIo {
                        ..
                    }
                    | DisposableCertificationScenarioExecutionError::SuccessFileMismatch) => {
                        last_success_file_error = Some(error);
                    }
                    error => return Err(error),
                },
            }
        }
        let Some(wait_interval) = bounded_poll_interval(Instant::now(), deadline, poll_interval)
        else {
            break;
        };
        if process_exit_code.is_none() {
            if let Some(exit_code) = process
                .wait_for(wait_interval)
                .map_err(DisposableCertificationScenarioExecutionError::Process)?
            {
                process_exit_code = Some(exit_code);
            }
        } else {
            std::thread::sleep(wait_interval);
        }
    }

    let Some(success_bytes) = success_bytes else {
        process
            .terminate(0x5752_4701)
            .map_err(DisposableCertificationScenarioExecutionError::Process)?;
        return Err(match last_success_file_error {
            Some(error) => error,
            None => DisposableCertificationScenarioExecutionError::SuccessFileMissing,
        });
    };

    if process_exit_code.is_none() {
        process_exit_code = process
            .wait_for(Duration::ZERO)
            .map_err(DisposableCertificationScenarioExecutionError::Process)?;
    }
    process
        .terminate(0x5752_4700)
        .map_err(DisposableCertificationScenarioExecutionError::Process)?;
    if process_exit_code.is_none() {
        process_exit_code = process
            .wait_for(scenario.shutdown_timeout())
            .map_err(DisposableCertificationScenarioExecutionError::Process)?;
    }
    let process_exit_code =
        process_exit_code.ok_or(DisposableCertificationScenarioExecutionError::ExitUnconfirmed)?;

    snapshot
        .verify_current_view()
        .map_err(DisposableCertificationScenarioExecutionError::Snapshot)?;
    if let ScenarioRunControl::Candidate(runner) = &control {
        runner
            .verify_current_policy()
            .map_err(DisposableCertificationScenarioExecutionError::RunnerPolicy)?;
    }
    let package = DisposableScenarioPackageObservation::new(
        *snapshot.package_tree_merkle(),
        executable_digest,
        snapshot.file_count(),
        snapshot.total_file_bytes(),
    )
    .map_err(DisposableCertificationScenarioExecutionError::ScenarioReport)?;
    let report = DisposableCertificationScenarioReport::successful(
        scenario,
        package,
        selected_timeout,
        &success_bytes,
    )
    .map_err(DisposableCertificationScenarioExecutionError::ScenarioReport)?;
    let pending = match control {
        ScenarioRunControl::Candidate(_) => None,
        ScenarioRunControl::Attested(pending) => Some(pending),
    };
    Ok(CompletedDisposableCertificationScenario {
        report,
        pending,
        diagnostics: DisposableCertificationScenarioDiagnostics {
            process_id,
            process_exit_code,
            success_file_path: success_path,
        },
    })
}

#[cfg(windows)]
fn bounded_poll_interval(
    now: Instant,
    deadline: Instant,
    poll_interval: Duration,
) -> Option<Duration> {
    let remaining = deadline.checked_duration_since(now)?;
    if remaining.is_zero() {
        return None;
    }
    Some(poll_interval.min(remaining))
}

#[cfg(windows)]
fn observation_precedes_deadline(observed_at: Instant, deadline: Instant) -> bool {
    observed_at < deadline
}

#[cfg(windows)]
fn validate_selected_timeout(
    scenario: &DisposableCertificationScenario,
    selected_timeout: Duration,
) -> Result<(), DisposableCertificationScenarioExecutionError> {
    let millis = u64::try_from(selected_timeout.as_millis())
        .map_err(|_| DisposableCertificationScenarioExecutionError::InvalidSelectedTimeout)?;
    if selected_timeout.is_zero()
        || millis == 0
        || selected_timeout != Duration::from_millis(millis)
        || selected_timeout > scenario.maximum_timeout()
    {
        return Err(DisposableCertificationScenarioExecutionError::InvalidSelectedTimeout);
    }
    Ok(())
}

#[cfg(windows)]
fn resolve_state_paths(
    scenario: &DisposableCertificationScenario,
    supplied: &BTreeMap<ScenarioStateRootId, PathBuf>,
    snapshot_root: &Path,
) -> Result<BTreeMap<ScenarioStateRootId, PathBuf>, DisposableCertificationScenarioExecutionError> {
    let expected: BTreeSet<&ScenarioStateRootId> = scenario
        .state_roots()
        .iter()
        .map(weregopher_domain::DisposableScenarioStateRoot::id)
        .collect();
    let actual: BTreeSet<&ScenarioStateRootId> = supplied.keys().collect();
    if expected != actual {
        return Err(DisposableCertificationScenarioExecutionError::StateRootSetMismatch);
    }
    let snapshot_root = direct_absolute_path(snapshot_root)?;
    let mut resolved: BTreeMap<ScenarioStateRootId, PathBuf> = BTreeMap::new();
    for (id, path) in supplied {
        let path = intended_new_absolute_path(path)?;
        if overlaps(&path, &snapshot_root) {
            return Err(DisposableCertificationScenarioExecutionError::StateRootOverlap);
        }
        for existing in resolved.values() {
            if overlaps(&path, existing) {
                return Err(DisposableCertificationScenarioExecutionError::StateRootOverlap);
            }
        }
        resolved.insert(id.clone(), path);
    }
    Ok(resolved)
}

#[cfg(windows)]
fn prepare_state_roots(
    scenario: &DisposableCertificationScenario,
    paths: &BTreeMap<ScenarioStateRootId, PathBuf>,
) -> Result<(), DisposableCertificationScenarioExecutionError> {
    for root in scenario.state_roots() {
        let path = paths
            .get(root.id())
            .ok_or(DisposableCertificationScenarioExecutionError::StateRootSetMismatch)?;
        ensure_path_missing(path)?;
    }
    for root in scenario.state_roots() {
        let path = paths
            .get(root.id())
            .ok_or(DisposableCertificationScenarioExecutionError::StateRootSetMismatch)?;
        if matches!(
            root.definition(),
            DisposableScenarioStateRootKind::EmptyDirectory
        ) {
            fs::create_dir(path).map_err(|source| {
                DisposableCertificationScenarioExecutionError::StateRootIo {
                    path: path.clone(),
                    source,
                }
            })?;
        }
    }
    for root in scenario.state_roots() {
        let path = paths
            .get(root.id())
            .ok_or(DisposableCertificationScenarioExecutionError::StateRootSetMismatch)?;
        match root.definition() {
            DisposableScenarioStateRootKind::EmptyDirectory => {
                let metadata = fs::symlink_metadata(path).map_err(|source| {
                    DisposableCertificationScenarioExecutionError::StateRootIo {
                        path: path.clone(),
                        source,
                    }
                })?;
                if metadata.file_type().is_symlink()
                    || metadata.file_attributes()
                        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                        != 0
                    || !metadata.is_dir()
                {
                    return Err(
                        DisposableCertificationScenarioExecutionError::StateRootPreparationMismatch,
                    );
                }
            }
            DisposableScenarioStateRootKind::SuccessFile { .. } => ensure_path_missing(path)?,
        }
    }
    Ok(())
}

#[cfg(windows)]
fn resolve_arguments(
    scenario: &DisposableCertificationScenario,
    paths: &BTreeMap<ScenarioStateRootId, PathBuf>,
) -> Result<Vec<OsString>, DisposableCertificationScenarioExecutionError> {
    let mut resolved = Vec::new();
    resolved
        .try_reserve_exact(scenario.arguments().len())
        .map_err(|_| DisposableCertificationScenarioExecutionError::ArgumentAllocationFailed)?;
    for argument in scenario.arguments() {
        match argument {
            DisposableScenarioArgument::Literal { value } => {
                resolved.push(OsString::from(value.as_str()));
            }
            DisposableScenarioArgument::StatePath { state_root, prefix } => {
                let path = paths
                    .get(state_root)
                    .ok_or(DisposableCertificationScenarioExecutionError::StateRootSetMismatch)?;
                let mut value = OsString::from(prefix.as_str());
                value.push(path.as_os_str());
                resolved.push(value);
            }
        }
    }
    Ok(resolved)
}

#[cfg(windows)]
fn read_success_file(
    path: &Path,
    definition: &DisposableScenarioStateRootKind,
) -> Result<Vec<u8>, DisposableCertificationScenarioExecutionError> {
    let DisposableScenarioStateRootKind::SuccessFile {
        sha256,
        size_bytes,
        maximum_bytes,
    } = definition
    else {
        return Err(DisposableCertificationScenarioExecutionError::SuccessFileMissing);
    };
    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
        .custom_flags(
            windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT
                | windows_sys::Win32::Storage::FileSystem::FILE_FLAG_SEQUENTIAL_SCAN,
        );
    let mut file = options.open(path).map_err(|source| {
        DisposableCertificationScenarioExecutionError::SuccessFileIo {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let metadata = file.metadata().map_err(|source| {
        DisposableCertificationScenarioExecutionError::SuccessFileIo {
            path: path.to_path_buf(),
            source,
        }
    })?;
    if metadata.file_attributes()
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
        || !metadata.is_file()
        || metadata.len() != *size_bytes
        || metadata.len() > *maximum_bytes
    {
        return Err(DisposableCertificationScenarioExecutionError::SuccessFileMismatch);
    }
    let maximum = usize::try_from(*maximum_bytes)
        .map_err(|_| DisposableCertificationScenarioExecutionError::SuccessFileMismatch)?;
    let expected = usize::try_from(*size_bytes)
        .map_err(|_| DisposableCertificationScenarioExecutionError::SuccessFileMismatch)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected)
        .map_err(|_| DisposableCertificationScenarioExecutionError::SuccessFileAllocationFailed)?;
    file.by_ref()
        .take(
            u64::try_from(maximum)
                .map_err(|_| DisposableCertificationScenarioExecutionError::SuccessFileMismatch)?
                + 1,
        )
        .read_to_end(&mut bytes)
        .map_err(
            |source| DisposableCertificationScenarioExecutionError::SuccessFileIo {
                path: path.to_path_buf(),
                source,
            },
        )?;
    if bytes.len() != expected
        || weregopher_domain::Sha256Digest::from_bytes(sha2::Sha256::digest(&bytes).into())
            != *sha256
    {
        return Err(DisposableCertificationScenarioExecutionError::SuccessFileMismatch);
    }
    Ok(bytes)
}

#[cfg(windows)]
fn intended_new_absolute_path(
    path: &Path,
) -> Result<PathBuf, DisposableCertificationScenarioExecutionError> {
    if !path.is_absolute() {
        return Err(DisposableCertificationScenarioExecutionError::InvalidStateRootPath);
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(DisposableCertificationScenarioExecutionError::InvalidStateRootPath)?;
    ExecutionPackagePath::new(name)
        .map_err(|_| DisposableCertificationScenarioExecutionError::InvalidStateRootPath)?;
    ensure_path_missing(path)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(DisposableCertificationScenarioExecutionError::InvalidStateRootPath)?;
    let parent = parent.canonicalize().map_err(|source| {
        DisposableCertificationScenarioExecutionError::StateRootIo {
            path: parent.to_path_buf(),
            source,
        }
    })?;
    let parent = direct_absolute_path(&parent)?;
    Ok(parent.join(name))
}

#[cfg(windows)]
fn ensure_path_missing(path: &Path) -> Result<(), DisposableCertificationScenarioExecutionError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(DisposableCertificationScenarioExecutionError::StateRootAlreadyExists),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(DisposableCertificationScenarioExecutionError::StateRootIo {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(windows)]
fn direct_absolute_path(
    path: &Path,
) -> Result<PathBuf, DisposableCertificationScenarioExecutionError> {
    const VERBATIM_PREFIX: [u16; 4] = [92, 92, 63, 92];
    const UNC_PREFIX: [u16; 4] = [85, 78, 67, 92];

    let units: Vec<u16> = path.as_os_str().encode_wide().collect();
    if !units.starts_with(&VERBATIM_PREFIX) {
        return Ok(path.to_path_buf());
    }
    let remainder = units
        .get(VERBATIM_PREFIX.len()..)
        .ok_or(DisposableCertificationScenarioExecutionError::InvalidStateRootPath)?;
    let mut direct = Vec::new();
    if remainder.starts_with(&UNC_PREFIX) {
        direct.extend_from_slice(&[92, 92]);
        direct.extend_from_slice(
            remainder
                .get(UNC_PREFIX.len()..)
                .ok_or(DisposableCertificationScenarioExecutionError::InvalidStateRootPath)?,
        );
    } else {
        direct.extend_from_slice(remainder);
    }
    Ok(PathBuf::from(OsString::from_wide(&direct)))
}

#[cfg(windows)]
fn overlaps(first: &Path, second: &Path) -> bool {
    let (Some(first), Some(second)) = (windows_path_case_key(first), windows_path_case_key(second))
    else {
        return true;
    };
    first.starts_with(&second) || second.starts_with(&first)
}

#[cfg(windows)]
fn windows_path_case_key(path: &Path) -> Option<PathBuf> {
    let source = path.to_str()?;
    let key = windows_ordinal_case_key(source).ok()?;
    Some(PathBuf::from(OsString::from_wide(&key)))
}

/// Failure to select a canonical scenario from verified runner assets.
#[derive(Debug, Error)]
pub enum DisposableCertificationScenarioVerificationError {
    /// The exact named probe asset was absent.
    #[error("verified probe-asset set is missing disposable scenario {0}")]
    MissingProbeAsset(CertificationRunnerArtifactName),
    /// The exact probe-asset bytes did not parse as a bounded scenario.
    #[error("verified disposable scenario document is invalid")]
    ScenarioDocument(#[source] DisposableCertificationScenarioDocumentError),
    /// Parsed scenario bytes were not already the canonical compact encoding.
    #[error("verified disposable scenario artifact is not canonically encoded")]
    NonCanonicalScenarioArtifact,
    /// Canonical scenario bytes or identity could not be produced.
    #[error("canonical disposable scenario is unavailable")]
    CanonicalScenarioUnavailable(#[source] serde_json::Error),
}

/// Failure to execute one verified disposable certification scenario.
#[cfg(windows)]
#[derive(Debug, Error)]
pub enum DisposableCertificationScenarioExecutionError {
    /// Selected timeout was zero, sub-millisecond, excessive, or unrepresentable.
    #[error("selected disposable scenario timeout is invalid")]
    InvalidSelectedTimeout,
    /// Scenario executable did not match the retained package executable.
    #[error("disposable scenario executable path does not match the retained package executable")]
    ExecutablePathMismatch,
    /// Caller state-root bindings did not exactly cover the scenario roots.
    #[error("disposable scenario state-root bindings do not match the exact scenario")]
    StateRootSetMismatch,
    /// One state-root path was malformed or unrepresentable.
    #[error("disposable scenario state-root path is invalid")]
    InvalidStateRootPath,
    /// One state root existed before the scenario.
    #[error("disposable scenario state root already exists")]
    StateRootAlreadyExists,
    /// A newly prepared empty directory did not retain its required direct shape.
    #[error("disposable scenario state-root preparation did not retain its required shape")]
    StateRootPreparationMismatch,
    /// State roots overlapped one another or the retained package snapshot.
    #[error("disposable scenario state roots overlap another controlled path")]
    StateRootOverlap,
    /// State-root filesystem preparation failed.
    #[error("disposable scenario state-root operation failed at {path}")]
    StateRootIo {
        /// Failing path.
        path: PathBuf,
        /// Operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// Memory could not be reserved for the bounded argument list.
    #[error("disposable scenario argument allocation failed")]
    ArgumentAllocationFailed,
    /// Scenario launch limits could not be represented on this platform.
    #[error("disposable scenario launch limits are invalid")]
    InvalidLaunchLimits,
    /// Windows process or Job Object operation failed.
    #[error("disposable scenario process operation failed")]
    Process(#[source] std::io::Error),
    /// The primary process was not observed inside its required Job Object.
    #[error("disposable scenario process is outside its required Job Object")]
    JobMembershipMissing,
    /// Monotonic deadline construction overflowed.
    #[error("disposable scenario deadline overflowed the monotonic clock")]
    DeadlineOverflow,
    /// The exact success file was not produced.
    #[error("disposable scenario did not produce its required success file")]
    SuccessFileMissing,
    /// Success-file filesystem access failed.
    #[error("disposable scenario success-file operation failed at {path}")]
    SuccessFileIo {
        /// Failing path.
        path: PathBuf,
        /// Operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// Success-file bytes, identity, type, or length differed from the scenario.
    #[error("disposable scenario success file does not match its exact contract")]
    SuccessFileMismatch,
    /// Memory could not be reserved for bounded success-file bytes.
    #[error("disposable scenario success-file allocation failed")]
    SuccessFileAllocationFailed,
    /// Primary-process termination could not be confirmed.
    #[error("disposable scenario primary-process exit was not confirmed")]
    ExitUnconfirmed,
    /// The retained package snapshot failed point-in-time revalidation.
    #[error("disposable scenario package snapshot validation failed")]
    Snapshot(#[source] PackageSnapshotError),
    /// Runner policy changed before or after a candidate-only run.
    #[error("disposable scenario runner policy is not current")]
    RunnerPolicy(#[source] CertificationRunnerPolicyError),
    /// The pre-run single-use attestation capability could not be created.
    #[error("failed to begin freshness-bound disposable scenario")]
    Attestation(#[source] AttestedCertificationPublicationError),
    /// Canonical successful scenario-report construction failed.
    #[error("failed to construct successful disposable scenario report")]
    ScenarioReport(#[source] DisposableCertificationScenarioReportError),
}

#[cfg(all(test, windows))]
mod tests {
    use std::{
        path::Path,
        time::{Duration, Instant},
    };

    use super::{
        DisposableCertificationScenarioExecutionError, bounded_poll_interval,
        intended_new_absolute_path, observation_precedes_deadline, overlaps,
    };

    #[test]
    fn state_root_paths_must_be_absolute_before_parent_resolution() {
        let result =
            intended_new_absolute_path(Path::new("relative-disposable-scenario-state-root"));

        assert!(matches!(
            result,
            Err(DisposableCertificationScenarioExecutionError::InvalidStateRootPath)
        ));
    }

    #[test]
    fn state_root_leaf_names_reject_windows_alias_and_device_syntax()
    -> Result<(), Box<dyn std::error::Error>> {
        let parent = std::env::temp_dir().canonicalize()?;

        for name in [
            "weregopher-state.",
            "weregopher-state ",
            "weregopher-state:stream",
            "NUL",
        ] {
            assert!(
                matches!(
                    intended_new_absolute_path(&parent.join(name)),
                    Err(DisposableCertificationScenarioExecutionError::InvalidStateRootPath)
                ),
                "accepted ambiguous state-root leaf {name}"
            );
        }
        Ok(())
    }

    #[test]
    fn polling_is_clamped_to_the_remaining_selected_deadline() {
        let now = Instant::now();
        let deadline = now + Duration::from_millis(10);

        assert_eq!(
            bounded_poll_interval(now, deadline, Duration::from_secs(1)),
            Some(Duration::from_millis(10))
        );
        assert_eq!(
            bounded_poll_interval(deadline, deadline, Duration::from_secs(1)),
            None
        );
        assert!(observation_precedes_deadline(now, deadline));
        assert!(!observation_precedes_deadline(deadline, deadline));
    }

    #[test]
    fn overlap_checks_use_windows_ordinal_case_semantics() -> Result<(), Box<dyn std::error::Error>>
    {
        let parent = std::env::temp_dir().canonicalize()?;

        assert!(overlaps(
            &parent.join("Weregopher-Scenario-State"),
            &parent.join("weregopher-scenario-state")
        ));
        Ok(())
    }
}
