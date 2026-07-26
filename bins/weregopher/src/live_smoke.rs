#![cfg_attr(
    not(any(windows, test)),
    allow(
        dead_code,
        reason = "staging helpers are exercised only by Windows builds and tests"
    )
)]

use std::{
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    path::{Component, Path, PathBuf},
    time::Duration,
};

#[cfg(windows)]
use std::{
    ffi::OsString,
    os::windows::ffi::{OsStrExt as _, OsStringExt as _},
    time::Instant,
};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use walkdir::WalkDir;
use weregopher_adapter_discord::{
    DISCORD_MAIN_ENTRY, DISCORD_PACKAGE_MANIFEST, DiscordSmokeCertificationReportDigest,
    DiscordSmokeStaticObservation, SMOKE_MUTABLE_DISPATCH_LOG_PATH,
    SMOKE_MUTABLE_KRISP_LOG_DIRECTORY_PATH, transform_smoke_source,
};
#[cfg(windows)]
use weregopher_adapter_discord::{
    DiscordSmokeCertificationReport, DiscordSmokeRuntimeObservation, SMOKE_ACTIVE_PROCESS_LIMIT,
    SMOKE_ADAPTER_ID, SMOKE_COMMAND_LINE_UTF16_LIMIT, SMOKE_JOB_MEMORY_LIMIT_BYTES,
    SMOKE_LAUNCH_ARGUMENT_BYTES, SMOKE_LAUNCH_ARGUMENT_LIMIT, SMOKE_MARKER_ARGUMENT_PREFIX,
    SMOKE_MARKER_CONTENT, SMOKE_PER_PROCESS_MEMORY_LIMIT_BYTES, SMOKE_TIMEOUT_MAX_SECONDS,
};
use weregopher_asar::{AsarArchive, AsarLimits};
use weregopher_domain::{
    CertificationClass, CertificationEvidenceDigest, CertificationProfileDigest,
    CompatibilityAnalysisDigest, PublicationStatus, Sha256Digest,
};
#[cfg(windows)]
use weregopher_fingerprint::{FingerprintOptions, PackageTreeManifest, fingerprint_package};

#[cfg(windows)]
use crate::discord_certification::{
    DiscordSmokeLocalCertificationDecision, approve_discord_smoke_certification,
    build_discord_smoke_certification,
};

const APP_ASAR_PATH: &str = "resources/app.asar";
const DISCORD_EXECUTABLE_PATH: &str = "Discord.exe";
#[cfg(test)]
const DISCORD_KRISP_STATE_ROOT_PATH: &str = "modules/discord_krisp-1/discord_krisp/KMS";
const MAX_COPY_ENTRIES: usize = 50_000;
const MAX_COPY_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_COPY_TOTAL_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_COPY_DEPTH: usize = 128;

#[derive(Debug, Serialize)]
pub(crate) struct DiscordLiveSmokeReport {
    adapter_id: &'static str,
    managed_root: PathBuf,
    package_tree_merkle: Sha256Digest,
    package_files: usize,
    package_bytes: u64,
    transformed_asar_sha256: Sha256Digest,
    omitted_mutable_path: &'static str,
    omitted_mutable_directory: &'static str,
    process_id: u32,
    process_exit_code: Option<u32>,
    marker_path: PathBuf,
    marker_content: &'static str,
    launch_mode: &'static str,
    certification_scope: &'static str,
    certification_report_sha256: DiscordSmokeCertificationReportDigest,
    compatibility_analysis_sha256: CompatibilityAnalysisDigest,
    certification_profile_sha256: CertificationProfileDigest,
    certification_evidence_sha256: CertificationEvidenceDigest,
    local_certification: Option<DiscordSmokeLocalCertificationReport>,
}

#[derive(Debug, Serialize)]
struct DiscordSmokeLocalCertificationReport {
    report_sha256: DiscordSmokeCertificationReportDigest,
    compatibility_analysis_sha256: CompatibilityAnalysisDigest,
    certification_profile_sha256: CertificationProfileDigest,
    certification_evidence_sha256: CertificationEvidenceDigest,
    policy_revision_sha256: Sha256Digest,
    class: CertificationClass,
    publication_status: PublicationStatus,
    policy_generation: u64,
    artifact_set_sha256: Sha256Digest,
    artifact_count: usize,
    total_artifact_bytes: usize,
}

#[derive(Debug)]
struct StageReceipt {
    root: PathBuf,
    source_app_asar_path: PathBuf,
    static_observation: DiscordSmokeStaticObservation,
    transformed_asar_sha256: Sha256Digest,
    omitted_dispatch_log: bool,
    omitted_krisp_log_directory: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReviewedMutablePath {
    DispatchLog,
    KrispLogDirectory,
}

#[derive(Debug)]
struct TransformedDiscordArchive {
    bytes: Vec<u8>,
    static_observation: DiscordSmokeStaticObservation,
}

#[cfg(not(windows))]
pub(crate) fn run_discord_live_smoke(
    vendor_root: &Path,
    managed_root: &Path,
    marker_path: &Path,
    timeout: Duration,
    allow_uncertified_local_smoke: bool,
    expected_certification_report: Option<Sha256Digest>,
    local_policy_revision: Option<Sha256Digest>,
) -> Result<DiscordLiveSmokeReport> {
    let _ = (
        vendor_root,
        managed_root,
        marker_path,
        timeout,
        allow_uncertified_local_smoke,
        expected_certification_report,
        local_policy_revision,
    );
    bail!("Discord live smoke launch is currently supported only on Windows")
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the smoke boundary keeps revalidation, Job configuration, launch, proof, and teardown order explicit"
)]
pub(crate) fn run_discord_live_smoke(
    vendor_root: &Path,
    managed_root: &Path,
    marker_path: &Path,
    timeout: Duration,
    allow_uncertified_local_smoke: bool,
    expected_certification_report: Option<Sha256Digest>,
    local_policy_revision: Option<Sha256Digest>,
) -> Result<DiscordLiveSmokeReport> {
    ensure!(
        allow_uncertified_local_smoke,
        "live smoke launch requires --allow-uncertified-local-smoke"
    );
    ensure!(!timeout.is_zero(), "smoke timeout must be nonzero");
    ensure!(
        timeout.as_secs() <= SMOKE_TIMEOUT_MAX_SECONDS,
        "smoke timeout exceeds the certification-report ceiling"
    );
    ensure!(
        expected_certification_report.is_some() == local_policy_revision.is_some(),
        "local smoke certification requires both exact report and policy-revision digests"
    );
    let marker_path = intended_new_absolute_path(marker_path, "marker")?;
    let user_data_path = sibling_user_data_path(&marker_path)?;
    ensure!(
        !user_data_path.exists(),
        "smoke user-data path already exists: {}",
        user_data_path.display()
    );

    let staged = stage_discord_package(vendor_root, managed_root)?;
    ensure!(
        staged.omitted_dispatch_log,
        "supported Discord build did not contain its exact mutable dispatch log"
    );
    ensure!(
        staged.omitted_krisp_log_directory,
        "supported Discord build did not contain its exact empty mutable Krisp log directory"
    );

    let fingerprint_options = FingerprintOptions::default();
    let first = fingerprint_package(&staged.root, &fingerprint_options)
        .context("failed to fingerprint the managed Discord package")?;
    let executable_path = staged.root.join(DISCORD_EXECUTABLE_PATH);
    let package_files = first.files().len();
    let package_bytes = manifest_total_bytes(&first)?;
    let executable_sha256 = first
        .files()
        .iter()
        .find(|record| record.normalized_path == DISCORD_EXECUTABLE_PATH)
        .map(|record| record.sha256)
        .ok_or_else(|| anyhow!("managed package manifest omitted Discord.exe"))?;

    #[cfg(windows)]
    {
        use weregopher_windows::{
            JobLimits, KillOnCloseJob, LockedExecutable, ProcessLaunchLimits,
        };

        let executable = LockedExecutable::open(&executable_path, 64)
            .context("failed to retain the managed Discord executable")?;
        let current = fingerprint_package(&staged.root, &fingerprint_options)
            .context("managed Discord package changed before launch")?;
        ensure!(
            current.package_tree_merkle() == first.package_tree_merkle(),
            "managed Discord package identity changed before launch"
        );

        fs::create_dir(&user_data_path).with_context(|| {
            format!(
                "failed to create isolated smoke user-data directory {}",
                user_data_path.display()
            )
        })?;
        let marker_argument = prefixed_path_argument(SMOKE_MARKER_ARGUMENT_PREFIX, &marker_path);
        let user_data_argument = prefixed_path_argument("--user-data-dir=", &user_data_path);
        let arguments = [marker_argument, user_data_argument];
        let launch_limits = ProcessLaunchLimits::new(
            SMOKE_LAUNCH_ARGUMENT_LIMIT,
            SMOKE_LAUNCH_ARGUMENT_BYTES,
            SMOKE_COMMAND_LINE_UTF16_LIMIT,
        )
        .context("invalid smoke launch limits")?;
        let job_limits = JobLimits::new(
            SMOKE_ACTIVE_PROCESS_LIMIT,
            SMOKE_PER_PROCESS_MEMORY_LIMIT_BYTES,
            SMOKE_JOB_MEMORY_LIMIT_BYTES,
        )
        .context("invalid smoke Job Object limits")?;
        let job =
            KillOnCloseJob::create(job_limits).context("failed to configure smoke Job Object")?;
        let process = job
            .launch(executable, &arguments, launch_limits)
            .context("failed to launch managed Discord package")?;
        ensure!(
            process
                .is_in_job()
                .context("failed to query smoke Job membership")?,
            "managed Discord process launched outside its required Job Object"
        );

        let process_id = process.id();
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| anyhow!("smoke timeout overflowed the monotonic clock"))?;
        let mut process_exit_code = None;
        loop {
            if marker_path.is_file() {
                break;
            }
            if let Some(exit_code) = process
                .wait_for(Duration::from_millis(100))
                .context("failed while waiting for managed Discord")?
            {
                process_exit_code = Some(exit_code);
                break;
            }
            if Instant::now() >= deadline {
                break;
            }
        }

        let marker = if marker_path.is_file() {
            let marker = read_bounded(&marker_path, 256, "smoke marker")?;
            ensure!(
                marker == SMOKE_MARKER_CONTENT.as_bytes(),
                "managed Discord wrote an unexpected smoke marker"
            );
            marker
        } else {
            if process_exit_code.is_none() {
                process
                    .terminate(0x5752_4701)
                    .context("failed to terminate timed-out managed Discord")?;
            }
            bail!(
                "managed Discord did not write its smoke marker within {} seconds",
                timeout.as_secs()
            );
        };

        if process_exit_code.is_none() {
            process_exit_code = process
                .wait_for(Duration::from_millis(100))
                .context("failed to collect an immediate Discord smoke exit")?;
        }
        if process_exit_code.is_none() {
            process
                .terminate(0x5752_4700)
                .context("failed to terminate managed Discord after smoke proof")?;
            process_exit_code = process
                .wait_for(Duration::from_secs(5))
                .context("failed to collect managed Discord exit code")?;
        }
        ensure!(
            process_exit_code.is_some(),
            "managed Discord process exit was not confirmed after smoke proof"
        );

        let source_app_asar_after = digest(&read_bounded(
            &staged.source_app_asar_path,
            AsarLimits::initial().max_archive_bytes(),
            "vendor Discord ASAR after smoke",
        )?);
        let runtime_observation = DiscordSmokeRuntimeObservation::successful(
            *first.package_tree_merkle(),
            executable_sha256,
            package_files,
            package_bytes,
            source_app_asar_after,
            &marker,
            timeout.as_secs(),
        )
        .context("failed to construct the Discord smoke runtime observation")?;
        let certification_report =
            DiscordSmokeCertificationReport::new(staged.static_observation, runtime_observation)
                .context("failed to validate the Discord smoke certification report")?;
        let certification_bundle = build_discord_smoke_certification(&certification_report)
            .context("failed to derive Discord smoke certification evidence")?;
        let local_certification = match (expected_certification_report, local_policy_revision) {
            (Some(expected), Some(revision)) => Some(
                approve_discord_smoke_certification(&certification_report, expected, revision)
                    .context("failed to assign local Discord smoke certification")?,
            ),
            (None, None) => None,
            (Some(_), None) | (None, Some(_)) => {
                bail!("local smoke certification inputs became inconsistent")
            }
        };

        Ok(DiscordLiveSmokeReport {
            adapter_id: SMOKE_ADAPTER_ID,
            managed_root: staged.root,
            package_tree_merkle: *first.package_tree_merkle(),
            package_files,
            package_bytes,
            transformed_asar_sha256: staged.transformed_asar_sha256,
            omitted_mutable_path: SMOKE_MUTABLE_DISPATCH_LOG_PATH,
            omitted_mutable_directory: SMOKE_MUTABLE_KRISP_LOG_DIRECTORY_PATH,
            process_id,
            process_exit_code,
            marker_path,
            marker_content: SMOKE_MARKER_CONTENT,
            launch_mode: "uncertified-local-smoke-job-owned",
            certification_scope: "adapter_disposable_smoke_only",
            certification_report_sha256: certification_bundle.report_digest(),
            compatibility_analysis_sha256: certification_bundle
                .compatibility_analysis_digest()
                .context("failed to identify Discord smoke compatibility analysis")?,
            certification_profile_sha256: certification_bundle
                .certification_profile_digest()
                .context("failed to identify Discord smoke certification profile")?,
            certification_evidence_sha256: certification_bundle
                .certification_evidence_digest()
                .context("failed to identify Discord smoke certification evidence")?,
            local_certification: local_certification.map(local_certification_report),
        })
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the staging boundary keeps exact path review, copy bounds, and transform receipt assembly explicit"
)]
fn stage_discord_package(vendor_root: &Path, managed_root: &Path) -> Result<StageReceipt> {
    let vendor_root = vendor_root
        .canonicalize()
        .with_context(|| format!("failed to resolve vendor root {}", vendor_root.display()))?;
    let vendor_root = direct_absolute_path(&vendor_root)?;
    ensure!(vendor_root.is_dir(), "vendor root is not a directory");
    let managed_root = intended_new_absolute_path(managed_root, "managed package root")?;
    ensure_disjoint(&vendor_root, &managed_root)?;
    fs::create_dir(&managed_root).with_context(|| {
        format!(
            "failed to create managed package root {}",
            managed_root.display()
        )
    })?;

    let mut entries = 0_usize;
    let mut total_bytes = 0_u64;
    let mut transformed_asar_sha256 = None;
    let mut source_app_asar_path = None;
    let mut static_observation = None;
    let mut copied_executable = false;
    let mut omitted_dispatch_log = false;
    let mut omitted_krisp_log_directory = false;

    for item in WalkDir::new(&vendor_root)
        .follow_links(false)
        .max_depth(MAX_COPY_DEPTH)
    {
        let item = item.context("failed to enumerate the Discord package")?;
        if item.path() == vendor_root {
            continue;
        }
        entries = entries
            .checked_add(1)
            .ok_or_else(|| anyhow!("managed package entry count overflowed"))?;
        ensure!(
            entries <= MAX_COPY_ENTRIES,
            "managed package exceeds its entry-count limit"
        );
        let relative = item
            .path()
            .strip_prefix(&vendor_root)
            .context("enumerated path escaped the vendor root")?;
        let normalized = normalized_relative_path(relative)?;
        let metadata = fs::symlink_metadata(item.path())
            .with_context(|| format!("failed to inspect vendor package entry {normalized}"))?;
        ensure_direct_entry(&metadata, &normalized)?;

        if let Some(omitted) = reviewed_mutable_path(item.path(), &normalized, &metadata)? {
            match omitted {
                ReviewedMutablePath::DispatchLog => omitted_dispatch_log = true,
                ReviewedMutablePath::KrispLogDirectory => omitted_krisp_log_directory = true,
            }
            continue;
        }

        let destination = managed_root.join(relative);
        if metadata.is_dir() {
            continue;
        }
        ensure!(metadata.is_file(), "unsupported package entry {normalized}");
        create_destination_parent(&destination, &normalized)?;
        ensure!(
            metadata.len() <= MAX_COPY_FILE_BYTES,
            "vendor package file exceeds its byte limit: {normalized}"
        );
        total_bytes = total_bytes
            .checked_add(metadata.len())
            .ok_or_else(|| anyhow!("managed package byte count overflowed"))?;
        ensure!(
            total_bytes <= MAX_COPY_TOTAL_BYTES,
            "managed package exceeds its aggregate byte limit"
        );

        if normalized == APP_ASAR_PATH {
            let TransformedDiscordArchive {
                bytes,
                static_observation: observation,
            } = transform_discord_archive(item.path())?;
            transformed_asar_sha256 = Some(*observation.transformed_app_asar_sha256());
            source_app_asar_path = Some(item.path().to_path_buf());
            static_observation = Some(observation);
            write_new(&destination, &bytes, "transformed Discord ASAR")?;
        } else {
            fs::copy(item.path(), &destination)
                .with_context(|| format!("failed to copy vendor package file {normalized}"))?;
        }
        if normalized == DISCORD_EXECUTABLE_PATH {
            copied_executable = true;
        }
    }

    ensure!(
        copied_executable,
        "Discord.exe was absent from the vendor package"
    );
    let transformed_asar_sha256 = transformed_asar_sha256
        .ok_or_else(|| anyhow!("resources/app.asar was absent from the vendor package"))?;
    let source_app_asar_path = source_app_asar_path
        .ok_or_else(|| anyhow!("resources/app.asar source path was not retained"))?;
    let static_observation = static_observation
        .ok_or_else(|| anyhow!("resources/app.asar transform observation was not retained"))?;
    Ok(StageReceipt {
        root: managed_root,
        source_app_asar_path,
        static_observation,
        transformed_asar_sha256,
        omitted_dispatch_log,
        omitted_krisp_log_directory,
    })
}

fn reviewed_mutable_path(
    path: &Path,
    normalized: &str,
    metadata: &fs::Metadata,
) -> Result<Option<ReviewedMutablePath>> {
    if normalized == SMOKE_MUTABLE_DISPATCH_LOG_PATH {
        ensure!(metadata.is_file(), "mutable dispatch path is not a file");
        return Ok(Some(ReviewedMutablePath::DispatchLog));
    }
    if normalized != SMOKE_MUTABLE_KRISP_LOG_DIRECTORY_PATH {
        return Ok(None);
    }
    ensure!(
        metadata.is_dir(),
        "reviewed mutable Discord log path is not a directory"
    );
    let mut contents = fs::read_dir(path)
        .context("failed to inspect the reviewed mutable Discord log directory")?;
    ensure!(
        contents.next().is_none(),
        "reviewed mutable Discord log directory is not empty"
    );
    Ok(Some(ReviewedMutablePath::KrispLogDirectory))
}

fn create_destination_parent(destination: &Path, normalized: &str) -> Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow!("managed package file has no parent: {normalized}"))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create managed package parent for {normalized}"))
}

fn transform_discord_archive(path: &Path) -> Result<TransformedDiscordArchive> {
    let limits = AsarLimits::initial();
    let input = read_bounded(path, limits.max_archive_bytes(), "Discord ASAR")?;
    let source_app_asar_sha256 = digest(&input);
    let mut archive = AsarArchive::parse(&input, limits).context("failed to parse Discord ASAR")?;
    let package_manifest = archive
        .file(DISCORD_PACKAGE_MANIFEST)
        .ok_or_else(|| anyhow!("Discord ASAR is missing package.json"))?
        .to_vec();
    let source = archive
        .file(DISCORD_MAIN_ENTRY)
        .ok_or_else(|| anyhow!("Discord ASAR is missing bundle.js"))?
        .to_vec();
    let transformed = transform_smoke_source(&package_manifest, &source)
        .context("Discord adapter rejected the package")?;
    archive
        .replace_file(DISCORD_MAIN_ENTRY, transformed.clone())
        .context("failed to replace Discord main source")?;
    let output = archive
        .to_bytes()
        .context("failed to rebuild Discord ASAR")?;
    let verified =
        AsarArchive::parse(&output, limits).context("failed to verify rebuilt Discord ASAR")?;
    ensure!(
        verified.file(DISCORD_MAIN_ENTRY) == Some(transformed.as_slice()),
        "rebuilt Discord ASAR did not retain transformed source"
    );
    let static_observation = DiscordSmokeStaticObservation::from_transform(
        source_app_asar_sha256,
        digest(&output),
        &package_manifest,
        &source,
        &transformed,
    )
    .context("failed to record the exact Discord adapter transform")?;
    Ok(TransformedDiscordArchive {
        bytes: output,
        static_observation,
    })
}

#[cfg(windows)]
fn manifest_total_bytes(manifest: &PackageTreeManifest) -> Result<u64> {
    manifest.files().iter().try_fold(0_u64, |total, record| {
        total
            .checked_add(record.size)
            .ok_or_else(|| anyhow!("managed package byte count overflowed"))
    })
}

#[cfg(windows)]
fn local_certification_report(
    decision: DiscordSmokeLocalCertificationDecision,
) -> DiscordSmokeLocalCertificationReport {
    DiscordSmokeLocalCertificationReport {
        report_sha256: decision.report_digest(),
        compatibility_analysis_sha256: decision.compatibility_analysis_digest(),
        certification_profile_sha256: decision.profile_digest(),
        certification_evidence_sha256: decision.evidence_digest(),
        policy_revision_sha256: *decision.policy_revision_digest().as_sha256(),
        class: decision.class(),
        publication_status: decision.publication_status(),
        policy_generation: decision.policy_generation(),
        artifact_set_sha256: *decision.artifact_set_digest().as_sha256(),
        artifact_count: decision.artifact_count(),
        total_artifact_bytes: decision.total_artifact_bytes(),
    }
}

fn read_bounded(path: &Path, max_bytes: usize, kind: &'static str) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to inspect {kind} at {}", path.display()))?;
    let length =
        usize::try_from(metadata.len()).context("file length exceeds the platform index")?;
    ensure!(length <= max_bytes, "{kind} exceeds its byte limit");
    let mut file = fs::File::open(path)
        .with_context(|| format!("failed to open {kind} at {}", path.display()))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| anyhow!("failed to allocate {kind} bytes"))?;
    file.read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {kind} at {}", path.display()))?;
    ensure!(bytes.len() == length, "{kind} length changed while reading");
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8], kind: &'static str) -> Result<()> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("failed to create {kind} at {}", path.display()))?;
    output
        .write_all(bytes)
        .with_context(|| format!("failed to write {kind} at {}", path.display()))?;
    output
        .sync_all()
        .with_context(|| format!("failed to sync {kind} at {}", path.display()))
}

fn intended_new_absolute_path(path: &Path, kind: &'static str) -> Result<PathBuf> {
    ensure!(!path.exists(), "{kind} already exists: {}", path.display());
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = parent
        .canonicalize()
        .with_context(|| format!("failed to resolve {kind} parent {}", parent.display()))?;
    let parent = direct_absolute_path(&parent)?;
    let name = path
        .file_name()
        .ok_or_else(|| anyhow!("{kind} must have a final path component"))?;
    Ok(parent.join(name))
}

#[cfg(windows)]
fn sibling_user_data_path(marker: &Path) -> Result<PathBuf> {
    let parent = marker
        .parent()
        .ok_or_else(|| anyhow!("smoke marker has no parent directory"))?;
    let name = marker
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("smoke marker name is not UTF-8"))?;
    Ok(parent.join(format!("{name}.user-data")))
}

fn ensure_disjoint(source: &Path, output: &Path) -> Result<()> {
    ensure!(
        !output.starts_with(source) && !source.starts_with(output),
        "managed package root overlaps the vendor package root"
    );
    Ok(())
}

#[cfg(not(windows))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "the cross-platform staging path helper keeps one fallible Windows-compatible interface"
)]
fn direct_absolute_path(path: &Path) -> Result<PathBuf> {
    Ok(path.to_path_buf())
}

#[cfg(windows)]
fn direct_absolute_path(path: &Path) -> Result<PathBuf> {
    const VERBATIM_PREFIX: [u16; 4] = [92, 92, 63, 92];
    const UNC_PREFIX: [u16; 4] = [85, 78, 67, 92];

    let units: Vec<u16> = path.as_os_str().encode_wide().collect();
    if !units.starts_with(&VERBATIM_PREFIX) {
        return Ok(path.to_path_buf());
    }
    let remainder = units
        .get(VERBATIM_PREFIX.len()..)
        .ok_or_else(|| anyhow!("canonical path lost its verbatim payload"))?;
    let mut direct = Vec::new();
    if remainder.starts_with(&UNC_PREFIX) {
        direct.extend_from_slice(&[92, 92]);
        direct.extend_from_slice(
            remainder
                .get(UNC_PREFIX.len()..)
                .ok_or_else(|| anyhow!("canonical UNC path lost its payload"))?,
        );
    } else {
        direct.extend_from_slice(remainder);
    }
    Ok(PathBuf::from(OsString::from_wide(&direct)))
}

fn normalized_relative_path(path: &Path) -> Result<String> {
    let mut normalized = String::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            bail!("package path contains a non-normal component")
        };
        let component = component
            .to_str()
            .ok_or_else(|| anyhow!("package path is not UTF-8"))?;
        ensure!(
            !component.is_empty(),
            "package path contains an empty component"
        );
        ensure!(
            !component.ends_with('.') && !component.ends_with(' '),
            "package path has an ambiguous Windows suffix"
        );
        ensure!(
            !component.chars().any(|value| value <= '\u{1f}'
                || matches!(value, '<' | '>' | ':' | '"' | '|' | '?' | '*')),
            "package path contains an unsafe Windows character"
        );
        if !normalized.is_empty() {
            normalized.push('/');
        }
        normalized.push_str(component);
    }
    ensure!(!normalized.is_empty(), "package path is empty");
    Ok(normalized)
}

fn ensure_direct_entry(metadata: &fs::Metadata, normalized: &str) -> Result<()> {
    ensure!(
        !metadata.file_type().is_symlink(),
        "package entry is a symbolic link: {normalized}"
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        ensure!(
            metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "package entry is a reparse point: {normalized}"
        );
    }
    Ok(())
}

#[cfg(windows)]
fn prefixed_path_argument(prefix: &str, path: &Path) -> OsString {
    let mut argument = OsString::from(prefix);
    argument.push(path.as_os_str());
    argument
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs};

    use serde_json::json;
    use sha2::{Digest as _, Sha256};
    use tempfile::tempdir;
    use weregopher_adapter_discord::{
        SMOKE_ADAPTER_ID, SMOKE_MUTABLE_DISPATCH_LOG_PATH, SMOKE_MUTABLE_KRISP_LOG_DIRECTORY_PATH,
    };
    use weregopher_asar::{AsarArchive, AsarLimits};

    use super::{APP_ASAR_PATH, DISCORD_KRISP_STATE_ROOT_PATH, digest, stage_discord_package};

    #[test]
    fn staging_transforms_asar_without_touching_vendor_or_copying_mutable_log()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempdir()?;
        let vendor = temporary.path().join("vendor");
        fs::create_dir_all(vendor.join("resources"))?;
        fs::create_dir_all(vendor.join("modules/discord_dispatch-1/discord_dispatch"))?;
        fs::create_dir_all(vendor.join(SMOKE_MUTABLE_KRISP_LOG_DIRECTORY_PATH))?;
        fs::write(vendor.join("Discord.exe"), b"fixture executable")?;
        let original = fixture_archive()?;
        fs::write(vendor.join(APP_ASAR_PATH), &original)?;
        fs::write(vendor.join(SMOKE_MUTABLE_DISPATCH_LOG_PATH), b"mutable")?;
        fs::write(vendor.join("stable.dat"), b"stable")?;

        let managed = temporary.path().join("managed");
        let receipt = stage_discord_package(&vendor, &managed)?;

        assert_eq!(fs::read(vendor.join(APP_ASAR_PATH))?, original);
        assert!(receipt.root.is_dir());
        assert_eq!(receipt.root.file_name(), managed.file_name());
        assert!(!managed.join(SMOKE_MUTABLE_DISPATCH_LOG_PATH).exists());
        assert!(
            !managed
                .join(SMOKE_MUTABLE_KRISP_LOG_DIRECTORY_PATH)
                .exists()
        );
        assert!(!managed.join(DISCORD_KRISP_STATE_ROOT_PATH).exists());
        assert_eq!(fs::read(managed.join("stable.dat"))?, b"stable");
        assert!(receipt.omitted_dispatch_log);
        assert!(receipt.omitted_krisp_log_directory);
        assert_eq!(
            receipt.source_app_asar_path.canonicalize()?,
            vendor.join(APP_ASAR_PATH).canonicalize()?
        );
        assert_eq!(
            receipt.static_observation.source_app_asar_sha256(),
            &digest(&original)
        );
        let output = fs::read(managed.join(APP_ASAR_PATH))?;
        assert_eq!(receipt.transformed_asar_sha256, digest(&output));
        assert_eq!(
            receipt.static_observation.transformed_app_asar_sha256(),
            &digest(&output)
        );
        let archive = AsarArchive::parse(&output, AsarLimits::initial())?;
        let transformed = archive.file("bundle.js").ok_or("missing bundle.js")?;
        assert!(transformed.ends_with(b"(()=>{console.log('discord')})();"));
        assert!(
            transformed
                .windows(SMOKE_ADAPTER_ID.len())
                .any(|window| window == SMOKE_ADAPTER_ID.as_bytes())
        );
        Ok(())
    }

    #[test]
    fn staging_rejects_content_inside_the_reviewed_mutable_log_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempdir()?;
        let vendor = temporary.path().join("vendor");
        fs::create_dir_all(vendor.join("resources"))?;
        fs::create_dir_all(vendor.join("modules/discord_dispatch-1/discord_dispatch"))?;
        fs::create_dir_all(vendor.join(SMOKE_MUTABLE_KRISP_LOG_DIRECTORY_PATH))?;
        fs::write(
            vendor
                .join(SMOKE_MUTABLE_KRISP_LOG_DIRECTORY_PATH)
                .join("unexpected"),
            b"content",
        )?;
        fs::write(vendor.join("Discord.exe"), b"fixture executable")?;
        fs::write(vendor.join(APP_ASAR_PATH), fixture_archive()?)?;
        fs::write(vendor.join(SMOKE_MUTABLE_DISPATCH_LOG_PATH), b"mutable")?;

        let Err(error) = stage_discord_package(&vendor, &temporary.path().join("managed")) else {
            return Err("content beneath a reviewed empty mutable path was accepted".into());
        };

        assert!(
            error
                .to_string()
                .contains("reviewed mutable Discord log directory is not empty")
        );
        Ok(())
    }

    fn fixture_archive() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let files = [
            ("bundle.js", b"(()=>{console.log('discord')})();".as_slice()),
            (
                "package.json",
                br#"{"name":"discord","main":"bundle.js"}"#.as_slice(),
            ),
        ];
        let mut offset = 0_usize;
        let mut members = BTreeMap::new();
        let mut body = Vec::new();
        for (path, bytes) in files {
            let hash = format!("{:x}", Sha256::digest(bytes));
            members.insert(
                path,
                json!({
                    "size": bytes.len(),
                    "offset": offset.to_string(),
                    "integrity": {
                        "algorithm": "SHA256",
                        "hash": hash,
                        "blockSize": 4_194_304,
                        "blocks": [hash],
                    }
                }),
            );
            body.extend_from_slice(bytes);
            offset += bytes.len();
        }
        let mut header = serde_json::to_vec(&json!({ "files": members }))?;
        let json_length = u32::try_from(header.len())?;
        while !header.len().is_multiple_of(4) {
            header.push(0);
        }
        let padded = u32::try_from(header.len())?;
        let mut archive = Vec::new();
        archive.extend_from_slice(&4_u32.to_le_bytes());
        archive.extend_from_slice(&(padded + 8).to_le_bytes());
        archive.extend_from_slice(&(padded + 4).to_le_bytes());
        archive.extend_from_slice(&json_length.to_le_bytes());
        archive.extend_from_slice(&header);
        archive.extend_from_slice(&body);
        Ok(archive)
    }
}
