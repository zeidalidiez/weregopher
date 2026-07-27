//! Native Windows exact-binary app-server schema and initialization probe.

use std::{
    ffi::OsString,
    fs::{self, File},
    io::{self, BufReader, Read as _},
    os::windows::fs::MetadataExt as _,
    path::Path,
    sync::mpsc::{self, RecvTimeoutError},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use thiserror::Error;
use weregopher_domain::{
    AppServerProbeChecks, AppServerProbeReport, G2ComponentSource, G2ProbeScope,
    OpenAiPackageInventory, Sha256Digest,
};
use weregopher_windows::{
    FileIdentityLease, JobLimits, KillOnCloseJob, LockedExecutable, OwnedJobStdioProcess,
    ProcessEnvironment, ProcessLaunchLimits,
};

use crate::app_server::{MAX_SCHEMA_FILE_BYTES, MAX_SCHEMA_FILES, MAX_SCHEMA_TOTAL_BYTES};
use crate::{
    AppServerClientInfo, AppServerHandshakeEvidence, AppServerProtocolError,
    AppServerProtocolLimits, AppServerSchemaError, OPENAI_APP_SERVER_PATH,
    hash_app_server_schema_bundle, probe_app_server_handshake,
};

const PROCESS_MEMORY_BYTES: u64 = 1024 * 1024 * 1024;
const JOB_MEMORY_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_ACTIVE_PROCESSES: u32 = 8;
const PIPE_BUFFER_BYTES: u32 = 64 * 1024;
const MAX_CAPTURED_STREAM_BYTES: usize = 1024 * 1024;
const SCHEMA_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const WAIT_SLICE: Duration = Duration::from_millis(50);
const TERMINATED_EXIT_CODE: u32 = 124;
const MAX_EXECUTABLE_PATH_COMPONENTS: usize = 256;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// Exact-binary app-server execution or evidence failure.
#[derive(Debug, Error)]
pub enum ExactAppServerProbeError {
    /// Package evidence did not identify the maintained direct app-server file.
    #[error("G2 package inventory does not identify the maintained app-server component")]
    InvalidInventory,
    /// The selected executable length differed from exact package evidence.
    #[error("selected app-server executable length does not match package evidence")]
    ExecutableLengthMismatch,
    /// The selected executable bytes differed from exact package evidence.
    #[error("selected app-server executable digest does not match package evidence")]
    ExecutableDigestMismatch,
    /// The Windows system root was unavailable for the explicit child environment.
    #[error("Windows system root is unavailable for the disposable app-server environment")]
    MissingSystemRoot,
    /// A required standard-I/O endpoint was unexpectedly unavailable.
    #[error("app-server process standard-I/O ownership is incomplete")]
    MissingStdio,
    /// One bounded execution phase exceeded its deadline.
    #[error("app-server phase {phase} exceeded its deadline")]
    Timeout {
        /// Sanitized phase label.
        phase: &'static str,
    },
    /// A child process returned a nonzero exit code.
    #[error("app-server phase {phase} exited with code {exit_code}")]
    ProcessFailed {
        /// Sanitized phase label.
        phase: &'static str,
        /// Exact process exit code.
        exit_code: u32,
    },
    /// Standard output or error exceeded the diagnostic byte ceiling.
    #[error("app-server phase {phase} {stream} exceeded its byte limit")]
    OutputTooLarge {
        /// Sanitized phase label.
        phase: &'static str,
        /// Standard stream label.
        stream: &'static str,
    },
    /// Generated output contained an unsupported filesystem object or shape.
    #[error("app-server generated schema output is invalid")]
    InvalidGeneratedOutput,
    /// A bounded worker thread failed unexpectedly.
    #[error("app-server probe worker terminated unexpectedly")]
    WorkerFailed,
    /// Filesystem or Windows process operations failed.
    #[error("app-server Windows probe operation failed: {0}")]
    Io(#[from] io::Error),
    /// App-server JSONL protocol validation failed.
    #[error(transparent)]
    Protocol(#[from] AppServerProtocolError),
    /// Generated schema hashing failed.
    #[error(transparent)]
    Schema(#[from] AppServerSchemaError),
}

/// Runs exact-version schema generation and the documented initialization
/// handshake against one package-bound app-server executable.
///
/// All three child processes are launched sequentially, atomically assigned to
/// bounded kill-on-close Job Objects, receive only explicit standard-I/O
/// handles, and use a fresh disposable state environment. Generated files are
/// hashed and removed with the temporary directory; raw output and protocol
/// traces are not returned or committed.
///
/// This is same-user unrestricted process execution. Job Objects provide
/// lifecycle/accounting controls, not a security sandbox. Callers must invoke
/// this only as an explicit final Windows feasibility probe.
///
/// # Errors
///
/// Returns [`ExactAppServerProbeError`] when package binding, executable
/// identity, disposable setup, schema generation, bounded output, process
/// lifecycle, or initialization semantics fail.
pub fn probe_exact_app_server(
    executable_path: &Path,
    inventory: &OpenAiPackageInventory,
) -> Result<AppServerProbeReport, ExactAppServerProbeError> {
    probe_exact_app_server_with_prefix(executable_path, inventory, &[])
}

fn probe_exact_app_server_with_prefix(
    executable_path: &Path,
    inventory: &OpenAiPackageInventory,
    command_prefix: &[OsString],
) -> Result<AppServerProbeReport, ExactAppServerProbeError> {
    let component = inventory.app_server();
    if component.source() != G2ComponentSource::PackageFile
        || component.path().as_str() != OPENAI_APP_SERVER_PATH
    {
        return Err(ExactAppServerProbeError::InvalidInventory);
    }
    let executable_lease =
        bind_exact_executable(executable_path, component.byte_length(), component.sha256())?;
    let disposable = create_disposable_environment()?;
    let typescript_output = disposable.root.path().join("generated-typescript");
    let json_schema_output = disposable.root.path().join("generated-json-schema");
    fs::create_dir(&typescript_output)?;
    fs::create_dir(&json_schema_output)?;

    run_to_exit(
        executable_path,
        &executable_lease,
        &schema_arguments("generate-ts", &typescript_output),
        command_prefix,
        &disposable.environment,
        SCHEMA_COMMAND_TIMEOUT,
        "generate-typescript",
    )?;
    run_to_exit(
        executable_path,
        &executable_lease,
        &schema_arguments("generate-json-schema", &json_schema_output),
        command_prefix,
        &disposable.environment,
        SCHEMA_COMMAND_TIMEOUT,
        "generate-json-schema",
    )?;

    let mut generated = Vec::new();
    collect_generated_files(&json_schema_output, "json-schema", &mut generated)?;
    collect_generated_files(&typescript_output, "typescript", &mut generated)?;
    let schema = hash_app_server_schema_bundle(generated)?;

    let handshake = run_handshake(
        executable_path,
        &executable_lease,
        command_prefix,
        &disposable.environment,
    )?;
    Ok(AppServerProbeReport::new(
        *inventory.source_build_fingerprint_digest(),
        *component.sha256(),
        *schema.digest(),
        *handshake.initialize_response_digest(),
        G2ProbeScope::ExactPackage,
        AppServerProbeChecks {
            stdio_jsonl: true,
            preinitialize_rejected: handshake.preinitialize_rejected(),
            initialize_succeeded: handshake.initialize_succeeded(),
            initialized_sent: handshake.initialized_sent(),
            clean_shutdown: true,
        },
    ))
}

fn bind_exact_executable(
    path: &Path,
    expected_length: u64,
    expected_digest: &Sha256Digest,
) -> Result<FileIdentityLease, ExactAppServerProbeError> {
    let mut file = File::open(path)?;
    if file.metadata()?.len() != expected_length {
        return Err(ExactAppServerProbeError::ExecutableLengthMismatch);
    }
    let mut hasher = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        observed = observed
            .checked_add(
                u64::try_from(read)
                    .map_err(|_| ExactAppServerProbeError::ExecutableLengthMismatch)?,
            )
            .ok_or(ExactAppServerProbeError::ExecutableLengthMismatch)?;
        if observed > expected_length {
            return Err(ExactAppServerProbeError::ExecutableLengthMismatch);
        }
        hasher.update(&buffer[..read]);
    }
    if observed != expected_length
        || Sha256Digest::from_bytes(hasher.finalize().into()) != *expected_digest
    {
        return Err(ExactAppServerProbeError::ExecutableDigestMismatch);
    }
    let lease = FileIdentityLease::from_file(file)?;
    let locked =
        LockedExecutable::open_matching_identity(path, MAX_EXECUTABLE_PATH_COMPONENTS, &lease)?;
    drop(locked);
    Ok(lease)
}

struct DisposableEnvironment {
    root: TempDir,
    environment: ProcessEnvironment,
}

fn create_disposable_environment() -> Result<DisposableEnvironment, ExactAppServerProbeError> {
    let root = tempfile::Builder::new()
        .prefix("weregopher-g2-app-server-")
        .tempdir()?;
    let profile = root.path().join("profile");
    let local = root.path().join("local");
    let roaming = root.path().join("roaming");
    let codex = root.path().join("codex");
    let temporary = root.path().join("temp");
    for directory in [&profile, &local, &roaming, &codex, &temporary] {
        fs::create_dir(directory)?;
    }
    let system_root =
        std::env::var_os("SYSTEMROOT").ok_or(ExactAppServerProbeError::MissingSystemRoot)?;
    let environment = ProcessEnvironment::new([
        (OsString::from("APPDATA"), roaming.into_os_string()),
        (OsString::from("CODEX_HOME"), codex.into_os_string()),
        (OsString::from("LOCALAPPDATA"), local.into_os_string()),
        (OsString::from("SYSTEMROOT"), system_root.clone()),
        (OsString::from("TEMP"), temporary.clone().into_os_string()),
        (OsString::from("TMP"), temporary.into_os_string()),
        (OsString::from("USERPROFILE"), profile.into_os_string()),
        (OsString::from("WINDIR"), system_root),
    ])?;
    Ok(DisposableEnvironment { root, environment })
}

fn schema_arguments(generator: &'static str, output: &Path) -> Vec<OsString> {
    vec![
        OsString::from("app-server"),
        OsString::from(generator),
        OsString::from("--out"),
        output.as_os_str().to_owned(),
    ]
}

fn launch_process(
    executable_path: &Path,
    executable_lease: &FileIdentityLease,
    arguments: &[OsString],
    command_prefix: &[OsString],
    environment: &ProcessEnvironment,
) -> Result<OwnedJobStdioProcess, ExactAppServerProbeError> {
    let executable = LockedExecutable::open_matching_identity(
        executable_path,
        MAX_EXECUTABLE_PATH_COMPONENTS,
        executable_lease,
    )?;
    let mut complete_arguments = Vec::new();
    complete_arguments
        .try_reserve_exact(command_prefix.len() + arguments.len())
        .map_err(|_| io::Error::other("app-server argument allocation failed"))?;
    complete_arguments.extend_from_slice(command_prefix);
    complete_arguments.extend_from_slice(arguments);
    let job = KillOnCloseJob::create(JobLimits::new(
        MAX_ACTIVE_PROCESSES,
        PROCESS_MEMORY_BYTES,
        JOB_MEMORY_BYTES,
    )?)?;
    Ok(job.launch_with_piped_stdio(
        executable,
        &complete_arguments,
        ProcessLaunchLimits::new(32, 4_096, 32_767)?,
        environment,
        PIPE_BUFFER_BYTES,
    )?)
}

fn run_to_exit(
    executable_path: &Path,
    executable_lease: &FileIdentityLease,
    arguments: &[OsString],
    command_prefix: &[OsString],
    environment: &ProcessEnvironment,
    timeout: Duration,
    phase: &'static str,
) -> Result<(), ExactAppServerProbeError> {
    let mut process = launch_process(
        executable_path,
        executable_lease,
        arguments,
        command_prefix,
        environment,
    )?;
    drop(
        process
            .take_stdin()
            .ok_or(ExactAppServerProbeError::MissingStdio)?,
    );
    let stdout = spawn_drain(
        process
            .take_stdout()
            .ok_or(ExactAppServerProbeError::MissingStdio)?,
    );
    let stderr = spawn_drain(
        process
            .take_stderr()
            .ok_or(ExactAppServerProbeError::MissingStdio)?,
    );
    let exit_code = wait_for_exit(&process, timeout, phase);
    if exit_code.is_err() {
        let _ = process.terminate(TERMINATED_EXIT_CODE);
        let _ = process.wait_for(SHUTDOWN_TIMEOUT);
    }
    let stdout_result = verify_drain(stdout, phase, "stdout");
    let stderr_result = verify_drain(stderr, phase, "stderr");
    let exit_code = exit_code?;
    stdout_result?;
    stderr_result?;
    if exit_code != 0 {
        return Err(ExactAppServerProbeError::ProcessFailed { phase, exit_code });
    }
    Ok(())
}

fn run_handshake(
    executable_path: &Path,
    executable_lease: &FileIdentityLease,
    command_prefix: &[OsString],
    environment: &ProcessEnvironment,
) -> Result<AppServerHandshakeEvidence, ExactAppServerProbeError> {
    let mut process = launch_process(
        executable_path,
        executable_lease,
        &[OsString::from("app-server")],
        command_prefix,
        environment,
    )?;
    let mut stdin = process
        .take_stdin()
        .ok_or(ExactAppServerProbeError::MissingStdio)?;
    let stdout = process
        .take_stdout()
        .ok_or(ExactAppServerProbeError::MissingStdio)?;
    let stderr = spawn_drain(
        process
            .take_stderr()
            .ok_or(ExactAppServerProbeError::MissingStdio)?,
    );
    let client = AppServerClientInfo::new(
        "weregopher",
        "Weregopher target feasibility",
        env!("CARGO_PKG_VERSION"),
    )?;
    let (sender, receiver) = mpsc::channel();
    let handshake_thread = thread::spawn(move || {
        let mut stdout = BufReader::new(stdout);
        let result = probe_app_server_handshake(
            &mut stdout,
            &mut stdin,
            &client,
            AppServerProtocolLimits::initial(),
        );
        drop(stdin);
        let _ = sender.send(result);
    });
    let handshake = match receiver.recv_timeout(HANDSHAKE_TIMEOUT) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => {
            terminate_after_timeout(&process)?;
            join_handshake(handshake_thread)?;
            verify_drain(stderr, "initialize", "stderr")?;
            return Err(ExactAppServerProbeError::Timeout {
                phase: "initialize",
            });
        }
        Err(RecvTimeoutError::Disconnected) => {
            terminate_after_timeout(&process)?;
            join_handshake(handshake_thread)?;
            verify_drain(stderr, "initialize", "stderr")?;
            return Err(ExactAppServerProbeError::WorkerFailed);
        }
    };
    join_handshake(handshake_thread)?;
    let handshake = match handshake {
        Ok(evidence) => evidence,
        Err(error) => {
            let _ = process.terminate(TERMINATED_EXIT_CODE);
            let _ = process.wait_for(SHUTDOWN_TIMEOUT);
            verify_drain(stderr, "initialize", "stderr")?;
            return Err(error.into());
        }
    };
    let exit_code = wait_for_exit(&process, SHUTDOWN_TIMEOUT, "shutdown")?;
    verify_drain(stderr, "initialize", "stderr")?;
    if exit_code != 0 {
        return Err(ExactAppServerProbeError::ProcessFailed {
            phase: "shutdown",
            exit_code,
        });
    }
    Ok(handshake)
}

fn wait_for_exit(
    process: &OwnedJobStdioProcess,
    timeout: Duration,
    phase: &'static str,
) -> Result<u32, ExactAppServerProbeError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(ExactAppServerProbeError::Timeout { phase })?;
    loop {
        let now = Instant::now();
        if now >= deadline {
            terminate_after_timeout(process)?;
            return Err(ExactAppServerProbeError::Timeout { phase });
        }
        let remaining = deadline.saturating_duration_since(now);
        if let Some(exit_code) = process.wait_for(remaining.min(WAIT_SLICE))? {
            return Ok(exit_code);
        }
    }
}

fn terminate_after_timeout(process: &OwnedJobStdioProcess) -> Result<(), ExactAppServerProbeError> {
    process.terminate(TERMINATED_EXIT_CODE)?;
    let _ = process.wait_for(SHUTDOWN_TIMEOUT)?;
    Ok(())
}

struct DrainObservation {
    too_large: bool,
}

fn spawn_drain(stream: File) -> JoinHandle<io::Result<DrainObservation>> {
    thread::spawn(move || {
        let mut stream = stream;
        let mut total = 0_usize;
        let mut too_large = false;
        let mut buffer = [0_u8; 8 * 1024];
        loop {
            let read = stream.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            total = total.saturating_add(read);
            too_large |= total > MAX_CAPTURED_STREAM_BYTES;
        }
        Ok(DrainObservation { too_large })
    })
}

fn verify_drain(
    worker: JoinHandle<io::Result<DrainObservation>>,
    phase: &'static str,
    stream: &'static str,
) -> Result<(), ExactAppServerProbeError> {
    let observation = worker
        .join()
        .map_err(|_| ExactAppServerProbeError::WorkerFailed)??;
    if observation.too_large {
        return Err(ExactAppServerProbeError::OutputTooLarge { phase, stream });
    }
    Ok(())
}

fn join_handshake(worker: JoinHandle<()>) -> Result<(), ExactAppServerProbeError> {
    worker
        .join()
        .map_err(|_| ExactAppServerProbeError::WorkerFailed)
}

fn collect_generated_files(
    root: &Path,
    root_label: &str,
    output: &mut Vec<(String, Vec<u8>)>,
) -> Result<(), ExactAppServerProbeError> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() || is_reparse_point(&metadata) {
        return Err(ExactAppServerProbeError::InvalidGeneratedOutput);
    }
    let mut entry_count = 0_usize;
    collect_generated_directory(root, root_label, 0, &mut entry_count, output)
}

fn collect_generated_directory(
    directory: &Path,
    relative: &str,
    depth: usize,
    entry_count: &mut usize,
    output: &mut Vec<(String, Vec<u8>)>,
) -> Result<(), ExactAppServerProbeError> {
    if depth > 64 || output.len() > MAX_SCHEMA_FILES {
        return Err(ExactAppServerProbeError::InvalidGeneratedOutput);
    }
    for entry in fs::read_dir(directory)? {
        *entry_count = entry_count
            .checked_add(1)
            .ok_or(ExactAppServerProbeError::InvalidGeneratedOutput)?;
        if *entry_count > MAX_SCHEMA_FILES * 4 {
            return Err(ExactAppServerProbeError::InvalidGeneratedOutput);
        }
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if is_reparse_point(&metadata) {
            return Err(ExactAppServerProbeError::InvalidGeneratedOutput);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ExactAppServerProbeError::InvalidGeneratedOutput)?;
        if name.is_empty() || matches!(name.as_str(), "." | "..") {
            return Err(ExactAppServerProbeError::InvalidGeneratedOutput);
        }
        let child_relative = format!("{relative}/{name}");
        if metadata.is_dir() {
            collect_generated_directory(
                &entry.path(),
                &child_relative,
                depth + 1,
                entry_count,
                output,
            )?;
        } else if metadata.is_file() {
            if output.len() == MAX_SCHEMA_FILES
                || metadata.len()
                    > u64::try_from(MAX_SCHEMA_FILE_BYTES)
                        .map_err(|_| ExactAppServerProbeError::InvalidGeneratedOutput)?
            {
                return Err(ExactAppServerProbeError::InvalidGeneratedOutput);
            }
            let mut bytes = Vec::new();
            File::open(entry.path())?
                .take(
                    u64::try_from(MAX_SCHEMA_FILE_BYTES)
                        .map_err(|_| ExactAppServerProbeError::InvalidGeneratedOutput)?
                        + 1,
                )
                .read_to_end(&mut bytes)?;
            if bytes.is_empty() || bytes.len() > MAX_SCHEMA_FILE_BYTES {
                return Err(ExactAppServerProbeError::InvalidGeneratedOutput);
            }
            let aggregate = output
                .iter()
                .try_fold(bytes.len(), |total, (_, existing)| {
                    total.checked_add(existing.len())
                })
                .ok_or(ExactAppServerProbeError::InvalidGeneratedOutput)?;
            if aggregate > MAX_SCHEMA_TOTAL_BYTES {
                return Err(ExactAppServerProbeError::InvalidGeneratedOutput);
            }
            output.push((child_relative, bytes));
        } else {
            return Err(ExactAppServerProbeError::InvalidGeneratedOutput);
        }
    }
    Ok(())
}

fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}
