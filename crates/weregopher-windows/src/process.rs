//! Locked executable paths and atomically Job-owned suspended process launch.

use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fmt,
    fs::{File, OpenOptions},
    io,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt as _,
        fs::{MetadataExt as _, OpenOptionsExt as _},
        io::{AsRawHandle as _, FromRawHandle as _, IntoRawHandle as _, OwnedHandle},
    },
    path::{Component, Path, PathBuf, Prefix},
    ptr,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use windows_sys::Win32::{
    Foundation::{
        HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_FLAG_SEQUENTIAL_SCAN, FILE_SHARE_READ, FILE_SHARE_WRITE,
    },
    System::{
        Pipes::CreatePipe,
        Threading::{
            CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
            DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess,
            InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION,
            ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess,
            UpdateProcThreadAttribute, WaitForSingleObject,
        },
    },
};

use crate::{FileIdentity, FileIdentityLease, KillOnCloseJob};

const WINDOWS_COMMAND_LINE_MAX_UNITS: usize = 32_767;
const WINDOWS_ENVIRONMENT_MAX_UNITS: usize = 32_767;
const MAX_ENVIRONMENT_VARIABLES: usize = 64;
const MAX_ENVIRONMENT_NAME_BYTES: usize = 128;
const MAX_ENVIRONMENT_VALUE_UNITS: usize = 4_096;
const MAX_ANONYMOUS_PIPE_BUFFER_BYTES: u32 = 4 * 1024 * 1024;
static NEXT_LOCK_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

fn allocate_lock_instance_id() -> io::Result<u64> {
    NEXT_LOCK_INSTANCE_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| io::Error::other("locked executable instance identity exhausted"))
}

/// Caller-selected bounds for one no-inheritance suspended launch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessLaunchLimits {
    arguments: usize,
    argument_units: usize,
    command_line_units: usize,
}

impl ProcessLaunchLimits {
    /// Validates argument cardinality plus per-argument and aggregate UTF-16 limits.
    ///
    /// The command-line limit includes the terminating NUL and cannot exceed the Windows limit.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] for zero, inverted, or Windows-incompatible limits.
    pub fn new(
        max_arguments: usize,
        max_argument_units: usize,
        max_command_line_units: usize,
    ) -> io::Result<Self> {
        if max_arguments == 0 || max_argument_units == 0 || max_command_line_units == 0 {
            return Err(invalid_input("process launch limits must be nonzero"));
        }
        if max_argument_units >= max_command_line_units {
            return Err(invalid_input(
                "per-argument UTF-16 limit must be below the aggregate command-line limit",
            ));
        }
        if max_command_line_units > WINDOWS_COMMAND_LINE_MAX_UNITS {
            return Err(invalid_input(
                "command-line limit exceeds the Windows CreateProcessW boundary",
            ));
        }
        Ok(Self {
            arguments: max_arguments,
            argument_units: max_argument_units,
            command_line_units: max_command_line_units,
        })
    }

    /// Maximum caller-supplied arguments, excluding `argv[0]`.
    #[must_use]
    pub const fn max_arguments(self) -> usize {
        self.arguments
    }

    /// Maximum UTF-16 code units in any argument before quoting.
    #[must_use]
    pub const fn max_argument_units(self) -> usize {
        self.argument_units
    }

    /// Maximum UTF-16 code units in the complete command line, including its NUL.
    #[must_use]
    pub const fn max_command_line_units(self) -> usize {
        self.command_line_units
    }
}

/// Explicit, bounded Unicode environment for one child process.
///
/// Names are restricted to canonical uppercase ASCII identifiers so
/// case-insensitive Windows duplicates cannot be smuggled into the environment.
/// Values may contain Unicode but not NUL or control characters. Debug output
/// reports only counts and sizes so environment values cannot leak through
/// diagnostics.
#[derive(Clone, Eq, PartialEq)]
pub struct ProcessEnvironment {
    block: Vec<u16>,
    variable_count: usize,
}

impl ProcessEnvironment {
    /// Constructs a sorted Windows Unicode environment block.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error for duplicate/noncanonical names,
    /// control-bearing or oversized values, excessive variable count, or an
    /// environment that exceeds the Windows block ceiling.
    pub fn new<I, K, V>(variables: I) -> io::Result<Self>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        let mut canonical = BTreeMap::new();
        for (name, value) in variables {
            if canonical.len() == MAX_ENVIRONMENT_VARIABLES {
                return Err(invalid_input(
                    "process environment exceeds its variable-count limit",
                ));
            }
            let name = name.into();
            let name = name
                .to_str()
                .ok_or_else(|| invalid_input("process environment name must be Unicode"))?;
            if name.is_empty()
                || name.len() > MAX_ENVIRONMENT_NAME_BYTES
                || !name.bytes().enumerate().all(|(index, byte)| {
                    byte.is_ascii_uppercase()
                        || byte == b'_'
                        || (index != 0 && byte.is_ascii_digit())
                })
            {
                return Err(invalid_input(
                    "process environment name is not canonical uppercase ASCII",
                ));
            }
            let value = value.into();
            let value_units = encode_units(value.as_os_str(), MAX_ENVIRONMENT_VALUE_UNITS)?;
            if value_units
                .iter()
                .any(|unit| *unit < u16::from(b' ') || *unit == 0x7f)
            {
                return Err(invalid_input(
                    "process environment value contains a control character",
                ));
            }
            if canonical.insert(name.to_owned(), value_units).is_some() {
                return Err(invalid_input(
                    "process environment contains a duplicate variable",
                ));
            }
        }
        encode_environment_block(&canonical)
    }

    /// Returns an explicit empty Windows environment block.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            block: vec![0, 0],
            variable_count: 0,
        }
    }

    fn block(&self) -> &[u16] {
        &self.block
    }
}

impl fmt::Debug for ProcessEnvironment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessEnvironment")
            .field("variable_count", &self.variable_count)
            .field("encoded_units", &self.block.len())
            .finish_non_exhaustive()
    }
}

fn encode_environment_block(
    variables: &BTreeMap<String, Vec<u16>>,
) -> io::Result<ProcessEnvironment> {
    if variables.is_empty() {
        return Ok(ProcessEnvironment::empty());
    }
    let mut required = 1_usize;
    for (name, value) in variables {
        required = required
            .checked_add(name.len())
            .and_then(|units| units.checked_add(1))
            .and_then(|units| units.checked_add(value.len()))
            .and_then(|units| units.checked_add(1))
            .ok_or_else(|| invalid_input("process environment length overflowed"))?;
    }
    if required > WINDOWS_ENVIRONMENT_MAX_UNITS {
        return Err(invalid_input(
            "process environment exceeds the Windows block limit",
        ));
    }
    let mut block = Vec::new();
    block
        .try_reserve_exact(required)
        .map_err(|_| io::Error::other("process environment allocation failed"))?;
    for (name, value) in variables {
        block.extend(name.bytes().map(u16::from));
        block.push(u16::from(b'='));
        block.extend_from_slice(value);
        block.push(0);
    }
    block.push(0);
    if block.len() != required {
        return Err(io::Error::other(
            "process environment sizing and emission disagreed",
        ));
    }
    Ok(ProcessEnvironment {
        block,
        variable_count: variables.len(),
    })
}

/// Opaque, exact Windows launch encoding prepared against one retained executable identity.
///
/// Construction validates UTF-16 encoding, C-runtime quoting expansion, aggregate command-line
/// length, and working-directory representability before an authorization boundary can retain this
/// value. It is neither cloneable nor serializable and carries a private binding to the exact
/// [`LockedExecutable`] instance that prepared it. Reopening the same file object through the same
/// textual path cannot satisfy that binding after the preparing lock is dropped.
#[must_use = "a prepared launch must be consumed with its exact locked executable"]
pub struct PreparedProcessLaunch {
    executable_path: PathBuf,
    executable_identity: FileIdentity,
    lock_instance_id: u64,
    application: Vec<u16>,
    current_directory: Vec<u16>,
    command_line: Vec<u16>,
    environment: Vec<u16>,
}

impl fmt::Debug for PreparedProcessLaunch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedProcessLaunch")
            .field("application_units", &self.application.len())
            .field("current_directory_units", &self.current_directory.len())
            .field("command_line_units", &self.command_line.len())
            .field("environment_units", &self.environment.len())
            .finish_non_exhaustive()
    }
}

/// Retains a direct absolute executable path and every ancestor against rebinding.
///
/// The capability rejects reparse points and keeps the executable open without write or delete
/// sharing. It proves path stability and regular-file shape, not a trusted signer, content hash,
/// architecture, adapter allowlist, or execution authority. Every successful open receives a
/// process-local private instance identity so prepared launch data cannot be rebound to a later lock.
pub struct LockedExecutable {
    path: PathBuf,
    component_count: usize,
    lock_instance_id: u64,
    _ancestors: Vec<FileIdentityLease>,
    file: FileIdentityLease,
}

impl LockedExecutable {
    /// Opens and locks an existing executable path without following reparse points.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error for zero limits, relative/parent/verbatim paths, excessive
    /// components, reparse points, or non-file objects. Other filesystem failures are preserved.
    pub fn open(path: &Path, max_components: usize) -> io::Result<Self> {
        if max_components == 0 {
            return Err(invalid_input(
                "locked executable component limit must be nonzero",
            ));
        }
        let component_count = validate_absolute_path(path, max_components)?;
        let parent = path
            .parent()
            .ok_or_else(|| invalid_input("locked executable must have an absolute parent"))?;
        let ancestors = open_directory_chain(parent)?;
        let file = open_regular_file(path)?;
        let file = FileIdentityLease::from_file(file)?;
        let lock_instance_id = allocate_lock_instance_id()?;
        Ok(Self {
            path: path.to_path_buf(),
            component_count,
            lock_instance_id,
            _ancestors: ancestors,
            file,
        })
    }

    /// Opens and locks an executable only when it is the exact retained file object expected by
    /// a higher-level artifact lease.
    ///
    /// This adds identity binding to [`Self::open`], but does not authenticate the file's bytes or
    /// authorize execution.
    ///
    /// # Errors
    ///
    /// Returns the errors documented by [`Self::open`], or an invalid-data error when the selected
    /// file object does not match `expected_identity`.
    pub fn open_matching_identity(
        path: &Path,
        max_components: usize,
        expected_identity: &FileIdentityLease,
    ) -> io::Result<Self> {
        let executable = Self::open(path, max_components)?;
        if !executable.file.has_same_identity(expected_identity) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "locked executable does not match the retained artifact identity",
            ));
        }
        Ok(executable)
    }

    /// Prepares the exact no-inheritance Windows command line for this retained executable.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input or allocation error when the executable path, working directory, or
    /// quoted arguments cannot be represented under `limits`.
    pub fn prepare_launch(
        &self,
        arguments: &[OsString],
        limits: ProcessLaunchLimits,
    ) -> io::Result<PreparedProcessLaunch> {
        self.prepare_launch_with_environment(arguments, limits, &ProcessEnvironment::empty())
    }

    /// Prepares a launch with one already validated explicit environment.
    ///
    /// # Errors
    ///
    /// Returns the path, argument, quoting, and allocation failures documented
    /// by [`Self::prepare_launch`].
    pub fn prepare_launch_with_environment(
        &self,
        arguments: &[OsString],
        limits: ProcessLaunchLimits,
        environment: &ProcessEnvironment,
    ) -> io::Result<PreparedProcessLaunch> {
        let application = encode_nul_terminated(self.path().as_os_str(), limits.argument_units)?;
        let current_directory_path = self
            .path()
            .parent()
            .ok_or_else(|| invalid_input("locked executable lost its absolute parent"))?;
        let current_directory =
            encode_nul_terminated(current_directory_path.as_os_str(), limits.argument_units)?;
        let command_line = build_command_line(self.path().as_os_str(), arguments, limits)?;
        Ok(PreparedProcessLaunch {
            executable_path: self.path.clone(),
            executable_identity: self.file.identity,
            lock_instance_id: self.lock_instance_id,
            application,
            current_directory,
            command_line,
            environment: environment.block().to_vec(),
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl fmt::Debug for LockedExecutable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LockedExecutable")
            .field("component_count", &self.component_count)
            .finish_non_exhaustive()
    }
}

/// Owns one resumed primary process, its locked executable path, and its kill-on-close job.
///
/// Dropping this value closes the sole Job Object handle and therefore terminates any process tree
/// still associated with it. This remains a lifecycle primitive, not an execution authorization or
/// sandbox claim.
pub struct OwnedJobProcess {
    job: KillOnCloseJob,
    process: OwnedHandle,
    process_id: u32,
    _executable: LockedExecutable,
}

impl OwnedJobProcess {
    /// Returns the Windows process identifier captured at creation.
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.process_id
    }

    /// Returns the limits enforced by the owned Job Object.
    #[must_use]
    pub const fn job_limits(&self) -> crate::JobLimits {
        self.job.limits()
    }

    /// Reports whether Windows associates the primary process with the owned job.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error when membership cannot be queried.
    pub fn is_in_job(&self) -> io::Result<bool> {
        self.job.contains_process(&self.process)
    }

    /// Terminates the complete owned process tree with the supplied exit code.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error when Windows cannot terminate the job.
    pub fn terminate(&self, exit_code: u32) -> io::Result<()> {
        self.job.terminate(exit_code)
    }

    /// Waits for at most `timeout` and returns the process exit code when available.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error when the duration cannot be represented by the bounded
    /// Windows millisecond timeout, or the operating-system error from waiting/querying.
    pub fn wait_for(&self, timeout: Duration) -> io::Result<Option<u32>> {
        wait_for_process(&self.process, timeout)
    }
}

impl fmt::Debug for OwnedJobProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedJobProcess")
            .field("process_id", &self.process_id)
            .field("job_limits", &self.job.limits())
            .finish_non_exhaustive()
    }
}

/// Atomically Job-owned process with exclusive parent ends for standard I/O.
///
/// The child inherits exactly its standard-input read handle and
/// standard-output/error write handles through an explicit Windows handle list.
/// Taking a stream transfers that parent endpoint to the caller. Dropping the
/// process owner still terminates the complete Job-owned process tree.
pub struct OwnedJobStdioProcess {
    process: OwnedJobProcess,
    stdin: Option<File>,
    stdout: Option<File>,
    stderr: Option<File>,
}

impl OwnedJobStdioProcess {
    /// Returns the Windows process identifier captured at creation.
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.process.id()
    }

    /// Reports whether Windows associates the process with its owned job.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error when membership cannot be queried.
    pub fn is_in_job(&self) -> io::Result<bool> {
        self.process.is_in_job()
    }

    /// Terminates the complete owned process tree.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error when Windows cannot terminate the job.
    pub fn terminate(&self, exit_code: u32) -> io::Result<()> {
        self.process.terminate(exit_code)
    }

    /// Waits for at most `timeout` and returns an available exit code.
    ///
    /// # Errors
    ///
    /// Returns the bounded wait errors documented by [`OwnedJobProcess::wait_for`].
    pub fn wait_for(&self, timeout: Duration) -> io::Result<Option<u32>> {
        self.process.wait_for(timeout)
    }

    /// Takes the exclusive parent writer connected to child standard input.
    pub fn take_stdin(&mut self) -> Option<File> {
        self.stdin.take()
    }

    /// Takes the exclusive parent reader connected to child standard output.
    pub fn take_stdout(&mut self) -> Option<File> {
        self.stdout.take()
    }

    /// Takes the exclusive parent reader connected to child standard error.
    pub fn take_stderr(&mut self) -> Option<File> {
        self.stderr.take()
    }
}

impl fmt::Debug for OwnedJobStdioProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedJobStdioProcess")
            .field("process_id", &self.process.id())
            .field("stdin_available", &self.stdin.is_some())
            .field("stdout_available", &self.stdout.is_some())
            .field("stderr_available", &self.stderr.is_some())
            .finish_non_exhaustive()
    }
}

impl KillOnCloseJob {
    /// Atomically associates a new suspended process with this job, then resumes its primary thread.
    ///
    /// The executable path capability is retained for the lifetime of the returned process owner.
    /// The child receives an explicit empty Unicode environment, no inherited handles, no console,
    /// and the executable's retained parent directory as its working directory. Arguments use the
    /// Windows C-runtime quoting rules and are bounded before process creation.
    ///
    /// This method consumes the Job Object so any failure after process creation closes the job and
    /// terminates the still-suspended process. `PROC_THREAD_ATTRIBUTE_JOB_LIST` establishes job
    /// membership as part of `CreateProcessW`, before the primary thread can execute.
    ///
    /// It does not verify executable content, signer, architecture, adapter authority, DLL policy,
    /// or compatibility. Higher layers must establish those claims before invoking this primitive.
    ///
    /// # Errors
    ///
    /// Returns a typed operating-system or invalid-input error for path encoding, argument bounds,
    /// attribute-list setup, process creation, job-membership verification, or primary-thread resume.
    pub fn launch(
        self,
        executable: LockedExecutable,
        arguments: &[OsString],
        limits: ProcessLaunchLimits,
    ) -> io::Result<OwnedJobProcess> {
        let prepared = executable.prepare_launch(arguments, limits)?;
        self.launch_prepared(executable, prepared)
    }

    /// Consumes a launch encoding previously prepared for this exact retained executable.
    ///
    /// Path, full-width file identity, and private lock-instance binding are checked before any
    /// process-creation operation. This keeps quoting and Windows representability validation on the
    /// pre-authorization side without permitting a prepared command line to be rebound after the
    /// original executable or ancestor handles are dropped.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error for an executable, path, or lock-instance binding mismatch, or
    /// the process-launch errors documented by [`Self::launch`].
    pub fn launch_prepared(
        self,
        executable: LockedExecutable,
        prepared: PreparedProcessLaunch,
    ) -> io::Result<OwnedJobProcess> {
        if executable.path != prepared.executable_path
            || executable.file.identity != prepared.executable_identity
            || executable.lock_instance_id != prepared.lock_instance_id
        {
            return Err(invalid_input(
                "prepared process launch does not match the retained executable",
            ));
        }
        launch_owned_process(self, executable, prepared)
    }

    /// Atomically launches a Job-owned process with bounded explicit
    /// environment and exactly inherited standard-I/O pipes.
    ///
    /// The process is created suspended with both the Job List and Handle List
    /// attributes. No child instruction executes before Job membership is
    /// verified, and unrelated inheritable handles are excluded. The supplied
    /// environment is explicit rather than inherited from the caller.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error for pipe-buffer bounds or the launch
    /// preparation errors documented by [`Self::launch`], and otherwise
    /// preserves Windows pipe, attribute-list, process, membership, or resume
    /// errors.
    pub fn launch_with_piped_stdio(
        self,
        executable: LockedExecutable,
        arguments: &[OsString],
        limits: ProcessLaunchLimits,
        environment: &ProcessEnvironment,
        pipe_buffer_bytes: u32,
    ) -> io::Result<OwnedJobStdioProcess> {
        let prepared =
            executable.prepare_launch_with_environment(arguments, limits, environment)?;
        launch_owned_stdio_process(self, executable, prepared, pipe_buffer_bytes)
    }
}

fn launch_owned_process(
    job: KillOnCloseJob,
    executable: LockedExecutable,
    mut prepared: PreparedProcessLaunch,
) -> io::Result<OwnedJobProcess> {
    let attributes = AttributeList::with_job(job.handle())?;
    let (process, thread, process_id) = create_suspended_process(
        &prepared.application,
        &mut prepared.command_line,
        &prepared.current_directory,
        &prepared.environment,
        &attributes,
        None,
    )?;
    complete_owned_process(job, executable, process, thread, process_id)
}

fn complete_owned_process(
    job: KillOnCloseJob,
    executable: LockedExecutable,
    process: OwnedHandle,
    thread: OwnedHandle,
    process_id: u32,
) -> io::Result<OwnedJobProcess> {
    let membership = job.contains_process(&process);
    if !matches!(membership, Ok(true)) {
        abort_created_process(&job, &process);
        return match membership {
            Ok(false) => Err(io::Error::other(
                "CreateProcessW returned a process outside its required Job Object",
            )),
            Err(error) => Err(error),
            Ok(true) => Err(io::Error::other("unreachable membership state")),
        };
    }

    if let Err(error) = resume_primary_thread(&thread) {
        abort_created_process(&job, &process);
        return Err(error);
    }
    drop(thread);

    Ok(OwnedJobProcess {
        job,
        process,
        process_id,
        _executable: executable,
    })
}

fn launch_owned_stdio_process(
    job: KillOnCloseJob,
    executable: LockedExecutable,
    mut prepared: PreparedProcessLaunch,
    pipe_buffer_bytes: u32,
) -> io::Result<OwnedJobStdioProcess> {
    let pipes = InheritedStdio::create(pipe_buffer_bytes)?;
    let inherited_handles = pipes.child_handles();
    let attributes = AttributeList::with_job_and_handles(job.handle(), &inherited_handles)?;
    let (process, thread, process_id) = create_suspended_process(
        &prepared.application,
        &mut prepared.command_line,
        &prepared.current_directory,
        &prepared.environment,
        &attributes,
        Some(&pipes),
    )?;
    drop(attributes);
    let (stdin, stdout, stderr) = pipes.into_parent_files();
    let process = complete_owned_process(job, executable, process, thread, process_id)?;
    Ok(OwnedJobStdioProcess {
        process,
        stdin: Some(stdin),
        stdout: Some(stdout),
        stderr: Some(stderr),
    })
}

struct InheritedStdio {
    child_stdin: OwnedHandle,
    parent_stdin: OwnedHandle,
    parent_stdout: OwnedHandle,
    child_stdout: OwnedHandle,
    parent_stderr: OwnedHandle,
    child_stderr: OwnedHandle,
}

impl InheritedStdio {
    fn create(buffer_bytes: u32) -> io::Result<Self> {
        if buffer_bytes == 0 || buffer_bytes > MAX_ANONYMOUS_PIPE_BUFFER_BYTES {
            return Err(invalid_input(
                "anonymous pipe buffer must be between 1 byte and 4 MiB",
            ));
        }
        let (child_stdin, parent_stdin) = create_inherited_pipe(buffer_bytes, true)?;
        let (parent_stdout, child_stdout) = create_inherited_pipe(buffer_bytes, false)?;
        let (parent_stderr, child_stderr) = create_inherited_pipe(buffer_bytes, false)?;
        Ok(Self {
            child_stdin,
            parent_stdin,
            parent_stdout,
            child_stdout,
            parent_stderr,
            child_stderr,
        })
    }

    fn child_handles(&self) -> [HANDLE; 3] {
        [
            self.child_stdin.as_raw_handle(),
            self.child_stdout.as_raw_handle(),
            self.child_stderr.as_raw_handle(),
        ]
    }

    fn into_parent_files(self) -> (File, File, File) {
        let Self {
            child_stdin,
            parent_stdin,
            parent_stdout,
            child_stdout,
            parent_stderr,
            child_stderr,
        } = self;
        drop(child_stdin);
        drop(child_stdout);
        drop(child_stderr);
        (
            owned_handle_into_file(parent_stdin),
            owned_handle_into_file(parent_stdout),
            owned_handle_into_file(parent_stderr),
        )
    }
}

#[allow(
    unsafe_code,
    reason = "transfers one uniquely owned Windows handle into one File owner"
)]
fn owned_handle_into_file(handle: OwnedHandle) -> File {
    // SAFETY: `handle` is uniquely owned and `into_raw_handle` transfers it
    // without closing. `File` adopts the exact handle and closes it once.
    unsafe { File::from_raw_handle(handle.into_raw_handle()) }
}

#[allow(
    unsafe_code,
    reason = "isolates CreatePipe and inheritance-flag configuration over checked owned handles"
)]
fn create_inherited_pipe(
    buffer_bytes: u32,
    child_reads: bool,
) -> io::Result<(OwnedHandle, OwnedHandle)> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| io::Error::other("pipe security structure size is invalid"))?,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    let mut read_handle = ptr::null_mut();
    let mut write_handle = ptr::null_mut();
    // SAFETY: both output locations and the initialized security attributes are
    // valid for the call. A failed call is handled before adopting handles.
    let created = unsafe {
        CreatePipe(
            ptr::from_mut(&mut read_handle),
            ptr::from_mut(&mut write_handle),
            ptr::from_ref(&attributes),
            buffer_bytes,
        )
    };
    if created == 0 {
        return Err(io::Error::last_os_error());
    }
    if read_handle.is_null() || write_handle.is_null() {
        close_pipe_handles(read_handle, write_handle);
        return Err(io::Error::other("CreatePipe returned incomplete handles"));
    }
    // SAFETY: successful CreatePipe transferred two distinct owned handles.
    let read_handle = unsafe { OwnedHandle::from_raw_handle(read_handle) };
    // SAFETY: same transfer as above for the distinct write handle.
    let write_handle = unsafe { OwnedHandle::from_raw_handle(write_handle) };
    let parent_handle = if child_reads {
        &write_handle
    } else {
        &read_handle
    };
    // SAFETY: the selected parent endpoint is live. Clearing its inheritance
    // flag prevents it from being included in child inheritance.
    let updated =
        unsafe { SetHandleInformation(parent_handle.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) };
    if updated == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((read_handle, write_handle))
}

#[allow(
    unsafe_code,
    reason = "adopts only non-null anomalous CreatePipe outputs for at-most-once cleanup"
)]
fn close_pipe_handles(read_handle: HANDLE, write_handle: HANDLE) {
    if !read_handle.is_null() {
        // SAFETY: this failure path owns the non-null CreatePipe output.
        drop(unsafe { OwnedHandle::from_raw_handle(read_handle) });
    }
    if !write_handle.is_null() {
        // SAFETY: this failure path owns the distinct non-null output.
        drop(unsafe { OwnedHandle::from_raw_handle(write_handle) });
    }
}

fn validate_absolute_path(path: &Path, max_components: usize) -> io::Result<usize> {
    if !path.is_absolute() {
        return Err(invalid_input("locked executable path must be absolute"));
    }

    let mut count = 0usize;
    for component in path.components() {
        count = count
            .checked_add(1)
            .ok_or_else(|| invalid_input("locked executable component count overflowed"))?;
        if count > max_components {
            return Err(invalid_input(
                "locked executable path exceeds its component limit",
            ));
        }
        match component {
            Component::Prefix(prefix)
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::UNC(_, _)) => {}
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                return Err(invalid_input(
                    "locked executable path contains an unsupported prefix or traversal",
                ));
            }
            Component::RootDir | Component::Normal(_) => {}
        }
    }
    if count == 0 {
        return Err(invalid_input("locked executable path is empty"));
    }
    Ok(count)
}

fn open_directory_chain(path: &Path) -> io::Result<Vec<FileIdentityLease>> {
    let count = path.components().count();
    let mut paths = Vec::new();
    paths
        .try_reserve_exact(count)
        .map_err(|_| io::Error::other("directory path-chain allocation failed"))?;
    paths.extend(
        path.ancestors()
            .filter(|ancestor| !ancestor.as_os_str().is_empty()),
    );
    paths.reverse();

    let mut leases = Vec::new();
    leases
        .try_reserve_exact(paths.len())
        .map_err(|_| io::Error::other("directory handle-chain allocation failed"))?;
    for ancestor in paths {
        leases.push(FileIdentityLease::from_file(open_direct_directory(
            ancestor,
        )?)?);
    }
    Ok(leases)
}

fn open_direct_directory(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_dir() {
        return Err(invalid_input(
            "locked executable ancestor is not a direct directory",
        ));
    }
    Ok(file)
}

fn open_regular_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).share_mode(FILE_SHARE_READ);
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_file() {
        return Err(invalid_input(
            "locked executable path is not a direct regular file",
        ));
    }
    Ok(file)
}

fn build_command_line(
    executable: &OsStr,
    arguments: &[OsString],
    limits: ProcessLaunchLimits,
) -> io::Result<Vec<u16>> {
    if arguments.len() > limits.arguments {
        return Err(invalid_input("process argument count exceeds its limit"));
    }

    let item_count = arguments
        .len()
        .checked_add(1)
        .ok_or_else(|| invalid_input("process argument count overflowed"))?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(item_count)
        .map_err(|_| io::Error::other("process argument allocation failed"))?;
    encoded.push(encode_units(executable, limits.argument_units)?);
    for argument in arguments {
        encoded.push(encode_units(argument, limits.argument_units)?);
    }

    let mut total_units = 1usize;
    for (index, item) in encoded.iter().enumerate() {
        if index != 0 {
            total_units = total_units
                .checked_add(1)
                .ok_or_else(|| invalid_input("command-line length overflowed"))?;
        }
        total_units = total_units
            .checked_add(quoted_units(item)?)
            .ok_or_else(|| invalid_input("command-line length overflowed"))?;
        if total_units > limits.command_line_units {
            return Err(invalid_input("command line exceeds its UTF-16 limit"));
        }
    }

    let mut command_line = Vec::new();
    command_line
        .try_reserve_exact(total_units)
        .map_err(|_| io::Error::other("command-line allocation failed"))?;
    for (index, item) in encoded.iter().enumerate() {
        if index != 0 {
            command_line.push(u16::from(b' '));
        }
        append_quoted(&mut command_line, item);
    }
    command_line.push(0);
    if command_line.len() != total_units {
        return Err(io::Error::other(
            "command-line sizing and emission disagreed",
        ));
    }
    Ok(command_line)
}

fn encode_nul_terminated(value: &OsStr, max_units: usize) -> io::Result<Vec<u16>> {
    let mut encoded = encode_units(value, max_units)?;
    encoded
        .try_reserve_exact(1)
        .map_err(|_| io::Error::other("NUL-terminated path allocation failed"))?;
    encoded.push(0);
    Ok(encoded)
}

fn encode_units(value: &OsStr, max_units: usize) -> io::Result<Vec<u16>> {
    let unit_count = value.encode_wide().count();
    if unit_count > max_units {
        return Err(invalid_input("UTF-16 argument exceeds its limit"));
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(unit_count)
        .map_err(|_| io::Error::other("UTF-16 argument allocation failed"))?;
    encoded.extend(value.encode_wide());
    if encoded.contains(&0) {
        return Err(invalid_input("Windows process values cannot contain NUL"));
    }
    Ok(encoded)
}

fn quoted_units(units: &[u16]) -> io::Result<usize> {
    if !needs_quotes(units) {
        return Ok(units.len());
    }

    let mut total = 1usize;
    let mut backslashes = 0usize;
    for unit in units {
        match *unit {
            value if value == u16::from(b'\\') => {
                backslashes = backslashes
                    .checked_add(1)
                    .ok_or_else(|| invalid_input("quoted argument length overflowed"))?;
            }
            value if value == u16::from(b'"') => {
                total = total
                    .checked_add(
                        backslashes
                            .checked_mul(2)
                            .and_then(|value| value.checked_add(2))
                            .ok_or_else(|| invalid_input("quoted argument length overflowed"))?,
                    )
                    .ok_or_else(|| invalid_input("quoted argument length overflowed"))?;
                backslashes = 0;
            }
            _ => {
                total = total
                    .checked_add(backslashes)
                    .and_then(|value| value.checked_add(1))
                    .ok_or_else(|| invalid_input("quoted argument length overflowed"))?;
                backslashes = 0;
            }
        }
    }
    total
        .checked_add(
            backslashes
                .checked_mul(2)
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| invalid_input("quoted argument length overflowed"))?,
        )
        .ok_or_else(|| invalid_input("quoted argument length overflowed"))
}

fn needs_quotes(units: &[u16]) -> bool {
    units.is_empty()
        || units.iter().any(|unit| {
            matches!(
                *unit,
                value if value == u16::from(b' ') || value == u16::from(b'\t') || value == u16::from(b'"')
            )
        })
}

fn append_quoted(output: &mut Vec<u16>, units: &[u16]) {
    if !needs_quotes(units) {
        output.extend_from_slice(units);
        return;
    }

    output.push(u16::from(b'"'));
    let mut backslashes = 0usize;
    for unit in units {
        if *unit == u16::from(b'\\') {
            backslashes += 1;
            continue;
        }
        if *unit == u16::from(b'"') {
            output.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2 + 1));
            output.push(*unit);
        } else {
            output.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
            output.push(*unit);
        }
        backslashes = 0;
    }
    output.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2));
    output.push(u16::from(b'"'));
}

struct AttributeList {
    pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
    _buffer: Vec<usize>,
    _job_handle: Box<HANDLE>,
    _inherited_handles: Option<Box<[HANDLE]>>,
}

impl AttributeList {
    fn with_job(job: &OwnedHandle) -> io::Result<Self> {
        create_process_attribute_list(job, &[])
    }

    fn with_job_and_handles(job: &OwnedHandle, handles: &[HANDLE]) -> io::Result<Self> {
        create_process_attribute_list(job, handles)
    }

    const fn pointer(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.pointer
    }
}

impl Drop for AttributeList {
    #[allow(
        unsafe_code,
        reason = "attribute pointer was initialized once and remains backed by the owned aligned buffer"
    )]
    fn drop(&mut self) {
        // SAFETY: `pointer` was successfully initialized and its backing buffer has not moved.
        unsafe { DeleteProcThreadAttributeList(self.pointer) };
    }
}

#[allow(
    unsafe_code,
    reason = "isolated Job List and optional Handle List initialization over retained aligned storage"
)]
fn create_process_attribute_list(
    job: &OwnedHandle,
    inherited_handles: &[HANDLE],
) -> io::Result<AttributeList> {
    let attribute_count = if inherited_handles.is_empty() { 1 } else { 2 };
    let mut required_bytes = 0usize;
    // SAFETY: a null first probe with the exact requested attribute count is the
    // documented size query.
    unsafe {
        InitializeProcThreadAttributeList(
            ptr::null_mut(),
            attribute_count,
            0,
            ptr::from_mut(&mut required_bytes),
        );
    }
    if required_bytes == 0 {
        return Err(io::Error::last_os_error());
    }

    let word_size = size_of::<usize>();
    let words = required_bytes
        .checked_add(word_size - 1)
        .and_then(|value| value.checked_div(word_size))
        .ok_or_else(|| io::Error::other("process attribute-list size overflowed"))?;
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(words)
        .map_err(|_| io::Error::other("process attribute-list allocation failed"))?;
    buffer.resize(words, 0usize);
    let pointer = buffer.as_mut_ptr().cast();

    // SAFETY: the aligned retained buffer has at least the exact byte count returned by the probe.
    let initialized = unsafe {
        InitializeProcThreadAttributeList(
            pointer,
            attribute_count,
            0,
            ptr::from_mut(&mut required_bytes),
        )
    };
    if initialized == 0 {
        return Err(io::Error::last_os_error());
    }

    let job_handle = Box::new(job.as_raw_handle());
    // SAFETY: the initialized list and boxed single-HANDLE array remain live and immovable until
    // after CreateProcessW returns; all reserved parameters are null/zero as documented.
    let updated = unsafe {
        UpdateProcThreadAttribute(
            pointer,
            0,
            usize::try_from(PROC_THREAD_ATTRIBUTE_JOB_LIST)
                .map_err(|_| io::Error::other("Job List attribute identifier is invalid"))?,
            ptr::from_ref(job_handle.as_ref()).cast(),
            size_of::<HANDLE>(),
            ptr::null_mut(),
            ptr::null(),
        )
    };
    if updated == 0 {
        let error = io::Error::last_os_error();
        // SAFETY: initialization succeeded above and must be paired with deletion on this path.
        unsafe { DeleteProcThreadAttributeList(pointer) };
        return Err(error);
    }

    let inherited_handles = if inherited_handles.is_empty() {
        None
    } else {
        let retained = inherited_handles.to_vec().into_boxed_slice();
        let byte_length = retained
            .len()
            .checked_mul(size_of::<HANDLE>())
            .ok_or_else(|| io::Error::other("inherited handle-list size overflowed"))?;
        // SAFETY: the initialized list and retained nonempty HANDLE array remain
        // live and immovable until after CreateProcessW returns.
        let updated = unsafe {
            UpdateProcThreadAttribute(
                pointer,
                0,
                usize::try_from(PROC_THREAD_ATTRIBUTE_HANDLE_LIST)
                    .map_err(|_| io::Error::other("Handle List attribute identifier is invalid"))?,
                retained.as_ptr().cast_mut().cast(),
                byte_length,
                ptr::null_mut(),
                ptr::null(),
            )
        };
        if updated == 0 {
            let error = io::Error::last_os_error();
            // SAFETY: initialization succeeded and must be paired with deletion.
            unsafe { DeleteProcThreadAttributeList(pointer) };
            return Err(error);
        }
        Some(retained)
    };

    Ok(AttributeList {
        pointer,
        _buffer: buffer,
        _job_handle: job_handle,
        _inherited_handles: inherited_handles,
    })
}

#[allow(
    unsafe_code,
    reason = "isolated CreateProcessW call with bounded retained UTF-16 buffers and initialized structures"
)]
fn create_suspended_process(
    application: &[u16],
    command_line: &mut [u16],
    current_directory: &[u16],
    environment: &[u16],
    attributes: &AttributeList,
    stdio: Option<&InheritedStdio>,
) -> io::Result<(OwnedHandle, OwnedHandle, u32)> {
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>())
        .map_err(|_| io::Error::other("extended startup structure size is invalid"))?;
    startup.lpAttributeList = attributes.pointer();
    if let Some(stdio) = stdio {
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = stdio.child_stdin.as_raw_handle();
        startup.StartupInfo.hStdOutput = stdio.child_stdout.as_raw_handle();
        startup.StartupInfo.hStdError = stdio.child_stderr.as_raw_handle();
    }
    let mut information = PROCESS_INFORMATION::default();
    let flags = CREATE_SUSPENDED
        | CREATE_UNICODE_ENVIRONMENT
        | CREATE_NO_WINDOW
        | EXTENDED_STARTUPINFO_PRESENT;

    // SAFETY: all pointers refer to live, correctly terminated/initialized buffers for the complete
    // call. The command line is mutable as required. Security attributes are null, handle
    // inheritance is either disabled or constrained by the explicit Handle List,
    // and PROCESS_INFORMATION is read only after a successful return.
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            i32::from(stdio.is_some()),
            flags,
            environment.as_ptr().cast(),
            current_directory.as_ptr(),
            ptr::from_ref(&startup).cast(),
            ptr::from_mut(&mut information),
        )
    };
    if created == 0 {
        return Err(io::Error::last_os_error());
    }
    if information.hProcess.is_null() || information.hThread.is_null() {
        close_partial_process_information(information);
        return Err(io::Error::other(
            "CreateProcessW returned incomplete process handles",
        ));
    }

    // SAFETY: successful CreateProcessW transfers one owned process handle and one owned thread
    // handle. Each is adopted exactly once.
    let process = unsafe { OwnedHandle::from_raw_handle(information.hProcess) };
    // SAFETY: same ownership transfer as above for the distinct primary-thread handle.
    let thread = unsafe { OwnedHandle::from_raw_handle(information.hThread) };
    Ok((process, thread, information.dwProcessId))
}

#[allow(
    unsafe_code,
    reason = "isolated cleanup of non-null handles returned by an anomalous successful CreateProcessW"
)]
fn close_partial_process_information(information: PROCESS_INFORMATION) {
    if !information.hProcess.is_null() {
        // SAFETY: this branch owns the non-null handle returned by CreateProcessW exactly once.
        drop(unsafe { OwnedHandle::from_raw_handle(information.hProcess) });
    }
    if !information.hThread.is_null() {
        // SAFETY: this branch owns the distinct non-null thread handle exactly once.
        drop(unsafe { OwnedHandle::from_raw_handle(information.hThread) });
    }
}

#[allow(
    unsafe_code,
    reason = "isolated ResumeThread call with a live owned primary-thread handle"
)]
fn resume_primary_thread(thread: &OwnedHandle) -> io::Result<()> {
    // SAFETY: `thread` owns the live primary-thread handle returned in suspended state.
    let previous_count = unsafe { ResumeThread(thread.as_raw_handle()) };
    if previous_count == u32::MAX {
        return Err(io::Error::last_os_error());
    }
    if previous_count != 1 {
        return Err(io::Error::other(
            "new primary thread had an unexpected suspension count",
        ));
    }
    Ok(())
}

fn abort_created_process(job: &KillOnCloseJob, process: &OwnedHandle) {
    let _ = terminate_process(process, 1);
    let _ = job.terminate(1);
}

#[allow(
    unsafe_code,
    reason = "isolated TerminateProcess call with a live owned process handle"
)]
fn terminate_process(process: &OwnedHandle, exit_code: u32) -> io::Result<()> {
    // SAFETY: `process` owns a live process handle for the duration of the call.
    let result = unsafe { TerminateProcess(process.as_raw_handle(), exit_code) };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "isolated bounded wait and exit-code query over a live owned process handle"
)]
fn wait_for_process(process: &OwnedHandle, timeout: Duration) -> io::Result<Option<u32>> {
    let milliseconds = u32::try_from(timeout.as_millis())
        .map_err(|_| invalid_input("process wait timeout exceeds the Windows millisecond range"))?;
    if milliseconds == u32::MAX {
        return Err(invalid_input(
            "process wait timeout cannot use the unbounded Windows sentinel",
        ));
    }

    // SAFETY: `process` owns a live waitable process handle and the timeout is finite.
    let wait = unsafe { WaitForSingleObject(process.as_raw_handle(), milliseconds) };
    match wait {
        WAIT_TIMEOUT => Ok(None),
        WAIT_OBJECT_0 => {
            let mut exit_code = 0u32;
            // SAFETY: the signaled process handle is live and `exit_code` is writable storage.
            let queried = unsafe {
                GetExitCodeProcess(process.as_raw_handle(), ptr::from_mut(&mut exit_code))
            };
            if queried == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Some(exit_code))
        }
        WAIT_FAILED => Err(io::Error::last_os_error()),
        _ => Err(io::Error::other(
            "WaitForSingleObject returned an unexpected result",
        )),
    }
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::{ProcessLaunchLimits, build_command_line};
    use std::ffi::{OsStr, OsString};

    #[test]
    fn command_line_quoting_handles_empty_and_quoted_arguments()
    -> Result<(), Box<dyn std::error::Error>> {
        let limits = ProcessLaunchLimits::new(3, 128, 1024)?;
        let command_line = build_command_line(
            OsStr::new("C:\\Program Files\\helper.exe"),
            &[
                OsString::from(""),
                OsString::from("plain"),
                OsString::from(r#"a"b"#),
            ],
            limits,
        )?;
        let rendered = String::from_utf16(&command_line[..command_line.len() - 1])?;
        assert_eq!(rendered, r#""C:\Program Files\helper.exe" "" plain "a\"b""#);

        let trailing_slash = build_command_line(
            OsStr::new(r"C:\helper.exe"),
            &[OsString::from("trailing slash \\")],
            ProcessLaunchLimits::new(1, 128, 1024)?,
        )?;
        let rendered = String::from_utf16(&trailing_slash[..trailing_slash.len() - 1])?;
        assert_eq!(rendered, r#"C:\helper.exe "trailing slash \\""#);

        let slash_before_quote = build_command_line(
            OsStr::new(r"C:\helper.exe"),
            &[OsString::from(r#"a\"b"#)],
            ProcessLaunchLimits::new(1, 128, 1024)?,
        )?;
        let rendered = String::from_utf16(&slash_before_quote[..slash_before_quote.len() - 1])?;
        assert_eq!(rendered, r#"C:\helper.exe "a\\\"b""#);
        Ok(())
    }
}
