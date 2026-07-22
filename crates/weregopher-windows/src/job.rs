//! Safe ownership wrapper around a bounded Windows Job Object.

use std::{
    fmt, io,
    mem::size_of,
    os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
    process::Child,
    ptr,
};

use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
};

/// Nonzero process-count and memory caps applied to one Windows Job Object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobLimits {
    active_processes: u32,
    process_memory_bytes: usize,
    job_memory_bytes: usize,
}

impl JobLimits {
    /// Validates the process-count, per-process memory, and aggregate job-memory limits.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] when any limit is zero, the per-process
    /// limit exceeds the aggregate limit, or a memory value cannot fit Windows `SIZE_T`.
    pub fn new(
        active_processes: u32,
        process_memory_bytes: u64,
        job_memory_bytes: u64,
    ) -> io::Result<Self> {
        if active_processes == 0 || process_memory_bytes == 0 || job_memory_bytes == 0 {
            return Err(invalid_limits("Job Object limits must be nonzero"));
        }
        if process_memory_bytes > job_memory_bytes {
            return Err(invalid_limits(
                "per-process memory cannot exceed aggregate job memory",
            ));
        }

        let process_memory_bytes = usize::try_from(process_memory_bytes).map_err(|_| {
            invalid_limits("per-process memory cannot be represented by Windows SIZE_T")
        })?;
        let job_memory_bytes = usize::try_from(job_memory_bytes).map_err(|_| {
            invalid_limits("aggregate job memory cannot be represented by Windows SIZE_T")
        })?;
        Ok(Self {
            active_processes,
            process_memory_bytes,
            job_memory_bytes,
        })
    }

    /// Maximum active processes in the job tree.
    #[must_use]
    pub const fn active_processes(self) -> u32 {
        self.active_processes
    }

    /// Per-process committed-memory ceiling in bytes.
    #[must_use]
    pub const fn process_memory_bytes(self) -> usize {
        self.process_memory_bytes
    }

    /// Aggregate committed-memory ceiling for the job in bytes.
    #[must_use]
    pub const fn job_memory_bytes(self) -> usize {
        self.job_memory_bytes
    }
}

/// Owns a configured Windows Job Object that terminates assigned processes when dropped.
///
/// This is a lifecycle and accounting primitive, not a sandbox. Assigning an already-running
/// [`Child`] does not close the spawn-before-assignment race; a later launch boundary must create
/// the primary process suspended, assign it, and only then resume it.
pub struct KillOnCloseJob {
    handle: OwnedHandle,
    limits: JobLimits,
}

impl KillOnCloseJob {
    /// Creates an unnamed Job Object and applies every supplied limit plus kill-on-close.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error if creation or limit configuration fails.
    pub fn create(limits: JobLimits) -> io::Result<Self> {
        let handle = create_job_handle()?;
        configure_limits(&handle, limits)?;
        Ok(Self { handle, limits })
    }

    /// Returns the limits configured when this job was created.
    #[must_use]
    pub const fn limits(&self) -> JobLimits {
        self.limits
    }

    /// Assigns one already-running child process to this job.
    ///
    /// This method exists for ownership adoption and testing. It does not claim race-free launch.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error when assignment is denied, including when the active
    /// process limit has been reached or the process cannot join this job.
    pub fn assign_child(&self, child: &Child) -> io::Result<()> {
        assign_child(&self.handle, child)
    }

    /// Reports whether the supplied child is currently assigned to this job.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error when membership cannot be queried.
    pub fn contains_child(&self, child: &Child) -> io::Result<bool> {
        contains_child(&self.handle, child)
    }

    /// Terminates every process currently associated with this job.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error when Windows cannot terminate the job.
    pub fn terminate(&self, exit_code: u32) -> io::Result<()> {
        terminate_job(&self.handle, exit_code)
    }
}

impl fmt::Debug for KillOnCloseJob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KillOnCloseJob")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

fn invalid_limits(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[allow(
    unsafe_code,
    reason = "isolated CreateJobObjectW call; the returned owned handle is checked before adoption"
)]
fn create_job_handle() -> io::Result<OwnedHandle> {
    // SAFETY: both optional pointers are null, requesting an unnamed Job Object with default
    // security. Windows returns either a live owned handle or null on failure.
    let raw_handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
    if raw_handle.is_null() {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: successful CreateJobObjectW transfers one owned handle to the caller. `OwnedHandle`
    // closes it exactly once and no other owner is constructed.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw_handle) })
}

#[allow(
    unsafe_code,
    reason = "isolated SetInformationJobObject call over an initialized fixed-size C structure"
)]
fn configure_limits(handle: &OwnedHandle, limits: JobLimits) -> io::Result<()> {
    let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_JOB_MEMORY
        | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    information.BasicLimitInformation.ActiveProcessLimit = limits.active_processes;
    information.ProcessMemoryLimit = limits.process_memory_bytes;
    information.JobMemoryLimit = limits.job_memory_bytes;
    let information_size = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
        .map_err(|_| invalid_limits("Job Object limit structure size exceeds the Windows API"))?;

    // SAFETY: `handle` owns a live Job Object. `information` is fully initialized for the exact
    // information class and remains immutably borrowed for the declared structure size.
    let result = unsafe {
        SetInformationJobObject(
            handle.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            ptr::from_ref(&information).cast(),
            information_size,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "isolated AssignProcessToJobObject call with live owned Job and Child handles"
)]
fn assign_child(handle: &OwnedHandle, child: &Child) -> io::Result<()> {
    // SAFETY: both references keep their owned handles alive for the duration of the call.
    let result = unsafe { AssignProcessToJobObject(handle.as_raw_handle(), child.as_raw_handle()) };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "isolated IsProcessInJob call with live handles and initialized BOOL output storage"
)]
fn contains_child(handle: &OwnedHandle, child: &Child) -> io::Result<bool> {
    let mut result = 0;
    // SAFETY: both handles remain alive and `result` points to writable BOOL-sized storage.
    let query = unsafe {
        IsProcessInJob(
            child.as_raw_handle(),
            handle.as_raw_handle(),
            ptr::from_mut(&mut result),
        )
    };
    if query == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result != 0)
}

#[allow(
    unsafe_code,
    reason = "isolated TerminateJobObject call with a live owned Job Object handle"
)]
fn terminate_job(handle: &OwnedHandle, exit_code: u32) -> io::Result<()> {
    // SAFETY: `handle` owns a live Job Object for the duration of the call.
    let result = unsafe { TerminateJobObject(handle.as_raw_handle(), exit_code) };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
