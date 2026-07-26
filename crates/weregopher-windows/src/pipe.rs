//! Current-user-only local named-pipe transport.

use std::{
    ffi::OsStr,
    fmt,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    mem::size_of,
    os::windows::{
        ffi::OsStrExt as _,
        io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
    },
    process::Child,
    ptr,
    str::FromStr,
    thread,
    time::{Duration, Instant},
};

use uuid::Uuid;
use windows_sys::Win32::{
    Foundation::{
        ERROR_INSUFFICIENT_BUFFER, ERROR_NO_DATA, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING,
        GENERIC_ALL, HANDLE, INVALID_HANDLE_VALUE,
    },
    Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAceEx, EqualSid, GetLengthSid,
        GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor, IsValidSid,
        SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SetSecurityDescriptorControl,
        SetSecurityDescriptorDacl, TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX},
    System::{
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, PIPE_NOWAIT,
            PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
            SetNamedPipeHandleState, WaitNamedPipeW,
        },
        SystemServices::SECURITY_DESCRIPTOR_REVISION,
        Threading::{
            GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

use crate::KillOnCloseJob;

const PIPE_PREFIX: &str = r"\\.\pipe\weregopher-runtime-";
const MAX_PIPE_BUFFER_BYTES: u32 = 4 * 1024 * 1024;
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(2);

/// A canonical local Weregopher pipe name with a random version-4 UUID suffix.
///
/// The address is a rendezvous coordinate, not an authentication secret. The
/// server independently authenticates the connected process, user, Job Object,
/// and protocol nonce.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct NamedPipeAddress(String);

impl NamedPipeAddress {
    /// Generates a new local address using operating-system randomness through [`Uuid::new_v4`].
    #[must_use]
    pub fn generate() -> Self {
        Self(format!("{PIPE_PREFIX}{}", Uuid::new_v4().hyphenated()))
    }

    /// Returns the canonical `\\.\pipe\...` address.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn wide_nul(&self) -> io::Result<Vec<u16>> {
        let units = OsStr::new(self.as_str()).encode_wide();
        let required = units
            .clone()
            .count()
            .checked_add(1)
            .ok_or_else(|| io::Error::other("named-pipe address length overflowed"))?;
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(required)
            .map_err(|_| io::Error::other("named-pipe address allocation failed"))?;
        encoded.extend(units);
        encoded.push(0);
        Ok(encoded)
    }
}

impl fmt::Debug for NamedPipeAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("NamedPipeAddress")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for NamedPipeAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for NamedPipeAddress {
    type Err = io::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let suffix = value.strip_prefix(PIPE_PREFIX).ok_or_else(|| {
            invalid_input("named-pipe address must use the local Weregopher prefix")
        })?;
        let identifier = Uuid::parse_str(suffix)
            .map_err(|_| invalid_input("named-pipe address suffix must be a UUID"))?;
        if identifier.get_version_num() != 4 || identifier.hyphenated().to_string() != suffix {
            return Err(invalid_input(
                "named-pipe address must use one canonical lowercase version-4 UUID",
            ));
        }
        Ok(Self(value.to_owned()))
    }
}

/// One unconnected, single-instance pipe protected by an explicit current-user DACL.
pub struct CurrentUserNamedPipeServer {
    address: NamedPipeAddress,
    pipe: File,
}

impl CurrentUserNamedPipeServer {
    /// Creates a local-only byte pipe with one instance and bounded kernel buffers.
    ///
    /// The DACL contains exactly one full-control ACE for the current process
    /// token's user SID. Remote clients are rejected by the pipe mode as an
    /// independent control.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error for zero or excessive buffer sizes and
    /// otherwise preserves token, security-descriptor, or pipe-creation errors.
    pub fn bind(buffer_bytes: u32) -> io::Result<Self> {
        if buffer_bytes == 0 || buffer_bytes > MAX_PIPE_BUFFER_BYTES {
            return Err(invalid_input(
                "named-pipe buffer must be between 1 byte and 4 MiB",
            ));
        }
        let address = NamedPipeAddress::generate();
        let wide_address = address.wide_nul()?;
        let mut security = CurrentUserSecurity::new()?;
        let attributes = security.attributes()?;
        let pipe = create_named_pipe(&wide_address, buffer_bytes, &attributes)?;
        Ok(Self { address, pipe })
    }

    /// Generated non-secret rendezvous address.
    #[must_use]
    pub const fn address(&self) -> &NamedPipeAddress {
        &self.address
    }

    /// Waits for and authenticates the exact launched child before exposing transport I/O.
    ///
    /// Authentication checks the kernel-reported client PID, equality of process
    /// token user SIDs, and membership of `expected_child` in `job`. Protocol
    /// nonce verification remains a higher-layer check performed before accepting
    /// a runtime hello.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::TimedOut`] when no client connects in time,
    /// [`io::ErrorKind::PermissionDenied`] for any peer identity/membership
    /// mismatch, or the underlying Windows error.
    pub fn accept(
        self,
        expected_child: &Child,
        job: &KillOnCloseJob,
        timeout: Duration,
    ) -> io::Result<VerifiedNamedPipe> {
        connect_with_timeout(&self.pipe, timeout)?;
        set_blocking(&self.pipe)?;
        let peer_process_id = named_pipe_client_process_id(&self.pipe)?;
        if peer_process_id == 0 || peer_process_id != expected_child.id() {
            return Err(permission_denied(
                "named-pipe client PID does not match the launched worker",
            ));
        }
        if !process_user_matches_current(peer_process_id)? {
            return Err(permission_denied(
                "named-pipe client does not run as the current user",
            ));
        }
        if !job.contains_child(expected_child)? || !job.contains_process_id(peer_process_id)? {
            return Err(permission_denied(
                "named-pipe client is not in the required Job Object",
            ));
        }
        Ok(VerifiedNamedPipe {
            pipe: self.pipe,
            peer_process_id,
        })
    }
}

impl fmt::Debug for CurrentUserNamedPipeServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CurrentUserNamedPipeServer")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

/// A connected server stream whose OS peer identity and Job membership were verified.
pub struct VerifiedNamedPipe {
    pipe: File,
    peer_process_id: u32,
}

impl VerifiedNamedPipe {
    /// Kernel-reported and expected launched worker PID.
    #[must_use]
    pub const fn peer_process_id(&self) -> u32 {
        self.peer_process_id
    }

    /// Duplicates this process's handle to the same verified duplex pipe instance.
    ///
    /// This supports one reader state machine and one writer state machine without
    /// exposing a raw handle or weakening the peer verification result.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error when handle duplication fails.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            pipe: self.pipe.try_clone()?,
            peer_process_id: self.peer_process_id,
        })
    }
}

impl fmt::Debug for VerifiedNamedPipe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedNamedPipe")
            .field("peer_process_id", &self.peer_process_id)
            .finish_non_exhaustive()
    }
}

impl Read for VerifiedNamedPipe {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.pipe.read(buffer)
    }
}

impl Write for VerifiedNamedPipe {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.pipe.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.pipe.flush()
    }
}

/// A client-side local named-pipe byte stream.
pub struct NamedPipeClient {
    pipe: File,
}

impl NamedPipeClient {
    /// Duplicates this process's handle to the same duplex pipe instance.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error when handle duplication fails.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            pipe: self.pipe.try_clone()?,
        })
    }
}

impl fmt::Debug for NamedPipeClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NamedPipeClient")
            .finish_non_exhaustive()
    }
}

impl Read for NamedPipeClient {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.pipe.read(buffer)
    }
}

impl Write for NamedPipeClient {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.pipe.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.pipe.flush()
    }
}

/// Connects to one existing local Weregopher pipe within a finite timeout.
///
/// # Errors
///
/// Returns an invalid-input error for zero or unrepresentable timeouts and
/// otherwise preserves `WaitNamedPipeW` or file-open errors.
pub fn connect_named_pipe(
    address: &NamedPipeAddress,
    timeout: Duration,
) -> io::Result<NamedPipeClient> {
    let timeout_millis = finite_timeout_millis(timeout)?;
    let wide_address = address.wide_nul()?;
    wait_named_pipe(&wide_address, timeout_millis)?;
    let pipe = OpenOptions::new()
        .read(true)
        .write(true)
        .open(address.as_str())?;
    Ok(NamedPipeClient { pipe })
}

fn finite_timeout_millis(timeout: Duration) -> io::Result<u32> {
    if timeout.is_zero() {
        return Err(invalid_input("named-pipe timeout must be nonzero"));
    }
    let rounded = timeout
        .as_millis()
        .checked_add(u128::from(
            !timeout.subsec_nanos().is_multiple_of(1_000_000),
        ))
        .ok_or_else(|| invalid_input("named-pipe timeout overflowed"))?;
    let milliseconds = u32::try_from(rounded)
        .map_err(|_| invalid_input("named-pipe timeout exceeds the Windows limit"))?;
    if milliseconds == u32::MAX {
        return Err(invalid_input(
            "named-pipe timeout cannot use the unbounded Windows sentinel",
        ));
    }
    Ok(milliseconds.max(1))
}

#[allow(
    unsafe_code,
    reason = "isolated CreateNamedPipeW call over terminated address and live security buffers"
)]
fn create_named_pipe(
    address: &[u16],
    buffer_bytes: u32,
    security: &SECURITY_ATTRIBUTES,
) -> io::Result<File> {
    let open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE;
    let pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS;
    // SAFETY: `address` is NUL-terminated and both it and `security` (including
    // the pointed-to descriptor/DACL) remain live for this call. A successful
    // return transfers one owned handle.
    let handle = unsafe {
        CreateNamedPipeW(
            address.as_ptr(),
            open_mode,
            pipe_mode,
            1,
            buffer_bytes,
            buffer_bytes,
            0,
            ptr::from_ref(security),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful call transferred one unique handle, adopted once.
    Ok(unsafe { File::from_raw_handle(handle) })
}

#[allow(
    unsafe_code,
    reason = "isolated nonblocking ConnectNamedPipe polling over one live server handle"
)]
fn connect_with_timeout(pipe: &File, timeout: Duration) -> io::Result<()> {
    finite_timeout_millis(timeout)?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| invalid_input("named-pipe accept deadline overflowed"))?;
    loop {
        // SAFETY: `pipe` owns a live non-overlapped named-pipe server handle;
        // null OVERLAPPED requests the configured nonblocking operation.
        if unsafe { ConnectNamedPipe(pipe.as_raw_handle(), ptr::null_mut()) } != 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error().map(i32::cast_unsigned) {
            Some(ERROR_PIPE_CONNECTED) => return Ok(()),
            Some(ERROR_PIPE_LISTENING | ERROR_NO_DATA) => {}
            _ => return Err(error),
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out waiting for named-pipe client",
            ));
        }
        thread::sleep(ACCEPT_POLL_INTERVAL.min(deadline.saturating_duration_since(now)));
    }
}

#[allow(
    unsafe_code,
    reason = "isolated SetNamedPipeHandleState call over a connected live server handle"
)]
fn set_blocking(pipe: &File) -> io::Result<()> {
    let blocking_byte_mode = PIPE_READMODE_BYTE | PIPE_WAIT;
    // SAFETY: the mode pointer is valid for the call and optional tuning
    // pointers are null. The handle remains owned by `pipe`.
    let result = unsafe {
        SetNamedPipeHandleState(
            pipe.as_raw_handle(),
            ptr::from_ref(&blocking_byte_mode),
            ptr::null(),
            ptr::null(),
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "isolated GetNamedPipeClientProcessId call with initialized PID output storage"
)]
fn named_pipe_client_process_id(pipe: &File) -> io::Result<u32> {
    let mut process_id = 0_u32;
    // SAFETY: `pipe` is connected and owns its handle; `process_id` is writable.
    let result = unsafe {
        GetNamedPipeClientProcessId(pipe.as_raw_handle(), ptr::from_mut(&mut process_id))
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(process_id)
}

#[allow(
    unsafe_code,
    reason = "isolated WaitNamedPipeW call over a terminated address and finite timeout"
)]
fn wait_named_pipe(address: &[u16], timeout_millis: u32) -> io::Result<()> {
    // SAFETY: `address` is NUL-terminated and retained for the call; the timeout
    // was checked not to be the unbounded sentinel.
    if unsafe { WaitNamedPipeW(address.as_ptr(), timeout_millis) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

struct TokenUserBuffer {
    words: Vec<usize>,
}

impl TokenUserBuffer {
    fn for_process(process: HANDLE) -> io::Result<Self> {
        let token = open_process_token(process)?;
        query_token_user(&token)
    }

    #[allow(
        unsafe_code,
        reason = "aligned token buffer was fully initialized for TOKEN_USER and remains immovable"
    )]
    fn sid(&self) -> io::Result<windows_sys::Win32::Security::PSID> {
        if self.words.len().saturating_mul(size_of::<usize>()) < size_of::<TOKEN_USER>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "token user buffer is shorter than TOKEN_USER",
            ));
        }
        // SAFETY: `words` provides `usize` alignment and was populated by
        // GetTokenInformation(TokenUser) for at least TOKEN_USER bytes.
        let token_user = unsafe { &*self.words.as_ptr().cast::<TOKEN_USER>() };
        if token_user.User.Sid.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "token user contains a null SID",
            ));
        }
        // SAFETY: Windows returned this SID pointer inside the retained token
        // information buffer. Validation does not retain it.
        if unsafe { IsValidSid(token_user.User.Sid) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "token user contains an invalid SID",
            ));
        }
        Ok(token_user.User.Sid)
    }
}

#[allow(
    unsafe_code,
    reason = "isolated OpenProcessToken call with writable owned-handle output"
)]
fn open_process_token(process: HANDLE) -> io::Result<OwnedHandle> {
    let mut token = ptr::null_mut();
    // SAFETY: `process` is either the live current-process pseudo-handle or an
    // owned queried process handle. `token` is writable output storage.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, ptr::from_mut(&mut token)) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if token.is_null() {
        return Err(io::Error::other("OpenProcessToken returned a null handle"));
    }
    // SAFETY: the successful call transferred one owned token handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(token) })
}

#[allow(
    unsafe_code,
    reason = "isolated two-pass GetTokenInformation query into aligned bounded storage"
)]
fn query_token_user(token: &OwnedHandle) -> io::Result<TokenUserBuffer> {
    let mut required = 0_u32;
    // SAFETY: the null first query is the documented size probe and `required`
    // is writable. The token remains live.
    let first = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            ptr::from_mut(&mut required),
        )
    };
    if first != 0 || required == 0 {
        return Err(io::Error::other(
            "TokenUser size probe returned an invalid result",
        ));
    }
    let probe_error = io::Error::last_os_error();
    if probe_error.raw_os_error().map(i32::cast_unsigned) != Some(ERROR_INSUFFICIENT_BUFFER) {
        return Err(probe_error);
    }
    let required_usize = usize::try_from(required)
        .map_err(|_| io::Error::other("TokenUser size cannot be represented"))?;
    let word_size = size_of::<usize>();
    let word_count = required_usize
        .checked_add(word_size - 1)
        .and_then(|value| value.checked_div(word_size))
        .ok_or_else(|| io::Error::other("TokenUser allocation size overflowed"))?;
    let mut words = Vec::new();
    words
        .try_reserve_exact(word_count)
        .map_err(|_| io::Error::other("TokenUser allocation failed"))?;
    words.resize(word_count, 0_usize);
    let mut actual = required;
    // SAFETY: `words` is aligned writable storage of at least `required`
    // bytes, the class matches TOKEN_USER, and the token remains live.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            words.as_mut_ptr().cast(),
            required,
            ptr::from_mut(&mut actual),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if actual > required || usize::try_from(actual).unwrap_or(usize::MAX) < size_of::<TOKEN_USER>()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TokenUser returned an inconsistent byte count",
        ));
    }
    Ok(TokenUserBuffer { words })
}

#[allow(
    unsafe_code,
    reason = "isolated process/token opens and EqualSid call while both token buffers remain live"
)]
fn process_user_matches_current(process_id: u32) -> io::Result<bool> {
    // SAFETY: the requested access is query-only, inheritance is disabled, and
    // a null result is handled before ownership adoption.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful OpenProcess transferred one owned handle.
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    // SAFETY: GetCurrentProcess returns a live non-owning pseudo-handle for this process.
    let current = TokenUserBuffer::for_process(unsafe { GetCurrentProcess() })?;
    let peer = TokenUserBuffer::for_process(process.as_raw_handle())?;
    let current_sid = current.sid()?;
    let peer_sid = peer.sid()?;
    // SAFETY: both validated SID pointers remain backed by live token buffers.
    Ok(unsafe { EqualSid(current_sid, peer_sid) } != 0)
}

struct CurrentUserSecurity {
    descriptor: SECURITY_DESCRIPTOR,
    _acl: Vec<u32>,
}

impl CurrentUserSecurity {
    #[allow(
        unsafe_code,
        reason = "isolated ACL/security-descriptor initialization from a validated current-user SID"
    )]
    fn new() -> io::Result<Self> {
        // SAFETY: GetCurrentProcess returns a live non-owning pseudo-handle.
        let token_user = TokenUserBuffer::for_process(unsafe { GetCurrentProcess() })?;
        let sid = token_user.sid()?;
        // SAFETY: `sid` was validated and remains backed by `token_user`.
        let sid_bytes = unsafe { GetLengthSid(sid) };
        if sid_bytes == 0 {
            return Err(io::Error::last_os_error());
        }
        let acl_bytes = size_of::<ACL>()
            .checked_add(size_of::<ACCESS_ALLOWED_ACE>())
            .and_then(|value| value.checked_sub(size_of::<u32>()))
            .and_then(|value| value.checked_add(usize::try_from(sid_bytes).ok()?))
            .ok_or_else(|| io::Error::other("current-user ACL size overflowed"))?;
        let word_count = acl_bytes
            .checked_add(size_of::<u32>() - 1)
            .and_then(|value| value.checked_div(size_of::<u32>()))
            .ok_or_else(|| io::Error::other("current-user ACL allocation size overflowed"))?;
        let mut acl = Vec::new();
        acl.try_reserve_exact(word_count)
            .map_err(|_| io::Error::other("current-user ACL allocation failed"))?;
        acl.resize(word_count, 0_u32);
        let acl_pointer = acl.as_mut_ptr().cast::<ACL>();
        let acl_length = u32::try_from(acl_bytes)
            .map_err(|_| io::Error::other("current-user ACL exceeds Windows limits"))?;
        // SAFETY: `acl` is aligned writable storage of `acl_length` bytes.
        if unsafe { InitializeAcl(acl_pointer, acl_length, ACL_REVISION) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the initialized ACL has exact room for this validated SID;
        // AddAccessAllowedAceEx copies the SID into the retained ACL.
        if unsafe { AddAccessAllowedAceEx(acl_pointer, ACL_REVISION, 0, GENERIC_ALL, sid) } == 0 {
            return Err(io::Error::last_os_error());
        }

        let mut descriptor = SECURITY_DESCRIPTOR::default();
        // SAFETY: `descriptor` is writable storage for the documented revision.
        if unsafe {
            InitializeSecurityDescriptor(
                ptr::from_mut(&mut descriptor).cast(),
                SECURITY_DESCRIPTOR_REVISION,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the initialized descriptor and ACL remain live together in
        // the returned owner; the DACL is present and not defaulted.
        if unsafe {
            SetSecurityDescriptorDacl(ptr::from_mut(&mut descriptor).cast(), 1, acl_pointer, 0)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: this marks the explicitly supplied DACL protected from inherited expansion.
        if unsafe {
            SetSecurityDescriptorControl(
                ptr::from_mut(&mut descriptor).cast(),
                SE_DACL_PROTECTED,
                SE_DACL_PROTECTED,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            descriptor,
            _acl: acl,
        })
    }

    fn attributes(&mut self) -> io::Result<SECURITY_ATTRIBUTES> {
        Ok(SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
                .map_err(|_| io::Error::other("SECURITY_ATTRIBUTES size is invalid"))?,
            lpSecurityDescriptor: ptr::from_mut(&mut self.descriptor).cast(),
            bInheritHandle: 0,
        })
    }
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn permission_denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
