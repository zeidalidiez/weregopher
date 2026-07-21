//! Minimal safe wrappers for Windows file-handle identity operations.
//!
//! This crate is the workspace's explicit unsafe-code exception. Its only two
//! unsafe operations call `GetFileInformationByHandleEx(FileIdInfo)` with a live
//! owned `File` and read the exactly sized output buffer only after Windows
//! reports successful initialization. No raw handle or pointer crosses the
//! public API.

#![cfg(windows)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::{fs::File, io, mem::MaybeUninit, os::windows::io::AsRawHandle as _};

use windows_sys::Win32::Storage::FileSystem::{
    FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FileIdentity {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

/// Owns an open file for at least as long as its captured identity is compared.
#[derive(Debug)]
pub struct FileIdentityLease {
    identity: FileIdentity,
    _file: File,
}

impl FileIdentityLease {
    /// Consumes an open file and captures its full Windows identity.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error when `FileIdInfo` is unavailable or
    /// the handle does not support trustworthy full-width identity.
    pub fn from_file(file: File) -> io::Result<Self> {
        let identity = identity_from_file(&file)?;
        Ok(Self {
            identity,
            _file: file,
        })
    }

    /// Compares two captured identities while both underlying handles are open.
    #[must_use]
    pub fn has_same_identity(&self, other: &Self) -> bool {
        self.identity == other.identity
    }
}

#[allow(
    unsafe_code,
    reason = "isolated Win32 FileIdInfo call with documented pointer and initialization invariants"
)]
fn identity_from_file(file: &File) -> io::Result<FileIdentity> {
    let mut info = MaybeUninit::<FILE_ID_INFO>::zeroed();
    let buffer_size = u32::try_from(std::mem::size_of::<FILE_ID_INFO>()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "FILE_ID_INFO size cannot be represented by the Windows API",
        )
    })?;
    // SAFETY: `file` owns a live Windows file handle. `info` points to writable,
    // correctly aligned storage exactly large enough for `FILE_ID_INFO`; the
    // information class matches that structure. A zero result is handled before
    // `assume_init`, and Windows initializes the complete structure on success.
    let result = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            info.as_mut_ptr().cast(),
            buffer_size,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: the successful call above initialized the complete output value.
    let info = unsafe { info.assume_init() };
    Ok(FileIdentity {
        volume_serial_number: info.VolumeSerialNumber,
        file_id: info.FileId.Identifier,
    })
}
