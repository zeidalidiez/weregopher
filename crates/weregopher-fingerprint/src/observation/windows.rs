//! Windows implementation for one leased package-file observation.

use std::{
    fs::File,
    io::{Read as _, Seek as _, SeekFrom},
    os::windows::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::Path,
};

use sha2::{Digest as _, Sha256};
use weregopher_windows::FileIdentityLease;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_FLAG_SEQUENTIAL_SCAN, FILE_SHARE_READ,
};

use super::{ObservationError, ObservationLimits, PackageFileObservation};
use crate::{PackageEntryType, PackageFileKind, PackageFileRecord, classify_package_file};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MetadataSnapshot {
    attributes: u32,
    creation_time: u64,
    last_write_time: u64,
    size: u64,
}

pub(super) fn observe(
    filesystem_path: &Path,
    normalized_path: &str,
    limits: ObservationLimits,
) -> Result<PackageFileObservation, ObservationError> {
    let mut file = open_locked(filesystem_path)?;
    let before = snapshot(&file, filesystem_path)?;
    reject_metadata_oversize(filesystem_path, before.size, limits.max_file_bytes)?;

    let first = hash_bounded(&mut file, filesystem_path, before.size)?;
    let second = hash_bounded(&mut file, filesystem_path, before.size)?;
    let after = snapshot(&file, filesystem_path)?;
    if before != after || first != second || first.0 != before.size {
        return Err(ObservationError::ChangedDuringObservation {
            path: filesystem_path.to_path_buf(),
        });
    }

    let retained_identity = FileIdentityLease::from_file(file)
        .map_err(|source| io_error("read opened-file identity", filesystem_path, source))?;
    verify_current_path(filesystem_path, &retained_identity)?;

    let kind = classify_package_file(normalized_path, PackageEntryType::RegularFile);
    Ok(PackageFileObservation {
        record: PackageFileRecord {
            normalized_path: normalized_path.to_owned(),
            size: first.0,
            sha256: weregopher_domain::Sha256Digest::from_bytes(first.1),
            executable: matches!(
                kind,
                PackageFileKind::NativeModule | PackageFileKind::Executable
            ),
            kind,
            signer_thumbprint: None,
        },
        identity_lease: retained_identity,
    })
}

fn reject_metadata_oversize(
    path: &Path,
    observed: u64,
    limit: u64,
) -> Result<(), ObservationError> {
    if observed > limit {
        Err(ObservationError::FileTooLarge {
            path: path.to_path_buf(),
            limit,
            observed,
        })
    } else {
        Ok(())
    }
}

pub(super) fn verify_current_path(
    path: &Path,
    retained_identity: &FileIdentityLease,
) -> Result<(), ObservationError> {
    open_current_path(path, retained_identity).map(drop)
}

pub(super) fn open_current_path(
    path: &Path,
    retained_identity: &FileIdentityLease,
) -> Result<File, ObservationError> {
    let current_file = open_locked(path)?;
    let _ = snapshot(&current_file, path)?;
    let identity_handle = current_file
        .try_clone()
        .map_err(|source| io_error("duplicate package path identity handle", path, source))?;
    let current_identity = FileIdentityLease::from_file(identity_handle)
        .map_err(|source| io_error("recheck package path identity", path, source))?;
    if retained_identity.has_same_identity(&current_identity) {
        Ok(current_file)
    } else {
        Err(ObservationError::PathIdentityChanged {
            path: path.to_path_buf(),
        })
    }
}

fn open_locked(path: &Path) -> Result<File, ObservationError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).share_mode(FILE_SHARE_READ).custom_flags(
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
    );
    options
        .open(path)
        .map_err(|source| io_error("open package file", path, source))
}

fn snapshot(file: &File, path: &Path) -> Result<MetadataSnapshot, ObservationError> {
    let metadata = file
        .metadata()
        .map_err(|source| io_error("read opened-file metadata", path, source))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(ObservationError::ReparsePoint {
            path: path.to_path_buf(),
        });
    }
    if !metadata.is_file() {
        return Err(ObservationError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    Ok(MetadataSnapshot {
        attributes: metadata.file_attributes(),
        creation_time: metadata.creation_time(),
        last_write_time: metadata.last_write_time(),
        size: metadata.file_size(),
    })
}

fn hash_bounded(
    file: &mut File,
    path: &Path,
    expected_size: u64,
) -> Result<(u64, [u8; 32]), ObservationError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|source| io_error("rewind package file", path, source))?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    while total < expected_size {
        let remaining = expected_size - total;
        let request = usize::try_from(remaining)
            .map_or(buffer.len(), |remaining| remaining.min(buffer.len()));
        let count = file
            .read(&mut buffer[..request])
            .map_err(|source| io_error("read package file", path, source))?;
        if count == 0 {
            break;
        }
        total += count as u64;
        hasher.update(&buffer[..count]);
    }
    Ok((total, hasher.finalize().into()))
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> ObservationError {
    ObservationError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}
