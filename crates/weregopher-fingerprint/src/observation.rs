//! Bounded, handle-retaining observation of one Windows package file.

use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::{ManifestError, PackageFileRecord, builder::validate_normalized_path};

#[cfg(windows)]
use std::fs::File;

/// Resource limits for one package-file observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationLimits {
    max_file_bytes: u64,
}

impl ObservationLimits {
    /// Creates nonzero observation limits.
    ///
    /// # Errors
    ///
    /// Returns [`ObservationError::InvalidLimits`] when `max_file_bytes` is zero.
    pub const fn new(max_file_bytes: u64) -> Result<Self, ObservationError> {
        if max_file_bytes == 0 {
            Err(ObservationError::InvalidLimits)
        } else {
            Ok(Self { max_file_bytes })
        }
    }

    /// Returns the maximum accepted logical file size and per-pass read bound.
    ///
    /// Observation hashes the file twice, so aggregate successful-read I/O can
    /// be twice this value.
    #[must_use]
    pub const fn max_file_bytes(self) -> u64 {
        self.max_file_bytes
    }

    #[cfg(windows)]
    pub(crate) const fn for_tree_budget(max_file_bytes: u64) -> Self {
        Self { max_file_bytes }
    }
}

/// A canonical file record with an open identity lease retained for its lifetime.
#[must_use = "keep the observation alive until final path validation and manifest construction"]
#[derive(Debug)]
pub struct PackageFileObservation {
    record: PackageFileRecord,
    #[cfg(windows)]
    identity_lease: weregopher_windows::FileIdentityLease,
}

impl PackageFileObservation {
    /// Returns the canonical evidence gathered while the identity lease is held.
    #[must_use]
    pub const fn record(&self) -> &PackageFileRecord {
        &self.record
    }

    /// Verifies that a filesystem path still names this retained file identity.
    ///
    /// A package scanner must call this while all observations remain alive
    /// after enumeration and before emitting a manifest. This check does not
    /// itself establish containment beneath a package root.
    ///
    /// # Errors
    ///
    /// Returns [`ObservationError`] if the platform is unsupported, the path
    /// cannot be reopened safely, or it names a different file identity.
    pub fn verify_current_path(&self, filesystem_path: &Path) -> Result<(), ObservationError> {
        #[cfg(windows)]
        {
            windows::verify_current_path(filesystem_path, &self.identity_lease)
        }

        #[cfg(not(windows))]
        {
            let _ = filesystem_path;
            Err(ObservationError::UnsupportedPlatform)
        }
    }

    #[cfg(windows)]
    pub(crate) fn open_current_file(
        &self,
        filesystem_path: &Path,
    ) -> Result<File, ObservationError> {
        windows::open_current_path(filesystem_path, &self.identity_lease)
    }
}

/// Observes one regular package file and retains its opened identity handle.
///
/// This primitive validates a caller-supplied normalized identity path but does
/// not establish that `filesystem_path` is contained beneath a package root.
/// On Windows, the open denies write/delete sharing while two matching,
/// individually bounded content observations and a final path-identity check
/// are completed.
///
/// # Errors
///
/// Returns [`ObservationError`] when the platform is unsupported, the identity
/// path is invalid, the file is not a direct regular file, limits are exceeded,
/// I/O fails, repeated reads differ, or the final path names another object.
pub fn observe_package_file(
    filesystem_path: &Path,
    normalized_path: &str,
    limits: ObservationLimits,
) -> Result<PackageFileObservation, ObservationError> {
    validate_normalized_path(normalized_path)?;

    #[cfg(windows)]
    {
        windows::observe(filesystem_path, normalized_path, limits)
    }

    #[cfg(not(windows))]
    {
        let _ = (filesystem_path, limits);
        Err(ObservationError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod windows;

/// One package file could not be observed safely within its declared limits.
#[derive(Debug, Error)]
pub enum ObservationError {
    /// Zero-byte limits would make every useful observation invalid.
    #[error("maximum file bytes must be greater than zero")]
    InvalidLimits,
    /// The caller supplied a noncanonical record identity path.
    #[error(transparent)]
    InvalidRecord(#[from] ManifestError),
    /// Direct file observation is not implemented on this operating system.
    #[error("package-file observation is currently supported only on Windows")]
    UnsupportedPlatform,
    /// An operating-system operation failed.
    #[error("failed to {operation} at {path}: {source}")]
    Io {
        /// Failed operation.
        operation: &'static str,
        /// Affected path.
        path: PathBuf,
        /// Operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// The opened object was a reparse point rather than direct file content.
    #[error("package file is a reparse point: {path}")]
    ReparsePoint {
        /// Rejected path.
        path: PathBuf,
    },
    /// The opened object was not a regular file.
    #[error("package entry is not a regular file: {path}")]
    NotRegularFile {
        /// Rejected path.
        path: PathBuf,
    },
    /// File bytes exceeded the configured per-file limit.
    #[error("package file at {path} exceeded {limit} bytes (observed {observed})")]
    FileTooLarge {
        /// Oversized path.
        path: PathBuf,
        /// Configured byte limit.
        limit: u64,
        /// Observed byte count or metadata size.
        observed: u64,
    },
    /// Repeated content or metadata observations did not agree.
    #[error("package file changed during observation: {path}")]
    ChangedDuringObservation {
        /// Unstable path.
        path: PathBuf,
    },
    /// The path no longer named the retained opened object.
    #[error("package path identity changed during observation: {path}")]
    PathIdentityChanged {
        /// Rebound path.
        path: PathBuf,
    },
}
