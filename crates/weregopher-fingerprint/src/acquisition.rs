//! Bounded Windows package-tree observation with retained file and directory identities.

use std::{
    fmt,
    path::{Path, PathBuf},
};

use thiserror::Error;

use crate::{
    MAX_PACKAGE_FILE_RECORDS, MAX_PACKAGE_RECORD_PATH_BYTES, ManifestError, ObservationError,
    PackageTreeManifest,
};

#[cfg(windows)]
use crate::PackageFileObservation;

/// Hard ceiling for directory leases retained by one package-tree observation.
pub const MAX_PACKAGE_TREE_DIRECTORIES: usize = MAX_PACKAGE_FILE_RECORDS;
/// Hard ceiling for canonical path components below one package root.
pub const MAX_PACKAGE_TREE_DEPTH: usize = 256;

/// Explicit resource limits for one complete package-tree observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageTreeObservationLimits {
    files: usize,
    directories: usize,
    depth: usize,
    file_bytes: u64,
    total_file_bytes: u64,
    path_bytes: usize,
}

impl PackageTreeObservationLimits {
    /// Creates nonzero limits within the package-manifest hard ceilings.
    ///
    /// `max_directories` includes the package root. `max_depth` counts root-relative
    /// path components, so a file directly beneath the root has depth one.
    ///
    /// # Errors
    ///
    /// Returns [`PackageTreeObservationError::InvalidLimits`] when a limit is zero
    /// or exceeds a fixed manifest/acquisition ceiling.
    pub const fn new(
        max_files: usize,
        max_directories: usize,
        max_depth: usize,
        max_file_bytes: u64,
        max_total_file_bytes: u64,
        max_path_bytes: usize,
    ) -> Result<Self, PackageTreeObservationError> {
        if max_files == 0
            || max_directories == 0
            || max_depth == 0
            || max_file_bytes == 0
            || max_total_file_bytes == 0
            || max_path_bytes == 0
        {
            return Err(PackageTreeObservationError::InvalidLimits {
                reason: "package-tree limits must all be nonzero",
            });
        }
        if max_files > MAX_PACKAGE_FILE_RECORDS {
            return Err(PackageTreeObservationError::InvalidLimits {
                reason: "package-tree file limit exceeds the manifest ceiling",
            });
        }
        if max_directories > MAX_PACKAGE_TREE_DIRECTORIES {
            return Err(PackageTreeObservationError::InvalidLimits {
                reason: "package-tree directory limit exceeds the acquisition ceiling",
            });
        }
        if max_depth > MAX_PACKAGE_TREE_DEPTH {
            return Err(PackageTreeObservationError::InvalidLimits {
                reason: "package-tree depth limit exceeds the acquisition ceiling",
            });
        }
        if max_path_bytes > MAX_PACKAGE_RECORD_PATH_BYTES {
            return Err(PackageTreeObservationError::InvalidLimits {
                reason: "package-tree path-byte limit exceeds the manifest ceiling",
            });
        }
        Ok(Self {
            files: max_files,
            directories: max_directories,
            depth: max_depth,
            file_bytes: max_file_bytes,
            total_file_bytes: max_total_file_bytes,
            path_bytes: max_path_bytes,
        })
    }

    /// Returns the maximum number of regular files.
    #[must_use]
    pub const fn max_files(self) -> usize {
        self.files
    }

    /// Returns the maximum number of directories, including the package root.
    #[must_use]
    pub const fn max_directories(self) -> usize {
        self.directories
    }

    /// Returns the maximum number of root-relative path components.
    #[must_use]
    pub const fn max_depth(self) -> usize {
        self.depth
    }

    /// Returns the maximum logical byte length of one regular file.
    #[must_use]
    pub const fn max_file_bytes(self) -> u64 {
        self.file_bytes
    }

    /// Returns the maximum aggregate logical bytes across regular files.
    #[must_use]
    pub const fn max_total_file_bytes(self) -> u64 {
        self.total_file_bytes
    }

    /// Returns the maximum aggregate UTF-8 bytes across normalized entry paths.
    #[must_use]
    pub const fn max_path_bytes(self) -> usize {
        self.path_bytes
    }
}

/// A bounded reader over one freshly identity-verified package file.
///
/// The underlying operating-system handle is private. Reads stop at the size
/// bound captured in the canonical package manifest even if the filesystem were
/// to report additional bytes.
#[must_use = "consume the reader or retain it until the managed copy is complete"]
pub struct PackageFileReader {
    file: std::fs::File,
    remaining: u64,
}

impl PackageFileReader {
    /// Returns the maximum number of bytes that remain readable.
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.remaining
    }
}

impl std::io::Read for PackageFileReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let request = usize::try_from(self.remaining)
            .map_or(buffer.len(), |remaining| remaining.min(buffer.len()));
        let count = std::io::Read::read(&mut self.file, &mut buffer[..request])?;
        self.remaining = self.remaining.saturating_sub(count as u64);
        Ok(count)
    }
}

impl fmt::Debug for PackageFileReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackageFileReader")
            .field("remaining", &self.remaining)
            .finish_non_exhaustive()
    }
}

/// A bounded package manifest whose direct files and directories remain identity-leased.
#[must_use = "retain the observation until its manifest has been consumed or snapshotted"]
pub struct PackageTreeObservation {
    manifest: PackageTreeManifest,
    total_file_bytes: u64,
    #[cfg(windows)]
    root: PathBuf,
    #[cfg(windows)]
    _root_ancestors: Vec<weregopher_windows::FileIdentityLease>,
    #[cfg(windows)]
    directories: Vec<ObservedTreeDirectory>,
    #[cfg(windows)]
    files: Vec<ObservedTreeFile>,
    limits: PackageTreeObservationLimits,
}

impl PackageTreeObservation {
    /// Returns the canonical manifest while all source identities remain retained.
    #[must_use]
    pub const fn manifest(&self) -> &PackageTreeManifest {
        &self.manifest
    }

    /// Returns the retained regular-file count.
    #[must_use]
    pub fn file_count(&self) -> usize {
        self.manifest.files.len()
    }

    /// Returns the retained directory count, including the package root.
    #[must_use]
    pub fn directory_count(&self) -> usize {
        #[cfg(windows)]
        {
            self.directories.len()
        }
        #[cfg(not(windows))]
        {
            0
        }
    }

    /// Returns the aggregate logical bytes represented by regular files.
    #[must_use]
    pub const fn total_file_bytes(&self) -> u64 {
        self.total_file_bytes
    }

    /// Reports whether this observation was acquired from exactly the supplied lexical root.
    ///
    /// This comparison intentionally does not resolve aliases or reopen the path. The Windows
    /// observation retains the original root identity separately; consumers use this predicate to
    /// bind capabilities that were configured for the same caller-selected package root.
    #[must_use]
    pub fn has_source_root(&self, root: &Path) -> bool {
        #[cfg(windows)]
        {
            self.root == root
        }

        #[cfg(not(windows))]
        {
            let _ = root;
            false
        }
    }

    /// Opens a new bounded reader over one exact retained package file.
    ///
    /// `normalized_path` must exactly match a canonical manifest record. The new
    /// direct non-reparse handle is compared with the retained full-width Windows
    /// identity before it is wrapped, and its file cursor starts at byte zero.
    /// This is a byte-copy capability for managed snapshot construction; it does
    /// not authorize transformation or execution.
    ///
    /// # Errors
    ///
    /// Returns [`PackageTreeObservationError`] when the normalized path is invalid
    /// or absent, the platform is unsupported, or the current direct path cannot
    /// be opened with the retained identity.
    pub fn open_file(
        &self,
        normalized_path: &str,
    ) -> Result<PackageFileReader, PackageTreeObservationError> {
        crate::builder::validate_normalized_path(normalized_path)?;
        #[cfg(windows)]
        {
            let index = self
                .files
                .binary_search_by(|file| {
                    file.observation
                        .record()
                        .normalized_path
                        .as_str()
                        .cmp(normalized_path)
                })
                .map_err(|_| PackageTreeObservationError::UnknownFile {
                    normalized_path: normalized_path.to_owned(),
                })?;
            let file = &self.files[index];
            let remaining = file.observation.record().size;
            let filesystem_path = join_normalized(&self.root, normalized_path);
            let file = file
                .observation
                .open_current_file(&filesystem_path)
                .map_err(|source| PackageTreeObservationError::FileObservation { source })?;
            Ok(PackageFileReader { file, remaining })
        }
        #[cfg(not(windows))]
        {
            Err(PackageTreeObservationError::UnsupportedPlatform)
        }
    }

    /// Revalidates directory membership and every retained path identity.
    ///
    /// This detects mutations visible during the check. It remains a live-tree
    /// observation rather than an immutable filesystem snapshot; callers must copy
    /// only manifest-listed leased files into a managed snapshot before making an
    /// immutability claim.
    ///
    /// # Errors
    ///
    /// Returns [`PackageTreeObservationError`] if the platform is unsupported or
    /// any directory membership, entry shape, limit, or retained identity changed.
    pub fn verify_current_tree(&self) -> Result<(), PackageTreeObservationError> {
        #[cfg(windows)]
        {
            windows::verify(self)
        }
        #[cfg(not(windows))]
        {
            Err(PackageTreeObservationError::UnsupportedPlatform)
        }
    }
}

impl fmt::Debug for PackageTreeObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackageTreeObservation")
            .field("package_tree_merkle", &self.manifest.package_tree_merkle)
            .field("file_count", &self.file_count())
            .field("directory_count", &self.directory_count())
            .field("total_file_bytes", &self.total_file_bytes)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// Observes every supported entry beneath an absolute Windows package root.
///
/// The initial fail-closed profile accepts direct regular files and directories,
/// rejects every reparse point and unsupported entry type, and rejects non-root
/// empty directories because format version 1 cannot bind their existence. Every
/// file and directory identity remains open through final membership validation.
///
/// # Errors
///
/// Returns [`PackageTreeObservationError`] for unsupported platforms, unsafe roots
/// or entries, resource-limit violations, concurrent mutation, file-observation
/// failures, or noncanonical manifest input.
pub fn observe_package_tree(
    root: &Path,
    limits: PackageTreeObservationLimits,
) -> Result<PackageTreeObservation, PackageTreeObservationError> {
    #[cfg(windows)]
    {
        windows::observe(root, limits)
    }
    #[cfg(not(windows))]
    {
        let _ = (root, limits);
        Err(PackageTreeObservationError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
struct ObservedTreeDirectory {
    normalized_path: String,
    identity_lease: weregopher_windows::FileIdentityLease,
}

#[cfg(windows)]
struct ObservedTreeFile {
    observation: PackageFileObservation,
}

#[cfg(windows)]
fn join_normalized(root: &Path, normalized_path: &str) -> PathBuf {
    let mut path = root.to_path_buf();
    for component in normalized_path.split('/') {
        if !component.is_empty() {
            path.push(component);
        }
    }
    path
}

#[cfg(windows)]
mod windows;

/// A complete package tree could not be observed safely within its declared limits.
#[derive(Debug, Error)]
pub enum PackageTreeObservationError {
    /// One or more caller-supplied limits are zero or exceed a hard ceiling.
    #[error("invalid package-tree limits: {reason}")]
    InvalidLimits {
        /// Stable explanation of the rejected limit relationship.
        reason: &'static str,
    },
    /// The host platform has no complete-tree observation implementation.
    #[error("package-tree observation is currently supported only on Windows")]
    UnsupportedPlatform,
    /// The package root is relative or uses an unsupported Windows path prefix.
    #[error("package root is not a supported absolute path: {path}")]
    InvalidRootPath {
        /// Rejected package root.
        path: PathBuf,
    },
    /// A fallible allocation for bounded retained state failed.
    #[error("failed to allocate {resource}")]
    Allocation {
        /// Kind of retained state that could not be allocated.
        resource: &'static str,
    },
    /// A filesystem operation failed.
    #[error("failed to {operation} at {path}: {source}")]
    Io {
        /// Stable description of the failed operation.
        operation: &'static str,
        /// Filesystem path at which the operation failed.
        path: PathBuf,
        /// Underlying operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// A root, ancestor, directory, or file is a reparse point.
    #[error("package-tree path is a reparse point: {path}")]
    ReparsePoint {
        /// Rejected reparse-point path.
        path: PathBuf,
    },
    /// A path required to be a directory was another filesystem type.
    #[error("package-tree path is not a direct directory: {path}")]
    NotDirectory {
        /// Rejected non-directory path.
        path: PathBuf,
    },
    /// A package entry is neither a direct regular file nor a direct directory.
    #[error("package entry has an unsupported filesystem type: {path}")]
    UnsupportedEntry {
        /// Rejected package-entry path.
        path: PathBuf,
    },
    /// An entry name is not Unicode or violates canonical manifest syntax.
    #[error("package entry name cannot be represented canonically: {path}")]
    InvalidEntryName {
        /// Rejected package-entry path.
        path: PathBuf,
    },
    /// An entry name aliases a reserved or lossy Windows spelling.
    #[error("package entry uses a Windows-ambiguous name: {path}")]
    AmbiguousWindowsName {
        /// Rejected package-entry path.
        path: PathBuf,
    },
    /// A root-relative entry is deeper than the configured ceiling.
    #[error("package entry at {path} has depth {actual}; limit is {max}")]
    DepthLimitExceeded {
        /// Entry that exceeded the depth ceiling.
        path: PathBuf,
        /// Observed root-relative depth.
        actual: usize,
        /// Configured maximum depth.
        max: usize,
    },
    /// The package contains more regular files than allowed.
    #[error("package has more than {max} files")]
    FileLimitExceeded {
        /// Configured maximum regular-file count.
        max: usize,
    },
    /// The package contains more directories than allowed.
    #[error("package has more than {max} directories including its root")]
    DirectoryLimitExceeded {
        /// Configured maximum directory count including the root.
        max: usize,
    },
    /// The package exceeded the aggregate bounded-entry ceiling during enumeration.
    #[error("package has more than {max} aggregate entries")]
    EntryLimitExceeded {
        /// Maximum aggregate non-root entries retained during enumeration.
        max: usize,
    },
    /// Normalized entry paths exceed the configured aggregate UTF-8 byte budget.
    #[error("package entry paths use more than {max} aggregate UTF-8 bytes")]
    PathBytesExceeded {
        /// Configured aggregate normalized-path byte ceiling.
        max: usize,
    },
    /// Regular files exceed the configured aggregate logical-byte budget.
    #[error("package files use more than {max} aggregate bytes (observed at least {observed})")]
    TotalFileBytesExceeded {
        /// Lower bound on the aggregate bytes encountered.
        observed: u64,
        /// Configured aggregate logical-byte ceiling.
        max: u64,
    },
    /// A non-root empty directory cannot be represented by manifest format version 1.
    #[error("package contains an unrepresentable empty directory: {path}")]
    EmptyDirectory {
        /// Unrepresentable empty-directory path.
        path: PathBuf,
    },
    /// Two normalized paths alias under conservative Windows case folding.
    #[error("case-insensitive package path collision between {first:?} and {second:?}")]
    CaseInsensitiveCollision {
        /// First normalized spelling encountered.
        first: String,
        /// Conflicting normalized spelling.
        second: String,
    },
    /// A canonical normalized path is absent from the retained manifest.
    #[error("package file is not present in the retained observation: {normalized_path:?}")]
    UnknownFile {
        /// Exact canonical path requested by the caller.
        normalized_path: String,
    },
    /// Directory membership or a retained filesystem identity no longer matches.
    #[error("package tree changed during observation: {path}")]
    ChangedDuringObservation {
        /// Path at or beneath which a change was detected.
        path: PathBuf,
    },
    /// Direct regular-file observation failed.
    #[error("failed to observe one package file: {source}")]
    FileObservation {
        /// Exact bounded file-observation failure.
        #[source]
        source: ObservationError,
    },
    /// Canonical manifest construction rejected the observed records.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
}
