//! Content-addressed package snapshots composed outside vendor installations.
//!
//! A lease can perform point-in-time revalidation of exact bytes, identities, and complete manifest
//! membership. It does not turn ordinary Windows directories into an OS sandbox or prevent an
//! unrestricted same-user process from adding a child after enumeration but before validation returns.

use std::{
    fmt,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

#[cfg(windows)]
use std::collections::BTreeSet;

use thiserror::Error;
#[cfg(windows)]
use weregopher_domain::ExecutionPackagePath;
use weregopher_domain::Sha256Digest;
use weregopher_fingerprint::{
    PackageTreeManifest, PackageTreeObservation, PackageTreeObservationError,
};

#[cfg(windows)]
use weregopher_fingerprint::{MAX_PACKAGE_RECORD_PATH_BYTES, PackageFileKind};
#[cfg(windows)]
use weregopher_windows::LockedExecutable;

use crate::{ManagedArtifactStore, MaterializationStoreError};

/// Independent bounds for publishing one observed package into a deterministic managed view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageSnapshotWriteLimits {
    files: usize,
    directories: usize,
    file_bytes: u64,
    total_bytes: u64,
    temp_attempts: usize,
}

impl PackageSnapshotWriteLimits {
    /// Constructs nonzero file, directory, per-file, aggregate-byte, and temporary-name limits.
    ///
    /// # Errors
    ///
    /// Returns [`PackageSnapshotError::InvalidLimits`] when any limit is zero.
    pub const fn new(
        max_files: usize,
        max_directories: usize,
        max_file_bytes: u64,
        max_total_bytes: u64,
        max_temp_attempts: usize,
    ) -> Result<Self, PackageSnapshotError> {
        if max_files == 0
            || max_directories == 0
            || max_file_bytes == 0
            || max_total_bytes == 0
            || max_temp_attempts == 0
        {
            Err(PackageSnapshotError::InvalidLimits)
        } else {
            Ok(Self {
                files: max_files,
                directories: max_directories,
                file_bytes: max_file_bytes,
                total_bytes: max_total_bytes,
                temp_attempts: max_temp_attempts,
            })
        }
    }
}

/// Independent bounds for reopening one already published package view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageSnapshotLeaseLimits {
    files: usize,
    directories: usize,
    file_bytes: u64,
    total_bytes: u64,
}

impl PackageSnapshotLeaseLimits {
    /// Constructs nonzero file, directory, per-file, and aggregate-byte limits.
    ///
    /// # Errors
    ///
    /// Returns [`PackageSnapshotError::InvalidLimits`] when any limit is zero.
    pub const fn new(
        max_files: usize,
        max_directories: usize,
        max_file_bytes: u64,
        max_total_bytes: u64,
    ) -> Result<Self, PackageSnapshotError> {
        if max_files == 0 || max_directories == 0 || max_file_bytes == 0 || max_total_bytes == 0 {
            Err(PackageSnapshotError::InvalidLimits)
        } else {
            Ok(Self {
                files: max_files,
                directories: max_directories,
                file_bytes: max_file_bytes,
                total_bytes: max_total_bytes,
            })
        }
    }
}

/// A manifest-scoped package snapshot with retained identities for its declared files and directories.
///
/// The logical allowlist is stable. The physical Windows namespace is not: ordinary directory handles
/// cannot prevent a same-user process from adding children beneath the view.
#[must_use = "keep the snapshot lease alive while manifest-scoped files are in use"]
pub struct PackageSnapshotLease<'store> {
    store: &'store ManagedArtifactStore,
    root: PathBuf,
    package_tree_merkle: Sha256Digest,
    file_count: usize,
    directory_count: usize,
    total_file_bytes: u64,
    created_blobs: usize,
    reused_blobs: usize,
    created_links: usize,
    reused_links: usize,
    #[cfg(windows)]
    platform: windows::WindowsPackageSnapshotLease,
}

/// Bounded reader over one manifest-listed, freshly reverified snapshot file.
///
/// The operating-system handle and physical path remain private. Unlisted filesystem children are
/// therefore outside this logical package-view capability even if a same-user process injects them
/// beneath the physical view.
#[must_use = "consume the reader or retain it until the manifest-listed bytes are no longer needed"]
pub struct PackageSnapshotFileReader {
    file: File,
    remaining: u64,
}

/// One exact manifest-listed executable retained together with its complete package lease.
///
/// This capability binds a direct locked executable path to the file identity and digest already
/// retained by the snapshot. It does not authenticate an adapter or authorize execution or launch.
#[cfg(windows)]
#[must_use = "retain the executable capability until a higher-level authorizer consumes it"]
pub struct PackageSnapshotExecutable<'lease, 'store> {
    lease: &'lease PackageSnapshotLease<'store>,
    normalized_path: String,
    digest: Sha256Digest,
    locked: LockedExecutable,
}

#[cfg(windows)]
impl PackageSnapshotExecutable<'_, '_> {
    /// Returns the manifest-relative executable path selected through the logical allowlist.
    #[must_use]
    pub fn normalized_path(&self) -> &str {
        &self.normalized_path
    }

    /// Returns the exact executable-byte digest retained by the package manifest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Returns the exact package-tree manifest identity retained by the complete lease.
    #[must_use]
    pub const fn package_tree_merkle(&self) -> Sha256Digest {
        self.lease.package_tree_merkle
    }

    /// Revalidates the complete current manifest view while this executable remains locked.
    ///
    /// # Errors
    ///
    /// Returns [`PackageSnapshotError`] when the retained managed root, a declared file identity,
    /// exact file bytes, directory identity, or visible membership no longer matches.
    pub fn verify_current_view(&self) -> Result<(), PackageSnapshotError> {
        self.lease.verify_current_view()
    }
}

#[cfg(windows)]
impl<'lease, 'store> PackageSnapshotExecutable<'lease, 'store> {
    pub(crate) const fn locked(&self) -> &LockedExecutable {
        &self.locked
    }

    pub(crate) fn into_launch_parts(
        self,
    ) -> (&'lease PackageSnapshotLease<'store>, LockedExecutable) {
        (self.lease, self.locked)
    }
}

#[cfg(windows)]
impl fmt::Debug for PackageSnapshotExecutable<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackageSnapshotExecutable")
            .field("normalized_path", &self.normalized_path)
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

impl PackageSnapshotFileReader {
    /// Returns the maximum number of manifest-listed bytes that remain readable.
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.remaining
    }
}

impl Read for PackageSnapshotFileReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let request = usize::try_from(self.remaining)
            .map_or(buffer.len(), |remaining| remaining.min(buffer.len()));
        let count = self.file.read(&mut buffer[..request])?;
        if request != 0 && count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "snapshot file ended before its manifest length",
            ));
        }
        self.remaining = self.remaining.saturating_sub(count as u64);
        Ok(count)
    }
}

impl fmt::Debug for PackageSnapshotFileReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackageSnapshotFileReader")
            .field("remaining", &self.remaining)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PackageSnapshotLease<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackageSnapshotLease")
            .field("package_tree_merkle", &self.package_tree_merkle)
            .field("file_count", &self.file_count)
            .field("directory_count", &self.directory_count)
            .field("total_file_bytes", &self.total_file_bytes)
            .field("created_blobs", &self.created_blobs)
            .field("reused_blobs", &self.reused_blobs)
            .field("created_links", &self.created_links)
            .field("reused_links", &self.reused_links)
            .finish_non_exhaustive()
    }
}

impl PackageSnapshotLease<'_> {
    /// Returns the exact package-tree identity represented by this view.
    #[must_use]
    pub const fn package_tree_merkle(&self) -> &Sha256Digest {
        &self.package_tree_merkle
    }

    /// Returns the unrestricted physical package-view root for diagnostics and adversarial tests.
    ///
    /// This path is deliberately named as unrestricted: another same-user process can add an
    /// unmanifested child after any membership enumeration, including before lease acquisition or
    /// [`Self::verify_current_view`] returns. Never traverse or resolve execution inputs from this path
    /// as a security-qualified package view. Use [`Self::open_file`] for manifest-scoped reads.
    #[must_use]
    pub fn unrestricted_physical_root(&self) -> &Path {
        &self.root
    }

    /// Opens one exact manifest-listed file through the logical package-view allowlist.
    ///
    /// The Windows implementation reopens the direct non-reparse file, rehashes it twice around
    /// metadata checks, compares its full identity with this lease's retained identity, and returns
    /// only its manifest-declared byte range. The physical root is never joined until after an exact
    /// allowlist lookup succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`PackageSnapshotError::UnknownFile`] for an unlisted path, or another snapshot error
    /// when the platform is unsupported or the listed file no longer matches this lease.
    pub fn open_file(
        &self,
        normalized_path: &str,
    ) -> Result<PackageSnapshotFileReader, PackageSnapshotError> {
        #[cfg(windows)]
        {
            self.store.lease.verify_root_path()?;
            let (file, remaining) = self.platform.open_file(&self.root, normalized_path)?;
            self.store.lease.verify_root_path()?;
            Ok(PackageSnapshotFileReader { file, remaining })
        }

        #[cfg(not(windows))]
        {
            let _ = normalized_path;
            Err(PackageSnapshotError::UnsupportedPlatform)
        }
    }

    /// Performs a diagnostic point-in-time revalidation of retained identities, exact file bytes,
    /// and directory membership.
    ///
    /// Success means each enumeration observed the expected state while it ran. It does **not** mean
    /// the physical tree is closed when this method returns: ordinary Windows directory handles do
    /// not prevent another same-user process from adding a child immediately after an enumeration.
    /// This method therefore cannot authorize unrestricted physical-root traversal. Use
    /// [`Self::open_file`] for manifest-scoped reads.
    ///
    /// # Errors
    ///
    /// Returns [`PackageSnapshotError`] when the managed root or any retained view identity,
    /// content digest, entry kind, or complete membership no longer matches this lease.
    pub fn verify_current_view(&self) -> Result<(), PackageSnapshotError> {
        #[cfg(windows)]
        {
            self.store.lease.verify_root_path()?;
            self.platform.verify_current(&self.root)?;
            self.store.lease.verify_root_path()?;
            Ok(())
        }

        #[cfg(not(windows))]
        {
            let _configured_store_root = self.store.root();
            Err(PackageSnapshotError::UnsupportedPlatform)
        }
    }

    /// Returns the number of retained package files.
    #[must_use]
    pub const fn file_count(&self) -> usize {
        self.file_count
    }

    /// Returns the number of retained directories, including the view root.
    #[must_use]
    pub const fn directory_count(&self) -> usize {
        self.directory_count
    }

    /// Returns the logical aggregate package-file bytes.
    #[must_use]
    pub const fn total_file_bytes(&self) -> u64 {
        self.total_file_bytes
    }

    /// Returns how many package content blobs this invocation created.
    #[must_use]
    pub const fn created_blobs(&self) -> usize {
        self.created_blobs
    }

    /// Returns how many package content blobs this invocation reverified and reused.
    #[must_use]
    pub const fn reused_blobs(&self) -> usize {
        self.reused_blobs
    }

    /// Returns how many package-tree hard links this invocation created.
    #[must_use]
    pub const fn created_links(&self) -> usize {
        self.created_links
    }

    /// Returns how many package-tree hard links this invocation reverified and reused.
    #[must_use]
    pub const fn reused_links(&self) -> usize {
        self.reused_links
    }
}

#[cfg(windows)]
impl<'store> PackageSnapshotLease<'store> {
    /// Retains one manifest-listed file as an identity-matched locked executable capability.
    ///
    /// The full package lease is borrowed by the returned value so manifest files and directories
    /// remain retained for its complete lifetime. This performs no adapter authentication and does
    /// not grant execution or launch authority.
    ///
    /// # Errors
    ///
    /// Returns [`PackageSnapshotError::UnknownFile`] for an unlisted path, or another snapshot
    /// error when managed-root verification or identity-matched path locking fails.
    pub fn lock_executable<'lease>(
        &'lease self,
        normalized_path: &str,
        max_path_components: usize,
    ) -> Result<PackageSnapshotExecutable<'lease, 'store>, PackageSnapshotError> {
        self.store.lease.verify_root_path()?;
        let (locked, digest) =
            self.platform
                .lock_executable(&self.root, normalized_path, max_path_components)?;
        self.store.lease.verify_root_path()?;
        Ok(PackageSnapshotExecutable {
            lease: self,
            normalized_path: normalized_path.to_owned(),
            digest,
            locked,
        })
    }
}

impl ManagedArtifactStore {
    /// Publishes an observed package into a content-addressed view and returns a retained lease.
    ///
    /// Every source file is addressed only through the observation's bounded exact-file reader.
    /// Managed content blobs are copied or independently reverified before the package tree is
    /// composed from same-store hard links. The source observation is reverified after publication.
    /// No vendor path is written.
    ///
    /// # Errors
    ///
    /// Returns [`PackageSnapshotError`] when the source root does not match this store's configured
    /// vendor root, limits fail, source or managed bytes change, paths are unsafe, publication fails,
    /// or the completed tree cannot be independently leased.
    pub fn snapshot_package<'store>(
        &'store self,
        package: &PackageTreeObservation,
        limits: PackageSnapshotWriteLimits,
    ) -> Result<PackageSnapshotLease<'store>, PackageSnapshotError> {
        #[cfg(windows)]
        {
            if !package.has_source_root(self.vendor_root()) {
                return Err(PackageSnapshotError::SourceRootMismatch);
            }
            let validated = validate_manifest(
                package.manifest(),
                limits.files,
                limits.directories,
                limits.file_bytes,
                limits.total_bytes,
            )?;
            package.verify_current_tree()?;
            windows::snapshot(self, package, limits, &validated)
        }

        #[cfg(not(windows))]
        {
            let _ = (package, limits);
            Err(PackageSnapshotError::UnsupportedPlatform)
        }
    }

    /// Reopens and revalidates an existing package snapshot without consulting the vendor tree.
    ///
    /// # Errors
    ///
    /// Returns [`PackageSnapshotError`] when limits fail, the platform is unsupported, or any
    /// expected directory or file is missing, unsafe, mutable, extra, or byte-inconsistent.
    pub fn lease_package_snapshot<'store>(
        &'store self,
        manifest: &PackageTreeManifest,
        limits: PackageSnapshotLeaseLimits,
    ) -> Result<PackageSnapshotLease<'store>, PackageSnapshotError> {
        #[cfg(windows)]
        {
            let validated = validate_manifest(
                manifest,
                limits.files,
                limits.directories,
                limits.file_bytes,
                limits.total_bytes,
            )?;
            windows::lease_existing(self, manifest, &validated)
        }

        #[cfg(not(windows))]
        {
            let _ = (manifest, limits);
            Err(PackageSnapshotError::UnsupportedPlatform)
        }
    }
}

#[cfg(windows)]
#[derive(Debug)]
pub(super) struct ValidatedSnapshot {
    directories: BTreeSet<String>,
    directory_count: usize,
    total_file_bytes: u64,
}

#[cfg(windows)]
impl ValidatedSnapshot {
    fn directory_count(&self) -> usize {
        self.directory_count
    }
}

#[cfg(windows)]
fn validate_manifest(
    manifest: &PackageTreeManifest,
    max_files: usize,
    max_directories: usize,
    max_file_bytes: u64,
    max_total_bytes: u64,
) -> Result<ValidatedSnapshot, PackageSnapshotError> {
    if manifest.files().len() > max_files {
        return Err(PackageSnapshotError::FileLimitExceeded {
            actual: manifest.files().len(),
            max: max_files,
        });
    }
    let mut directories = BTreeSet::new();
    let mut directory_path_bytes = 0_usize;
    let mut total_file_bytes = 0_u64;
    for record in manifest.files() {
        validate_windows_snapshot_path(&record.normalized_path)?;
        if record.kind == PackageFileKind::SymbolicLink {
            return Err(PackageSnapshotError::UnsupportedFileKind {
                normalized_path: record.normalized_path.clone(),
            });
        }
        if record.size > max_file_bytes {
            return Err(PackageSnapshotError::FileTooLarge {
                normalized_path: record.normalized_path.clone(),
                actual_bytes: record.size,
                max_bytes: max_file_bytes,
            });
        }
        total_file_bytes = total_file_bytes
            .checked_add(record.size)
            .ok_or(PackageSnapshotError::TotalByteCountOverflow)?;
        if total_file_bytes > max_total_bytes {
            return Err(PackageSnapshotError::TotalBytesExceeded {
                actual_bytes: total_file_bytes,
                max_bytes: max_total_bytes,
            });
        }
        let mut prefix = String::new();
        prefix
            .try_reserve_exact(record.normalized_path.len())
            .map_err(|_| PackageSnapshotError::AllocationFailed {
                resource: "snapshot directory prefix",
            })?;
        let component_count = record.normalized_path.split('/').count();
        for component in record
            .normalized_path
            .split('/')
            .take(component_count.saturating_sub(1))
        {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            if directories.contains(&prefix) {
                continue;
            }
            let next_directory_count = directories
                .len()
                .checked_add(2)
                .ok_or(PackageSnapshotError::DirectoryCountOverflow)?;
            if next_directory_count > max_directories {
                return Err(PackageSnapshotError::DirectoryLimitExceeded {
                    actual: next_directory_count,
                    max: max_directories,
                });
            }
            directory_path_bytes = directory_path_bytes.checked_add(prefix.len()).ok_or(
                PackageSnapshotError::DirectoryPathBytesExceeded {
                    actual: usize::MAX,
                    max: MAX_PACKAGE_RECORD_PATH_BYTES,
                },
            )?;
            if directory_path_bytes > MAX_PACKAGE_RECORD_PATH_BYTES {
                return Err(PackageSnapshotError::DirectoryPathBytesExceeded {
                    actual: directory_path_bytes,
                    max: MAX_PACKAGE_RECORD_PATH_BYTES,
                });
            }
            let mut retained = String::new();
            retained.try_reserve_exact(prefix.len()).map_err(|_| {
                PackageSnapshotError::AllocationFailed {
                    resource: "snapshot directory paths",
                }
            })?;
            retained.push_str(&prefix);
            directories.insert(retained);
        }
    }
    let directory_count = directories
        .len()
        .checked_add(1)
        .ok_or(PackageSnapshotError::DirectoryCountOverflow)?;
    if directory_count > max_directories {
        return Err(PackageSnapshotError::DirectoryLimitExceeded {
            actual: directory_count,
            max: max_directories,
        });
    }
    Ok(ValidatedSnapshot {
        directories,
        directory_count,
        total_file_bytes,
    })
}

#[cfg(windows)]
fn validate_windows_snapshot_path(normalized_path: &str) -> Result<(), PackageSnapshotError> {
    ExecutionPackagePath::new(normalized_path)
        .map(|_validated| ())
        .map_err(|_source| PackageSnapshotError::UnsafeWindowsPath {
            normalized_path: normalized_path.to_owned(),
        })
}

#[cfg(windows)]
mod windows;

/// Failure publishing or leasing one managed package view.
#[derive(Debug, Error)]
pub enum PackageSnapshotError {
    /// One or more caller-selected limits are zero.
    #[error("package snapshot limits must be nonzero")]
    InvalidLimits,
    /// Package snapshots are not implemented on this platform.
    #[error("package snapshots are currently supported only on Windows")]
    UnsupportedPlatform,
    /// The observed source root differs from the vendor root bound to the managed store.
    #[error("package observation root does not match the managed store vendor root")]
    SourceRootMismatch,
    /// The package manifest exceeds the file-count limit.
    #[error("package snapshot has {actual} files; limit is {max}")]
    FileLimitExceeded {
        /// Actual file count.
        actual: usize,
        /// Maximum permitted file count.
        max: usize,
    },
    /// The package manifest exceeds the directory-count limit.
    #[error("package snapshot has {actual} directories; limit is {max}")]
    DirectoryLimitExceeded {
        /// Actual directory count, including the root.
        actual: usize,
        /// Maximum permitted directory count.
        max: usize,
    },
    /// A package file exceeds the per-file byte limit.
    #[error("package file {normalized_path} has {actual_bytes} bytes; limit is {max_bytes}")]
    FileTooLarge {
        /// Canonical package-relative path.
        normalized_path: String,
        /// Observed bytes.
        actual_bytes: u64,
        /// Maximum permitted bytes.
        max_bytes: u64,
    },
    /// Aggregate package bytes exceed the operation limit.
    #[error("package snapshot has at least {actual_bytes} bytes; limit is {max_bytes}")]
    TotalBytesExceeded {
        /// Count when the limit was crossed.
        actual_bytes: u64,
        /// Maximum permitted aggregate bytes.
        max_bytes: u64,
    },
    /// Package byte aggregation overflowed.
    #[error("package snapshot byte count overflowed")]
    TotalByteCountOverflow,
    /// Implied directory counting overflowed.
    #[error("package snapshot directory count overflowed")]
    DirectoryCountOverflow,
    /// Aggregate retained directory-path bytes exceed the canonical transport ceiling.
    #[error("snapshot directory paths retain {actual} bytes; limit is {max}")]
    DirectoryPathBytesExceeded {
        /// Aggregate bytes retained when the limit was crossed.
        actual: usize,
        /// Maximum aggregate retained directory-path bytes.
        max: usize,
    },
    /// Publication receipt counting overflowed.
    #[error("package snapshot publication count overflowed")]
    PublicationCountOverflow,
    /// The current snapshot profile cannot reproduce this record kind.
    #[error("unsupported package file kind at {normalized_path}")]
    UnsupportedFileKind {
        /// Canonical package-relative path.
        normalized_path: String,
    },
    /// A canonical transport path is ambiguous under supported Windows path semantics.
    #[error("package path is unsafe for a physical Windows snapshot: {normalized_path}")]
    UnsafeWindowsPath {
        /// Canonical package-relative path.
        normalized_path: String,
    },
    /// A package file cannot be represented by the platform's I/O length type.
    #[error("package file {normalized_path} is too large for platform I/O: {bytes} bytes")]
    PlatformFileSizeUnsupported {
        /// Canonical package-relative path.
        normalized_path: String,
        /// Declared file length.
        bytes: u64,
    },
    /// A fixed managed content-addressed path could not be derived from its digest.
    #[error("could not construct managed package-content path for {digest}")]
    ContentPathConstructionFailed {
        /// Digest whose fixed path could not be constructed.
        digest: Sha256Digest,
    },
    /// Reading an identity-verified source file failed during snapshot publication.
    #[error("could not read observed package source file {normalized_path}: {source}")]
    SourceRead {
        /// Canonical package-relative path.
        normalized_path: String,
        /// Underlying read failure.
        #[source]
        source: std::io::Error,
    },
    /// Rehashed source bytes no longer match their observed digest.
    #[error("observed package source bytes changed at {normalized_path}")]
    SourceFileMismatch {
        /// Canonical package-relative path.
        normalized_path: String,
    },
    /// Reading or revalidating the observed source package failed.
    #[error("package source observation failed")]
    PackageSource(#[from] PackageTreeObservationError),
    /// Managed content-addressed blob publication failed.
    #[error("managed content publication failed")]
    ManagedContent(#[from] MaterializationStoreError),
    /// A Windows filesystem operation failed.
    #[error("{operation} failed for {path}: {source}")]
    Io {
        /// Operation attempted.
        operation: &'static str,
        /// Affected managed path.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// A managed view path encountered a reparse point.
    #[error("managed package view contains a reparse point at {path}")]
    ReparsePoint {
        /// Affected path.
        path: PathBuf,
    },
    /// A required managed view directory is not a direct directory.
    #[error("managed package view path is not a directory: {path}")]
    NotDirectory {
        /// Affected path.
        path: PathBuf,
    },
    /// A required managed view file is missing, unsafe, or byte-inconsistent.
    #[error("managed package view file does not match its manifest: {normalized_path}")]
    FileMismatch {
        /// Canonical package-relative path.
        normalized_path: String,
    },
    /// A caller requested a path outside the manifest-scoped logical package view.
    #[error("package snapshot does not contain manifest file {normalized_path}")]
    UnknownFile {
        /// Rejected caller-supplied path.
        normalized_path: String,
    },
    /// A manifest-listed executable could not be locked to its retained file identity.
    #[error("could not lock package executable {normalized_path}: {source}")]
    ExecutableLock {
        /// Canonical package-relative path.
        normalized_path: String,
        /// Identity-matched locked-path acquisition failure.
        #[source]
        source: std::io::Error,
    },
    /// The managed package view contains missing or extra membership.
    #[error("managed package view membership differs from its manifest")]
    MembershipMismatch,
    /// Bounded snapshot state could not be allocated.
    #[error("could not allocate bounded package snapshot state for {resource}")]
    AllocationFailed {
        /// State being allocated.
        resource: &'static str,
    },
}
