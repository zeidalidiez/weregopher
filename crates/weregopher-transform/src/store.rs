//! Windows-first managed content-addressed publication for verified transform artifacts.

use std::{
    fmt,
    path::{Path, PathBuf},
};

#[cfg(windows)]
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use weregopher_domain::Sha256Digest;
#[cfg(windows)]
use weregopher_windows::LockedExecutable;

use crate::MaterializationManifest;

/// Bounds the lexical directory chains retained while a managed store root is in use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedStoreRootLimits {
    path_components: usize,
}

impl ManagedStoreRootLimits {
    /// Constructs a nonzero retained-component limit for each root path.
    ///
    /// # Errors
    ///
    /// Returns [`MaterializationStoreError::InvalidLimits`] when the limit is zero.
    pub const fn new(max_path_components: usize) -> Result<Self, MaterializationStoreError> {
        if max_path_components == 0 {
            Err(MaterializationStoreError::InvalidLimits)
        } else {
            Ok(Self {
                path_components: max_path_components,
            })
        }
    }
}

/// Independent bounds for one verified-manifest publication operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaterializationWriteLimits {
    blobs: usize,
    blob_bytes: usize,
    total_bytes: usize,
    temp_attempts: usize,
}

impl MaterializationWriteLimits {
    /// Constructs nonzero blob-count, per-blob, aggregate-byte, and temporary-name limits.
    ///
    /// # Errors
    ///
    /// Returns [`MaterializationStoreError::InvalidLimits`] when any limit is zero.
    pub const fn new(
        max_blobs: usize,
        max_blob_bytes: usize,
        max_total_bytes: usize,
        max_temp_attempts: usize,
    ) -> Result<Self, MaterializationStoreError> {
        if max_blobs == 0 || max_blob_bytes == 0 || max_total_bytes == 0 || max_temp_attempts == 0 {
            Err(MaterializationStoreError::InvalidLimits)
        } else {
            Ok(Self {
                blobs: max_blobs,
                blob_bytes: max_blob_bytes,
                total_bytes: max_total_bytes,
                temp_attempts: max_temp_attempts,
            })
        }
    }
}

/// Independent bounds for one execution-time managed-artifact lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedArtifactLeaseLimits {
    blobs: usize,
    blob_bytes: usize,
    total_bytes: usize,
}

impl ManagedArtifactLeaseLimits {
    /// Constructs nonzero blob-count, per-blob, and aggregate-byte limits.
    ///
    /// # Errors
    ///
    /// Returns [`MaterializationStoreError::InvalidLimits`] when any limit is zero.
    pub const fn new(
        max_blobs: usize,
        max_blob_bytes: usize,
        max_total_bytes: usize,
    ) -> Result<Self, MaterializationStoreError> {
        if max_blobs == 0 || max_blob_bytes == 0 || max_total_bytes == 0 {
            Err(MaterializationStoreError::InvalidLimits)
        } else {
            Ok(Self {
                blobs: max_blobs,
                blob_bytes: max_blob_bytes,
                total_bytes: max_total_bytes,
            })
        }
    }
}

/// An existing managed root retained through direct Windows directory handles.
#[must_use = "keep the managed store alive for the complete publication operation"]
pub struct ManagedArtifactStore {
    root: PathBuf,
    #[cfg(windows)]
    vendor_root: PathBuf,
    #[cfg(windows)]
    pub(crate) lease: windows::ManagedRootLease,
}

impl fmt::Debug for ManagedArtifactStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedArtifactStore")
            .field("root_components", &self.root.components().count())
            .finish_non_exhaustive()
    }
}

impl ManagedArtifactStore {
    /// Acquires an existing direct-directory store root that is disjoint from one vendor root.
    ///
    /// The Windows implementation rejects relative, parent-segment, unsupported-prefix,
    /// reparse-backed, non-directory, over-component, equal, ancestor, and descendant placements.
    /// It retains every store-root ancestor handle without delete sharing until this value is
    /// dropped. The vendor chain is held only during placement comparison so this capability does
    /// not block later vendor updates.
    ///
    /// # Errors
    ///
    /// Returns [`MaterializationStoreError`] when the platform is unsupported, either path is
    /// invalid or unsafe, handle acquisition fails, or the roots overlap by live object identity.
    pub fn open(
        root: &Path,
        vendor_root: &Path,
        limits: ManagedStoreRootLimits,
    ) -> Result<Self, MaterializationStoreError> {
        #[cfg(windows)]
        {
            let lease = windows::ManagedRootLease::open(root, vendor_root, limits.path_components)?;
            Ok(Self {
                root: root.to_path_buf(),
                vendor_root: vendor_root.to_path_buf(),
                lease,
            })
        }

        #[cfg(not(windows))]
        {
            let _ = (root, vendor_root, limits);
            Err(MaterializationStoreError::UnsupportedPlatform)
        }
    }

    /// Returns the caller-selected root path represented by the retained capability.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[cfg(windows)]
    pub(crate) fn vendor_root(&self) -> &Path {
        &self.vendor_root
    }

    /// Atomically creates or verifies every unique blob retained by one verified manifest.
    ///
    /// Inputs are independently bounded and digest-checked before filesystem writes. On Windows,
    /// publication uses direct retained directories, create-new temporary files, bounded writes,
    /// file synchronization, no-replace hard-link publication, and post-publication identity and
    /// byte verification. Existing content is reused only after the same direct-file checks.
    ///
    /// # Errors
    ///
    /// Returns [`MaterializationStoreError`] when limits, retained digest bindings, directory
    /// safety, I/O, atomic publication, cleanup, or post-write integrity checks fail.
    pub fn materialize(
        &self,
        manifest: &MaterializationManifest<'_, '_, '_, '_, '_>,
        limits: MaterializationWriteLimits,
    ) -> Result<MaterializationReceipt, MaterializationStoreError> {
        #[cfg(windows)]
        {
            let total_bytes = validate_manifest(manifest, limits)?;
            windows::materialize(&self.lease, manifest, limits, total_bytes)
        }

        #[cfg(not(windows))]
        {
            let _ = (manifest, limits);
            Err(MaterializationStoreError::UnsupportedPlatform)
        }
    }

    /// Revalidates every manifest blob and retains direct read handles for a later consumer.
    ///
    /// The returned opaque lease borrows this store capability so root and fanout directory
    /// identities remain retained. Each blob is opened without following a reparse point, checked
    /// twice against its exact length and digest, and held without write or delete sharing. The
    /// lease proves only the observed bytes and live filesystem identities; it grants no execution
    /// or launch authority.
    ///
    /// # Errors
    ///
    /// Returns [`MaterializationStoreError`] when limits or digest bindings fail, a required
    /// directory or blob is missing or unsafe, or repeated integrity observations disagree.
    pub fn lease_manifest(
        &self,
        manifest: &MaterializationManifest<'_, '_, '_, '_, '_>,
        limits: ManagedArtifactLeaseLimits,
    ) -> Result<ManagedArtifactLease<'_>, MaterializationStoreError> {
        #[cfg(windows)]
        {
            let total_bytes = validate_manifest_bounds(
                manifest,
                limits.blobs,
                limits.blob_bytes,
                limits.total_bytes,
            )?;
            let platform = windows::lease_manifest(&self.lease, manifest)?;
            Ok(ManagedArtifactLease {
                store: self,
                manifest_digest: *manifest.digest(),
                total_blob_bytes: total_bytes,
                platform,
            })
        }

        #[cfg(not(windows))]
        {
            let _ = (manifest, limits);
            Err(MaterializationStoreError::UnsupportedPlatform)
        }
    }
}

/// Integrity-checked outcome of one complete manifest publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializationReceipt {
    manifest_digest: Sha256Digest,
    created_blobs: usize,
    reused_blobs: usize,
    total_blob_bytes: usize,
}

impl MaterializationReceipt {
    /// Returns the canonical manifest identity whose blobs were published.
    #[must_use]
    pub const fn manifest_digest(&self) -> &Sha256Digest {
        &self.manifest_digest
    }

    /// Returns how many digest paths were newly published.
    #[must_use]
    pub const fn created_blobs(&self) -> usize {
        self.created_blobs
    }

    /// Returns how many digest paths already contained the exact expected bytes.
    #[must_use]
    pub const fn reused_blobs(&self) -> usize {
        self.reused_blobs
    }

    /// Returns the logical bytes represented by unique blobs in this operation.
    #[must_use]
    pub const fn total_blob_bytes(&self) -> usize {
        self.total_blob_bytes
    }
}

/// A reverified set of direct managed-artifact handles retained for one consumer lifetime.
#[must_use = "keep the artifact lease alive while any returned blob path is in use"]
pub struct ManagedArtifactLease<'store> {
    store: &'store ManagedArtifactStore,
    manifest_digest: Sha256Digest,
    total_blob_bytes: usize,
    #[cfg(windows)]
    platform: windows::ManagedManifestLease,
}

/// One exact managed blob retained as an identity-matched locked executable.
///
/// This capability keeps the complete manifest lease alive and proves only retained blob identity
/// and bytes. It does not authenticate adapter authority or authorize execution or launch.
#[cfg(windows)]
#[must_use = "retain the executable capability until a higher-level authorizer consumes it"]
pub struct ManagedArtifactExecutable<'lease, 'store> {
    lease: &'lease ManagedArtifactLease<'store>,
    digest: Sha256Digest,
    max_path_components: usize,
    _locked: LockedExecutable,
}

#[cfg(windows)]
impl ManagedArtifactExecutable<'_, '_> {
    /// Returns the exact managed executable-byte digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Returns the exact managed manifest identity retained by the complete lease.
    #[must_use]
    pub const fn manifest_digest(&self) -> Sha256Digest {
        self.lease.manifest_digest
    }

    /// Revalidates the retained managed root and identity-matches a fresh direct path lock.
    ///
    /// # Errors
    ///
    /// Returns [`MaterializationStoreError`] when the root, manifest membership, or exact blob
    /// identity no longer matches this capability.
    pub fn verify_current(&self) -> Result<(), MaterializationStoreError> {
        self.lease.store.lease.verify_root_path()?;
        let _current = self
            .lease
            .platform
            .lock_executable(&self.digest, self.max_path_components)?;
        self.lease.store.lease.verify_root_path()
    }
}

#[cfg(windows)]
impl fmt::Debug for ManagedArtifactExecutable<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedArtifactExecutable")
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ManagedArtifactLease<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedArtifactLease")
            .field("manifest_digest", &self.manifest_digest)
            .field(
                "store_root_components",
                &self.store.root.components().count(),
            )
            .field("blob_count", &self.blob_count())
            .field("total_blob_bytes", &self.total_blob_bytes)
            .finish_non_exhaustive()
    }
}

impl ManagedArtifactLease<'_> {
    /// Returns the canonical manifest identity reverified by this lease.
    #[must_use]
    pub const fn manifest_digest(&self) -> &Sha256Digest {
        &self.manifest_digest
    }

    /// Returns the number of retained direct blob handles.
    #[must_use]
    pub fn blob_count(&self) -> usize {
        #[cfg(windows)]
        {
            self.platform.blob_count()
        }

        #[cfg(not(windows))]
        {
            0
        }
    }

    /// Returns the logical aggregate bytes reverified by this lease.
    #[must_use]
    pub const fn total_blob_bytes(&self) -> usize {
        self.total_blob_bytes
    }

    /// Returns the closed absolute path retained for one leased digest.
    #[must_use]
    pub fn blob_path(&self, digest: &Sha256Digest) -> Option<&Path> {
        #[cfg(windows)]
        {
            self.platform.blob_path(digest)
        }

        #[cfg(not(windows))]
        {
            let _ = digest;
            None
        }
    }
}

#[cfg(windows)]
impl<'store> ManagedArtifactLease<'store> {
    /// Retains one leased manifest blob as an identity-matched locked executable capability.
    ///
    /// # Errors
    ///
    /// Returns [`MaterializationStoreError::MissingBlob`] when `digest` is outside this manifest
    /// lease, or another store error when root verification or executable locking fails.
    pub fn lock_executable<'lease>(
        &'lease self,
        digest: &Sha256Digest,
        max_path_components: usize,
    ) -> Result<ManagedArtifactExecutable<'lease, 'store>, MaterializationStoreError> {
        self.store.lease.verify_root_path()?;
        let locked = self.platform.lock_executable(digest, max_path_components)?;
        self.store.lease.verify_root_path()?;
        Ok(ManagedArtifactExecutable {
            lease: self,
            digest: *digest,
            max_path_components,
            _locked: locked,
        })
    }
}

#[cfg(windows)]
fn validate_manifest(
    manifest: &MaterializationManifest<'_, '_, '_, '_, '_>,
    limits: MaterializationWriteLimits,
) -> Result<usize, MaterializationStoreError> {
    validate_manifest_bounds(
        manifest,
        limits.blobs,
        limits.blob_bytes,
        limits.total_bytes,
    )
}

#[cfg(windows)]
fn validate_manifest_bounds(
    manifest: &MaterializationManifest<'_, '_, '_, '_, '_>,
    max_blobs: usize,
    max_blob_bytes: usize,
    max_total_bytes: usize,
) -> Result<usize, MaterializationStoreError> {
    if manifest.blob_count() > max_blobs {
        return Err(MaterializationStoreError::BlobLimitExceeded {
            actual: manifest.blob_count(),
            max: max_blobs,
        });
    }
    let mut total = 0_usize;
    for (digest, bytes) in manifest.blobs() {
        if bytes.len() > max_blob_bytes {
            return Err(MaterializationStoreError::BlobTooLarge {
                digest: *digest,
                actual_bytes: bytes.len(),
                max_bytes: max_blob_bytes,
            });
        }
        total = total
            .checked_add(bytes.len())
            .ok_or(MaterializationStoreError::TotalByteCountOverflow)?;
        if total > max_total_bytes {
            return Err(MaterializationStoreError::TotalBytesExceeded {
                actual_bytes: total,
                max_bytes: max_total_bytes,
            });
        }
    }
    for (expected, bytes) in manifest.blobs() {
        if digest(bytes) != *expected {
            return Err(MaterializationStoreError::VerifiedBlobDigestMismatch {
                digest: *expected,
            });
        }
    }
    Ok(total)
}

#[cfg(windows)]
fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

#[cfg(windows)]
pub(crate) mod windows;

/// Failure acquiring, publishing, or leasing a managed content-addressed artifact store.
#[derive(Debug, Error)]
pub enum MaterializationStoreError {
    /// One or more caller-selected limits were zero.
    #[error("managed artifact limits must be nonzero")]
    InvalidLimits,
    /// Managed-store filesystem operations are currently implemented only on Windows.
    #[error("managed artifact store operations are currently supported only on Windows")]
    UnsupportedPlatform,
    /// A root path was not an accepted absolute Windows path without parent or unsafe prefixes.
    #[error("invalid absolute {kind} root path: {path}")]
    InvalidRootPath {
        /// Safe root category.
        kind: &'static str,
        /// Rejected path.
        path: PathBuf,
    },
    /// A root path exceeded its bounded lexical component count.
    #[error("{kind} root has {actual} components; limit is {max}")]
    RootComponentLimitExceeded {
        /// Safe root category.
        kind: &'static str,
        /// Exact lexical component count.
        actual: usize,
        /// Caller-selected component limit.
        max: usize,
    },
    /// Retaining a bounded directory-handle chain could not reserve its capacity.
    #[error("could not allocate {components} managed-root handle slots")]
    RootLeaseAllocationFailed {
        /// Exact requested handle-slot count.
        components: usize,
    },
    /// An operating-system operation failed.
    #[error("failed to {operation} at {path}: {source}")]
    Io {
        /// Static operation label.
        operation: &'static str,
        /// Affected path.
        path: PathBuf,
        /// Operating-system failure.
        #[source]
        source: std::io::Error,
    },
    /// A required direct directory was backed by a Windows reparse point.
    #[error("managed materialization directory is a reparse point: {path}")]
    ReparsePoint {
        /// Rejected path.
        path: PathBuf,
    },
    /// A required directory path opened a non-directory object.
    #[error("managed materialization path is not a directory: {path}")]
    NotDirectory {
        /// Rejected path.
        path: PathBuf,
    },
    /// The managed store and vendor installation roots overlap by live object identity.
    #[error("managed store root overlaps the vendor installation root")]
    StoreOverlapsVendor,
    /// Unique blobs exceeded the independent writer limit.
    #[error("materialization contains {actual} unique blobs; writer limit is {max}")]
    BlobLimitExceeded {
        /// Exact manifest blob count.
        actual: usize,
        /// Caller-selected blob limit.
        max: usize,
    },
    /// One retained blob exceeded the independent writer limit.
    #[error("blob {digest} contains {actual_bytes} bytes; writer limit is {max_bytes}")]
    BlobTooLarge {
        /// Content identity only; payload bytes are never reported.
        digest: Sha256Digest,
        /// Exact retained byte count.
        actual_bytes: usize,
        /// Caller-selected per-blob limit.
        max_bytes: usize,
    },
    /// Aggregate blob-byte arithmetic overflowed.
    #[error("materialization aggregate blob bytes overflowed the platform index")]
    TotalByteCountOverflow,
    /// Aggregate unique-blob bytes exceeded the independent writer limit.
    #[error(
        "materialization contains at least {actual_bytes} blob bytes; writer limit is {max_bytes}"
    )]
    TotalBytesExceeded {
        /// Count at the first excess.
        actual_bytes: usize,
        /// Caller-selected aggregate limit.
        max_bytes: usize,
    },
    /// Completed blob-count arithmetic overflowed the platform index.
    #[error("materialized blob count overflowed the platform index")]
    BlobCountOverflow,
    /// A supposedly verified digest-to-byte association did not hash as declared.
    #[error("retained verified bytes no longer match blob digest {digest}")]
    VerifiedBlobDigestMismatch {
        /// Mismatched identity.
        digest: Sha256Digest,
    },
    /// The already-validated digest could not be rendered into the fixed store layout.
    #[error("could not construct the closed content path for {digest}")]
    ContentPathConstructionFailed {
        /// Digest whose path could not be rendered.
        digest: Sha256Digest,
    },
    /// One required canonical digest path was absent from the managed store.
    #[error("managed store is missing required blob {digest}")]
    MissingBlob {
        /// Missing content identity.
        digest: Sha256Digest,
    },
    /// A leased managed blob could not be locked to its retained file identity.
    #[error("could not lock managed executable {digest}: {source}")]
    ExecutableLock {
        /// Managed executable-byte identity.
        digest: Sha256Digest,
        /// Identity-matched locked-path acquisition failure.
        #[source]
        source: std::io::Error,
    },
    /// A pre-existing content path did not contain the exact expected direct-file bytes.
    #[error("content path for {digest} contains conflicting or unstable bytes")]
    ExistingBlobMismatch {
        /// Conflicting content identity.
        digest: Sha256Digest,
    },
    /// A content path was a reparse point or non-regular object.
    #[error("content path for {digest} is not a direct regular file")]
    InvalidBlobObject {
        /// Rejected content identity.
        digest: Sha256Digest,
    },
    /// All bounded create-new temporary-name attempts collided.
    #[error("could not allocate a unique temporary name for {digest} in {attempts} attempts")]
    TemporaryNameAttemptsExhausted {
        /// Blob being staged.
        digest: Sha256Digest,
        /// Caller-selected attempt limit.
        attempts: usize,
    },
    /// Post-publication handles did not identify the staged file object.
    #[error("published content path for {digest} did not retain the staged file identity")]
    PublicationIdentityMismatch {
        /// Mismatched published identity.
        digest: Sha256Digest,
    },
    /// A bounded temporary file could not be removed after publication or failure.
    #[error("failed to clean temporary materialization file at {path}: {source}")]
    TemporaryCleanupFailed {
        /// Closed internally generated temporary path.
        path: PathBuf,
        /// Removal failure.
        #[source]
        source: std::io::Error,
    },
}
