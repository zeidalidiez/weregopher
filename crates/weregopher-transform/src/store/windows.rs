//! Windows managed-store implementation.

use std::{
    collections::{BTreeMap, btree_map::Entry},
    fs::{self, File, OpenOptions},
    io::{Cursor, Read as _, Seek as _, SeekFrom, Write as _},
    os::windows::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Component, Path, PathBuf, Prefix},
};

use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use weregopher_domain::Sha256Digest;
use weregopher_windows::FileIdentityLease;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_FLAG_SEQUENTIAL_SCAN, FILE_SHARE_READ, FILE_SHARE_WRITE,
};

use super::{MaterializationReceipt, MaterializationStoreError, MaterializationWriteLimits};
use crate::{MaterializationManifest, materialization::content_path};

#[derive(Debug)]
pub(crate) struct ManagedRootLease {
    root: PathBuf,
    ancestors: Vec<FileIdentityLease>,
}

pub(super) struct ManagedManifestLease {
    _content_root: FileIdentityLease,
    _fanouts: BTreeMap<String, FileIdentityLease>,
    blobs: BTreeMap<Sha256Digest, ManagedBlobLease>,
}

struct ManagedBlobLease {
    path: PathBuf,
    _identity: FileIdentityLease,
}

impl ManagedManifestLease {
    pub(super) fn blob_count(&self) -> usize {
        self.blobs.len()
    }

    pub(super) fn blob_path(&self, digest: &Sha256Digest) -> Option<&Path> {
        self.blobs.get(digest).map(|blob| blob.path.as_path())
    }
}

impl ManagedRootLease {
    pub(super) fn open(
        root: &Path,
        vendor_root: &Path,
        max_components: usize,
    ) -> Result<Self, MaterializationStoreError> {
        validate_root_path(root, "managed store", max_components)?;
        validate_root_path(vendor_root, "vendor", max_components)?;
        let ancestors = open_directory_chain(root)?;
        let vendor_ancestors = open_directory_chain(vendor_root)?;
        let store_root = ancestors
            .last()
            .ok_or_else(|| invalid_root("managed store", root))?;
        let vendor_root_lease = vendor_ancestors
            .last()
            .ok_or_else(|| invalid_root("vendor", vendor_root))?;
        if vendor_ancestors
            .iter()
            .any(|ancestor| store_root.has_same_identity(ancestor))
            || ancestors
                .iter()
                .any(|ancestor| vendor_root_lease.has_same_identity(ancestor))
        {
            return Err(MaterializationStoreError::StoreOverlapsVendor);
        }
        let lease = Self {
            root: root.to_path_buf(),
            ancestors,
        };
        lease.verify_root_path()?;
        Ok(lease)
    }

    pub(crate) fn verify_root_path(&self) -> Result<(), MaterializationStoreError> {
        let current = open_direct_directory(&self.root)?;
        let retained = self
            .ancestors
            .last()
            .ok_or_else(|| invalid_root("managed store", &self.root))?;
        if retained.has_same_identity(&current) {
            Ok(())
        } else {
            Err(MaterializationStoreError::Io {
                operation: "verify managed root identity",
                path: self.root.clone(),
                source: std::io::Error::other("managed root path identity changed"),
            })
        }
    }
}

pub(super) fn materialize(
    lease: &ManagedRootLease,
    manifest: &MaterializationManifest<'_, '_, '_, '_, '_>,
    limits: MaterializationWriteLimits,
    total_bytes: usize,
) -> Result<MaterializationReceipt, MaterializationStoreError> {
    lease.verify_root_path()?;
    let content_root_path = lease.root.join("sha256");
    let _content_root_lease = ensure_direct_directory(&content_root_path)?;
    let mut created = 0_usize;
    let mut reused = 0_usize;

    for (digest, bytes) in manifest.blobs() {
        let relative = content_path(digest).map_err(|_| {
            MaterializationStoreError::ContentPathConstructionFailed { digest: *digest }
        })?;
        let fanout = relative
            .get(7..9)
            .ok_or(MaterializationStoreError::ContentPathConstructionFailed { digest: *digest })?;
        let filename = relative
            .get(10..)
            .ok_or(MaterializationStoreError::ContentPathConstructionFailed { digest: *digest })?;
        let fanout_path = content_root_path.join(fanout);
        let _fanout_lease = ensure_direct_directory(&fanout_path)?;
        let content_path = fanout_path.join(filename);

        match open_existing_blob(&content_path, digest)? {
            Some(file) => {
                let _verified = verify_blob(file, &content_path, digest, bytes.len())?;
                reused = reused
                    .checked_add(1)
                    .ok_or(MaterializationStoreError::BlobCountOverflow)?;
            }
            None => match stage_and_publish(
                &fanout_path,
                &content_path,
                digest,
                bytes,
                limits.temp_attempts,
            )? {
                Publication::Created => {
                    created = created
                        .checked_add(1)
                        .ok_or(MaterializationStoreError::BlobCountOverflow)?;
                }
                Publication::Reused => {
                    reused = reused
                        .checked_add(1)
                        .ok_or(MaterializationStoreError::BlobCountOverflow)?;
                }
            },
        }
    }
    lease.verify_root_path()?;
    Ok(MaterializationReceipt {
        manifest_digest: *manifest.digest(),
        created_blobs: created,
        reused_blobs: reused,
        total_blob_bytes: total_bytes,
    })
}

pub(crate) fn publish_reader(
    lease: &ManagedRootLease,
    digest: &Sha256Digest,
    expected_bytes: usize,
    reader: &mut dyn std::io::Read,
    temp_attempts: usize,
) -> Result<Publication, MaterializationStoreError> {
    lease.verify_root_path()?;
    let content_root_path = lease.root.join("sha256");
    let _content_root_lease = ensure_direct_directory(&content_root_path)?;
    let relative = content_path(digest).map_err(|_| {
        MaterializationStoreError::ContentPathConstructionFailed { digest: *digest }
    })?;
    let fanout = relative
        .get(7..9)
        .ok_or(MaterializationStoreError::ContentPathConstructionFailed { digest: *digest })?;
    let filename = relative
        .get(10..)
        .ok_or(MaterializationStoreError::ContentPathConstructionFailed { digest: *digest })?;
    let fanout_path = content_root_path.join(fanout);
    let _fanout_lease = ensure_direct_directory(&fanout_path)?;
    let destination = fanout_path.join(filename);
    let publication = match open_existing_blob(&destination, digest)? {
        Some(file) => {
            let _verified = verify_blob(file, &destination, digest, expected_bytes)?;
            Publication::Reused
        }
        None => stage_and_publish_reader(
            &fanout_path,
            &destination,
            digest,
            reader,
            expected_bytes,
            temp_attempts,
        )?,
    };
    lease.verify_root_path()?;
    Ok(publication)
}

pub(super) fn lease_manifest(
    lease: &ManagedRootLease,
    manifest: &MaterializationManifest<'_, '_, '_, '_, '_>,
) -> Result<ManagedManifestLease, MaterializationStoreError> {
    lease.verify_root_path()?;
    let content_root_path = lease.root.join("sha256");
    let content_root = open_direct_directory(&content_root_path)?;
    let mut fanouts = BTreeMap::new();
    let mut blobs = BTreeMap::new();
    for (digest, bytes) in manifest.blobs() {
        let relative = content_path(digest).map_err(|_| {
            MaterializationStoreError::ContentPathConstructionFailed { digest: *digest }
        })?;
        let fanout = relative
            .get(7..9)
            .ok_or(MaterializationStoreError::ContentPathConstructionFailed { digest: *digest })?;
        let filename = relative
            .get(10..)
            .ok_or(MaterializationStoreError::ContentPathConstructionFailed { digest: *digest })?;
        let fanout_path = content_root_path.join(fanout);
        if let Entry::Vacant(entry) = fanouts.entry(fanout.to_owned()) {
            entry.insert(open_direct_directory(&fanout_path)?);
        }
        let blob_path = fanout_path.join(filename);
        let file = open_existing_blob(&blob_path, digest)?
            .ok_or(MaterializationStoreError::MissingBlob { digest: *digest })?;
        let file = verify_blob(file, &blob_path, digest, bytes.len())?;
        let identity = FileIdentityLease::from_file(file)
            .map_err(|source| io_error("retain managed blob identity", &blob_path, source))?;
        blobs.insert(
            *digest,
            ManagedBlobLease {
                path: blob_path,
                _identity: identity,
            },
        );
    }
    lease.verify_root_path()?;
    Ok(ManagedManifestLease {
        _content_root: content_root,
        _fanouts: fanouts,
        blobs,
    })
}

fn validate_root_path(
    path: &Path,
    kind: &'static str,
    max_components: usize,
) -> Result<(), MaterializationStoreError> {
    let component_count = path.components().count();
    if component_count > max_components {
        return Err(MaterializationStoreError::RootComponentLimitExceeded {
            kind,
            actual: component_count,
            max: max_components,
        });
    }
    if !path.is_absolute() || component_count == 0 {
        return Err(invalid_root(kind, path));
    }
    for component in path.components() {
        match component {
            Component::Prefix(prefix)
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::UNC(_, _)) => {}
            Component::RootDir | Component::Normal(_) => {}
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                return Err(invalid_root(kind, path));
            }
        }
    }
    Ok(())
}

fn invalid_root(kind: &'static str, path: &Path) -> MaterializationStoreError {
    MaterializationStoreError::InvalidRootPath {
        kind,
        path: path.to_path_buf(),
    }
}

fn open_directory_chain(path: &Path) -> Result<Vec<FileIdentityLease>, MaterializationStoreError> {
    let component_count = path.components().count();
    let mut ancestors = Vec::new();
    ancestors.try_reserve_exact(component_count).map_err(|_| {
        MaterializationStoreError::RootLeaseAllocationFailed {
            components: component_count,
        }
    })?;
    ancestors.extend(
        path.ancestors()
            .filter(|ancestor| !ancestor.as_os_str().is_empty()),
    );
    ancestors.reverse();
    let mut leases = Vec::new();
    leases.try_reserve_exact(component_count).map_err(|_| {
        MaterializationStoreError::RootLeaseAllocationFailed {
            components: component_count,
        }
    })?;
    for ancestor in ancestors {
        leases.push(open_direct_directory(ancestor)?);
    }
    Ok(leases)
}

fn ensure_direct_directory(path: &Path) -> Result<FileIdentityLease, MaterializationStoreError> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(source) => return Err(io_error("create managed directory", path, source)),
    }
    open_direct_directory(path)
}

fn open_direct_directory(path: &Path) -> Result<FileIdentityLease, MaterializationStoreError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(path)
        .map_err(|source| io_error("open direct directory", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("read direct-directory metadata", path, source))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(MaterializationStoreError::ReparsePoint {
            path: path.to_path_buf(),
        });
    }
    if !metadata.is_dir() {
        return Err(MaterializationStoreError::NotDirectory {
            path: path.to_path_buf(),
        });
    }
    FileIdentityLease::from_file(file)
        .map_err(|source| io_error("read direct-directory identity", path, source))
}

fn open_existing_blob(
    path: &Path,
    digest: &Sha256Digest,
) -> Result<Option<File>, MaterializationStoreError> {
    open_blob_with_share(path, digest, FILE_SHARE_READ)
}

fn open_published_link(
    path: &Path,
    digest: &Sha256Digest,
) -> Result<Option<File>, MaterializationStoreError> {
    open_blob_with_share(path, digest, FILE_SHARE_READ | FILE_SHARE_WRITE)
}

fn open_blob_with_share(
    path: &Path,
    digest: &Sha256Digest,
    share_mode: u32,
) -> Result<Option<File>, MaterializationStoreError> {
    let mut options = OpenOptions::new();
    options.read(true).share_mode(share_mode).custom_flags(
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
    );
    match options.open(path) {
        Ok(file) => {
            validate_regular_file(&file, path, digest)?;
            Ok(Some(file))
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(io_error("open content-addressed blob", path, source)),
    }
}

fn validate_regular_file(
    file: &File,
    path: &Path,
    digest: &Sha256Digest,
) -> Result<FileMetadataSnapshot, MaterializationStoreError> {
    let metadata = file
        .metadata()
        .map_err(|source| io_error("read content-file metadata", path, source))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_file() {
        return Err(MaterializationStoreError::InvalidBlobObject { digest: *digest });
    }
    Ok(FileMetadataSnapshot {
        attributes: metadata.file_attributes(),
        creation_time: metadata.creation_time(),
        last_write_time: metadata.last_write_time(),
        size: metadata.file_size(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileMetadataSnapshot {
    attributes: u32,
    creation_time: u64,
    last_write_time: u64,
    size: u64,
}

fn verify_blob(
    mut file: File,
    path: &Path,
    expected_digest: &Sha256Digest,
    expected_bytes: usize,
) -> Result<File, MaterializationStoreError> {
    let expected_size = u64::try_from(expected_bytes).map_err(|_| {
        MaterializationStoreError::ExistingBlobMismatch {
            digest: *expected_digest,
        }
    })?;
    let before = validate_regular_file(&file, path, expected_digest)?;
    if before.size != expected_size {
        return Err(MaterializationStoreError::ExistingBlobMismatch {
            digest: *expected_digest,
        });
    }
    let first = hash_exact(&mut file, path, expected_size)?;
    let second = hash_exact(&mut file, path, expected_size)?;
    let after = validate_regular_file(&file, path, expected_digest)?;
    if before != after || first != second || first != *expected_digest {
        return Err(MaterializationStoreError::ExistingBlobMismatch {
            digest: *expected_digest,
        });
    }
    Ok(file)
}

fn hash_exact(
    file: &mut File,
    path: &Path,
    expected_bytes: u64,
) -> Result<Sha256Digest, MaterializationStoreError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|source| io_error("rewind content-addressed blob", path, source))?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    while total < expected_bytes {
        let remaining = expected_bytes - total;
        let request = usize::try_from(remaining)
            .map_or(buffer.len(), |remaining| remaining.min(buffer.len()));
        let read = file
            .read(&mut buffer[..request])
            .map_err(|source| io_error("read content-addressed blob", path, source))?;
        if read == 0 {
            return Err(MaterializationStoreError::Io {
                operation: "read complete content-addressed blob",
                path: path.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "content-addressed blob ended before its declared length",
                ),
            });
        }
        total = total
            .checked_add(read as u64)
            .ok_or(MaterializationStoreError::TotalByteCountOverflow)?;
        hasher.update(&buffer[..read]);
    }
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Publication {
    Created,
    Reused,
}

fn stage_and_publish(
    directory: &Path,
    destination: &Path,
    expected_digest: &Sha256Digest,
    bytes: &[u8],
    temp_attempts: usize,
) -> Result<Publication, MaterializationStoreError> {
    let mut reader = Cursor::new(bytes);
    stage_and_publish_reader(
        directory,
        destination,
        expected_digest,
        &mut reader,
        bytes.len(),
        temp_attempts,
    )
}

fn stage_and_publish_reader(
    directory: &Path,
    destination: &Path,
    expected_digest: &Sha256Digest,
    reader: &mut dyn std::io::Read,
    expected_bytes: usize,
    temp_attempts: usize,
) -> Result<Publication, MaterializationStoreError> {
    let (temporary_path, temporary_file) =
        create_temporary_file(directory, expected_digest, temp_attempts)?;
    let result = stage_and_publish_inner(
        temporary_file,
        &temporary_path,
        destination,
        expected_digest,
        reader,
        expected_bytes,
    );
    let cleanup = fs::remove_file(&temporary_path);
    match cleanup {
        Ok(()) => result,
        Err(source) => Err(MaterializationStoreError::TemporaryCleanupFailed {
            path: temporary_path,
            source,
        }),
    }
}

fn copy_exact(
    reader: &mut dyn std::io::Read,
    writer: &mut File,
    temporary_path: &Path,
    expected_bytes: usize,
) -> Result<(), MaterializationStoreError> {
    let mut remaining = expected_bytes;
    let mut buffer = [0_u8; 16 * 1024];
    while remaining != 0 {
        let request = remaining.min(buffer.len());
        let read = reader
            .read(&mut buffer[..request])
            .map_err(|source| io_error("read package source", temporary_path, source))?;
        if read == 0 {
            return Err(io_error(
                "read complete package source",
                temporary_path,
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "package source ended before its declared length",
                ),
            ));
        }
        writer
            .write_all(&buffer[..read])
            .map_err(|source| io_error("write temporary content file", temporary_path, source))?;
        remaining -= read;
    }
    let mut extra = [0_u8; 1];
    if reader
        .read(&mut extra)
        .map_err(|source| io_error("check package source length", temporary_path, source))?
        != 0
    {
        return Err(io_error(
            "check package source length",
            temporary_path,
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "package source exceeded its declared length",
            ),
        ));
    }
    Ok(())
}

fn create_temporary_file(
    directory: &Path,
    digest: &Sha256Digest,
    attempts: usize,
) -> Result<(PathBuf, File), MaterializationStoreError> {
    for _ in 0..attempts {
        let name = format!(".weregopher-{}.tmp", Uuid::new_v4().as_simple());
        let path = directory.join(name);
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN);
        match options.open(&path) {
            Ok(file) => {
                if let Err(error) = validate_regular_file(&file, &path, digest) {
                    drop(file);
                    fs::remove_file(&path).map_err(|source| {
                        MaterializationStoreError::TemporaryCleanupFailed {
                            path: path.clone(),
                            source,
                        }
                    })?;
                    return Err(error);
                }
                return Ok((path, file));
            }
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(io_error("create temporary content file", &path, source)),
        }
    }
    Err(MaterializationStoreError::TemporaryNameAttemptsExhausted {
        digest: *digest,
        attempts,
    })
}

fn stage_and_publish_inner(
    mut temporary_file: File,
    temporary_path: &Path,
    destination: &Path,
    expected_digest: &Sha256Digest,
    reader: &mut dyn std::io::Read,
    expected_bytes: usize,
) -> Result<Publication, MaterializationStoreError> {
    copy_exact(reader, &mut temporary_file, temporary_path, expected_bytes)?;
    temporary_file
        .sync_all()
        .map_err(|source| io_error("flush temporary content file", temporary_path, source))?;
    let temporary_file = verify_blob(
        temporary_file,
        temporary_path,
        expected_digest,
        expected_bytes,
    )?;
    let transition_file =
        open_published_link(temporary_path, expected_digest)?.ok_or_else(|| {
            io_error(
                "open temporary content for handle transition",
                temporary_path,
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "temporary content path was not found",
                ),
            )
        })?;
    let write_identity = FileIdentityLease::from_file(temporary_file)
        .map_err(|source| io_error("read temporary content identity", temporary_path, source))?;
    let transition_identity = FileIdentityLease::from_file(transition_file)
        .map_err(|source| io_error("read temporary transition identity", temporary_path, source))?;
    if !write_identity.has_same_identity(&transition_identity) {
        return Err(MaterializationStoreError::PublicationIdentityMismatch {
            digest: *expected_digest,
        });
    }
    drop(write_identity);
    let locked_file = open_existing_blob(temporary_path, expected_digest)?.ok_or_else(|| {
        io_error(
            "lock temporary content for publication",
            temporary_path,
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "temporary content path was not found",
            ),
        )
    })?;
    let locked_file = verify_blob(locked_file, temporary_path, expected_digest, expected_bytes)?;
    let temporary_identity = FileIdentityLease::from_file(locked_file).map_err(|source| {
        io_error(
            "read locked temporary content identity",
            temporary_path,
            source,
        )
    })?;
    if !transition_identity.has_same_identity(&temporary_identity) {
        return Err(MaterializationStoreError::PublicationIdentityMismatch {
            digest: *expected_digest,
        });
    }
    drop(transition_identity);

    match fs::hard_link(temporary_path, destination) {
        Ok(()) => {
            let published = open_existing_blob(destination, expected_digest)?.ok_or_else(|| {
                io_error(
                    "open newly published content file",
                    destination,
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "published content path was not found",
                    ),
                )
            })?;
            let published = verify_blob(published, destination, expected_digest, expected_bytes)?;
            let published_identity = FileIdentityLease::from_file(published).map_err(|source| {
                io_error("read published content identity", destination, source)
            })?;
            if !temporary_identity.has_same_identity(&published_identity) {
                return Err(MaterializationStoreError::PublicationIdentityMismatch {
                    digest: *expected_digest,
                });
            }
            Ok(Publication::Created)
        }
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = open_existing_blob(destination, expected_digest)?.ok_or_else(|| {
                io_error(
                    "open concurrently published content file",
                    destination,
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "concurrently published content path was not found",
                    ),
                )
            })?;
            let _verified = verify_blob(existing, destination, expected_digest, expected_bytes)?;
            Ok(Publication::Reused)
        }
        Err(source) => Err(io_error(
            "atomically publish content-addressed blob",
            destination,
            source,
        )),
    }
}

fn io_error(
    operation: &'static str,
    path: &Path,
    source: std::io::Error,
) -> MaterializationStoreError {
    MaterializationStoreError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn exact_reader_copy_rejects_short_and_surplus_streams()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = tempdir()?;

        let exact_path = fixture.path().join("exact.bin");
        let mut exact_file = File::create(&exact_path)?;
        copy_exact(&mut Cursor::new(b"exact"), &mut exact_file, &exact_path, 5)?;
        drop(exact_file);
        assert_eq!(fs::read(&exact_path)?, b"exact");

        let short_path = fixture.path().join("short.bin");
        let mut short_file = File::create(&short_path)?;
        assert!(matches!(
            copy_exact(
                &mut Cursor::new(b"short"),
                &mut short_file,
                &short_path,
                6,
            ),
            Err(MaterializationStoreError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::UnexpectedEof
        ));

        let surplus_path = fixture.path().join("surplus.bin");
        let mut surplus_file = File::create(&surplus_path)?;
        assert!(matches!(
            copy_exact(
                &mut Cursor::new(b"surplus"),
                &mut surplus_file,
                &surplus_path,
                6,
            ),
            Err(MaterializationStoreError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::InvalidData
        ));
        Ok(())
    }
}
