//! Windows immutable package-view publication and leasing.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read as _, Seek as _, SeekFrom},
    os::windows::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
};

use sha2::{Digest as _, Sha256};
use weregopher_domain::Sha256Digest;
use weregopher_fingerprint::{PackageTreeManifest, PackageTreeObservation};
use weregopher_windows::{FileIdentityLease, LockedExecutable};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_FLAG_SEQUENTIAL_SCAN, FILE_SHARE_READ, FILE_SHARE_WRITE,
};

use super::{
    PackageSnapshotError, PackageSnapshotLease, PackageSnapshotWriteLimits, ValidatedSnapshot,
};
use crate::{
    ManagedArtifactStore,
    materialization::content_path,
    store::windows::{Publication, ReaderPublicationError, publish_reader},
};

const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
const ERROR_SHARING_VIOLATION_CODE: i32 = 32;
const MAX_TRANSIENT_DIRECTORY_OPEN_ATTEMPTS: usize = 16;

pub(super) struct WindowsPackageSnapshotLease {
    _ancestors: Vec<FileIdentityLease>,
    directories: BTreeMap<String, DirectoryLease>,
    files: BTreeMap<String, SnapshotFileLease>,
}

struct DirectoryLease {
    path: PathBuf,
    identity: FileIdentityLease,
}

struct SnapshotFileLease {
    size: u64,
    digest: Sha256Digest,
    identity: FileIdentityLease,
}

impl WindowsPackageSnapshotLease {
    pub(super) fn verify_current(&self, root: &Path) -> Result<(), PackageSnapshotError> {
        for directory in self.directories.values() {
            let current = open_direct_directory(&directory.path)?;
            if !directory.identity.has_same_identity(&current) {
                return Err(PackageSnapshotError::MembershipMismatch);
            }
        }
        for (normalized_path, retained) in &self.files {
            let path = join_normalized(root, normalized_path);
            let file = open_verified_file(&path, normalized_path, retained.size, retained.digest)?;
            let current = FileIdentityLease::from_file(file).map_err(|source| {
                io_error("revalidate package-view file identity", &path, source)
            })?;
            if !retained.identity.has_same_identity(&current) {
                return Err(PackageSnapshotError::FileMismatch {
                    normalized_path: normalized_path.clone(),
                });
            }
        }
        verify_membership(&self.directories, &self.files)
    }

    pub(super) fn open_file(
        &self,
        root: &Path,
        normalized_path: &str,
    ) -> Result<(File, u64), PackageSnapshotError> {
        let retained =
            self.files
                .get(normalized_path)
                .ok_or_else(|| PackageSnapshotError::UnknownFile {
                    normalized_path: normalized_path.to_owned(),
                })?;
        let path = join_normalized(root, normalized_path);
        let mut file = open_verified_file(&path, normalized_path, retained.size, retained.digest)?;
        let identity_file = file
            .try_clone()
            .map_err(|source| io_error("duplicate package-view file handle", &path, source))?;
        let current = FileIdentityLease::from_file(identity_file)
            .map_err(|source| io_error("revalidate package-view file identity", &path, source))?;
        if !retained.identity.has_same_identity(&current) {
            return Err(PackageSnapshotError::FileMismatch {
                normalized_path: normalized_path.to_owned(),
            });
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|source| io_error("rewind package-view file reader", &path, source))?;
        Ok((file, retained.size))
    }

    pub(super) fn lock_executable(
        &self,
        root: &Path,
        normalized_path: &str,
        max_path_components: usize,
    ) -> Result<(LockedExecutable, Sha256Digest), PackageSnapshotError> {
        let retained =
            self.files
                .get(normalized_path)
                .ok_or_else(|| PackageSnapshotError::UnknownFile {
                    normalized_path: normalized_path.to_owned(),
                })?;
        let path = join_normalized(root, normalized_path);
        let locked = LockedExecutable::open_matching_identity(
            &path,
            max_path_components,
            &retained.identity,
        )
        .map_err(|source| PackageSnapshotError::ExecutableLock {
            normalized_path: normalized_path.to_owned(),
            source,
        })?;
        Ok((locked, retained.digest))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ViewEntryKind {
    Directory,
    File,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PublicationCounts {
    created_blobs: usize,
    reused_blobs: usize,
    created_links: usize,
    reused_links: usize,
}

pub(super) fn snapshot<'store>(
    store: &'store ManagedArtifactStore,
    package: &PackageTreeObservation,
    limits: PackageSnapshotWriteLimits,
    validated: &ValidatedSnapshot,
) -> Result<PackageSnapshotLease<'store>, PackageSnapshotError> {
    store.lease.verify_root_path()?;
    verify_source_bytes(package)?;
    let mut counts = PublicationCounts::default();
    let mut published_digests = BTreeSet::new();
    for record in package.manifest().files() {
        if !published_digests.insert(record.sha256) {
            continue;
        }
        let expected_bytes = usize::try_from(record.size).map_err(|_| {
            PackageSnapshotError::PlatformFileSizeUnsupported {
                normalized_path: record.normalized_path.clone(),
                bytes: record.size,
            }
        })?;
        let mut reader = package.open_file(&record.normalized_path)?;
        let publication = publish_reader(
            &store.lease,
            &record.sha256,
            expected_bytes,
            &mut reader,
            limits.temp_attempts,
        )
        .map_err(|source| match source {
            ReaderPublicationError::SourceRead(source) => PackageSnapshotError::SourceRead {
                normalized_path: record.normalized_path.clone(),
                source,
            },
            ReaderPublicationError::SourceLengthMismatch
            | ReaderPublicationError::SourceDigestMismatch => {
                PackageSnapshotError::SourceFileMismatch {
                    normalized_path: record.normalized_path.clone(),
                }
            }
            ReaderPublicationError::Store(source) => PackageSnapshotError::ManagedContent(source),
        })?;
        match publication {
            Publication::Created => increment(&mut counts.created_blobs)?,
            Publication::Reused => increment(&mut counts.reused_blobs)?,
        }
    }
    package.verify_current_tree()?;
    compose_links(store, package.manifest(), validated, &mut counts)?;
    verify_source_bytes(package)?;
    package.verify_current_tree()?;
    lease_view(store, package.manifest(), validated, counts)
}

fn verify_source_bytes(package: &PackageTreeObservation) -> Result<(), PackageSnapshotError> {
    let mut buffer = [0_u8; 16 * 1024];
    for record in package.manifest().files() {
        let mut reader = package.open_file(&record.normalized_path)?;
        let mut hasher = Sha256::new();
        while reader.remaining() != 0 {
            let read =
                reader
                    .read(&mut buffer)
                    .map_err(|source| PackageSnapshotError::SourceRead {
                        normalized_path: record.normalized_path.clone(),
                        source,
                    })?;
            if read == 0 {
                return Err(PackageSnapshotError::SourceFileMismatch {
                    normalized_path: record.normalized_path.clone(),
                });
            }
            hasher.update(&buffer[..read]);
        }
        let digest = Sha256Digest::from_bytes(hasher.finalize().into());
        if digest != record.sha256 {
            return Err(PackageSnapshotError::SourceFileMismatch {
                normalized_path: record.normalized_path.clone(),
            });
        }
    }
    Ok(())
}

pub(super) fn lease_existing<'store>(
    store: &'store ManagedArtifactStore,
    manifest: &PackageTreeManifest,
    validated: &ValidatedSnapshot,
) -> Result<PackageSnapshotLease<'store>, PackageSnapshotError> {
    store.lease.verify_root_path()?;
    lease_view(store, manifest, validated, PublicationCounts::default())
}

fn compose_links(
    store: &ManagedArtifactStore,
    manifest: &PackageTreeManifest,
    validated: &ValidatedSnapshot,
    counts: &mut PublicationCounts,
) -> Result<(), PackageSnapshotError> {
    let paths = view_paths(store.root(), manifest.package_tree_merkle())?;
    let _package_views = ensure_direct_directory(&paths.package_views)?;
    let _identity_root = ensure_direct_directory(&paths.identity_root)?;
    let _view_root = ensure_direct_directory(&paths.view_root)?;
    let content_root_path = store.root().join("sha256");
    let _content_root = if manifest.is_empty() {
        None
    } else {
        Some(open_mutable_directory(&content_root_path)?)
    };
    let mut content_fanouts = BTreeMap::new();
    for record in manifest.files() {
        let relative = content_path(&record.sha256).map_err(|_| {
            PackageSnapshotError::ContentPathConstructionFailed {
                digest: record.sha256,
            }
        })?;
        let fanout =
            relative
                .get(7..9)
                .ok_or(PackageSnapshotError::ContentPathConstructionFailed {
                    digest: record.sha256,
                })?;
        if !content_fanouts.contains_key(fanout) {
            let path = content_root_path.join(fanout);
            content_fanouts.insert(fanout.to_owned(), open_mutable_directory(&path)?);
        }
    }
    let mut retained_directories = BTreeMap::new();
    for normalized in &validated.directories {
        let path = join_normalized(&paths.view_root, normalized);
        retained_directories.insert(normalized.clone(), ensure_direct_directory(&path)?);
    }

    for record in manifest.files() {
        let source_path = content_blob_path(store.root(), &record.sha256)?;
        let destination = join_normalized(&paths.view_root, &record.normalized_path);
        let source_file = open_verified_file(
            &source_path,
            &record.normalized_path,
            record.size,
            record.sha256,
        )?;
        let source_identity = FileIdentityLease::from_file(source_file)
            .map_err(|source| io_error("retain content blob identity", &source_path, source))?;
        let expectation = ViewLinkExpectation {
            source_path: &source_path,
            destination: &destination,
            normalized_path: &record.normalized_path,
            expected_size: record.size,
            expected_digest: record.sha256,
            source_identity: &source_identity,
        };
        create_or_verify_view_link(&expectation, counts)?;
    }
    Ok(())
}

struct ViewLinkExpectation<'a> {
    source_path: &'a Path,
    destination: &'a Path,
    normalized_path: &'a str,
    expected_size: u64,
    expected_digest: Sha256Digest,
    source_identity: &'a FileIdentityLease,
}

fn create_or_verify_view_link(
    expectation: &ViewLinkExpectation<'_>,
    counts: &mut PublicationCounts,
) -> Result<(), PackageSnapshotError> {
    create_or_verify_view_link_with(expectation, counts, |source, destination| {
        fs::hard_link(source, destination)
    })
}

fn create_or_verify_view_link_with<F>(
    expectation: &ViewLinkExpectation<'_>,
    counts: &mut PublicationCounts,
    create_link: F,
) -> Result<(), PackageSnapshotError>
where
    F: FnOnce(&Path, &Path) -> std::io::Result<()>,
{
    if let Some(destination_file) = open_optional_verified_file(
        expectation.destination,
        expectation.normalized_path,
        expectation.expected_size,
        expectation.expected_digest,
    )? {
        verify_link_identity(
            destination_file,
            expectation.destination,
            expectation.normalized_path,
            expectation.source_identity,
        )?;
        increment(&mut counts.reused_links)?;
        return Ok(());
    }

    let creation_error = create_link(expectation.source_path, expectation.destination).err();
    let Some(destination_file) = open_optional_verified_file(
        expectation.destination,
        expectation.normalized_path,
        expectation.expected_size,
        expectation.expected_digest,
    )?
    else {
        return Err(creation_error.map_or_else(
            || PackageSnapshotError::FileMismatch {
                normalized_path: expectation.normalized_path.to_owned(),
            },
            |source| {
                io_error(
                    "publish package-view hard link",
                    expectation.destination,
                    source,
                )
            },
        ));
    };
    verify_link_identity(
        destination_file,
        expectation.destination,
        expectation.normalized_path,
        expectation.source_identity,
    )?;
    if creation_error.is_some() {
        increment(&mut counts.reused_links)
    } else {
        increment(&mut counts.created_links)
    }
}

fn verify_link_identity(
    destination_file: File,
    destination: &Path,
    normalized_path: &str,
    source_identity: &FileIdentityLease,
) -> Result<(), PackageSnapshotError> {
    let destination_identity = FileIdentityLease::from_file(destination_file)
        .map_err(|source| io_error("retain package-view file identity", destination, source))?;
    if source_identity.has_same_identity(&destination_identity) {
        Ok(())
    } else {
        Err(PackageSnapshotError::FileMismatch {
            normalized_path: normalized_path.to_owned(),
        })
    }
}

fn lease_view<'store>(
    store: &'store ManagedArtifactStore,
    manifest: &PackageTreeManifest,
    validated: &ValidatedSnapshot,
    counts: PublicationCounts,
) -> Result<PackageSnapshotLease<'store>, PackageSnapshotError> {
    let paths = view_paths(store.root(), manifest.package_tree_merkle())?;
    let mut ancestors = Vec::new();
    ancestors
        .try_reserve_exact(2)
        .map_err(|_| PackageSnapshotError::AllocationFailed {
            resource: "view ancestor leases",
        })?;
    ancestors.push(open_mutable_directory(&paths.package_views)?);
    ancestors.push(open_mutable_directory(&paths.identity_root)?);

    let mut directories = BTreeMap::new();
    directories.insert(
        String::new(),
        DirectoryLease {
            path: paths.view_root.clone(),
            identity: open_direct_directory(&paths.view_root)?,
        },
    );
    for normalized in &validated.directories {
        let path = join_normalized(&paths.view_root, normalized);
        directories.insert(
            normalized.clone(),
            DirectoryLease {
                path: path.clone(),
                identity: open_direct_directory(&path)?,
            },
        );
    }

    let mut files = BTreeMap::new();
    for record in manifest.files() {
        let path = join_normalized(&paths.view_root, &record.normalized_path);
        let file = open_verified_file(&path, &record.normalized_path, record.size, record.sha256)?;
        let identity = FileIdentityLease::from_file(file)
            .map_err(|source| io_error("retain package-view file identity", &path, source))?;
        files.insert(
            record.normalized_path.clone(),
            SnapshotFileLease {
                size: record.size,
                digest: record.sha256,
                identity,
            },
        );
    }
    verify_membership(&directories, &files)?;
    store.lease.verify_root_path()?;

    Ok(PackageSnapshotLease {
        store,
        root: paths.view_root,
        package_tree_merkle: *manifest.package_tree_merkle(),
        file_count: manifest.files().len(),
        directory_count: validated.directory_count(),
        total_file_bytes: validated.total_file_bytes,
        created_blobs: counts.created_blobs,
        reused_blobs: counts.reused_blobs,
        created_links: counts.created_links,
        reused_links: counts.reused_links,
        platform: WindowsPackageSnapshotLease {
            _ancestors: ancestors,
            directories,
            files,
        },
    })
}

fn verify_membership(
    directories: &BTreeMap<String, DirectoryLease>,
    files: &BTreeMap<String, SnapshotFileLease>,
) -> Result<(), PackageSnapshotError> {
    let mut expected = BTreeMap::new();
    for directory in directories.keys().filter(|directory| !directory.is_empty()) {
        expected.insert(directory.clone(), ViewEntryKind::Directory);
    }
    for normalized_path in files.keys() {
        expected.insert(normalized_path.clone(), ViewEntryKind::File);
    }

    let mut actual = BTreeMap::new();
    for (normalized_directory, directory) in directories {
        let entries = fs::read_dir(&directory.path).map_err(|source| {
            io_error("enumerate package-view directory", &directory.path, source)
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| {
                io_error("read package-view directory entry", &directory.path, source)
            })?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| PackageSnapshotError::MembershipMismatch)?;
            let normalized = if normalized_directory.is_empty() {
                name
            } else {
                format!("{normalized_directory}/{name}")
            };
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|source| io_error("inspect package-view entry", &path, source))?;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(PackageSnapshotError::ReparsePoint { path });
            }
            let kind = if metadata.is_dir() {
                ViewEntryKind::Directory
            } else if metadata.is_file() {
                ViewEntryKind::File
            } else {
                return Err(PackageSnapshotError::MembershipMismatch);
            };
            if actual.len() >= expected.len() || actual.insert(normalized, kind).is_some() {
                return Err(PackageSnapshotError::MembershipMismatch);
            }
        }
    }
    if actual == expected {
        Ok(())
    } else {
        Err(PackageSnapshotError::MembershipMismatch)
    }
}

struct ViewPaths {
    package_views: PathBuf,
    identity_root: PathBuf,
    view_root: PathBuf,
}

fn view_paths(
    store_root: &Path,
    package_tree_merkle: &Sha256Digest,
) -> Result<ViewPaths, PackageSnapshotError> {
    let package_views = store_root.join("package-views");
    let identity_root = package_views.join(view_identity_name(package_tree_merkle)?);
    let view_root = identity_root.join("tree");
    Ok(ViewPaths {
        package_views,
        identity_root,
        view_root,
    })
}

fn view_identity_name(digest: &Sha256Digest) -> Result<String, PackageSnapshotError> {
    let mut name = String::from("sha256-");
    name.try_reserve_exact(64)
        .map_err(|_| PackageSnapshotError::AllocationFailed {
            resource: "package view identity",
        })?;
    for byte in digest.as_bytes() {
        name.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
        name.push(char::from(LOWER_HEX[usize::from(byte & 0x0f)]));
    }
    Ok(name)
}

fn content_blob_path(
    store_root: &Path,
    digest: &Sha256Digest,
) -> Result<PathBuf, PackageSnapshotError> {
    let relative = content_path(digest)
        .map_err(|_| PackageSnapshotError::ContentPathConstructionFailed { digest: *digest })?;
    Ok(store_root.join(relative))
}

fn join_normalized(root: &Path, normalized: &str) -> PathBuf {
    let mut path = root.to_path_buf();
    for component in normalized.split('/') {
        path.push(component);
    }
    path
}

fn ensure_direct_directory(path: &Path) -> Result<FileIdentityLease, PackageSnapshotError> {
    ensure_direct_directory_with(path, |path| fs::create_dir(path))
}

fn ensure_direct_directory_with<F>(
    path: &Path,
    create_directory: F,
) -> Result<FileIdentityLease, PackageSnapshotError>
where
    F: FnOnce(&Path) -> std::io::Result<()>,
{
    if let Some(directory) = open_optional_directory(path, FILE_SHARE_READ | FILE_SHARE_WRITE)? {
        return Ok(directory);
    }
    let creation_error = create_directory(path).err();
    match open_optional_directory(path, FILE_SHARE_READ | FILE_SHARE_WRITE)? {
        Some(directory) => Ok(directory),
        None => Err(creation_error.map_or_else(
            || {
                io_error(
                    "open newly created package-view directory",
                    path,
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "package-view directory was not found after creation",
                    ),
                )
            },
            |source| io_error("create package-view directory", path, source),
        )),
    }
}

fn open_direct_directory(path: &Path) -> Result<FileIdentityLease, PackageSnapshotError> {
    open_directory(path, FILE_SHARE_READ)
}

fn open_mutable_directory(path: &Path) -> Result<FileIdentityLease, PackageSnapshotError> {
    open_directory(path, FILE_SHARE_READ | FILE_SHARE_WRITE)
}

fn open_directory(path: &Path, share_mode: u32) -> Result<FileIdentityLease, PackageSnapshotError> {
    open_optional_directory(path, share_mode)?.ok_or_else(|| {
        io_error(
            "open direct package-view directory",
            path,
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "package-view directory was not found",
            ),
        )
    })
}

fn open_optional_directory(
    path: &Path,
    share_mode: u32,
) -> Result<Option<FileIdentityLease>, PackageSnapshotError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(share_mode)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = match retry_transient_directory_open(|| options.open(path)) {
        Ok(file) => file,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(io_error("open direct package-view directory", path, source));
        }
    };
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect package-view directory", path, source))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(PackageSnapshotError::ReparsePoint {
            path: path.to_path_buf(),
        });
    }
    if !metadata.is_dir() {
        return Err(PackageSnapshotError::NotDirectory {
            path: path.to_path_buf(),
        });
    }
    FileIdentityLease::from_file(file)
        .map(Some)
        .map_err(|source| io_error("retain package-view directory identity", path, source))
}

fn retry_transient_directory_open<T>(
    mut open: impl FnMut() -> std::io::Result<T>,
) -> std::io::Result<T> {
    let mut attempts = 1_usize;
    loop {
        match open() {
            Err(source)
                if source.raw_os_error() == Some(ERROR_SHARING_VIOLATION_CODE)
                    && attempts < MAX_TRANSIENT_DIRECTORY_OPEN_ATTEMPTS =>
            {
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            result => return result,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileMetadataSnapshot {
    attributes: u32,
    creation_time: u64,
    last_write_time: u64,
    size: u64,
}

fn open_verified_file(
    path: &Path,
    normalized_path: &str,
    expected_size: u64,
    expected_digest: Sha256Digest,
) -> Result<File, PackageSnapshotError> {
    open_optional_verified_file(path, normalized_path, expected_size, expected_digest)?.ok_or_else(
        || PackageSnapshotError::FileMismatch {
            normalized_path: normalized_path.to_owned(),
        },
    )
}

fn open_optional_verified_file(
    path: &Path,
    normalized_path: &str,
    expected_size: u64,
    expected_digest: Sha256Digest,
) -> Result<Option<File>, PackageSnapshotError> {
    let mut options = OpenOptions::new();
    options.read(true).share_mode(FILE_SHARE_READ).custom_flags(
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
    );
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io_error("open package-view file", path, source)),
    };
    let before = file_metadata(&file, path, normalized_path)?;
    if before.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || before.size != expected_size {
        return Err(PackageSnapshotError::FileMismatch {
            normalized_path: normalized_path.to_owned(),
        });
    }
    let first = hash_exact(&mut file, path, expected_size)?;
    let second = hash_exact(&mut file, path, expected_size)?;
    let after = file_metadata(&file, path, normalized_path)?;
    if before != after || first != second || first != expected_digest {
        return Err(PackageSnapshotError::FileMismatch {
            normalized_path: normalized_path.to_owned(),
        });
    }
    Ok(Some(file))
}

fn file_metadata(
    file: &File,
    path: &Path,
    normalized_path: &str,
) -> Result<FileMetadataSnapshot, PackageSnapshotError> {
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect package-view file", path, source))?;
    if !metadata.is_file() {
        return Err(PackageSnapshotError::FileMismatch {
            normalized_path: normalized_path.to_owned(),
        });
    }
    Ok(FileMetadataSnapshot {
        attributes: metadata.file_attributes(),
        creation_time: metadata.creation_time(),
        last_write_time: metadata.last_write_time(),
        size: metadata.file_size(),
    })
}

fn hash_exact(
    file: &mut File,
    path: &Path,
    expected_bytes: u64,
) -> Result<Sha256Digest, PackageSnapshotError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|source| io_error("rewind package-view file", path, source))?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    while total < expected_bytes {
        let request = usize::try_from(expected_bytes - total)
            .map_or(buffer.len(), |remaining| remaining.min(buffer.len()));
        let read = file
            .read(&mut buffer[..request])
            .map_err(|source| io_error("read package-view file", path, source))?;
        if read == 0 {
            return Err(io_error(
                "read complete package-view file",
                path,
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "package-view file ended before its declared length",
                ),
            ));
        }
        total = total
            .checked_add(read as u64)
            .ok_or(PackageSnapshotError::TotalByteCountOverflow)?;
        hasher.update(&buffer[..read]);
    }
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

fn increment(value: &mut usize) -> Result<(), PackageSnapshotError> {
    *value = value
        .checked_add(1)
        .ok_or(PackageSnapshotError::PublicationCountOverflow)?;
    Ok(())
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> PackageSnapshotError {
    PackageSnapshotError::Io {
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
    fn concurrent_hard_link_winner_is_reused_after_any_creation_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = tempdir()?;
        let source_path = fixture.path().join("source.bin");
        let destination = fixture.path().join("destination.bin");
        fs::write(&source_path, b"shared")?;
        let digest = Sha256Digest::from_bytes(Sha256::digest(b"shared").into());
        let source_file = open_verified_file(&source_path, "source.bin", 6, digest)?;
        let source_identity = FileIdentityLease::from_file(source_file)?;
        let mut counts = PublicationCounts::default();
        let expectation = ViewLinkExpectation {
            source_path: &source_path,
            destination: &destination,
            normalized_path: "destination.bin",
            expected_size: 6,
            expected_digest: digest,
            source_identity: &source_identity,
        };

        create_or_verify_view_link_with(&expectation, &mut counts, |source, destination| {
            fs::hard_link(source, destination)?;
            Err(std::io::Error::from_raw_os_error(32))
        })?;

        assert_eq!(counts.created_links, 0);
        assert_eq!(counts.reused_links, 1);
        assert_eq!(fs::read(destination)?, b"shared");
        Ok(())
    }

    #[test]
    fn concurrent_directory_winner_is_reopened_after_any_creation_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = tempdir()?;
        let path = fixture.path().join("winner");

        let _lease = ensure_direct_directory_with(&path, |path| {
            fs::create_dir(path)?;
            Err(std::io::Error::from_raw_os_error(32))
        })?;

        assert!(path.is_dir());
        Ok(())
    }

    #[test]
    fn direct_directory_open_retries_only_bounded_sharing_violations()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut transient_attempts = 0_usize;
        let value = retry_transient_directory_open(|| {
            transient_attempts += 1;
            if transient_attempts < 3 {
                Err(std::io::Error::from_raw_os_error(32))
            } else {
                Ok(7_u8)
            }
        })?;
        assert_eq!(value, 7);
        assert_eq!(transient_attempts, 3);

        let mut permanent_attempts = 0_usize;
        let error = retry_transient_directory_open(|| -> std::io::Result<()> {
            permanent_attempts += 1;
            Err(std::io::Error::from_raw_os_error(5))
        })
        .err()
        .ok_or("a permanent error must fail")?;
        assert_eq!(error.raw_os_error(), Some(5));
        assert_eq!(permanent_attempts, 1);
        Ok(())
    }
}
