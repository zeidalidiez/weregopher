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
use weregopher_windows::FileIdentityLease;
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
    store::windows::{Publication, publish_reader},
};

const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

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
        match publish_reader(
            &store.lease,
            &record.sha256,
            expected_bytes,
            &mut reader,
            limits.temp_attempts,
        )? {
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
        match fs::symlink_metadata(&destination) {
            Ok(_) => increment(&mut counts.reused_links)?,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                match fs::hard_link(&source_path, &destination) {
                    Ok(()) => increment(&mut counts.created_links)?,
                    Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                        increment(&mut counts.reused_links)?;
                    }
                    Err(source) => {
                        return Err(io_error(
                            "publish package-view hard link",
                            &destination,
                            source,
                        ));
                    }
                }
            }
            Err(source) => {
                return Err(io_error(
                    "inspect package-view destination",
                    &destination,
                    source,
                ));
            }
        }
        let destination_file = open_verified_file(
            &destination,
            &record.normalized_path,
            record.size,
            record.sha256,
        )?;
        let destination_identity =
            FileIdentityLease::from_file(destination_file).map_err(|source| {
                io_error("retain package-view file identity", &destination, source)
            })?;
        if !source_identity.has_same_identity(&destination_identity) {
            return Err(PackageSnapshotError::FileMismatch {
                normalized_path: record.normalized_path.clone(),
            });
        }
    }
    Ok(())
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
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(source) => return Err(io_error("create package-view directory", path, source)),
    }
    open_mutable_directory(path)
}

fn open_direct_directory(path: &Path) -> Result<FileIdentityLease, PackageSnapshotError> {
    open_directory(path, FILE_SHARE_READ)
}

fn open_mutable_directory(path: &Path) -> Result<FileIdentityLease, PackageSnapshotError> {
    open_directory(path, FILE_SHARE_READ | FILE_SHARE_WRITE)
}

fn open_directory(path: &Path, share_mode: u32) -> Result<FileIdentityLease, PackageSnapshotError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(share_mode)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(path)
        .map_err(|source| io_error("open direct package-view directory", path, source))?;
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
        .map_err(|source| io_error("retain package-view directory identity", path, source))
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
    let mut options = OpenOptions::new();
    options.read(true).share_mode(FILE_SHARE_READ).custom_flags(
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
    );
    let mut file = options.open(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            PackageSnapshotError::FileMismatch {
                normalized_path: normalized_path.to_owned(),
            }
        } else {
            io_error("open package-view file", path, source)
        }
    })?;
    let before = file_metadata(&file, path)?;
    if before.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || before.size != expected_size {
        return Err(PackageSnapshotError::FileMismatch {
            normalized_path: normalized_path.to_owned(),
        });
    }
    let first = hash_exact(&mut file, path, expected_size)?;
    let second = hash_exact(&mut file, path, expected_size)?;
    let after = file_metadata(&file, path)?;
    if before != after || first != second || first != expected_digest {
        return Err(PackageSnapshotError::FileMismatch {
            normalized_path: normalized_path.to_owned(),
        });
    }
    Ok(file)
}

fn file_metadata(file: &File, path: &Path) -> Result<FileMetadataSnapshot, PackageSnapshotError> {
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect package-view file", path, source))?;
    if !metadata.is_file() {
        return Err(PackageSnapshotError::Io {
            operation: "inspect package-view regular file",
            path: path.to_path_buf(),
            source: std::io::Error::other("package-view entry is not a regular file"),
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
