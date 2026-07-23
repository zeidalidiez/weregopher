//! Secure, deterministic filesystem traversal and Merkle construction.

use std::{
    collections::{BTreeMap, btree_map::Entry},
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read},
    path::{Component, Path, PathBuf},
};

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use walkdir::WalkDir;
use weregopher_domain::Sha256Digest;

use crate::{
    FingerprintOptions, PACKAGE_TREE_FORMAT_VERSION, PackageFileKind, PackageFileRecord,
    PackageTreeManifest,
};

const FILE_HASH_DOMAIN: &[u8] = b"weregopher.package.file.v1\0";
const DIRECTORY_HASH_DOMAIN: &[u8] = b"weregopher.package.directory.v1\0";
const SYMLINK_HASH_DOMAIN: &[u8] = b"weregopher.package.symlink-target.v1\0";
const READ_BUFFER_BYTES: usize = 64 * 1024;

/// Scans an installed package directory without following links or modifying package files.
///
/// # Errors
///
/// Returns [`FingerprintError`] when the root is not a direct directory, an entry
/// crosses the configured trust boundary, filesystem evidence changes during the
/// scan, or canonical path/Merkle construction cannot complete safely.
pub fn fingerprint_package(
    root: &Path,
    options: &FingerprintOptions,
) -> Result<PackageTreeManifest, FingerprintError> {
    // Matching complete observations catch additions, removals, link swaps, and
    // same-size/timestamp-restored mutations that one metadata check cannot. This
    // is stable observational evidence, not a build lease; activation must later
    // hold the separate lease required by the runtime contract.
    let first = scan_package_once(root, options)?;
    let second = scan_package_once(root, options)?;
    require_stable_observations(root, &first, second)
}

fn scan_package_once(
    root: &Path,
    options: &FingerprintOptions,
) -> Result<PackageTreeManifest, FingerprintError> {
    let root_metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(FingerprintError::RootNotDirectory {
                path: root.to_path_buf(),
            });
        }
        Err(source) => {
            return Err(FingerprintError::Io {
                path: root.to_path_buf(),
                source,
            });
        }
    };
    if !root_metadata.is_dir()
        || root_metadata.file_type().is_symlink()
        || is_reparse_point(&root_metadata)
    {
        return Err(FingerprintError::RootNotDirectory {
            path: root.to_path_buf(),
        });
    }
    let root_identity = file_identity(root, &root_metadata)?;

    let canonical_root = fs::canonicalize(root).map_err(|source| FingerprintError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    let mut tree = DirectoryNode::default();
    let mut records = Vec::new();
    let mut file_leases = Vec::new();
    let mut case_folded_paths = BTreeMap::<String, String>::new();
    let mut observed_identities = Vec::new();
    let mut observed_entries = 0_usize;

    for result in WalkDir::new(&canonical_root).follow_links(false) {
        let entry = result.map_err(|error| FingerprintError::Walk {
            path: error.path().map(Path::to_path_buf),
            message: error.to_string(),
        })?;
        if entry.depth() == 0 {
            continue;
        }

        let relative = entry.path().strip_prefix(&canonical_root).map_err(|_| {
            FingerprintError::EntryOutsideRoot {
                path: entry.path().to_path_buf(),
            }
        })?;
        let normalized_path = normalize_relative_path(relative)?;

        observed_entries = observed_entries.saturating_add(1);
        if observed_entries > options.max_entries {
            return Err(FingerprintError::EntryLimitExceeded {
                limit: options.max_entries,
            });
        }
        reject_case_collision(&mut case_folded_paths, &normalized_path)?;
        verify_entry_resolves_inside_root(entry.path(), &canonical_root)?;

        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|source| FingerprintError::Io {
                path: entry.path().to_path_buf(),
                source,
            })?;
        let identity = file_identity(entry.path(), &metadata)?;
        observed_identities.push((entry.path().to_path_buf(), identity));

        if metadata.file_type().is_symlink() {
            let record = scan_symbolic_link(entry.path(), normalized_path, &canonical_root)?;
            let leaf_hash = hash_file_record(&record);
            tree.insert_leaf(&record.normalized_path, leaf_hash, record.kind)?;
            records.push(record);
        } else if is_reparse_point(&metadata) {
            return Err(FingerprintError::UnsupportedReparsePoint {
                path: entry.path().to_path_buf(),
            });
        } else if metadata.is_dir() {
            tree.insert_directory(&normalized_path)?;
        } else if metadata.is_file() {
            let (record, lease) = scan_file(entry.path(), normalized_path, &canonical_root)?;
            let leaf_hash = hash_file_record(&record);
            tree.insert_leaf(&record.normalized_path, leaf_hash, record.kind)?;
            records.push(record);
            file_leases.push(lease);
        } else {
            return Err(FingerprintError::UnsupportedEntryType {
                path: entry.path().to_path_buf(),
            });
        }
    }

    records.sort_by(|left, right| left.normalized_path.cmp(&right.normalized_path));
    let manifest = PackageTreeManifest {
        format_version: PACKAGE_TREE_FORMAT_VERSION,
        package_tree_merkle: tree.hash(""),
        files: records,
    };
    for (path, identity) in observed_identities {
        verify_path_identity(&path, &identity)?;
    }
    verify_root_unchanged(root, &canonical_root, &root_identity)?;
    drop(file_leases);
    Ok(manifest)
}

fn require_stable_observations(
    root: &Path,
    first: &PackageTreeManifest,
    second: PackageTreeManifest,
) -> Result<PackageTreeManifest, FingerprintError> {
    if first != &second {
        return Err(FingerprintError::PackageChangedDuringScan {
            root: root.to_path_buf(),
        });
    }
    Ok(second)
}

fn verify_root_unchanged(
    root: &Path,
    canonical_root: &Path,
    expected_identity: &FileIdentity,
) -> Result<(), FingerprintError> {
    let metadata = fs::symlink_metadata(root).map_err(|source| FingerprintError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    let ending_root = fs::canonicalize(root).map_err(|source| FingerprintError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || is_reparse_point(&metadata)
        || !same_file_identity(&file_identity(root, &metadata)?, expected_identity)
        || ending_root != canonical_root
    {
        return Err(FingerprintError::PackageChangedDuringScan {
            root: root.to_path_buf(),
        });
    }
    Ok(())
}

fn scan_file(
    path: &Path,
    normalized_path: String,
    canonical_root: &Path,
) -> Result<(PackageFileRecord, File), FingerprintError> {
    let (sha256, size, lease) = hash_file_contents(path, canonical_root)?;
    let kind = classify_file(&normalized_path);
    let executable = matches!(
        kind,
        PackageFileKind::NativeModule | PackageFileKind::Executable
    );
    Ok((
        PackageFileRecord {
            normalized_path,
            size,
            sha256,
            executable,
            kind,
            signer_thumbprint: None,
        },
        lease,
    ))
}

fn scan_symbolic_link(
    path: &Path,
    normalized_path: String,
    canonical_root: &Path,
) -> Result<PackageFileRecord, FingerprintError> {
    let target_before = fs::read_link(path).map_err(|source| FingerprintError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let normalized_target = normalize_safe_link_target(path, &target_before)?;
    verify_entry_resolves_inside_root(path, canonical_root)?;
    let target_after = fs::read_link(path).map_err(|source| FingerprintError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if target_before != target_after {
        return Err(FingerprintError::EntryChangedDuringScan {
            path: path.to_path_buf(),
        });
    }
    let mut hasher = Sha256::new();
    hasher.update(SYMLINK_HASH_DOMAIN);
    update_length_prefixed(&mut hasher, normalized_target.as_bytes());
    let bytes: [u8; 32] = hasher.finalize().into();

    Ok(PackageFileRecord {
        normalized_path,
        size: normalized_target.len() as u64,
        sha256: Sha256Digest::from_bytes(bytes),
        executable: false,
        kind: PackageFileKind::SymbolicLink,
        signer_thumbprint: None,
    })
}

fn hash_file_contents(
    path: &Path,
    canonical_root: &Path,
) -> Result<(Sha256Digest, u64, File), FingerprintError> {
    let mut file = open_file_no_follow(path).map_err(|source| FingerprintError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let before = file.metadata().map_err(|source| FingerprintError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !before.is_file() || is_reparse_point(&before) {
        return Err(FingerprintError::EntryChangedDuringScan {
            path: path.to_path_buf(),
        });
    }
    let before_modified = before.modified().map_err(|source| FingerprintError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; READ_BUFFER_BYTES].into_boxed_slice();
    let mut read_total = 0_u64;

    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| FingerprintError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        read_total = read_total.saturating_add(read as u64);
    }

    let after = file.metadata().map_err(|source| FingerprintError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let after_modified = after.modified().map_err(|source| FingerprintError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let path_after = fs::symlink_metadata(path).map_err(|source| FingerprintError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let path_after_modified = path_after
        .modified()
        .map_err(|source| FingerprintError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let changed = before.len() != after.len()
        || read_total != after.len()
        || before_modified != after_modified
        || !path_after.is_file()
        || path_after.file_type().is_symlink()
        || is_reparse_point(&path_after)
        || path_after.len() != after.len()
        || path_after_modified != after_modified;
    if changed {
        return Err(FingerprintError::FileChangedDuringScan {
            path: path.to_path_buf(),
        });
    }
    verify_entry_resolves_inside_root(path, canonical_root)?;

    let bytes: [u8; 32] = hasher.finalize().into();
    Ok((Sha256Digest::from_bytes(bytes), read_total, file))
}

#[cfg(windows)]
#[derive(Debug)]
struct FileIdentity {
    lease: weregopher_windows::FileIdentityLease,
}

#[cfg(not(windows))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    file: u64,
}

fn verify_path_identity(path: &Path, expected: &FileIdentity) -> Result<(), FingerprintError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| FingerprintError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !same_file_identity(&file_identity(path, &metadata)?, expected) {
        return Err(FingerprintError::EntryChangedDuringScan {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(windows)]
fn file_identity(path: &Path, metadata: &Metadata) -> Result<FileIdentity, FingerprintError> {
    let file = if metadata.is_dir() {
        open_directory_no_follow(path)
    } else {
        open_file_no_follow(path)
    }
    .map_err(|source| FingerprintError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let lease = weregopher_windows::FileIdentityLease::from_file(file).map_err(|source| {
        FingerprintError::Io {
            path: path.to_path_buf(),
            source,
        }
    })?;
    Ok(FileIdentity { lease })
}

#[cfg(windows)]
fn same_file_identity(left: &FileIdentity, right: &FileIdentity) -> bool {
    left.lease.has_same_identity(&right.lease)
}

#[cfg(unix)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "the cross-platform scanner keeps one fallible file-identity interface"
)]
fn file_identity(path: &Path, metadata: &Metadata) -> Result<FileIdentity, FingerprintError> {
    use std::os::unix::fs::MetadataExt as _;

    let _ = path;
    Ok(FileIdentity {
        device: metadata.dev(),
        file: metadata.ino(),
    })
}

#[cfg(not(windows))]
fn same_file_identity(left: &FileIdentity, right: &FileIdentity) -> bool {
    left == right
}

#[cfg(not(any(unix, windows)))]
fn file_identity(path: &Path, _metadata: &Metadata) -> Result<FileIdentity, FingerprintError> {
    Err(FingerprintError::FileIdentityUnavailable {
        path: path.to_path_buf(),
    })
}

fn verify_entry_resolves_inside_root(
    path: &Path,
    canonical_root: &Path,
) -> Result<(), FingerprintError> {
    let resolved = fs::canonicalize(path).map_err(|source| FingerprintError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !resolved.starts_with(canonical_root) || resolved == canonical_root {
        return Err(FingerprintError::EntryOutsideRoot {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(windows)]
fn open_file_no_follow(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(windows)]
fn open_directory_no_follow(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(unix)]
fn open_file_no_follow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_file_no_follow(path: &Path) -> io::Result<File> {
    File::open(path)
}

fn classify_file(normalized_path: &str) -> PackageFileKind {
    let extension = Path::new(normalized_path)
        .extension()
        .and_then(|value| value.to_str());
    if extension.is_some_and(|value| value.eq_ignore_ascii_case("asar")) {
        PackageFileKind::Asar
    } else if extension.is_some_and(|value| value.eq_ignore_ascii_case("node")) {
        PackageFileKind::NativeModule
    } else if extension.is_some_and(|value| {
        ["exe", "dll", "com", "scr", "cpl"]
            .iter()
            .any(|candidate| value.eq_ignore_ascii_case(candidate))
    }) {
        PackageFileKind::Executable
    } else {
        PackageFileKind::Regular
    }
}

fn normalize_relative_path(path: &Path) -> Result<String, FingerprintError> {
    let mut segments = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(segment) => {
                let text = segment
                    .to_str()
                    .ok_or_else(|| FingerprintError::NonUnicodePath {
                        path: path.to_path_buf(),
                    })?;
                segments.push(text);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(FingerprintError::EntryOutsideRoot {
                    path: path.to_path_buf(),
                });
            }
        }
    }
    if segments.is_empty() {
        return Err(FingerprintError::EntryOutsideRoot {
            path: path.to_path_buf(),
        });
    }
    Ok(segments.join("/"))
}

fn normalize_safe_link_target(link: &Path, target: &Path) -> Result<String, FingerprintError> {
    let mut segments = Vec::new();
    for component in target.components() {
        match component {
            Component::Normal(segment) => {
                let text = segment
                    .to_str()
                    .ok_or_else(|| FingerprintError::NonUnicodePath {
                        path: target.to_path_buf(),
                    })?;
                segments.push(text);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(FingerprintError::UnsafeSymbolicLinkTarget {
                    link: link.to_path_buf(),
                    target: target.to_path_buf(),
                });
            }
        }
    }
    if segments.is_empty() {
        return Err(FingerprintError::UnsafeSymbolicLinkTarget {
            link: link.to_path_buf(),
            target: target.to_path_buf(),
        });
    }
    Ok(segments.join("/"))
}

fn reject_case_collision(
    observed: &mut BTreeMap<String, String>,
    normalized_path: &str,
) -> Result<(), FingerprintError> {
    let folded = normalized_path.to_lowercase();
    if let Some(first) = observed.get(&folded) {
        if first != normalized_path {
            return Err(FingerprintError::CaseInsensitiveCollision {
                first: first.clone(),
                second: normalized_path.to_owned(),
            });
        }
    } else {
        observed.insert(folded, normalized_path.to_owned());
    }
    Ok(())
}

fn hash_file_record(record: &PackageFileRecord) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(FILE_HASH_DOMAIN);
    update_length_prefixed(&mut hasher, record.normalized_path.as_bytes());
    hasher.update(record.size.to_le_bytes());
    hasher.update(record.sha256.as_bytes());
    hasher.update([u8::from(record.executable), record.kind.tag()]);
    match record.signer_thumbprint {
        Some(signer) => {
            hasher.update([1]);
            hasher.update(signer.as_bytes());
        }
        None => hasher.update([0]),
    }
    let bytes: [u8; 32] = hasher.finalize().into();
    Sha256Digest::from_bytes(bytes)
}

fn update_length_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

#[derive(Debug, Default)]
struct DirectoryNode {
    children: BTreeMap<String, TreeChild>,
}

#[derive(Debug)]
enum TreeChild {
    Directory(DirectoryNode),
    Leaf {
        hash: Sha256Digest,
        kind: PackageFileKind,
    },
}

impl DirectoryNode {
    fn insert_directory(&mut self, normalized_path: &str) -> Result<(), FingerprintError> {
        let components: Vec<&str> = normalized_path.split('/').collect();
        self.insert_directory_components(&components, normalized_path)
    }

    fn insert_directory_components(
        &mut self,
        components: &[&str],
        full_path: &str,
    ) -> Result<(), FingerprintError> {
        if components.is_empty() {
            return Ok(());
        }
        let child = match self.children.entry(components[0].to_owned()) {
            Entry::Vacant(entry) => entry.insert(TreeChild::Directory(Self::default())),
            Entry::Occupied(entry) => entry.into_mut(),
        };
        match child {
            TreeChild::Directory(directory) => {
                directory.insert_directory_components(&components[1..], full_path)
            }
            TreeChild::Leaf { .. } => Err(FingerprintError::PathTypeConflict {
                path: full_path.to_owned(),
            }),
        }
    }

    fn insert_leaf(
        &mut self,
        normalized_path: &str,
        hash: Sha256Digest,
        kind: PackageFileKind,
    ) -> Result<(), FingerprintError> {
        let mut components: Vec<&str> = normalized_path.split('/').collect();
        let filename = components
            .pop()
            .ok_or_else(|| FingerprintError::PathTypeConflict {
                path: normalized_path.to_owned(),
            })?;
        let parent_path = components.join("/");
        let parent = self.directory_mut(&components, &parent_path)?;
        match parent.children.entry(filename.to_owned()) {
            Entry::Vacant(entry) => {
                entry.insert(TreeChild::Leaf { hash, kind });
                Ok(())
            }
            Entry::Occupied(_) => Err(FingerprintError::PathTypeConflict {
                path: normalized_path.to_owned(),
            }),
        }
    }

    fn directory_mut<'a>(
        &'a mut self,
        components: &[&str],
        full_path: &str,
    ) -> Result<&'a mut Self, FingerprintError> {
        if components.is_empty() {
            return Ok(self);
        }
        let child = match self.children.entry(components[0].to_owned()) {
            Entry::Vacant(entry) => entry.insert(TreeChild::Directory(Self::default())),
            Entry::Occupied(entry) => entry.into_mut(),
        };
        match child {
            TreeChild::Directory(directory) => directory.directory_mut(&components[1..], full_path),
            TreeChild::Leaf { .. } => Err(FingerprintError::PathTypeConflict {
                path: full_path.to_owned(),
            }),
        }
    }

    fn hash(&self, normalized_path: &str) -> Sha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(DIRECTORY_HASH_DOMAIN);
        update_length_prefixed(&mut hasher, normalized_path.as_bytes());
        hasher.update((self.children.len() as u64).to_le_bytes());

        for (name, child) in &self.children {
            update_length_prefixed(&mut hasher, name.as_bytes());
            let child_path = if normalized_path.is_empty() {
                name.clone()
            } else {
                format!("{normalized_path}/{name}")
            };
            match child {
                TreeChild::Directory(directory) => {
                    hasher.update([1]);
                    hasher.update(directory.hash(&child_path).as_bytes());
                }
                TreeChild::Leaf { hash, kind } => {
                    hasher.update([2, kind.tag()]);
                    hasher.update(hash.as_bytes());
                }
            }
        }
        let bytes: [u8; 32] = hasher.finalize().into();
        Sha256Digest::from_bytes(bytes)
    }
}

#[cfg(windows)]
fn is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &Metadata) -> bool {
    false
}

/// A package tree could not be scanned into stable observational evidence.
#[derive(Debug, Error)]
pub enum FingerprintError {
    /// The supplied root is absent, not a directory, or itself a link/reparse point.
    #[error("package root is not a direct directory: {path}", path = .path.display())]
    RootNotDirectory {
        /// Supplied package root.
        path: PathBuf,
    },
    /// Filesystem access failed.
    #[error("filesystem error at {path}: {source}", path = .path.display())]
    Io {
        /// Affected path.
        path: PathBuf,
        /// Operating-system error.
        #[source]
        source: io::Error,
    },
    /// The filesystem did not provide the stable identity needed for race detection.
    #[error("stable filesystem identity is unavailable at {path}", path = .path.display())]
    FileIdentityUnavailable {
        /// Path lacking a stable volume/file identifier.
        path: PathBuf,
    },
    /// Recursive directory traversal failed.
    #[error("package traversal failed at {path:?}: {message}")]
    Walk {
        /// Best available affected path.
        path: Option<PathBuf>,
        /// Traversal error text.
        message: String,
    },
    /// Observed entry count exceeded the configured trust-boundary budget.
    #[error("package entry limit exceeded ({limit})")]
    EntryLimitExceeded {
        /// Configured maximum observed entries.
        limit: usize,
    },
    /// An entry could not be represented without lossy path conversion.
    #[error("package path is not valid Unicode: {path}", path = .path.display())]
    NonUnicodePath {
        /// Affected path.
        path: PathBuf,
    },
    /// A traversal entry did not remain below the canonical package root.
    #[error("package entry escaped root: {path}", path = .path.display())]
    EntryOutsideRoot {
        /// Escaping entry.
        path: PathBuf,
    },
    /// Two distinct names collapse under Windows-style case-insensitive lookup.
    #[error("case-insensitive package path collision: `{first}` and `{second}`")]
    CaseInsensitiveCollision {
        /// First observed spelling.
        first: String,
        /// Conflicting spelling.
        second: String,
    },
    /// Non-link reparse points require an explicit future semantic contract.
    #[error("unsupported package reparse point: {path}", path = .path.display())]
    UnsupportedReparsePoint {
        /// Reparse-point path.
        path: PathBuf,
    },
    /// A symbolic link is absolute, traverses upward, or otherwise escapes the safe subset.
    #[error(
        "unsafe symbolic link target at {link}: {target}",
        link = .link.display(),
        target = .target.display()
    )]
    UnsafeSymbolicLinkTarget {
        /// Link path.
        link: PathBuf,
        /// Rejected target.
        target: PathBuf,
    },
    /// Entry was neither a directory, regular file, nor supported symbolic link.
    #[error("unsupported package entry type: {path}", path = .path.display())]
    UnsupportedEntryType {
        /// Unsupported entry path.
        path: PathBuf,
    },
    /// Filesystem content changed while it was being hashed.
    #[error("package file changed during fingerprint scan: {path}", path = .path.display())]
    FileChangedDuringScan {
        /// Mutated file path.
        path: PathBuf,
    },
    /// A path changed type or link identity while it was inspected.
    #[error("package entry changed during fingerprint scan: {path}", path = .path.display())]
    EntryChangedDuringScan {
        /// Changed package path.
        path: PathBuf,
    },
    /// Two complete observations did not describe the same package tree.
    #[error("package tree changed between fingerprint observations: {root}", root = .root.display())]
    PackageChangedDuringScan {
        /// Package root whose observations differed.
        root: PathBuf,
    },
    /// A path was observed as both directory and leaf.
    #[error("package path has conflicting entry types: {path}")]
    PathTypeConflict {
        /// Conflicting normalized path.
        path: String,
    },
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    #[cfg(not(windows))]
    use super::verify_path_identity;
    use super::{
        FingerprintError, FingerprintOptions, file_identity, require_stable_observations,
        scan_package_once,
    };

    #[test]
    fn differing_complete_observations_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let package = tempdir()?;
        let file = package.path().join("app.js");
        fs::write(&file, b"first")?;
        let first = scan_package_once(package.path(), &FingerprintOptions::default())?;

        fs::write(file, b"second")?;
        let second = scan_package_once(package.path(), &FingerprintOptions::default())?;

        assert!(matches!(
            require_stable_observations(package.path(), &first, second),
            Err(FingerprintError::PackageChangedDuringScan { .. })
        ));
        Ok(())
    }

    #[cfg(not(windows))]
    #[test]
    fn replacing_a_path_with_matching_metadata_changes_its_file_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let package = tempdir()?;
        let path = package.path().join("app.js");
        let displaced = package.path().join("app.old.js");
        fs::write(&path, b"same-size")?;
        let metadata = fs::symlink_metadata(&path)?;
        let identity = file_identity(&path, &metadata)?;

        fs::rename(&path, displaced)?;
        fs::write(&path, b"same-size")?;

        assert!(matches!(
            verify_path_identity(&path, &identity),
            Err(FingerprintError::EntryChangedDuringScan { .. })
        ));
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn retained_file_identity_prevents_path_replacement() -> Result<(), Box<dyn std::error::Error>>
    {
        let package = tempdir()?;
        let path = package.path().join("app.js");
        let displaced = package.path().join("app.old.js");
        fs::write(&path, b"same-size")?;
        let metadata = fs::symlink_metadata(&path)?;
        let _identity = file_identity(&path, &metadata)?;

        let Err(error) = fs::rename(&path, displaced) else {
            return Err("retained file identity allowed rename".into());
        };
        assert_eq!(error.raw_os_error(), Some(32));
        Ok(())
    }
}
