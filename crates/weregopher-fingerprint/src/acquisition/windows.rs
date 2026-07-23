//! Windows implementation for bounded package-tree observation.

use std::{
    collections::BTreeMap,
    fs::{self, File, Metadata, OpenOptions},
    os::windows::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Component, Path, Prefix},
};

use weregopher_windows::{FileIdentityLease, windows_ordinal_case_key};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_READ,
};

use super::{
    ObservedTreeDirectory, ObservedTreeFile, PackageTreeObservation, PackageTreeObservationError,
    PackageTreeObservationLimits, join_normalized,
};
use crate::{ObservationError, ObservationLimits, build_package_manifest, observe_package_file};

const MAX_ROOT_COMPONENTS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryKind {
    Directory,
    File,
}

struct PendingEntry {
    normalized_path: String,
    depth: usize,
    kind: EntryKind,
}

struct ScanBudget {
    limits: PackageTreeObservationLimits,
    entry_count: usize,
    file_count: usize,
    directory_count: usize,
    path_bytes: usize,
    folded_paths: BTreeMap<Vec<u16>, String>,
}

impl ScanBudget {
    fn new(limits: PackageTreeObservationLimits) -> Self {
        Self {
            limits,
            entry_count: 0,
            file_count: 0,
            directory_count: 1,
            path_bytes: 0,
            folded_paths: BTreeMap::new(),
        }
    }

    fn retain_path(
        &mut self,
        filesystem_path: &Path,
        normalized_path: &str,
        depth: usize,
        kind: EntryKind,
    ) -> Result<(), PackageTreeObservationError> {
        let max_entries = self
            .limits
            .max_files()
            .checked_add(self.limits.max_directories())
            .and_then(|value| value.checked_sub(1))
            .ok_or(PackageTreeObservationError::InvalidLimits {
                reason: "package-tree aggregate entry limit overflowed",
            })?;
        self.entry_count =
            self.entry_count
                .checked_add(1)
                .ok_or(PackageTreeObservationError::InvalidLimits {
                    reason: "package-tree observed entry count overflowed",
                })?;
        match kind {
            EntryKind::File => {
                self.file_count = self.file_count.checked_add(1).ok_or(
                    PackageTreeObservationError::FileLimitExceeded {
                        max: self.limits.max_files(),
                    },
                )?;
                if self.file_count > self.limits.max_files() {
                    return Err(PackageTreeObservationError::FileLimitExceeded {
                        max: self.limits.max_files(),
                    });
                }
            }
            EntryKind::Directory => {
                self.directory_count = self.directory_count.checked_add(1).ok_or(
                    PackageTreeObservationError::DirectoryLimitExceeded {
                        max: self.limits.max_directories(),
                    },
                )?;
                if self.directory_count > self.limits.max_directories() {
                    return Err(PackageTreeObservationError::DirectoryLimitExceeded {
                        max: self.limits.max_directories(),
                    });
                }
            }
        }
        if self.entry_count > max_entries {
            return Err(PackageTreeObservationError::EntryLimitExceeded { max: max_entries });
        }
        if depth > self.limits.max_depth() {
            return Err(PackageTreeObservationError::DepthLimitExceeded {
                path: filesystem_path.to_path_buf(),
                actual: depth,
                max: self.limits.max_depth(),
            });
        }
        self.path_bytes = self.path_bytes.checked_add(normalized_path.len()).ok_or(
            PackageTreeObservationError::PathBytesExceeded {
                max: self.limits.max_path_bytes(),
            },
        )?;
        if self.path_bytes > self.limits.max_path_bytes() {
            return Err(PackageTreeObservationError::PathBytesExceeded {
                max: self.limits.max_path_bytes(),
            });
        }

        let folded = windows_ordinal_case_key(normalized_path).map_err(|source| {
            io_error(
                "derive Windows ordinal package path key",
                filesystem_path,
                source,
            )
        })?;
        if let Some(first) = self.folded_paths.get(&folded) {
            if first != normalized_path {
                return Err(PackageTreeObservationError::CaseInsensitiveCollision {
                    first: try_clone_string(first, "Windows ordinal package collision")?,
                    second: try_clone_string(normalized_path, "Windows ordinal package collision")?,
                });
            }
        } else {
            self.folded_paths.insert(
                folded,
                try_clone_string(normalized_path, "Windows ordinal package paths")?,
            );
        }
        Ok(())
    }
}

fn try_clone_string(
    source: &str,
    resource: &'static str,
) -> Result<String, PackageTreeObservationError> {
    let mut retained = String::new();
    retained
        .try_reserve_exact(source.len())
        .map_err(|_| PackageTreeObservationError::Allocation { resource })?;
    retained.push_str(source);
    Ok(retained)
}

#[allow(
    clippy::too_many_lines,
    reason = "the traversal keeps one auditable fail-closed state machine in lexical scope"
)]
pub(super) fn observe(
    root: &Path,
    limits: PackageTreeObservationLimits,
) -> Result<PackageTreeObservation, PackageTreeObservationError> {
    validate_root_path(root)?;
    let (root_ancestors, root_identity) = open_root_chain(root)?;

    let mut directories = Vec::new();
    directories
        .try_reserve_exact(1)
        .map_err(|_| PackageTreeObservationError::Allocation {
            resource: "package directory leases",
        })?;
    directories.push(ObservedTreeDirectory {
        normalized_path: String::new(),
        identity_lease: root_identity,
    });

    let mut files = Vec::new();
    let mut stack = Vec::new();
    stack
        .try_reserve_exact(1)
        .map_err(|_| PackageTreeObservationError::Allocation {
            resource: "package directory traversal stack",
        })?;
    stack.push((0_usize, 0_usize));

    let mut budget = ScanBudget::new(limits);
    let mut total_file_bytes = 0_u64;
    while let Some((directory_index, depth)) = stack.pop() {
        let directory_normalized = directories[directory_index].normalized_path.clone();
        let directory_path = join_normalized(root, &directory_normalized);
        let entries =
            read_directory_entries(&directory_path, &directory_normalized, depth, &mut budget)?;
        if entries.is_empty() && !directory_normalized.is_empty() {
            return Err(PackageTreeObservationError::EmptyDirectory {
                path: directory_path,
            });
        }

        for entry in entries.into_iter().rev() {
            let filesystem_path = join_normalized(root, &entry.normalized_path);
            match entry.kind {
                EntryKind::Directory => {
                    if directories.len() >= limits.max_directories() {
                        return Err(PackageTreeObservationError::DirectoryLimitExceeded {
                            max: limits.max_directories(),
                        });
                    }
                    let identity_lease =
                        FileIdentityLease::from_file(open_direct_directory(&filesystem_path)?)
                            .map_err(|source| {
                                io_error(
                                    "read package directory identity",
                                    &filesystem_path,
                                    source,
                                )
                            })?;
                    directories.try_reserve(1).map_err(|_| {
                        PackageTreeObservationError::Allocation {
                            resource: "package directory leases",
                        }
                    })?;
                    let next_index = directories.len();
                    directories.push(ObservedTreeDirectory {
                        normalized_path: entry.normalized_path,
                        identity_lease,
                    });
                    stack
                        .try_reserve(1)
                        .map_err(|_| PackageTreeObservationError::Allocation {
                            resource: "package directory traversal stack",
                        })?;
                    stack.push((next_index, entry.depth));
                }
                EntryKind::File => {
                    if files.len() >= limits.max_files() {
                        return Err(PackageTreeObservationError::FileLimitExceeded {
                            max: limits.max_files(),
                        });
                    }
                    let remaining = limits
                        .max_total_file_bytes()
                        .checked_sub(total_file_bytes)
                        .ok_or(PackageTreeObservationError::TotalFileBytesExceeded {
                            observed: total_file_bytes,
                            max: limits.max_total_file_bytes(),
                        })?;
                    let file_limit = limits.max_file_bytes().min(remaining);
                    let observation = match observe_package_file(
                        &filesystem_path,
                        &entry.normalized_path,
                        ObservationLimits::for_tree_budget(file_limit),
                    ) {
                        Ok(observation) => observation,
                        Err(ObservationError::FileTooLarge { observed, .. })
                            if observed > remaining =>
                        {
                            return Err(PackageTreeObservationError::TotalFileBytesExceeded {
                                observed: total_file_bytes.saturating_add(observed),
                                max: limits.max_total_file_bytes(),
                            });
                        }
                        Err(source) => {
                            return Err(PackageTreeObservationError::FileObservation { source });
                        }
                    };
                    total_file_bytes = total_file_bytes
                        .checked_add(observation.record().size)
                        .ok_or(PackageTreeObservationError::TotalFileBytesExceeded {
                            observed: u64::MAX,
                            max: limits.max_total_file_bytes(),
                        })?;
                    if total_file_bytes > limits.max_total_file_bytes() {
                        return Err(PackageTreeObservationError::TotalFileBytesExceeded {
                            observed: total_file_bytes,
                            max: limits.max_total_file_bytes(),
                        });
                    }
                    files
                        .try_reserve(1)
                        .map_err(|_| PackageTreeObservationError::Allocation {
                            resource: "package file observations",
                        })?;
                    files.push(ObservedTreeFile { observation });
                }
            }
        }
    }

    files.sort_by(|left, right| {
        left.observation
            .record()
            .normalized_path
            .cmp(&right.observation.record().normalized_path)
    });
    let mut records = Vec::new();
    records.try_reserve_exact(files.len()).map_err(|_| {
        PackageTreeObservationError::Allocation {
            resource: "canonical package file records",
        }
    })?;
    records.extend(files.iter().map(|file| file.observation.record().clone()));
    let manifest = build_package_manifest(records)?;
    let observation = PackageTreeObservation {
        manifest,
        total_file_bytes,
        root: root.to_path_buf(),
        _root_ancestors: root_ancestors,
        directories,
        files,
        limits,
    };
    verify(&observation)?;
    Ok(observation)
}

pub(super) fn verify(
    observation: &PackageTreeObservation,
) -> Result<(), PackageTreeObservationError> {
    let mut expected = BTreeMap::new();
    for directory in observation.directories.iter().skip(1) {
        expected.insert(directory.normalized_path.clone(), EntryKind::Directory);
    }
    for file in &observation.files {
        expected.insert(
            file.observation.record().normalized_path.clone(),
            EntryKind::File,
        );
    }

    let mut actual = BTreeMap::new();
    let mut budget = ScanBudget::new(observation.limits);
    for directory in &observation.directories {
        let directory_path = join_normalized(&observation.root, &directory.normalized_path);
        verify_directory_identity(directory, &directory_path)?;
        let depth = normalized_depth(&directory.normalized_path);
        for entry in read_directory_entries(
            &directory_path,
            &directory.normalized_path,
            depth,
            &mut budget,
        )? {
            actual.insert(entry.normalized_path, entry.kind);
        }
    }
    if actual != expected {
        return Err(PackageTreeObservationError::ChangedDuringObservation {
            path: observation.root.clone(),
        });
    }

    for file in &observation.files {
        let filesystem_path = join_normalized(
            &observation.root,
            &file.observation.record().normalized_path,
        );
        file.observation
            .verify_current_path(&filesystem_path)
            .map_err(|source| map_file_verification_error(source, &filesystem_path))?;
    }
    Ok(())
}

fn read_directory_entries(
    directory_path: &Path,
    directory_normalized: &str,
    directory_depth: usize,
    budget: &mut ScanBudget,
) -> Result<Vec<PendingEntry>, PackageTreeObservationError> {
    let read_dir = fs::read_dir(directory_path)
        .map_err(|source| io_error("enumerate package directory", directory_path, source))?;
    let mut entries = Vec::new();
    for entry in read_dir {
        let entry = entry
            .map_err(|source| io_error("read package directory entry", directory_path, source))?;
        let filesystem_path = entry.path();
        let name = entry.file_name().into_string().map_err(|_| {
            PackageTreeObservationError::InvalidEntryName {
                path: filesystem_path.clone(),
            }
        })?;
        validate_windows_name(&name, &filesystem_path)?;
        let normalized_path = if directory_normalized.is_empty() {
            name
        } else {
            format!("{directory_normalized}/{name}")
        };
        crate::builder::validate_normalized_path(&normalized_path).map_err(|_| {
            PackageTreeObservationError::InvalidEntryName {
                path: filesystem_path.clone(),
            }
        })?;
        let depth = directory_depth.checked_add(1).ok_or(
            PackageTreeObservationError::DepthLimitExceeded {
                path: filesystem_path.clone(),
                actual: usize::MAX,
                max: budget.limits.max_depth(),
            },
        )?;
        let metadata = fs::symlink_metadata(&filesystem_path)
            .map_err(|source| io_error("read package entry metadata", &filesystem_path, source))?;
        let kind = classify_metadata(&metadata, &filesystem_path)?;
        budget.retain_path(&filesystem_path, &normalized_path, depth, kind)?;
        entries
            .try_reserve(1)
            .map_err(|_| PackageTreeObservationError::Allocation {
                resource: "package directory entries",
            })?;
        entries.push(PendingEntry {
            normalized_path,
            depth,
            kind,
        });
    }
    entries.sort_by(|left, right| left.normalized_path.cmp(&right.normalized_path));
    Ok(entries)
}

fn classify_metadata(
    metadata: &Metadata,
    path: &Path,
) -> Result<EntryKind, PackageTreeObservationError> {
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(PackageTreeObservationError::ReparsePoint {
            path: path.to_path_buf(),
        });
    }
    if metadata.is_dir() {
        Ok(EntryKind::Directory)
    } else if metadata.is_file() {
        Ok(EntryKind::File)
    } else {
        Err(PackageTreeObservationError::UnsupportedEntry {
            path: path.to_path_buf(),
        })
    }
}

fn validate_root_path(path: &Path) -> Result<(), PackageTreeObservationError> {
    if !path.is_absolute() {
        return Err(PackageTreeObservationError::InvalidRootPath {
            path: path.to_path_buf(),
        });
    }
    let mut count = 0_usize;
    for component in path.components() {
        count =
            count
                .checked_add(1)
                .ok_or_else(|| PackageTreeObservationError::InvalidRootPath {
                    path: path.to_path_buf(),
                })?;
        if count > MAX_ROOT_COMPONENTS {
            return Err(PackageTreeObservationError::InvalidRootPath {
                path: path.to_path_buf(),
            });
        }
        match component {
            Component::Prefix(prefix)
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::UNC(_, _)) => {}
            Component::RootDir | Component::Normal(_) => {}
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                return Err(PackageTreeObservationError::InvalidRootPath {
                    path: path.to_path_buf(),
                });
            }
        }
    }
    if count == 0 {
        return Err(PackageTreeObservationError::InvalidRootPath {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn open_root_chain(
    root: &Path,
) -> Result<(Vec<FileIdentityLease>, FileIdentityLease), PackageTreeObservationError> {
    let mut paths = root
        .ancestors()
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
        .collect::<Vec<_>>();
    paths.reverse();
    let mut leases = Vec::new();
    leases
        .try_reserve_exact(paths.len())
        .map_err(|_| PackageTreeObservationError::Allocation {
            resource: "package root ancestor leases",
        })?;
    for path in paths {
        let file = open_direct_directory(path)?;
        leases.push(
            FileIdentityLease::from_file(file)
                .map_err(|source| io_error("read package root ancestor identity", path, source))?,
        );
    }
    let root = leases
        .pop()
        .ok_or_else(|| PackageTreeObservationError::InvalidRootPath {
            path: root.to_path_buf(),
        })?;
    Ok((leases, root))
}

fn open_direct_directory(path: &Path) -> Result<File, PackageTreeObservationError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(path)
        .map_err(|source| io_error("open package directory", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("read opened-directory metadata", path, source))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(PackageTreeObservationError::ReparsePoint {
            path: path.to_path_buf(),
        });
    }
    if !metadata.is_dir() {
        return Err(PackageTreeObservationError::NotDirectory {
            path: path.to_path_buf(),
        });
    }
    Ok(file)
}

fn verify_directory_identity(
    directory: &ObservedTreeDirectory,
    filesystem_path: &Path,
) -> Result<(), PackageTreeObservationError> {
    let current = FileIdentityLease::from_file(open_direct_directory(filesystem_path)?).map_err(
        |source| {
            io_error(
                "recheck package directory identity",
                filesystem_path,
                source,
            )
        },
    )?;
    if directory.identity_lease.has_same_identity(&current) {
        Ok(())
    } else {
        Err(PackageTreeObservationError::ChangedDuringObservation {
            path: filesystem_path.to_path_buf(),
        })
    }
}

fn map_file_verification_error(
    source: ObservationError,
    filesystem_path: &Path,
) -> PackageTreeObservationError {
    match source {
        ObservationError::ChangedDuringObservation { .. }
        | ObservationError::PathIdentityChanged { .. } => {
            PackageTreeObservationError::ChangedDuringObservation {
                path: filesystem_path.to_path_buf(),
            }
        }
        source => PackageTreeObservationError::FileObservation { source },
    }
}

fn validate_windows_name(name: &str, path: &Path) -> Result<(), PackageTreeObservationError> {
    if name.ends_with([' ', '.']) {
        return Err(PackageTreeObservationError::AmbiguousWindowsName {
            path: path.to_path_buf(),
        });
    }
    let stem = name
        .split_once('.')
        .map_or(name, |(stem, _extension)| stem)
        .trim_end_matches([' ', '.']);
    let uppercase = stem.to_ascii_uppercase();
    let reserved = matches!(uppercase.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || uppercase.strip_prefix("COM").is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
        || uppercase.strip_prefix("LPT").is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        });
    if reserved {
        Err(PackageTreeObservationError::AmbiguousWindowsName {
            path: path.to_path_buf(),
        })
    } else {
        Ok(())
    }
}

fn normalized_depth(path: &str) -> usize {
    if path.is_empty() {
        0
    } else {
        path.split('/').count()
    }
}

fn io_error(
    operation: &'static str,
    path: &Path,
    source: std::io::Error,
) -> PackageTreeObservationError {
    PackageTreeObservationError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_superscript_dos_device_aliases() {
        for name in ["COM¹", "COM².log", "COM³", "LPT¹", "LPT².txt", "LPT³"] {
            assert!(matches!(
                validate_windows_name(name, Path::new(name)),
                Err(PackageTreeObservationError::AmbiguousWindowsName { .. })
            ));
        }
    }
}
