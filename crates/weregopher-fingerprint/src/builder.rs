//! Pure, deterministic package-tree Merkle construction.

use std::collections::{BTreeMap, btree_map::Entry};

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use weregopher_domain::Sha256Digest;

use crate::{
    MAX_NORMALIZED_PACKAGE_PATH_CHARS, PACKAGE_TREE_FORMAT_VERSION, PackageFileKind,
    PackageFileRecord, PackageTreeManifest,
};

const FILE_HASH_DOMAIN: &[u8] = b"weregopher.package.file.v1\0";
const DIRECTORY_HASH_DOMAIN: &[u8] = b"weregopher.package.directory.v1\0";

/// Constructs a canonical package manifest from already-observed file records.
///
/// The function performs no filesystem access. Callers must supply content digests
/// and metadata obtained under their own immutable snapshot or build lease.
///
/// # Errors
///
/// Returns [`ManifestError`] when records contain invalid or conflicting paths,
/// case-insensitive path aliases, or inconsistent file metadata.
pub fn build_package_manifest(
    mut files: Vec<PackageFileRecord>,
) -> Result<PackageTreeManifest, ManifestError> {
    files.sort_by(|left, right| left.normalized_path.cmp(&right.normalized_path));

    let mut tree = DirectoryNode::default();
    let mut case_folded_paths = BTreeMap::<String, String>::new();
    for record in &files {
        validate_normalized_path(&record.normalized_path)?;
        validate_executable_kind(record)?;
        reject_case_collision(&mut case_folded_paths, &record.normalized_path)?;
        tree.insert_leaf(
            &record.normalized_path,
            hash_file_record(record),
            record.kind,
        )?;
    }

    Ok(PackageTreeManifest {
        format_version: PACKAGE_TREE_FORMAT_VERSION,
        package_tree_merkle: tree.hash(""),
        files,
    })
}

fn validate_executable_kind(record: &PackageFileRecord) -> Result<(), ManifestError> {
    let expected = matches!(
        record.kind,
        PackageFileKind::NativeModule | PackageFileKind::Executable
    );
    if record.executable == expected {
        Ok(())
    } else {
        Err(ManifestError::ExecutableKindMismatch {
            path: record.normalized_path.clone(),
        })
    }
}

fn reject_case_collision(
    observed: &mut BTreeMap<String, String>,
    normalized_path: &str,
) -> Result<(), ManifestError> {
    let mut prefix = String::new();
    for component in normalized_path.split('/') {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(component);

        let folded = prefix.to_lowercase();
        if let Some(first) = observed.get(&folded) {
            if first != &prefix {
                return Err(ManifestError::CaseInsensitiveCollision {
                    first: first.clone(),
                    second: prefix,
                });
            }
        } else {
            observed.insert(folded, prefix.clone());
        }
    }
    Ok(())
}

pub(crate) fn validate_normalized_path(path: &str) -> Result<(), ManifestError> {
    let invalid_length = path.chars().count() > MAX_NORMALIZED_PACKAGE_PATH_CHARS;
    let invalid_character = path
        .chars()
        .any(|character| character.is_control() || matches!(character, '\\' | ':'));
    let invalid_segment = path
        .split('/')
        .any(|component| component.is_empty() || matches!(component, "." | ".."));
    if invalid_length || invalid_character || invalid_segment {
        Err(ManifestError::InvalidPath {
            path: path.to_owned(),
        })
    } else {
        Ok(())
    }
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
    Sha256Digest::from_bytes(hasher.finalize().into())
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
    fn insert_leaf(
        &mut self,
        normalized_path: &str,
        hash: Sha256Digest,
        kind: PackageFileKind,
    ) -> Result<(), ManifestError> {
        let mut components: Vec<&str> = normalized_path.split('/').collect();
        let filename = components.pop().unwrap_or_default();
        let parent = self.directory_mut(&components, normalized_path)?;
        match parent.children.entry(filename.to_owned()) {
            Entry::Vacant(entry) => {
                entry.insert(TreeChild::Leaf { hash, kind });
                Ok(())
            }
            Entry::Occupied(_) => Err(ManifestError::PathConflict {
                path: normalized_path.to_owned(),
            }),
        }
    }

    fn directory_mut<'a>(
        &'a mut self,
        components: &[&str],
        full_path: &str,
    ) -> Result<&'a mut Self, ManifestError> {
        if components.is_empty() {
            return Ok(self);
        }
        let child = match self.children.entry(components[0].to_owned()) {
            Entry::Vacant(entry) => entry.insert(TreeChild::Directory(Self::default())),
            Entry::Occupied(entry) => entry.into_mut(),
        };
        match child {
            TreeChild::Directory(directory) => directory.directory_mut(&components[1..], full_path),
            TreeChild::Leaf { .. } => Err(ManifestError::PathConflict {
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
        Sha256Digest::from_bytes(hasher.finalize().into())
    }
}

/// A package manifest could not be represented as one canonical tree.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ManifestError {
    /// A path was not a nonempty, root-relative `/`-separated canonical path.
    #[error("package record path is not canonical: {path:?}")]
    InvalidPath {
        /// Rejected path.
        path: String,
    },
    /// Two preserved spellings collapse under conservative Windows case folding.
    #[error("case-insensitive package path collision between {first:?} and {second:?}")]
    CaseInsensitiveCollision {
        /// First observed spelling.
        first: String,
        /// Conflicting spelling.
        second: String,
    },
    /// Executability disagreed with the canonical file classification.
    #[error("package record executability disagrees with file kind: {path:?}")]
    ExecutableKindMismatch {
        /// Inconsistent record path.
        path: String,
    },
    /// A path was repeated or used as both a leaf and a directory.
    #[error("package path has conflicting entry types: {path}")]
    PathConflict {
        /// Conflicting normalized path.
        path: String,
    },
}
