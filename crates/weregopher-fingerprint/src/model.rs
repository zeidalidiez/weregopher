//! Serializable package-tree fingerprint evidence.

use std::fmt;

use schemars::JsonSchema;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, IgnoredAny, SeqAccess, Visitor},
};
use weregopher_domain::Sha256Digest;

/// Current deterministic package-tree Merkle algorithm version.
pub const PACKAGE_TREE_FORMAT_VERSION: u16 = 1;

/// Maximum Unicode scalar count accepted in one normalized package path.
pub const MAX_NORMALIZED_PACKAGE_PATH_CHARS: usize = 32_767;

/// Maximum file/link records retained by one package-tree manifest.
pub const MAX_PACKAGE_FILE_RECORDS: usize = 65_536;

/// Maximum aggregate UTF-8 bytes retained across normalized package paths.
pub const MAX_PACKAGE_RECORD_PATH_BYTES: usize = 16 * 1024 * 1024;

/// Canonical package-tree identity assembled from pre-observed package records.
///
/// The manifest binds its ordered records and Merkle root, but does not by itself
/// prove that acquisition used an immutable filesystem snapshot. That provenance
/// remains a separate property of the producer.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageTreeManifest {
    /// Version of path, leaf, and directory canonicalization rules.
    #[schemars(range(min = 1, max = 1))]
    pub(crate) format_version: u16,
    /// Root directory Merkle digest.
    pub(crate) package_tree_merkle: Sha256Digest,
    /// Canonically sorted included file/link records.
    #[schemars(length(max = 65_536))]
    pub(crate) files: Vec<PackageFileRecord>,
}

impl PackageTreeManifest {
    /// Returns the canonical package-tree format version.
    #[must_use]
    pub const fn format_version(&self) -> u16 {
        self.format_version
    }

    /// Returns the canonical Merkle root bound to the ordered records.
    #[must_use]
    pub const fn package_tree_merkle(&self) -> &Sha256Digest {
        &self.package_tree_merkle
    }

    /// Returns the canonically ordered package file records.
    #[must_use]
    pub fn files(&self) -> &[PackageFileRecord] {
        &self.files
    }

    /// Reports whether the manifest contains no package file records.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

impl<'de> Deserialize<'de> for PackageTreeManifest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedPackageTreeManifest::deserialize(deserializer)?;
        if unchecked.format_version != PACKAGE_TREE_FORMAT_VERSION {
            return Err(D::Error::custom("unsupported package-tree format version"));
        }

        let is_canonical_order = unchecked
            .files
            .windows(2)
            .all(|pair| pair[0].normalized_path.as_str() < pair[1].normalized_path.as_str());
        if !is_canonical_order {
            return Err(D::Error::custom(
                "package records are not in canonical path order",
            ));
        }

        let expected_root = unchecked.package_tree_merkle;
        let manifest = crate::build_package_manifest(unchecked.files).map_err(D::Error::custom)?;
        if manifest.package_tree_merkle != expected_root {
            return Err(D::Error::custom(
                "package-tree Merkle root does not match the canonical records",
            ));
        }
        Ok(manifest)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedPackageTreeManifest {
    format_version: u16,
    package_tree_merkle: Sha256Digest,
    #[serde(deserialize_with = "deserialize_package_file_records")]
    files: Vec<PackageFileRecord>,
}

/// Canonical evidence for one included package file or symbolic link.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageFileRecord {
    /// Root-relative path using `/`, with original case preserved.
    #[schemars(
        length(min = 1, max = 32_767),
        regex(
            pattern = r"^(?!.*(?:^|/)\.{1,2}(?:/|$))(?!.*//)[^/\\:\u0000-\u001f\u007f-\u009f](?:[^\\:\u0000-\u001f\u007f-\u009f]*[^/\\:\u0000-\u001f\u007f-\u009f])?$"
        )
    )]
    pub normalized_path: String,
    /// File byte length, or canonical link-target text length for a symbolic link.
    pub size: u64,
    /// Content digest, or domain-separated link-target digest.
    pub sha256: Sha256Digest,
    /// Whether the file is expected to contain directly loadable machine code.
    pub executable: bool,
    /// Deterministic file classification.
    pub kind: PackageFileKind,
    /// Authenticode signer thumbprint when a later evidence stage supplies it.
    pub signer_thumbprint: Option<Sha256Digest>,
}

/// Package file classification used by manifests and later analyzers.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageFileKind {
    /// Ordinary package file.
    Regular,
    /// Electron ASAR archive.
    Asar,
    /// Node/Electron native module.
    NativeModule,
    /// Windows executable image or loadable library.
    Executable,
    /// Symbolic link whose target semantics are part of package identity.
    SymbolicLink,
}

impl PackageFileKind {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Regular => 1,
            Self::Asar => 2,
            Self::NativeModule => 3,
            Self::Executable => 4,
            Self::SymbolicLink => 5,
        }
    }
}

fn deserialize_package_file_records<'de, D>(
    deserializer: D,
) -> Result<Vec<PackageFileRecord>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(PackageFileRecordsVisitor)
}

struct PackageFileRecordsVisitor;

impl<'de> Visitor<'de> for PackageFileRecordsVisitor {
    type Value = Vec<PackageFileRecord>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "at most {MAX_PACKAGE_FILE_RECORDS} package file records using at most {MAX_PACKAGE_RECORD_PATH_BYTES} aggregate path bytes"
        )
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let disclosed = sequence.size_hint().unwrap_or(0);
        if disclosed > MAX_PACKAGE_FILE_RECORDS {
            return Err(A::Error::custom(format_args!(
                "package file record limit is {MAX_PACKAGE_FILE_RECORDS}; input disclosed {disclosed}"
            )));
        }
        let capacity = disclosed.min(MAX_PACKAGE_FILE_RECORDS);
        let mut records = Vec::new();
        records
            .try_reserve_exact(capacity)
            .map_err(|_| A::Error::custom("package file record allocation failed"))?;
        let mut path_bytes = 0_usize;
        while records.len() < MAX_PACKAGE_FILE_RECORDS {
            let Some(record) = sequence.next_element::<PackageFileRecord>()? else {
                return Ok(records);
            };
            path_bytes = path_bytes
                .checked_add(record.normalized_path.len())
                .ok_or_else(|| {
                    A::Error::custom(format_args!(
                        "package record path bytes exceed {MAX_PACKAGE_RECORD_PATH_BYTES}"
                    ))
                })?;
            if path_bytes > MAX_PACKAGE_RECORD_PATH_BYTES {
                return Err(A::Error::custom(format_args!(
                    "package record path bytes {path_bytes} exceed {MAX_PACKAGE_RECORD_PATH_BYTES}"
                )));
            }
            records.push(record);
        }
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            Err(A::Error::custom(format_args!(
                "package file record limit is {MAX_PACKAGE_FILE_RECORDS}"
            )))
        } else {
            Ok(records)
        }
    }
}
