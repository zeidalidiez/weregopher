//! Serializable package-tree fingerprint evidence.

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use weregopher_domain::Sha256Digest;

/// Current deterministic package-tree Merkle algorithm version.
pub const PACKAGE_TREE_FORMAT_VERSION: u16 = 1;

/// Maximum Unicode scalar count accepted in one normalized package path.
pub const MAX_NORMALIZED_PACKAGE_PATH_CHARS: usize = 32_767;

/// Canonical immutable evidence assembled from pre-observed package records.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct PackageTreeManifest {
    /// Version of path, leaf, and directory canonicalization rules.
    #[schemars(range(min = 1, max = 1))]
    pub(crate) format_version: u16,
    /// Root directory Merkle digest.
    pub package_tree_merkle: Sha256Digest,
    /// Canonically sorted included file/link records.
    pub files: Vec<PackageFileRecord>,
}

impl PackageTreeManifest {
    /// Returns the canonical package-tree format version.
    #[must_use]
    pub const fn format_version(&self) -> u16 {
        self.format_version
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
struct UncheckedPackageTreeManifest {
    format_version: u16,
    package_tree_merkle: Sha256Digest,
    files: Vec<PackageFileRecord>,
}

/// Canonical evidence for one included package file or symbolic link.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
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
