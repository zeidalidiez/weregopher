//! Immutable package-build identity contracts.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ApplicationFamilyId, Sha256Digest};

/// A normalized target-machine architecture.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    /// AMD64/x86-64.
    X86_64,
    /// ARM64/AArch64.
    Aarch64,
}

/// The installation technology that owns a discovered package.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallationKind {
    /// Windows MSIX or `AppX` package.
    Msix,
    /// Squirrel-managed versioned desktop installation.
    Squirrel,
    /// Windows Installer package.
    Msi,
    /// Generic executable-installed application.
    Exe,
    /// User-managed portable directory.
    Portable,
    /// Installation technology was not identified.
    Unknown,
}

/// Windows package identity fields that affect activation and compatibility.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct PackageIdentity {
    /// Package manifest identity name.
    pub package_name: String,
    /// Package family name.
    pub package_family_name: String,
    /// Versioned package full name.
    pub package_full_name: String,
    /// Publisher identifier from the package identity.
    pub publisher_id: String,
    /// Declared application IDs relevant to launch and activation.
    pub application_ids: Vec<String>,
}

/// Compound immutable identity for one discovered application build.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct BuildFingerprint {
    /// Durable application-family identity.
    pub family: ApplicationFamilyId,
    /// Owning installation technology.
    pub installation_kind: InstallationKind,
    /// Machine architecture.
    pub architecture: Architecture,
    /// Vendor update channel, when known.
    pub channel: Option<String>,
    /// Windows execution identity, when present.
    pub package_identity: Option<PackageIdentity>,
    /// Installation/package version text.
    pub package_version: Option<String>,
    /// Product version resource text.
    pub product_version: Option<String>,
    /// Application-specific internal version text.
    pub internal_version: Option<String>,
    /// Canonical Merkle root of the complete package tree.
    pub package_tree_merkle: Sha256Digest,
    /// Digest of `app.asar`, when present.
    pub app_asar_sha256: Option<Sha256Digest>,
    /// Merkle root of entries physically backed by `app.asar.unpacked`.
    pub app_asar_unpacked_merkle: Option<Sha256Digest>,
    /// Digest of the resolved main entry.
    pub main_entry_sha256: Option<Sha256Digest>,
    /// Merkle root of resolved preload entries.
    pub preload_merkle: Option<Sha256Digest>,
    /// Merkle root of packaged renderer assets.
    pub renderer_merkle: Option<Sha256Digest>,
    /// Merkle root of native modules.
    pub native_module_merkle: Option<Sha256Digest>,
    /// Merkle root of vendor helper binaries.
    pub helper_binary_merkle: Option<Sha256Digest>,
    /// SHA-256 thumbprint of the package or primary executable signer.
    pub signer_thumbprint: Option<Sha256Digest>,
    /// Detected Electron version.
    pub electron_version: Option<String>,
    /// Detected Chromium version.
    pub chromium_version: Option<String>,
    /// Detected Node version.
    pub node_version: Option<String>,
    /// Detected V8 version.
    pub v8_version: Option<String>,
}

impl BuildFingerprint {
    /// Constructs a package-tree-only fingerprint before optional evidence is available.
    #[must_use]
    pub fn minimal(
        family: ApplicationFamilyId,
        installation_kind: InstallationKind,
        architecture: Architecture,
        package_tree_merkle: Sha256Digest,
    ) -> Self {
        Self {
            family,
            installation_kind,
            architecture,
            channel: None,
            package_identity: None,
            package_version: None,
            product_version: None,
            internal_version: None,
            package_tree_merkle,
            app_asar_sha256: None,
            app_asar_unpacked_merkle: None,
            main_entry_sha256: None,
            preload_merkle: None,
            renderer_merkle: None,
            native_module_merkle: None,
            helper_binary_merkle: None,
            signer_thumbprint: None,
            electron_version: None,
            chromium_version: None,
            node_version: None,
            v8_version: None,
        }
    }
}
