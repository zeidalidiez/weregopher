//! Read-only candidate installation evidence and provenance contracts.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{Architecture, CandidateTarget, InstallationKind, PackageIdentity};

/// Confidence attached to one discovered value.
///
/// Confidence describes acquisition strength only. It is not a compatibility,
/// authenticity, or security certification.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryConfidence {
    /// Maintained search input that has not yet been observed on the host.
    Advisory,
    /// A value inferred from mutually supporting observations.
    Corroborated,
    /// A value read directly from the named local evidence source.
    DirectObservation,
}

/// Local source from which a candidate value was obtained.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverySource {
    /// Windows package catalog or package-management API.
    PackageCatalog,
    /// Windows uninstall registry metadata.
    UninstallRegistry,
    /// Maintained product-specific installation-location hint.
    KnownInstallLocation,
    /// Start Menu or other local shortcut metadata.
    Shortcut,
    /// Read-only inspection of an installation's local filesystem layout.
    FilesystemLayout,
    /// Metadata from an already-running local process.
    RunningProcess,
    /// Portable root explicitly selected by the user.
    UserSelectedPath,
    /// Installed package manifest metadata.
    PackageManifest,
    /// Executable version-resource metadata.
    ExecutableVersionResource,
    /// Authenticode signature metadata.
    AuthenticodeSignature,
}

/// A discovered value together with its acquisition strength and provenance.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedValue<T> {
    /// Value obtained or inferred during discovery.
    pub value: T,
    /// Acquisition strength of this value.
    pub confidence: DiscoveryConfidence,
    /// Local evidence source supporting this value.
    pub source: DiscoverySource,
}

impl<T> DerivedValue<T> {
    /// Binds a discovered value to its confidence and source.
    pub const fn new(value: T, confidence: DiscoveryConfidence, source: DiscoverySource) -> Self {
        Self {
            value,
            confidence,
            source,
        }
    }
}

/// Read-only evidence describing one possible installed application.
///
/// This record is a discovery result, not an immutable build fingerprint. It
/// does not assert Electron use, package compatibility, signer trust, or a
/// coherent package-tree observation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateInstallationEvidence {
    /// Candidate catalog target whose rules produced this record.
    pub target: CandidateTarget,
    /// Observed or inferred installation technology.
    pub installation_kind: DerivedValue<InstallationKind>,
    /// Platform-native installation root text.
    pub root_path: DerivedValue<String>,
    /// Platform-native primary executable path, when identified.
    pub primary_executable_path: Option<DerivedValue<String>>,
    /// Windows package identity, when supplied by a package catalog.
    pub package_identity: Option<DerivedValue<PackageIdentity>>,
    /// Executable/package architecture, when observed or inferred.
    pub architecture: Option<DerivedValue<Architecture>>,
    /// Vendor channel text, when observed or inferred.
    pub channel: Option<DerivedValue<String>>,
    /// Package or product version text, when observed.
    pub observed_version: Option<DerivedValue<String>>,
}
