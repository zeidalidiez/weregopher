//! Read-only installed-application discovery.
//!
//! This crate emits candidate evidence only. Discovery does not establish
//! Electron use, compatibility, signer trust, or a coherent package snapshot.

#![forbid(unsafe_code)]

mod correlation;
mod package_catalog;
mod uninstall;
mod verification;
#[cfg(windows)]
mod windows_package_catalog;
#[cfg(windows)]
mod windows_registry;

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use thiserror::Error;
use weregopher_domain::{
    CandidateInstallationEvidence, CandidateTarget, DerivedValue, DiscoveryConfidence,
    DiscoverySource, InstallationKind,
};

pub use correlation::{
    CandidateEvidenceGroup, correlate_candidate_evidence, discover_current_user_candidate_evidence,
};
pub use package_catalog::{PackageCatalogEntry, evidence_from_package_catalog_entry};
pub use uninstall::{UninstallRegistryEntry, evidence_from_uninstall_entry};
pub use verification::{
    CandidateLayoutMarker, CandidateLayoutMarkerKind, CandidatePathKind,
    CandidateVerificationInput, verification_inputs_for_candidate,
};
#[cfg(windows)]
pub use windows_package_catalog::discover_windows_package_catalog;
#[cfg(windows)]
pub use windows_registry::discover_windows_uninstall_registry;

/// Reports that Windows uninstall-registry discovery is unavailable on this
/// platform.
///
/// # Errors
///
/// Always returns [`DiscoveryError::UnsupportedPlatform`].
#[cfg(not(windows))]
pub fn discover_windows_uninstall_registry()
-> Result<Vec<CandidateInstallationEvidence>, DiscoveryError> {
    Err(DiscoveryError::UnsupportedPlatform)
}

/// Reports that Windows package-catalog discovery is unavailable on this
/// platform.
///
/// # Errors
///
/// Always returns [`DiscoveryError::UnsupportedPlatform`].
#[cfg(not(windows))]
pub fn discover_windows_package_catalog()
-> Result<Vec<CandidateInstallationEvidence>, DiscoveryError> {
    Err(DiscoveryError::UnsupportedPlatform)
}

/// Failure while reading bounded local discovery evidence.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// The current process has no per-user local application-data root.
    #[error("LOCALAPPDATA is unavailable")]
    MissingLocalAppData,
    /// The platform does not provide the requested discovery source.
    #[error("the requested discovery source is supported only on Windows")]
    UnsupportedPlatform,
    /// A candidate path could not be inspected.
    #[error("failed to inspect candidate path {path:?}: {source}")]
    Inspect {
        /// Path whose metadata lookup failed.
        path: PathBuf,
        /// Filesystem error returned by the operating system.
        #[source]
        source: io::Error,
    },
    /// A discovered Windows path could not be represented by the serialized contract.
    #[error("candidate path is not valid Unicode: {path:?}")]
    NonUnicodePath {
        /// Path that could not be represented as a Rust string.
        path: PathBuf,
    },
    /// A Windows uninstall-registry key or value could not be read.
    #[error("failed to read uninstall-registry location {location}: {source}")]
    RegistryRead {
        /// Registry view, key, or value being read.
        location: String,
        /// Registry error returned by the operating system.
        #[source]
        source: io::Error,
    },
    /// One registry view exceeded the bounded number of uninstall keys.
    #[error("uninstall-registry location {location} exceeded its {limit}-key limit")]
    RegistryEntryLimit {
        /// Registry view whose enumeration exceeded the limit.
        location: String,
        /// Maximum accepted keys in one view.
        limit: usize,
    },
    /// A registry string exceeded the accepted discovery bound.
    #[error(
        "uninstall-registry value {value_name} at {location} exceeded its {limit}-character limit"
    )]
    RegistryTextLimit {
        /// Registry key containing the oversized value.
        location: String,
        /// Name of the oversized registry value.
        value_name: &'static str,
        /// Maximum accepted Unicode scalar values.
        limit: usize,
    },
    /// Registry discovery produced more candidate records than accepted.
    #[error("uninstall-registry discovery exceeded its {limit}-candidate result limit")]
    RegistryResultLimit {
        /// Maximum accepted candidate records.
        limit: usize,
    },
    /// A Windows package-catalog operation failed.
    #[cfg(windows)]
    #[error("failed package-catalog operation {operation}: {source}")]
    PackageCatalogRead {
        /// Package-catalog operation being performed.
        operation: String,
        /// Windows Runtime error returned by the operating system.
        #[source]
        source: windows::core::Error,
    },
    /// A package-catalog string or collection exceeded its accepted bound.
    #[error("package-catalog field {field} exceeded its {limit}-item limit")]
    PackageCatalogLimit {
        /// Package field or collection whose bound was exceeded.
        field: &'static str,
        /// Maximum accepted items or Unicode scalar values.
        limit: usize,
    },
    /// More evidence records were supplied than bounded correlation accepts.
    #[error("candidate-evidence correlation exceeded its {limit}-record input limit")]
    CorrelationInputLimit {
        /// Maximum accepted evidence records.
        limit: usize,
    },
    /// A candidate root contains more direct entries than verification accepts.
    #[error("candidate verification root {path:?} exceeded its {limit}-entry limit")]
    VerificationEntryLimit {
        /// Candidate root whose direct entries exceeded the bound.
        path: String,
        /// Maximum accepted direct entries.
        limit: usize,
    },
    /// More versioned package roots were found than verification accepts.
    #[error("candidate verification exceeded its {limit}-package-root limit")]
    VerificationCandidateLimit {
        /// Maximum accepted versioned package roots.
        limit: usize,
    },
}

#[derive(Clone, Copy)]
struct KnownLocationRule {
    target: CandidateTarget,
    relative_root: &'static [&'static str],
    marker: &'static str,
    marker_is_primary_executable: bool,
    installation_kind: InstallationKind,
    channel: &'static str,
}

const KNOWN_USER_LOCATION_RULES: &[KnownLocationRule] = &[
    KnownLocationRule {
        target: CandidateTarget::Discord,
        relative_root: &["Discord"],
        marker: "Update.exe",
        marker_is_primary_executable: false,
        installation_kind: InstallationKind::Squirrel,
        channel: "stable",
    },
    KnownLocationRule {
        target: CandidateTarget::Discord,
        relative_root: &["DiscordPTB"],
        marker: "Update.exe",
        marker_is_primary_executable: false,
        installation_kind: InstallationKind::Squirrel,
        channel: "ptb",
    },
    KnownLocationRule {
        target: CandidateTarget::Discord,
        relative_root: &["DiscordCanary"],
        marker: "Update.exe",
        marker_is_primary_executable: false,
        installation_kind: InstallationKind::Squirrel,
        channel: "canary",
    },
    KnownLocationRule {
        target: CandidateTarget::VisualStudioCode,
        relative_root: &["Programs", "Microsoft VS Code"],
        marker: "Code.exe",
        marker_is_primary_executable: true,
        installation_kind: InstallationKind::Exe,
        channel: "stable",
    },
    KnownLocationRule {
        target: CandidateTarget::VisualStudioCode,
        relative_root: &["Programs", "Microsoft VS Code Insiders"],
        marker: "Code - Insiders.exe",
        marker_is_primary_executable: true,
        installation_kind: InstallationKind::Exe,
        channel: "insiders",
    },
];

/// Discovers supported per-user installations beneath a supplied Windows
/// `LOCALAPPDATA` root.
///
/// The source checks a fixed, bounded rule set and performs metadata reads only.
/// A record is emitted only when both the expected directory and its direct
/// marker file exist without following a final-component symbolic link.
///
/// # Errors
///
/// Returns [`DiscoveryError`] when a candidate metadata lookup fails for a
/// reason other than absence, or when an observed path is not representable in
/// the serialized evidence contract.
pub fn discover_known_user_locations(
    local_app_data: &Path,
) -> Result<Vec<CandidateInstallationEvidence>, DiscoveryError> {
    let mut discovered = Vec::new();

    for rule in KNOWN_USER_LOCATION_RULES {
        let root = join_components(local_app_data, rule.relative_root);
        if !is_direct_kind(&root, ExpectedKind::Directory)? {
            continue;
        }

        let marker = root.join(rule.marker);
        if !is_direct_kind(&marker, ExpectedKind::File)? {
            continue;
        }

        discovered.push(evidence_for_rule(*rule, &root, &marker)?);
    }

    Ok(discovered)
}

/// Discovers supported installations under the current Windows user's
/// `LOCALAPPDATA` directory.
///
/// # Errors
///
/// Returns [`DiscoveryError::UnsupportedPlatform`] off Windows,
/// [`DiscoveryError::MissingLocalAppData`] when the environment does not expose
/// the current-user root, or an inspection error from
/// [`discover_known_user_locations`].
#[cfg(windows)]
pub fn discover_current_user_known_locations()
-> Result<Vec<CandidateInstallationEvidence>, DiscoveryError> {
    let local_app_data =
        std::env::var_os("LOCALAPPDATA").ok_or(DiscoveryError::MissingLocalAppData)?;
    discover_known_user_locations(Path::new(&local_app_data))
}

/// Reports that current-user Windows discovery is unavailable on this platform.
///
/// # Errors
///
/// Always returns [`DiscoveryError::UnsupportedPlatform`].
#[cfg(not(windows))]
pub fn discover_current_user_known_locations()
-> Result<Vec<CandidateInstallationEvidence>, DiscoveryError> {
    Err(DiscoveryError::UnsupportedPlatform)
}

fn join_components(root: &Path, components: &[&str]) -> PathBuf {
    let mut path = root.to_path_buf();
    for component in components {
        path.push(component);
    }
    path
}

#[derive(Clone, Copy)]
enum ExpectedKind {
    Directory,
    File,
}

fn is_direct_kind(path: &Path, expected: ExpectedKind) -> Result<bool, DiscoveryError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(match expected {
            ExpectedKind::Directory => metadata.file_type().is_dir(),
            ExpectedKind::File => metadata.file_type().is_file(),
        }),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(DiscoveryError::Inspect {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn evidence_for_rule(
    rule: KnownLocationRule,
    root: &Path,
    marker: &Path,
) -> Result<CandidateInstallationEvidence, DiscoveryError> {
    let root_path = path_text(root)?;
    let primary_executable_path = rule
        .marker_is_primary_executable
        .then(|| path_text(marker))
        .transpose()?
        .map(|value| {
            DerivedValue::new(
                value,
                DiscoveryConfidence::DirectObservation,
                DiscoverySource::FilesystemLayout,
            )
        });

    Ok(CandidateInstallationEvidence {
        target: rule.target,
        installation_kind: DerivedValue::new(
            rule.installation_kind,
            DiscoveryConfidence::Corroborated,
            DiscoverySource::FilesystemLayout,
        ),
        root_path: DerivedValue::new(
            root_path,
            DiscoveryConfidence::DirectObservation,
            DiscoverySource::KnownInstallLocation,
        ),
        primary_executable_path,
        package_identity: None,
        architecture: None,
        channel: Some(DerivedValue::new(
            rule.channel.to_owned(),
            DiscoveryConfidence::Corroborated,
            DiscoverySource::KnownInstallLocation,
        )),
        observed_version: None,
    })
}

fn path_text(path: &Path) -> Result<String, DiscoveryError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| DiscoveryError::NonUnicodePath {
            path: path.to_path_buf(),
        })
}
