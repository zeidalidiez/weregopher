//! Read-only installed-application discovery.
//!
//! This crate emits candidate evidence only. Discovery does not establish
//! Electron use, compatibility, signer trust, or a coherent package snapshot.

#![forbid(unsafe_code)]

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use thiserror::Error;
use weregopher_domain::{
    CandidateInstallationEvidence, CandidateTarget, DerivedValue, DiscoveryConfidence,
    DiscoverySource, InstallationKind,
};

/// Failure while reading bounded local discovery evidence.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// The current process has no per-user local application-data root.
    #[error("LOCALAPPDATA is unavailable")]
    MissingLocalAppData,
    /// The platform does not provide the requested discovery source.
    #[error("current-user known-location discovery is supported only on Windows")]
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
