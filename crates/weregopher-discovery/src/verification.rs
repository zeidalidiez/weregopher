//! Candidate-specific, bounded package-layout marker discovery.
//!
//! These records are verification inputs, not Electron detection, package
//! identity, compatibility, or authorization claims. Later fingerprinting must
//! re-observe selected files under a coherent package lease.

use std::{collections::BTreeSet, fs, io, path::Path};

use weregopher_domain::{
    CandidateInstallationEvidence, CandidateTarget, DerivedValue, DiscoveryConfidence,
    DiscoverySource,
};

use crate::{CandidateEvidenceGroup, DiscoveryError};

const MAX_DIRECT_PACKAGE_ROOT_ENTRIES: usize = 128;
const MAX_VERSIONED_PACKAGE_ROOTS: usize = 16;

/// Semantic role of one fixed package-layout marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateLayoutMarkerKind {
    /// Product executable used as the candidate's main process.
    PrimaryExecutable,
    /// Electron application archive such as `resources/app.asar`.
    ApplicationArchive,
    /// Optional unpacked companion directory for an application archive.
    UnpackedApplicationDirectory,
    /// Unpacked application `package.json`.
    ApplicationManifest,
    /// Fixed unpacked main-process entry path.
    MainProcessEntry,
    /// Supporting Electron runtime resource at a maintained fixed path.
    ElectronResource,
}

/// Filesystem entry shape observed for a package-layout marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidatePathKind {
    /// Direct regular file observation.
    File,
    /// Direct directory observation.
    Directory,
}

/// One fixed-path marker retained with direct-observation provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateLayoutMarker {
    kind: CandidateLayoutMarkerKind,
    path_kind: CandidatePathKind,
    path: DerivedValue<String>,
}

impl CandidateLayoutMarker {
    /// Semantic role of the marker.
    #[must_use]
    pub const fn kind(&self) -> CandidateLayoutMarkerKind {
        self.kind
    }

    /// Observed filesystem entry shape.
    #[must_use]
    pub const fn path_kind(&self) -> CandidatePathKind {
        self.path_kind
    }

    /// Marker path and direct-observation provenance.
    #[must_use]
    pub const fn path(&self) -> &DerivedValue<String> {
        &self.path
    }
}

/// Bounded, candidate-specific input for later package verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateVerificationInput {
    target: CandidateTarget,
    discovery_observations: Vec<CandidateInstallationEvidence>,
    package_root_path: String,
    primary_executable_path: String,
    markers: Vec<CandidateLayoutMarker>,
}

impl CandidateVerificationInput {
    /// Candidate target whose maintained rule produced this input.
    #[must_use]
    pub const fn target(&self) -> CandidateTarget {
        self.target
    }

    /// Original, unmerged source observations that selected this candidate.
    #[must_use]
    pub fn discovery_observations(&self) -> &[CandidateInstallationEvidence] {
        &self.discovery_observations
    }

    /// Physical package root selected for later coherent observation.
    #[must_use]
    pub fn package_root_path(&self) -> &str {
        &self.package_root_path
    }

    /// Fixed product executable observed under the package root.
    #[must_use]
    pub fn primary_executable_path(&self) -> &str {
        &self.primary_executable_path
    }

    /// Distinct fixed-path markers in deterministic rule order.
    #[must_use]
    pub fn markers(&self) -> &[CandidateLayoutMarker] {
        &self.markers
    }
}

/// Produces bounded package-verification inputs for currently supported
/// candidate layouts.
///
/// Discord inputs select complete direct `app-<version>` package directories.
/// Visual Studio Code inputs require the maintained unpacked main-process
/// layout. Codex and Hermes Agent remain fail-closed until their artifact
/// identities are established from direct evidence.
///
/// # Errors
///
/// Returns an inspection, non-Unicode-path, or input-bound error when a fixed
/// marker cannot be examined safely or a candidate root exceeds its bounds.
pub fn verification_inputs_for_candidate(
    group: &CandidateEvidenceGroup,
) -> Result<Vec<CandidateVerificationInput>, DiscoveryError> {
    match group.target() {
        CandidateTarget::Discord => discord_verification_inputs(group),
        CandidateTarget::VisualStudioCode => vscode_verification_inputs(group),
        CandidateTarget::Codex | CandidateTarget::HermesAgent => Ok(Vec::new()),
    }
}

fn discord_verification_inputs(
    group: &CandidateEvidenceGroup,
) -> Result<Vec<CandidateVerificationInput>, DiscoveryError> {
    let Some(root) = representative_root(group) else {
        return Ok(Vec::new());
    };
    if !root.is_absolute() {
        return Ok(Vec::new());
    }
    let Some(executable_name) = discord_executable_name(single_channel(group).as_deref()) else {
        return Ok(Vec::new());
    };
    if probe_path(root, &[], CandidatePathKind::Directory)?.is_none() {
        return Ok(Vec::new());
    }

    let mut package_roots = Vec::new();
    let entries = fs::read_dir(root).map_err(|source| DiscoveryError::Inspect {
        path: root.to_path_buf(),
        source,
    })?;
    for (index, entry_result) in entries.enumerate() {
        if index >= MAX_DIRECT_PACKAGE_ROOT_ENTRIES {
            return Err(DiscoveryError::VerificationEntryLimit {
                path: path_to_string(root)?,
                limit: MAX_DIRECT_PACKAGE_ROOT_ENTRIES,
            });
        }
        let entry = entry_result.map_err(|source| DiscoveryError::Inspect {
            path: root.to_path_buf(),
            source,
        })?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        if !is_discord_version_directory_name(file_name) {
            continue;
        }
        let path = entry.path();
        if probe_path(&path, &[], CandidatePathKind::Directory)?.is_some() {
            package_roots.push(path);
        }
    }
    package_roots.sort_by_cached_key(|path| path.to_string_lossy().to_ascii_lowercase());
    if package_roots.len() > MAX_VERSIONED_PACKAGE_ROOTS {
        return Err(DiscoveryError::VerificationCandidateLimit {
            limit: MAX_VERSIONED_PACKAGE_ROOTS,
        });
    }

    let mut inputs = Vec::new();
    for package_root in package_roots {
        if let Some(input) = discord_package_input(group, &package_root, executable_name)? {
            inputs.push(input);
        }
    }
    Ok(inputs)
}

fn discord_package_input(
    group: &CandidateEvidenceGroup,
    package_root: &Path,
    executable_name: &str,
) -> Result<Option<CandidateVerificationInput>, DiscoveryError> {
    let Some(primary) = marker(
        package_root,
        &[executable_name],
        CandidateLayoutMarkerKind::PrimaryExecutable,
        CandidatePathKind::File,
    )?
    else {
        return Ok(None);
    };
    let Some(archive) = marker(
        package_root,
        &["resources", "app.asar"],
        CandidateLayoutMarkerKind::ApplicationArchive,
        CandidatePathKind::File,
    )?
    else {
        return Ok(None);
    };

    let primary_executable_path = primary.path.value.clone();
    let mut markers = vec![primary, archive];
    push_optional_marker(
        &mut markers,
        package_root,
        &["resources", "app.asar.unpacked"],
        CandidateLayoutMarkerKind::UnpackedApplicationDirectory,
        CandidatePathKind::Directory,
    )?;
    for resource in [
        "resources.pak",
        "chrome_100_percent.pak",
        "chrome_200_percent.pak",
        "icudtl.dat",
        "v8_context_snapshot.bin",
        "snapshot_blob.bin",
    ] {
        push_optional_marker(
            &mut markers,
            package_root,
            &[resource],
            CandidateLayoutMarkerKind::ElectronResource,
            CandidatePathKind::File,
        )?;
    }

    Ok(Some(CandidateVerificationInput {
        target: CandidateTarget::Discord,
        discovery_observations: group.observations().to_vec(),
        package_root_path: path_to_string(package_root)?,
        primary_executable_path,
        markers,
    }))
}

fn vscode_verification_inputs(
    group: &CandidateEvidenceGroup,
) -> Result<Vec<CandidateVerificationInput>, DiscoveryError> {
    let Some(root) = representative_root(group) else {
        return Ok(Vec::new());
    };
    if !root.is_absolute() {
        return Ok(Vec::new());
    }
    let Some(executable_name) = vscode_executable_name(single_channel(group).as_deref()) else {
        return Ok(Vec::new());
    };
    if probe_path(root, &[], CandidatePathKind::Directory)?.is_none() {
        return Ok(Vec::new());
    }

    let Some(primary) = marker(
        root,
        &[executable_name],
        CandidateLayoutMarkerKind::PrimaryExecutable,
        CandidatePathKind::File,
    )?
    else {
        return Ok(Vec::new());
    };
    let Some(manifest) = marker(
        root,
        &["resources", "app", "package.json"],
        CandidateLayoutMarkerKind::ApplicationManifest,
        CandidatePathKind::File,
    )?
    else {
        return Ok(Vec::new());
    };
    let Some(main_entry) = marker(
        root,
        &["resources", "app", "out", "main.js"],
        CandidateLayoutMarkerKind::MainProcessEntry,
        CandidatePathKind::File,
    )?
    else {
        return Ok(Vec::new());
    };

    let primary_executable_path = primary.path.value.clone();
    let mut markers = vec![primary, manifest, main_entry];
    for resource in [
        "resources.pak",
        "chrome_100_percent.pak",
        "chrome_200_percent.pak",
        "icudtl.dat",
        "v8_context_snapshot.bin",
        "snapshot_blob.bin",
    ] {
        push_optional_marker(
            &mut markers,
            root,
            &[resource],
            CandidateLayoutMarkerKind::ElectronResource,
            CandidatePathKind::File,
        )?;
    }

    Ok(vec![CandidateVerificationInput {
        target: CandidateTarget::VisualStudioCode,
        discovery_observations: group.observations().to_vec(),
        package_root_path: path_to_string(root)?,
        primary_executable_path,
        markers,
    }])
}

fn representative_root(group: &CandidateEvidenceGroup) -> Option<&Path> {
    group
        .observations()
        .first()
        .map(|evidence| Path::new(&evidence.root_path.value))
}

fn single_channel(group: &CandidateEvidenceGroup) -> Option<String> {
    let channels = group
        .observations()
        .iter()
        .filter_map(|evidence| evidence.channel.as_ref())
        .map(|channel| channel.value.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    if channels.len() == 1 {
        channels.into_iter().next()
    } else {
        None
    }
}

fn discord_executable_name(channel: Option<&str>) -> Option<&'static str> {
    match channel {
        Some("stable") => Some("Discord.exe"),
        Some("ptb") => Some("DiscordPTB.exe"),
        Some("canary") => Some("DiscordCanary.exe"),
        _ => None,
    }
}

fn vscode_executable_name(channel: Option<&str>) -> Option<&'static str> {
    match channel {
        Some("stable") => Some("Code.exe"),
        Some("insiders") => Some("Code - Insiders.exe"),
        _ => None,
    }
}

fn is_discord_version_directory_name(name: &str) -> bool {
    name.strip_prefix("app-").is_some_and(|version| {
        !version.is_empty()
            && version
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
    })
}

fn push_optional_marker(
    markers: &mut Vec<CandidateLayoutMarker>,
    root: &Path,
    components: &[&str],
    kind: CandidateLayoutMarkerKind,
    path_kind: CandidatePathKind,
) -> Result<(), DiscoveryError> {
    if let Some(value) = marker(root, components, kind, path_kind)? {
        markers.push(value);
    }
    Ok(())
}

fn marker(
    root: &Path,
    components: &[&str],
    kind: CandidateLayoutMarkerKind,
    path_kind: CandidatePathKind,
) -> Result<Option<CandidateLayoutMarker>, DiscoveryError> {
    let Some(path) = probe_path(root, components, path_kind)? else {
        return Ok(None);
    };
    Ok(Some(CandidateLayoutMarker {
        kind,
        path_kind,
        path: DerivedValue::new(
            path_to_string(&path)?,
            DiscoveryConfidence::DirectObservation,
            DiscoverySource::FilesystemLayout,
        ),
    }))
}

fn probe_path(
    root: &Path,
    components: &[&str],
    expected: CandidatePathKind,
) -> Result<Option<std::path::PathBuf>, DiscoveryError> {
    let mut path = root.to_path_buf();
    if components.is_empty() {
        return metadata_matches(&path, expected).map(|matches| matches.then_some(path));
    }

    for (index, component) in components.iter().enumerate() {
        path.push(component);
        let path_kind = if index + 1 == components.len() {
            expected
        } else {
            CandidatePathKind::Directory
        };
        if !metadata_matches(&path, path_kind)? {
            return Ok(None);
        }
    }
    Ok(Some(path))
}

fn metadata_matches(path: &Path, expected: CandidatePathKind) -> Result<bool, DiscoveryError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(DiscoveryError::Inspect {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() {
        return Ok(false);
    }
    Ok(match expected {
        CandidatePathKind::File => metadata.is_file(),
        CandidatePathKind::Directory => metadata.is_dir(),
    })
}

fn path_to_string(path: &Path) -> Result<String, DiscoveryError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| DiscoveryError::NonUnicodePath {
            path: path.to_path_buf(),
        })
}
