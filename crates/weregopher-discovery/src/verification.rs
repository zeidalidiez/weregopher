//! Candidate-specific, bounded package-layout marker discovery.
//!
//! These records are verification inputs, not Electron detection, package
//! identity, compatibility, or authorization claims. Later fingerprinting must
//! re-observe selected files under a coherent package lease.

use std::{
    collections::BTreeSet,
    fs, io,
    path::{Path, PathBuf},
};

use weregopher_domain::{
    Architecture, CandidateInstallationEvidence, CandidateTarget, DerivedValue,
    DiscoveryConfidence, DiscoverySource, InstallationKind,
};

use crate::{
    CandidateEvidenceGroup, DiscoveryError, has_direct_directory_ancestors, is_reparse_point,
    package_catalog::package_full_name_matches,
};

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
    /// Application or package manifest at a maintained fixed path.
    ApplicationManifest,
    /// Fixed unpacked main-process entry path.
    MainProcessEntry,
    /// Candidate-specific helper executable bundled inside the package.
    BundledHelper,
    /// Candidate-specific installation metadata at a maintained fixed path.
    InstallationMetadata,
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
/// layout. Codex requires its exact package-catalog identity and observed MSIX
/// layout. Hermes Agent requires its source-backed packaged desktop layout.
///
/// # Errors
///
/// Returns an inspection, non-Unicode-path, or input-bound error when a fixed
/// marker cannot be examined safely or a candidate root exceeds its bounds.
pub fn verification_inputs_for_candidate(
    group: &CandidateEvidenceGroup,
) -> Result<Vec<CandidateVerificationInput>, DiscoveryError> {
    match group.target() {
        CandidateTarget::Codex => codex_verification_inputs(group),
        CandidateTarget::HermesAgent => hermes_verification_inputs(group),
        CandidateTarget::Discord => discord_verification_inputs(group),
        CandidateTarget::VisualStudioCode => vscode_verification_inputs(group),
    }
}

fn discord_verification_inputs(
    group: &CandidateEvidenceGroup,
) -> Result<Vec<CandidateVerificationInput>, DiscoveryError> {
    if consistent_installation_kind(group) != Some(InstallationKind::Squirrel) {
        return Ok(Vec::new());
    }
    let Some(root) = representative_root(group) else {
        return Ok(Vec::new());
    };
    if !root.is_absolute() {
        return Ok(Vec::new());
    }
    let Some(executable_name) = discord_executable_name(single_channel(group).as_deref()) else {
        return Ok(Vec::new());
    };
    if !matches!(
        probe_path(root, &[], CandidatePathKind::Directory)?,
        ProbeOutcome::Present(_)
    ) {
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
        if matches!(
            probe_path(&path, &[], CandidatePathKind::Directory)?,
            ProbeOutcome::Present(_)
        ) {
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
    if !push_optional_marker(
        &mut markers,
        package_root,
        &["resources", "app.asar.unpacked"],
        CandidateLayoutMarkerKind::UnpackedApplicationDirectory,
        CandidatePathKind::Directory,
    )? {
        return Ok(None);
    }
    for resource in [
        "resources.pak",
        "chrome_100_percent.pak",
        "chrome_200_percent.pak",
        "icudtl.dat",
        "v8_context_snapshot.bin",
        "snapshot_blob.bin",
    ] {
        if !push_optional_marker(
            &mut markers,
            package_root,
            &[resource],
            CandidateLayoutMarkerKind::ElectronResource,
            CandidatePathKind::File,
        )? {
            return Ok(None);
        }
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
    if !matches!(
        consistent_installation_kind(group),
        Some(InstallationKind::Exe | InstallationKind::Msix)
    ) {
        return Ok(Vec::new());
    }
    let Some(root) = representative_root(group) else {
        return Ok(Vec::new());
    };
    if !root.is_absolute() {
        return Ok(Vec::new());
    }
    let Some(executable_name) = vscode_executable_name(single_channel(group).as_deref()) else {
        return Ok(Vec::new());
    };
    if !matches!(
        probe_path(root, &[], CandidatePathKind::Directory)?,
        ProbeOutcome::Present(_)
    ) {
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
        if !push_optional_marker(
            &mut markers,
            root,
            &[resource],
            CandidateLayoutMarkerKind::ElectronResource,
            CandidatePathKind::File,
        )? {
            return Ok(Vec::new());
        }
    }

    Ok(vec![CandidateVerificationInput {
        target: CandidateTarget::VisualStudioCode,
        discovery_observations: group.observations().to_vec(),
        package_root_path: path_to_string(root)?,
        primary_executable_path,
        markers,
    }])
}

fn codex_verification_inputs(
    group: &CandidateEvidenceGroup,
) -> Result<Vec<CandidateVerificationInput>, DiscoveryError> {
    if !has_exact_codex_package_evidence(group) {
        return Ok(Vec::new());
    }
    let Some(root) = representative_root(group) else {
        return Ok(Vec::new());
    };
    if !root.is_absolute()
        || !matches!(
            probe_path(root, &[], CandidatePathKind::Directory)?,
            ProbeOutcome::Present(_)
        )
    {
        return Ok(Vec::new());
    }

    let Some(primary) = marker(
        root,
        &["app", "ChatGPT.exe"],
        CandidateLayoutMarkerKind::PrimaryExecutable,
        CandidatePathKind::File,
    )?
    else {
        return Ok(Vec::new());
    };
    let Some(manifest) = marker(
        root,
        &["AppxManifest.xml"],
        CandidateLayoutMarkerKind::ApplicationManifest,
        CandidatePathKind::File,
    )?
    else {
        return Ok(Vec::new());
    };
    let Some(archive) = marker(
        root,
        &["app", "resources", "app.asar"],
        CandidateLayoutMarkerKind::ApplicationArchive,
        CandidatePathKind::File,
    )?
    else {
        return Ok(Vec::new());
    };

    let primary_executable_path = primary.path.value.clone();
    let mut markers = vec![primary, manifest, archive];
    if !push_optional_marker(
        &mut markers,
        root,
        &["app", "resources", "app.asar.unpacked"],
        CandidateLayoutMarkerKind::UnpackedApplicationDirectory,
        CandidatePathKind::Directory,
    )? {
        return Ok(Vec::new());
    }
    for helper in ["codex.exe", "codex-code-mode-host.exe"] {
        if !push_optional_marker(
            &mut markers,
            root,
            &["app", "resources", helper],
            CandidateLayoutMarkerKind::BundledHelper,
            CandidatePathKind::File,
        )? {
            return Ok(Vec::new());
        }
    }
    for resource in [
        "resources.pak",
        "chrome_100_percent.pak",
        "chrome_200_percent.pak",
        "icudtl.dat",
        "v8_context_snapshot.bin",
        "snapshot_blob.bin",
    ] {
        if !push_optional_marker(
            &mut markers,
            root,
            &["app", resource],
            CandidateLayoutMarkerKind::ElectronResource,
            CandidatePathKind::File,
        )? {
            return Ok(Vec::new());
        }
    }

    Ok(vec![CandidateVerificationInput {
        target: CandidateTarget::Codex,
        discovery_observations: group.observations().to_vec(),
        package_root_path: path_to_string(root)?,
        primary_executable_path,
        markers,
    }])
}

fn hermes_verification_inputs(
    group: &CandidateEvidenceGroup,
) -> Result<Vec<CandidateVerificationInput>, DiscoveryError> {
    if !has_supported_hermes_evidence(group) {
        return Ok(Vec::new());
    }
    let Some(root) = representative_root(group) else {
        return Ok(Vec::new());
    };
    if !root.is_absolute()
        || !matches!(
            probe_path(root, &[], CandidatePathKind::Directory)?,
            ProbeOutcome::Present(_)
        )
    {
        return Ok(Vec::new());
    }

    let Some(primary) = marker(
        root,
        &["Hermes.exe"],
        CandidateLayoutMarkerKind::PrimaryExecutable,
        CandidatePathKind::File,
    )?
    else {
        return Ok(Vec::new());
    };
    let Some(archive) = marker(
        root,
        &["resources", "app.asar"],
        CandidateLayoutMarkerKind::ApplicationArchive,
        CandidatePathKind::File,
    )?
    else {
        return Ok(Vec::new());
    };
    let Some(unpacked) = marker(
        root,
        &["resources", "app.asar.unpacked"],
        CandidateLayoutMarkerKind::UnpackedApplicationDirectory,
        CandidatePathKind::Directory,
    )?
    else {
        return Ok(Vec::new());
    };
    let Some(main_entry) = marker(
        root,
        &[
            "resources",
            "app.asar.unpacked",
            "dist",
            "electron-main.mjs",
        ],
        CandidateLayoutMarkerKind::MainProcessEntry,
        CandidatePathKind::File,
    )?
    else {
        return Ok(Vec::new());
    };
    let Some(install_metadata) = marker(
        root,
        &["resources", "install-stamp.json"],
        CandidateLayoutMarkerKind::InstallationMetadata,
        CandidatePathKind::File,
    )?
    else {
        return Ok(Vec::new());
    };

    let primary_executable_path = primary.path.value.clone();
    let mut markers = vec![primary, archive, unpacked, main_entry, install_metadata];
    for resource in [
        "resources.pak",
        "chrome_100_percent.pak",
        "chrome_200_percent.pak",
        "icudtl.dat",
        "v8_context_snapshot.bin",
        "snapshot_blob.bin",
    ] {
        if !push_optional_marker(
            &mut markers,
            root,
            &[resource],
            CandidateLayoutMarkerKind::ElectronResource,
            CandidatePathKind::File,
        )? {
            return Ok(Vec::new());
        }
    }

    Ok(vec![CandidateVerificationInput {
        target: CandidateTarget::HermesAgent,
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

fn consistent_installation_kind(group: &CandidateEvidenceGroup) -> Option<InstallationKind> {
    let mut kinds = group
        .observations()
        .iter()
        .map(|evidence| evidence.installation_kind.value);
    let first = kinds.next()?;
    kinds.all(|kind| kind == first).then_some(first)
}

fn has_exact_codex_package_evidence(group: &CandidateEvidenceGroup) -> bool {
    let Some(first) = group.observations().first() else {
        return false;
    };
    let Some(first_identity) = first
        .package_identity
        .as_ref()
        .map(|identity| &identity.value)
    else {
        return false;
    };
    let Some(first_architecture) = first
        .architecture
        .as_ref()
        .map(|architecture| architecture.value)
    else {
        return false;
    };
    let Some(first_version) = first
        .observed_version
        .as_ref()
        .map(|version| &version.value)
    else {
        return false;
    };

    group.observations().iter().all(|evidence| {
        if evidence.installation_kind.value != InstallationKind::Msix
            || evidence.installation_kind.confidence != DiscoveryConfidence::DirectObservation
            || evidence.installation_kind.source != DiscoverySource::PackageCatalog
            || evidence.root_path.confidence != DiscoveryConfidence::DirectObservation
            || evidence.root_path.source != DiscoverySource::PackageCatalog
            || evidence.primary_executable_path.is_some()
            || evidence.channel.is_some()
        {
            return false;
        }
        let Some(identity) = evidence.package_identity.as_ref() else {
            return false;
        };
        let Some(architecture) = evidence.architecture.as_ref() else {
            return false;
        };
        let Some(version) = evidence.observed_version.as_ref() else {
            return false;
        };
        if identity.confidence != DiscoveryConfidence::DirectObservation
            || identity.source != DiscoverySource::PackageCatalog
            || architecture.value != Architecture::X86_64
            || architecture.confidence != DiscoveryConfidence::DirectObservation
            || architecture.source != DiscoverySource::PackageCatalog
            || version.confidence != DiscoveryConfidence::DirectObservation
            || version.source != DiscoverySource::PackageCatalog
            || &identity.value != first_identity
            || architecture.value != first_architecture
            || &version.value != first_version
        {
            return false;
        }
        let value = &identity.value;
        value.package_name == "OpenAI.Codex"
            && value.package_family_name == "OpenAI.Codex_2p2nqsd0c76g0"
            && value.publisher_id == "2p2nqsd0c76g0"
            && value.application_ids.iter().any(|value| value == "App")
            && package_full_name_matches(
                &value.package_name,
                &version.value,
                Some(architecture.value),
                &value.publisher_id,
                &value.package_full_name,
            )
    })
}

fn has_supported_hermes_evidence(group: &CandidateEvidenceGroup) -> bool {
    !group.observations().is_empty()
        && group
            .observations()
            .iter()
            .all(is_supported_hermes_observation)
}

fn is_supported_hermes_observation(evidence: &CandidateInstallationEvidence) -> bool {
    if evidence.channel.is_some()
        || evidence.package_identity.is_some()
        || evidence.architecture.is_some()
    {
        return false;
    }
    let Some(primary) = evidence.primary_executable_path.as_ref() else {
        return false;
    };
    if primary.confidence != DiscoveryConfidence::DirectObservation
        || primary.source != DiscoverySource::FilesystemLayout
        || Path::new(&primary.value) != Path::new(&evidence.root_path.value).join("Hermes.exe")
    {
        return false;
    }

    match evidence.installation_kind.value {
        InstallationKind::Exe => {
            evidence.installation_kind.confidence == DiscoveryConfidence::Corroborated
                && evidence.installation_kind.source == DiscoverySource::FilesystemLayout
                && evidence.root_path.confidence == DiscoveryConfidence::DirectObservation
                && evidence.root_path.source == DiscoverySource::KnownInstallLocation
                && evidence.observed_version.is_none()
        }
        InstallationKind::Unknown => {
            evidence.installation_kind.confidence == DiscoveryConfidence::Advisory
                && evidence.installation_kind.source == DiscoverySource::UninstallRegistry
                && evidence.root_path.confidence == DiscoveryConfidence::DirectObservation
                && evidence.root_path.source == DiscoverySource::UninstallRegistry
                && evidence.observed_version.as_ref().is_none_or(|version| {
                    version.confidence == DiscoveryConfidence::DirectObservation
                        && version.source == DiscoverySource::UninstallRegistry
                        && !version.value.trim().is_empty()
                        && version.value == version.value.trim()
                })
        }
        InstallationKind::Msix
        | InstallationKind::Msi
        | InstallationKind::Squirrel
        | InstallationKind::Portable => false,
    }
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
        version.split('.').all(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
        })
    })
}

fn push_optional_marker(
    markers: &mut Vec<CandidateLayoutMarker>,
    root: &Path,
    components: &[&str],
    kind: CandidateLayoutMarkerKind,
    path_kind: CandidatePathKind,
) -> Result<bool, DiscoveryError> {
    match probe_path(root, components, path_kind)? {
        ProbeOutcome::Absent => Ok(true),
        ProbeOutcome::Rejected => Ok(false),
        ProbeOutcome::Present(path) => {
            markers.push(marker_from_path(&path, kind, path_kind)?);
            Ok(true)
        }
    }
}

fn marker(
    root: &Path,
    components: &[&str],
    kind: CandidateLayoutMarkerKind,
    path_kind: CandidatePathKind,
) -> Result<Option<CandidateLayoutMarker>, DiscoveryError> {
    let ProbeOutcome::Present(path) = probe_path(root, components, path_kind)? else {
        return Ok(None);
    };
    marker_from_path(&path, kind, path_kind).map(Some)
}

fn marker_from_path(
    path: &Path,
    kind: CandidateLayoutMarkerKind,
    path_kind: CandidatePathKind,
) -> Result<CandidateLayoutMarker, DiscoveryError> {
    Ok(CandidateLayoutMarker {
        kind,
        path_kind,
        path: DerivedValue::new(
            path_to_string(path)?,
            DiscoveryConfidence::DirectObservation,
            DiscoverySource::FilesystemLayout,
        ),
    })
}

enum ProbeOutcome {
    Absent,
    Rejected,
    Present(PathBuf),
}

fn probe_path(
    root: &Path,
    components: &[&str],
    expected: CandidatePathKind,
) -> Result<ProbeOutcome, DiscoveryError> {
    let mut path = root.to_path_buf();
    if !has_direct_directory_ancestors(root)? {
        return Ok(ProbeOutcome::Rejected);
    }
    if components.is_empty() {
        return Ok(ProbeOutcome::Present(path));
    }

    for (index, component) in components.iter().enumerate() {
        path.push(component);
        let path_kind = if index + 1 == components.len() {
            expected
        } else {
            CandidatePathKind::Directory
        };
        match metadata_outcome(&path, path_kind)? {
            MetadataOutcome::Absent => return Ok(ProbeOutcome::Absent),
            MetadataOutcome::Rejected => return Ok(ProbeOutcome::Rejected),
            MetadataOutcome::Matches => {}
        }
    }
    Ok(ProbeOutcome::Present(path))
}

enum MetadataOutcome {
    Absent,
    Rejected,
    Matches,
}

fn metadata_outcome(
    path: &Path,
    expected: CandidatePathKind,
) -> Result<MetadataOutcome, DiscoveryError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(MetadataOutcome::Absent);
        }
        Err(source) => {
            return Err(DiscoveryError::Inspect {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Ok(MetadataOutcome::Rejected);
    }
    let matches = match expected {
        CandidatePathKind::File => metadata.is_file(),
        CandidatePathKind::Directory => metadata.is_dir(),
    };
    Ok(if matches {
        MetadataOutcome::Matches
    } else {
        MetadataOutcome::Rejected
    })
}

fn path_to_string(path: &Path) -> Result<String, DiscoveryError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| DiscoveryError::NonUnicodePath {
            path: path.to_path_buf(),
        })
}
