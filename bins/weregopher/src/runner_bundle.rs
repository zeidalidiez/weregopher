//! Closed on-disk loading for exact certification-runner identity preimages.

#![cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "runner bundles are consumed by the Windows live-smoke boundary"
    )
)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read as _,
    path::{Component, Path, PathBuf},
};

use thiserror::Error;
use walkdir::WalkDir;
use weregopher_domain::{
    CertificationRunnerArtifactName, CertificationRunnerComponentDescriptor,
    CertificationRunnerComponentDocumentError, CertificationRunnerComponentRole,
    CertificationRunnerComponentTextError, CertificationRunnerDocumentError,
    CertificationRunnerIdentity, MAX_CERTIFICATION_RUNNER_COMPONENT_ARTIFACT_BYTES,
    MAX_CERTIFICATION_RUNNER_COMPONENT_DESCRIPTOR_BYTES,
    MAX_CERTIFICATION_RUNNER_IDENTITY_DOCUMENT_BYTES,
};

const IDENTITY_FILE: &str = "identity.json";
const COMPONENT_DIRECTORY: &str = "components";
const ARTIFACT_DIRECTORY: &str = "artifacts";
const MAX_ARTIFACT_PATH_DEPTH: usize = 130;
const MAX_TOTAL_RUNNER_ARTIFACT_BYTES: usize =
    weregopher_transform::MAX_TOTAL_CERTIFICATION_RUNNER_COMPONENT_ARTIFACT_BYTES;
const MAX_RUNNER_ARTIFACTS: usize =
    weregopher_transform::MAX_CERTIFICATION_RUNNER_COMPONENT_ARTIFACT_COUNT;

/// Owned exact runner bundle retained through a complete certification run.
pub(crate) struct LoadedCertificationRunnerBundle {
    identity: CertificationRunnerIdentity,
    descriptors: BTreeMap<CertificationRunnerComponentRole, CertificationRunnerComponentDescriptor>,
    artifacts: BTreeMap<
        CertificationRunnerComponentRole,
        BTreeMap<CertificationRunnerArtifactName, Vec<u8>>,
    >,
}

impl LoadedCertificationRunnerBundle {
    pub(crate) const fn identity(&self) -> &CertificationRunnerIdentity {
        &self.identity
    }

    pub(crate) const fn descriptors(
        &self,
    ) -> &BTreeMap<CertificationRunnerComponentRole, CertificationRunnerComponentDescriptor> {
        &self.descriptors
    }

    pub(crate) fn borrowed_artifacts(
        &self,
    ) -> BTreeMap<CertificationRunnerComponentRole, BTreeMap<CertificationRunnerArtifactName, &[u8]>>
    {
        let mut borrowed = BTreeMap::new();
        for (role, artifacts) in &self.artifacts {
            let mut role_artifacts = BTreeMap::new();
            for (name, bytes) in artifacts {
                role_artifacts.insert(name.clone(), bytes.as_slice());
            }
            borrowed.insert(*role, role_artifacts);
        }
        borrowed
    }
}

/// Loads one exact closed runner bundle without following symbolic links.
///
/// Layout:
///
/// - `identity.json`
/// - `components/<role>.json`
/// - `artifacts/<role>/<descriptor artifact name>`
///
/// # Errors
///
/// Rejects unsafe or unknown entries, missing fixed roles, noncanonical identity or descriptor
/// bytes, invalid bounded documents, excessive artifact paths or bytes, and unstable reads.
pub(crate) fn load_certification_runner_bundle(
    root: &Path,
) -> Result<LoadedCertificationRunnerBundle, RunnerBundleError> {
    validate_kind(root, EntryKind::Directory)?;
    validate_root_members(root)?;

    let identity_bytes = read_bounded_file(
        &root.join(IDENTITY_FILE),
        MAX_CERTIFICATION_RUNNER_IDENTITY_DOCUMENT_BYTES,
    )?;
    let identity = CertificationRunnerIdentity::from_json_slice(&identity_bytes)
        .map_err(RunnerBundleError::Identity)?;
    if identity
        .canonical_json_bytes()
        .map_err(RunnerBundleError::CanonicalDocument)?
        != identity_bytes
    {
        return Err(RunnerBundleError::NonCanonicalIdentity);
    }

    let descriptors = load_descriptors(&root.join(COMPONENT_DIRECTORY))?;
    let artifacts = load_artifacts(&root.join(ARTIFACT_DIRECTORY), &descriptors)?;
    Ok(LoadedCertificationRunnerBundle {
        identity,
        descriptors,
        artifacts,
    })
}

fn validate_root_members(root: &Path) -> Result<(), RunnerBundleError> {
    let expected = BTreeMap::from([
        (IDENTITY_FILE, EntryKind::File),
        (COMPONENT_DIRECTORY, EntryKind::Directory),
        (ARTIFACT_DIRECTORY, EntryKind::Directory),
    ]);
    let mut observed = BTreeSet::new();
    for result in fs::read_dir(root).map_err(|source| RunnerBundleError::ReadDirectory {
        path: root.to_path_buf(),
        source,
    })? {
        let entry = result.map_err(RunnerBundleError::ReadDirectoryEntry)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| RunnerBundleError::NonUtf8Entry { path: entry.path() })?;
        let kind = expected
            .get(name.as_str())
            .ok_or_else(|| RunnerBundleError::UnexpectedEntry { path: entry.path() })?;
        validate_kind(&entry.path(), *kind)?;
        observed.insert(name);
    }
    for name in expected.keys() {
        if !observed.contains(*name) {
            return Err(RunnerBundleError::MissingEntry {
                path: root.join(name),
            });
        }
    }
    Ok(())
}

fn load_descriptors(
    root: &Path,
) -> Result<
    BTreeMap<CertificationRunnerComponentRole, CertificationRunnerComponentDescriptor>,
    RunnerBundleError,
> {
    let mut descriptors = BTreeMap::new();
    for result in fs::read_dir(root).map_err(|source| RunnerBundleError::ReadDirectory {
        path: root.to_path_buf(),
        source,
    })? {
        let entry = result.map_err(RunnerBundleError::ReadDirectoryEntry)?;
        validate_kind(&entry.path(), EntryKind::File)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| RunnerBundleError::NonUtf8Entry { path: entry.path() })?;
        let role = runner_roles()
            .into_iter()
            .find(|role| component_filename(*role) == name)
            .ok_or_else(|| RunnerBundleError::UnexpectedEntry { path: entry.path() })?;
        let bytes = read_bounded_file(
            &entry.path(),
            MAX_CERTIFICATION_RUNNER_COMPONENT_DESCRIPTOR_BYTES,
        )?;
        let descriptor = CertificationRunnerComponentDescriptor::from_json_slice(&bytes)
            .map_err(|source| RunnerBundleError::Descriptor { role, source })?;
        if descriptor
            .canonical_json_bytes()
            .map_err(RunnerBundleError::CanonicalDocument)?
            != bytes
        {
            return Err(RunnerBundleError::NonCanonicalDescriptor { role });
        }
        if descriptors.insert(role, descriptor).is_some() {
            return Err(RunnerBundleError::DuplicateRole { role });
        }
    }
    for role in runner_roles() {
        if !descriptors.contains_key(&role) {
            return Err(RunnerBundleError::MissingRole { role });
        }
    }
    Ok(descriptors)
}

fn load_artifacts(
    root: &Path,
    descriptors: &BTreeMap<
        CertificationRunnerComponentRole,
        CertificationRunnerComponentDescriptor,
    >,
) -> Result<
    BTreeMap<CertificationRunnerComponentRole, BTreeMap<CertificationRunnerArtifactName, Vec<u8>>>,
    RunnerBundleError,
> {
    validate_role_directories(root)?;
    let mut all_artifacts = BTreeMap::new();
    let mut artifact_count = 0_usize;
    let mut total_bytes = 0_usize;
    for role in runner_roles() {
        let descriptor = descriptors
            .get(&role)
            .ok_or(RunnerBundleError::MissingRole { role })?;
        let role_root = root.join(role_name(role));
        let expected_directories = expected_artifact_directories(descriptor);
        let mut artifacts = BTreeMap::new();
        for result in WalkDir::new(&role_root)
            .follow_links(false)
            .max_depth(MAX_ARTIFACT_PATH_DEPTH)
        {
            let entry =
                result.map_err(|source| RunnerBundleError::WalkArtifacts { role, source })?;
            if entry.path() == role_root {
                continue;
            }
            let relative = entry.path().strip_prefix(&role_root).map_err(|_| {
                RunnerBundleError::ArtifactEscapedRole {
                    path: entry.path().to_path_buf(),
                }
            })?;
            let normalized = normalized_relative_path(relative)?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(|source| {
                RunnerBundleError::InspectEntry {
                    path: entry.path().to_path_buf(),
                    source,
                }
            })?;
            validate_direct_metadata(entry.path(), &metadata)?;
            if metadata.is_dir() {
                if !expected_directories.contains(&normalized) {
                    return Err(RunnerBundleError::UnexpectedEntry {
                        path: entry.path().to_path_buf(),
                    });
                }
                continue;
            }
            if !metadata.is_file() {
                return Err(RunnerBundleError::UnsafeEntry {
                    path: entry.path().to_path_buf(),
                });
            }
            artifact_count = artifact_count
                .checked_add(1)
                .ok_or(RunnerBundleError::TooManyArtifacts)?;
            if artifact_count > MAX_RUNNER_ARTIFACTS {
                return Err(RunnerBundleError::TooManyArtifacts);
            }
            let name = CertificationRunnerArtifactName::new(normalized)
                .map_err(RunnerBundleError::ArtifactName)?;
            let maximum = usize::try_from(MAX_CERTIFICATION_RUNNER_COMPONENT_ARTIFACT_BYTES)
                .map_err(|_| RunnerBundleError::ArtifactTooLarge {
                    path: entry.path().to_path_buf(),
                })?;
            let bytes = read_bounded_file(entry.path(), maximum)?;
            total_bytes = total_bytes
                .checked_add(bytes.len())
                .ok_or(RunnerBundleError::TotalArtifactBytesExceeded)?;
            if total_bytes > MAX_TOTAL_RUNNER_ARTIFACT_BYTES {
                return Err(RunnerBundleError::TotalArtifactBytesExceeded);
            }
            if artifacts.insert(name, bytes).is_some() {
                return Err(RunnerBundleError::DuplicateArtifactPath {
                    path: entry.path().to_path_buf(),
                });
            }
        }
        all_artifacts.insert(role, artifacts);
    }
    Ok(all_artifacts)
}

fn validate_role_directories(root: &Path) -> Result<(), RunnerBundleError> {
    let mut observed = BTreeSet::new();
    for result in fs::read_dir(root).map_err(|source| RunnerBundleError::ReadDirectory {
        path: root.to_path_buf(),
        source,
    })? {
        let entry = result.map_err(RunnerBundleError::ReadDirectoryEntry)?;
        validate_kind(&entry.path(), EntryKind::Directory)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| RunnerBundleError::NonUtf8Entry { path: entry.path() })?;
        let role = runner_roles()
            .into_iter()
            .find(|role| role_name(*role) == name)
            .ok_or_else(|| RunnerBundleError::UnexpectedEntry { path: entry.path() })?;
        if !observed.insert(role) {
            return Err(RunnerBundleError::DuplicateRole { role });
        }
    }
    for role in runner_roles() {
        if !observed.contains(&role) {
            return Err(RunnerBundleError::MissingRole { role });
        }
    }
    Ok(())
}

fn expected_artifact_directories(
    descriptor: &CertificationRunnerComponentDescriptor,
) -> BTreeSet<String> {
    let mut directories = BTreeSet::new();
    for artifact in descriptor.artifacts() {
        let mut parent = String::new();
        let mut components = artifact.name().as_str().split('/').peekable();
        while let Some(component) = components.next() {
            if components.peek().is_none() {
                break;
            }
            if !parent.is_empty() {
                parent.push('/');
            }
            parent.push_str(component);
            directories.insert(parent.clone());
        }
    }
    directories
}

fn read_bounded_file(path: &Path, maximum: usize) -> Result<Vec<u8>, RunnerBundleError> {
    validate_kind(path, EntryKind::File)?;
    let metadata = fs::metadata(path).map_err(|source| RunnerBundleError::InspectEntry {
        path: path.to_path_buf(),
        source,
    })?;
    let length = usize::try_from(metadata.len()).map_err(|_| RunnerBundleError::FileTooLarge {
        path: path.to_path_buf(),
        maximum,
    })?;
    if length > maximum {
        return Err(RunnerBundleError::FileTooLarge {
            path: path.to_path_buf(),
            maximum,
        });
    }
    let mut file = File::open(path).map_err(|source| RunnerBundleError::OpenFile {
        path: path.to_path_buf(),
        source,
    })?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| RunnerBundleError::FileAllocationFailed {
            path: path.to_path_buf(),
        })?;
    let limit = u64::try_from(maximum)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| RunnerBundleError::FileTooLarge {
            path: path.to_path_buf(),
            maximum,
        })?;
    file.by_ref()
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|source| RunnerBundleError::ReadFile {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() != length || bytes.len() > maximum {
        return Err(RunnerBundleError::FileChanged {
            path: path.to_path_buf(),
        });
    }
    Ok(bytes)
}

#[derive(Clone, Copy)]
enum EntryKind {
    File,
    Directory,
}

fn validate_kind(path: &Path, kind: EntryKind) -> Result<(), RunnerBundleError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| RunnerBundleError::InspectEntry {
            path: path.to_path_buf(),
            source,
        })?;
    validate_direct_metadata(path, &metadata)?;
    let correct = match kind {
        EntryKind::File => metadata.is_file(),
        EntryKind::Directory => metadata.is_dir(),
    };
    if !correct {
        return Err(RunnerBundleError::UnsafeEntry {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn validate_direct_metadata(path: &Path, metadata: &fs::Metadata) -> Result<(), RunnerBundleError> {
    if metadata.file_type().is_symlink() {
        return Err(RunnerBundleError::UnsafeEntry {
            path: path.to_path_buf(),
        });
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(RunnerBundleError::UnsafeEntry {
                path: path.to_path_buf(),
            });
        }
    }
    Ok(())
}

fn normalized_relative_path(path: &Path) -> Result<String, RunnerBundleError> {
    let mut normalized = String::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err(RunnerBundleError::UnsafeArtifactPath {
                path: path.to_path_buf(),
            });
        };
        let component = component
            .to_str()
            .ok_or_else(|| RunnerBundleError::NonUtf8Entry {
                path: path.to_path_buf(),
            })?;
        if !normalized.is_empty() {
            normalized.push('/');
        }
        normalized.push_str(component);
    }
    if normalized.is_empty() {
        return Err(RunnerBundleError::UnsafeArtifactPath {
            path: path.to_path_buf(),
        });
    }
    Ok(normalized)
}

const fn runner_roles() -> [CertificationRunnerComponentRole; 11] {
    [
        CertificationRunnerComponentRole::RunnerImage,
        CertificationRunnerComponentRole::HostImage,
        CertificationRunnerComponentRole::HostPatchSet,
        CertificationRunnerComponentRole::ElectronRuntime,
        CertificationRunnerComponentRole::LanguageRuntimeSet,
        CertificationRunnerComponentRole::ToolchainSet,
        CertificationRunnerComponentRole::HostAgent,
        CertificationRunnerComponentRole::Verifier,
        CertificationRunnerComponentRole::ProbeAssetSet,
        CertificationRunnerComponentRole::SourceRevision,
        CertificationRunnerComponentRole::ExceptionProvenance,
    ]
}

const fn role_name(role: CertificationRunnerComponentRole) -> &'static str {
    match role {
        CertificationRunnerComponentRole::RunnerImage => "runner_image",
        CertificationRunnerComponentRole::HostImage => "host_image",
        CertificationRunnerComponentRole::HostPatchSet => "host_patch_set",
        CertificationRunnerComponentRole::ElectronRuntime => "electron_runtime",
        CertificationRunnerComponentRole::LanguageRuntimeSet => "language_runtime_set",
        CertificationRunnerComponentRole::ToolchainSet => "toolchain_set",
        CertificationRunnerComponentRole::HostAgent => "host_agent",
        CertificationRunnerComponentRole::Verifier => "verifier",
        CertificationRunnerComponentRole::ProbeAssetSet => "probe_asset_set",
        CertificationRunnerComponentRole::SourceRevision => "source_revision",
        CertificationRunnerComponentRole::ExceptionProvenance => "exception_provenance",
    }
}

fn component_filename(role: CertificationRunnerComponentRole) -> String {
    format!("{}.json", role_name(role))
}

/// Failure to load a closed exact runner bundle.
#[derive(Debug, Error)]
pub(crate) enum RunnerBundleError {
    #[error("failed to inspect runner-bundle entry {path}")]
    InspectEntry {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("unsafe runner-bundle entry {path}")]
    UnsafeEntry { path: PathBuf },
    #[error("failed to enumerate runner-bundle directory {path}")]
    ReadDirectory {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read runner-bundle directory entry")]
    ReadDirectoryEntry(#[source] std::io::Error),
    #[error("runner-bundle entry is not UTF-8: {path}")]
    NonUtf8Entry { path: PathBuf },
    #[error("unexpected runner-bundle entry {path}")]
    UnexpectedEntry { path: PathBuf },
    #[error("missing runner-bundle entry {path}")]
    MissingEntry { path: PathBuf },
    #[error("runner-bundle role appears more than once: {role:?}")]
    DuplicateRole {
        role: CertificationRunnerComponentRole,
    },
    #[error("runner-bundle role is missing: {role:?}")]
    MissingRole {
        role: CertificationRunnerComponentRole,
    },
    #[error("invalid bounded runner identity")]
    Identity(#[source] CertificationRunnerDocumentError),
    #[error("runner identity bytes are not canonical")]
    NonCanonicalIdentity,
    #[error("invalid bounded runner descriptor for {role:?}")]
    Descriptor {
        role: CertificationRunnerComponentRole,
        #[source]
        source: CertificationRunnerComponentDocumentError,
    },
    #[error("runner descriptor bytes are not canonical for {role:?}")]
    NonCanonicalDescriptor {
        role: CertificationRunnerComponentRole,
    },
    #[error("canonical runner-bundle document is unavailable")]
    CanonicalDocument(#[source] serde_json::Error),
    #[error("failed to walk runner artifacts for {role:?}")]
    WalkArtifacts {
        role: CertificationRunnerComponentRole,
        #[source]
        source: walkdir::Error,
    },
    #[error("runner artifact escaped its role root: {path}")]
    ArtifactEscapedRole { path: PathBuf },
    #[error("unsafe runner artifact path {path}")]
    UnsafeArtifactPath { path: PathBuf },
    #[error("invalid runner artifact name")]
    ArtifactName(#[source] CertificationRunnerComponentTextError),
    #[error("runner bundle has too many artifacts")]
    TooManyArtifacts,
    #[error("runner artifact is unrepresentably large: {path}")]
    ArtifactTooLarge { path: PathBuf },
    #[error("runner artifacts exceed their aggregate byte ceiling")]
    TotalArtifactBytesExceeded,
    #[error("duplicate runner artifact path {path}")]
    DuplicateArtifactPath { path: PathBuf },
    #[error("runner-bundle file {path} exceeds its {maximum}-byte limit")]
    FileTooLarge { path: PathBuf, maximum: usize },
    #[error("failed to open runner-bundle file {path}")]
    OpenFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("runner-bundle file allocation failed for {path}")]
    FileAllocationFailed { path: PathBuf },
    #[error("failed to read runner-bundle file {path}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("runner-bundle file changed while it was read: {path}")]
    FileChanged { path: PathBuf },
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        path::Path,
    };

    use sha2::{Digest as _, Sha256};
    use tempfile::tempdir;
    use weregopher_domain::{
        CertificationElectronRuntimeDigest, CertificationExceptionProvenanceDigest,
        CertificationHostAgentDigest, CertificationHostImageDigest,
        CertificationHostPatchSetDigest, CertificationLanguageRuntimeSetDigest,
        CertificationProbeAssetSetDigest, CertificationRunnerArtifactName,
        CertificationRunnerComponentArtifact, CertificationRunnerComponentDescriptor,
        CertificationRunnerComponentId, CertificationRunnerComponentProvenanceDigest,
        CertificationRunnerComponentRole, CertificationRunnerComponentVersion,
        CertificationRunnerEnvironmentIdentity, CertificationRunnerIdentity,
        CertificationRunnerImageDigest, CertificationRunnerProvenanceIdentity,
        CertificationRunnerToolingIdentity, CertificationSourceRevisionDigest,
        CertificationToolchainSetDigest, CertificationVerifierDigest, Sha256Digest,
    };

    use super::{
        ARTIFACT_DIRECTORY, COMPONENT_DIRECTORY, IDENTITY_FILE, RunnerBundleError,
        component_filename, load_certification_runner_bundle, role_name, runner_roles,
    };

    #[test]
    fn closed_canonical_runner_bundle_loads_every_exact_role_and_artifact()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = tempdir()?;
        let identity = write_fixture(fixture.path())?;
        let loaded = load_certification_runner_bundle(fixture.path())?;
        assert_eq!(loaded.identity(), &identity);
        assert_eq!(loaded.descriptors().len(), 11);
        let borrowed = loaded.borrowed_artifacts();
        assert_eq!(borrowed.len(), 11);
        assert_eq!(borrowed.values().map(BTreeMap::len).sum::<usize>(), 11);
        Ok(())
    }

    #[test]
    fn runner_bundle_rejects_noncanonical_documents_and_unknown_artifact_directories()
    -> Result<(), Box<dyn std::error::Error>> {
        let noncanonical = tempdir()?;
        write_fixture(noncanonical.path())?;
        let descriptor = noncanonical
            .path()
            .join(COMPONENT_DIRECTORY)
            .join(component_filename(
                CertificationRunnerComponentRole::RunnerImage,
            ));
        let mut bytes = fs::read(&descriptor)?;
        bytes.push(b'\n');
        fs::write(&descriptor, bytes)?;
        assert!(matches!(
            load_certification_runner_bundle(noncanonical.path()),
            Err(RunnerBundleError::NonCanonicalDescriptor {
                role: CertificationRunnerComponentRole::RunnerImage
            })
        ));

        let unknown = tempdir()?;
        write_fixture(unknown.path())?;
        fs::create_dir(
            unknown
                .path()
                .join(ARTIFACT_DIRECTORY)
                .join(role_name(CertificationRunnerComponentRole::RunnerImage))
                .join("unknown"),
        )?;
        assert!(matches!(
            load_certification_runner_bundle(unknown.path()),
            Err(RunnerBundleError::UnexpectedEntry { .. })
        ));
        Ok(())
    }

    fn write_fixture(
        root: &Path,
    ) -> Result<CertificationRunnerIdentity, Box<dyn std::error::Error>> {
        fs::create_dir(root.join(COMPONENT_DIRECTORY))?;
        fs::create_dir(root.join(ARTIFACT_DIRECTORY))?;
        let mut digests = BTreeMap::new();
        for (index, role) in runner_roles().into_iter().enumerate() {
            let tag = u8::try_from(index + 1)?;
            let bytes = vec![tag; 3];
            let artifact_name =
                CertificationRunnerArtifactName::new(format!("nested/{tag:02}.bin"))?;
            let descriptor = CertificationRunnerComponentDescriptor::new(
                role,
                CertificationRunnerComponentId::new(format!("weregopher.fixture.{tag:02}"))?,
                CertificationRunnerComponentVersion::new(format!("1.0.{tag}"))?,
                CertificationRunnerComponentProvenanceDigest::new(digest(&[tag, 0])),
                BTreeSet::from([CertificationRunnerComponentArtifact::new(
                    artifact_name.clone(),
                    digest(&bytes),
                    u64::try_from(bytes.len())?,
                )?]),
            )?;
            digests.insert(role, *descriptor.canonical_document_digest()?.as_sha256());
            fs::write(
                root.join(COMPONENT_DIRECTORY)
                    .join(component_filename(role)),
                descriptor.canonical_json_bytes()?,
            )?;
            let role_root = root.join(ARTIFACT_DIRECTORY).join(role_name(role));
            fs::create_dir(&role_root)?;
            let artifact_path = role_root.join("nested").join(format!("{tag:02}.bin"));
            let parent = artifact_path
                .parent()
                .ok_or("fixture artifact has no parent")?;
            fs::create_dir(parent)?;
            fs::write(artifact_path, bytes)?;
        }
        let identity = CertificationRunnerIdentity::new(
            CertificationRunnerEnvironmentIdentity::windows_x86_64(
                CertificationRunnerImageDigest::new(role_digest(
                    &digests,
                    CertificationRunnerComponentRole::RunnerImage,
                )?),
                CertificationHostImageDigest::new(role_digest(
                    &digests,
                    CertificationRunnerComponentRole::HostImage,
                )?),
                CertificationHostPatchSetDigest::new(role_digest(
                    &digests,
                    CertificationRunnerComponentRole::HostPatchSet,
                )?),
                CertificationElectronRuntimeDigest::new(role_digest(
                    &digests,
                    CertificationRunnerComponentRole::ElectronRuntime,
                )?),
                CertificationLanguageRuntimeSetDigest::new(role_digest(
                    &digests,
                    CertificationRunnerComponentRole::LanguageRuntimeSet,
                )?),
            ),
            CertificationRunnerToolingIdentity::new(
                CertificationToolchainSetDigest::new(role_digest(
                    &digests,
                    CertificationRunnerComponentRole::ToolchainSet,
                )?),
                CertificationHostAgentDigest::new(role_digest(
                    &digests,
                    CertificationRunnerComponentRole::HostAgent,
                )?),
                CertificationVerifierDigest::new(role_digest(
                    &digests,
                    CertificationRunnerComponentRole::Verifier,
                )?),
                CertificationProbeAssetSetDigest::new(role_digest(
                    &digests,
                    CertificationRunnerComponentRole::ProbeAssetSet,
                )?),
            ),
            CertificationRunnerProvenanceIdentity::new(
                CertificationSourceRevisionDigest::new(role_digest(
                    &digests,
                    CertificationRunnerComponentRole::SourceRevision,
                )?),
                CertificationExceptionProvenanceDigest::new(role_digest(
                    &digests,
                    CertificationRunnerComponentRole::ExceptionProvenance,
                )?),
            ),
        );
        fs::write(root.join(IDENTITY_FILE), identity.canonical_json_bytes()?)?;
        Ok(identity)
    }

    fn role_digest(
        digests: &BTreeMap<CertificationRunnerComponentRole, Sha256Digest>,
        role: CertificationRunnerComponentRole,
    ) -> Result<Sha256Digest, Box<dyn std::error::Error>> {
        digests
            .get(&role)
            .copied()
            .ok_or_else(|| format!("missing fixture digest for {role:?}").into())
    }

    fn digest(bytes: &[u8]) -> Sha256Digest {
        Sha256Digest::from_bytes(Sha256::digest(bytes).into())
    }
}
