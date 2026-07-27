//! Read-only, exact-build `OpenAI` package inventory construction.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use weregopher_asar::{AsarError, AsarLimits, AsarReadOnlyIndex};
use weregopher_domain::{
    Architecture, BuildFingerprint, G2ComponentEvidence, G2ComponentSource, G2ContractError,
    G2PackagePath, InstallationKind, OpenAiPackageInventory, PackageIdentity, Sha256Digest,
};
use weregopher_fingerprint::{PackageFileKind, PackageFileRecord, PackageTreeManifest};

/// Durable application-family identifier accepted by the initial G2 slice.
pub const OPENAI_WINDOWS_FAMILY: &str = "openai.chatgpt.windows";
/// Maintained package-relative desktop entry for the initial exact target.
pub const OPENAI_DESKTOP_ENTRY_PATH: &str = "app/ChatGPT.exe";
/// Maintained package-relative application archive for the initial exact target.
pub const OPENAI_APPLICATION_ARCHIVE_PATH: &str = "app/resources/app.asar";
/// Maintained package-relative bundled app-server executable for the initial exact target.
pub const OPENAI_APP_SERVER_PATH: &str = "app/resources/codex.exe";

const PACKAGE_MANIFEST_PATH: &str = "package.json";
const MAX_PACKAGE_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_STATIC_CANDIDATE_BYTES: usize = 16 * 1024 * 1024;
const PRELOAD_SIGNAL: &[u8] = b"contextBridge";
const EXPOSE_SIGNAL: &[u8] = b"exposeInMainWorld";

/// Fail-closed package analysis error for the initial `OpenAI` G2 target.
#[derive(Debug, Error)]
pub enum OpenAiPackageAnalysisError {
    /// The build identifies another application family.
    #[error("G2 OpenAI analysis requires family {OPENAI_WINDOWS_FAMILY}")]
    UnsupportedFamily,
    /// The build is not the initial Windows x64 MSIX target.
    #[error("G2 OpenAI analysis requires a Windows x64 MSIX build")]
    UnsupportedTarget,
    /// The build omitted Windows package identity.
    #[error("G2 OpenAI analysis requires package identity")]
    MissingPackageIdentity,
    /// Package identity did not match the maintained initial target.
    #[error("G2 OpenAI package identity is not a maintained exact target")]
    UnsupportedPackageIdentity,
    /// Application identifiers were not canonically ordered and unique.
    #[error("G2 OpenAI package application identifiers are not canonical")]
    NonCanonicalApplicationIds,
    /// The build fingerprint and supplied package tree disagree.
    #[error("G2 OpenAI package tree does not match the build fingerprint")]
    PackageTreeMismatch,
    /// A required direct package component is absent.
    #[error("G2 OpenAI package is missing required component {role}")]
    MissingPackageComponent {
        /// Semantic role whose maintained path was absent.
        role: &'static str,
    },
    /// A required package component has the wrong manifest classification.
    #[error("G2 OpenAI package component {role} has an unexpected kind")]
    UnexpectedPackageComponentKind {
        /// Semantic role whose manifest classification was rejected.
        role: &'static str,
    },
    /// Supplied application-archive bytes did not match the package manifest.
    #[error("G2 OpenAI application archive bytes do not match package evidence")]
    ApplicationArchiveDigestMismatch,
    /// An already-populated build field contradicted observed archive evidence.
    #[error("G2 OpenAI build fingerprint contradicts observed {field} evidence")]
    BuildEvidenceMismatch {
        /// Build-fingerprint field that contradicted direct bytes.
        field: &'static str,
    },
    /// The application archive was malformed or unsupported.
    #[error("G2 OpenAI application archive is invalid: {0}")]
    Archive(#[from] AsarError),
    /// The application archive omitted its package manifest.
    #[error("G2 OpenAI application archive has no package.json")]
    MissingPackageManifest,
    /// The application package manifest exceeded the analyzer ceiling.
    #[error("G2 OpenAI package.json exceeds its byte limit")]
    PackageManifestTooLarge,
    /// The application package manifest was malformed.
    #[error("G2 OpenAI package.json is invalid: {0}")]
    InvalidPackageManifest(#[source] serde_json::Error),
    /// The package manifest omitted its main entry.
    #[error("G2 OpenAI package.json has no nonempty main entry")]
    MissingMainEntry,
    /// The package main path was noncanonical.
    #[error("G2 OpenAI package.json main entry is not canonical")]
    InvalidMainEntry,
    /// The exact package-derived main member was absent.
    #[error("G2 OpenAI application archive does not contain its declared main entry")]
    MissingMainMember,
    /// No bounded static preload candidate contained required bridge evidence.
    #[error("G2 OpenAI package has no bounded contextBridge preload candidate")]
    MissingPreloadCandidate,
    /// A candidate source exceeded the static inspection ceiling.
    #[error("G2 OpenAI JavaScript candidate exceeds its byte limit")]
    CandidateSourceTooLarge,
    /// No packaged renderer entry candidate was found.
    #[error("G2 OpenAI package has no packaged HTML renderer candidate")]
    MissingRendererCandidate,
    /// Canonical evidence serialization failed.
    #[error("failed to serialize canonical G2 package evidence: {0}")]
    SerializeEvidence(#[source] serde_json::Error),
    /// A canonical G2 evidence invariant failed.
    #[error("invalid canonical G2 package evidence: {0}")]
    Contract(#[from] G2ContractError),
}

#[derive(Deserialize)]
struct PackageManifest {
    main: Option<String>,
}

/// Builds a content-addressed inventory from a pre-fingerprinted exact package
/// tree and the exact bytes of its application archive.
///
/// This function does not discover paths, access the filesystem, execute
/// package code, or authorize a later probe. Preload candidates are exact
/// archive members containing both maintained `contextBridge` signals; the
/// exact-package renderer probe must still prove which candidate executes.
///
/// # Errors
///
/// Returns [`OpenAiPackageAnalysisError`] when target identity, package-tree
/// binding, required components, archive integrity, manifest resolution, or
/// bounded preload/renderer candidate discovery fails.
pub fn analyze_openai_package(
    build: &BuildFingerprint,
    package_tree: &PackageTreeManifest,
    application_archive_bytes: &[u8],
) -> Result<OpenAiPackageInventory, OpenAiPackageAnalysisError> {
    validate_target(build)?;
    if &build.package_tree_merkle != package_tree.package_tree_merkle() {
        return Err(OpenAiPackageAnalysisError::PackageTreeMismatch);
    }
    let identity = build
        .package_identity
        .as_ref()
        .ok_or(OpenAiPackageAnalysisError::MissingPackageIdentity)?;
    validate_package_identity(identity, build.package_version.as_deref())?;

    let desktop = required_record(
        package_tree,
        OPENAI_DESKTOP_ENTRY_PATH,
        PackageFileKind::Executable,
        "desktop_entry",
    )?;
    let archive_record = required_record(
        package_tree,
        OPENAI_APPLICATION_ARCHIVE_PATH,
        PackageFileKind::Asar,
        "application_archive",
    )?;
    let app_server = required_record(
        package_tree,
        OPENAI_APP_SERVER_PATH,
        PackageFileKind::Executable,
        "app_server",
    )?;
    if digest(application_archive_bytes) != archive_record.sha256 {
        return Err(OpenAiPackageAnalysisError::ApplicationArchiveDigestMismatch);
    }
    if build
        .app_asar_sha256
        .is_some_and(|expected| expected != archive_record.sha256)
    {
        return Err(OpenAiPackageAnalysisError::BuildEvidenceMismatch {
            field: "app_asar_sha256",
        });
    }

    let archive = AsarReadOnlyIndex::parse(application_archive_bytes, AsarLimits::initial())?;
    let (main_entry, preload_candidates, renderer_candidates) =
        analyze_application_archive(build, &archive)?;

    OpenAiPackageInventory::new(
        canonical_digest(build)?,
        canonical_digest(identity)?,
        package_component(desktop)?,
        package_component(archive_record)?,
        main_entry,
        preload_candidates,
        renderer_candidates,
        package_component(app_server)?,
    )
    .map_err(Into::into)
}

fn analyze_application_archive(
    build: &BuildFingerprint,
    archive: &AsarReadOnlyIndex,
) -> Result<
    (
        G2ComponentEvidence,
        Vec<G2ComponentEvidence>,
        Vec<G2ComponentEvidence>,
    ),
    OpenAiPackageAnalysisError,
> {
    let package_manifest = archive
        .packed_file(PACKAGE_MANIFEST_PATH)
        .ok_or(OpenAiPackageAnalysisError::MissingPackageManifest)?;
    if package_manifest.len() > MAX_PACKAGE_MANIFEST_BYTES {
        return Err(OpenAiPackageAnalysisError::PackageManifestTooLarge);
    }
    let package_manifest: PackageManifest = serde_json::from_slice(package_manifest)
        .map_err(OpenAiPackageAnalysisError::InvalidPackageManifest)?;
    let main_path = normalize_main_entry(
        package_manifest
            .main
            .as_deref()
            .ok_or(OpenAiPackageAnalysisError::MissingMainEntry)?,
    )?;
    let main_bytes = archive
        .packed_file(main_path.as_str())
        .ok_or(OpenAiPackageAnalysisError::MissingMainMember)?;
    let main_digest = digest(main_bytes);
    if build
        .main_entry_sha256
        .is_some_and(|expected| expected != main_digest)
    {
        return Err(OpenAiPackageAnalysisError::BuildEvidenceMismatch {
            field: "main_entry_sha256",
        });
    }

    let mut preload_candidates = Vec::new();
    let mut renderer_candidates = Vec::new();
    for path in archive.packed_file_paths() {
        let Some(bytes) = archive.packed_file(path) else {
            continue;
        };
        if is_javascript(path)
            && contains_bytes(bytes, PRELOAD_SIGNAL)
            && contains_bytes(bytes, EXPOSE_SIGNAL)
        {
            if bytes.len() > MAX_STATIC_CANDIDATE_BYTES {
                return Err(OpenAiPackageAnalysisError::CandidateSourceTooLarge);
            }
            preload_candidates.push(archive_component(path, bytes)?);
        }
        if path.to_ascii_lowercase().ends_with(".html") {
            renderer_candidates.push(archive_component(path, bytes)?);
        }
    }
    if preload_candidates.is_empty() {
        return Err(OpenAiPackageAnalysisError::MissingPreloadCandidate);
    }
    if renderer_candidates.is_empty() {
        return Err(OpenAiPackageAnalysisError::MissingRendererCandidate);
    }
    Ok((
        G2ComponentEvidence::new(
            G2ComponentSource::ApplicationArchiveMember,
            main_path,
            main_digest,
            u64::try_from(main_bytes.len()).map_err(|_| G2ContractError::EmptyComponent)?,
        )?,
        preload_candidates,
        renderer_candidates,
    ))
}

fn validate_target(build: &BuildFingerprint) -> Result<(), OpenAiPackageAnalysisError> {
    if build.family.as_str() != OPENAI_WINDOWS_FAMILY {
        return Err(OpenAiPackageAnalysisError::UnsupportedFamily);
    }
    if build.installation_kind != InstallationKind::Msix
        || build.architecture != Architecture::X86_64
    {
        return Err(OpenAiPackageAnalysisError::UnsupportedTarget);
    }
    Ok(())
}

fn validate_package_identity(
    identity: &PackageIdentity,
    package_version: Option<&str>,
) -> Result<(), OpenAiPackageAnalysisError> {
    let mut canonical_ids = identity.application_ids.clone();
    canonical_ids.sort();
    canonical_ids.dedup();
    if canonical_ids != identity.application_ids {
        return Err(OpenAiPackageAnalysisError::NonCanonicalApplicationIds);
    }
    let Some(version) = package_version else {
        return Err(OpenAiPackageAnalysisError::UnsupportedPackageIdentity);
    };
    let expected_full_name = format!("OpenAI.Codex_{version}_x64__{}", identity.publisher_id);
    if identity.package_name != "OpenAI.Codex"
        || identity.package_family_name != "OpenAI.Codex_2p2nqsd0c76g0"
        || identity.publisher_id != "2p2nqsd0c76g0"
        || !identity
            .application_ids
            .iter()
            .any(|application_id| application_id == "App")
        || identity.package_full_name != expected_full_name
    {
        return Err(OpenAiPackageAnalysisError::UnsupportedPackageIdentity);
    }
    Ok(())
}

fn required_record<'a>(
    package_tree: &'a PackageTreeManifest,
    path: &str,
    expected_kind: PackageFileKind,
    role: &'static str,
) -> Result<&'a PackageFileRecord, OpenAiPackageAnalysisError> {
    let record = package_tree
        .files()
        .iter()
        .find(|record| record.normalized_path == path)
        .ok_or(OpenAiPackageAnalysisError::MissingPackageComponent { role })?;
    if record.kind != expected_kind || record.size == 0 {
        return Err(OpenAiPackageAnalysisError::UnexpectedPackageComponentKind { role });
    }
    Ok(record)
}

fn package_component(record: &PackageFileRecord) -> Result<G2ComponentEvidence, G2ContractError> {
    G2ComponentEvidence::new(
        G2ComponentSource::PackageFile,
        G2PackagePath::new(record.normalized_path.clone())?,
        record.sha256,
        record.size,
    )
}

fn archive_component(path: &str, bytes: &[u8]) -> Result<G2ComponentEvidence, G2ContractError> {
    G2ComponentEvidence::new(
        G2ComponentSource::ApplicationArchiveMember,
        G2PackagePath::new(path)?,
        digest(bytes),
        u64::try_from(bytes.len()).map_err(|_| G2ContractError::EmptyComponent)?,
    )
}

fn normalize_main_entry(value: &str) -> Result<G2PackagePath, OpenAiPackageAnalysisError> {
    let value = value.strip_prefix("./").unwrap_or(value);
    if value.is_empty() {
        return Err(OpenAiPackageAnalysisError::MissingMainEntry);
    }
    G2PackagePath::new(value).map_err(|_| OpenAiPackageAnalysisError::InvalidMainEntry)
}

fn is_javascript(path: &str) -> bool {
    let lowercase = path.to_ascii_lowercase();
    [".js", ".cjs", ".mjs"]
        .iter()
        .any(|extension| lowercase.ends_with(extension))
}

fn contains_bytes(bytes: &[u8], needle: &[u8]) -> bool {
    bytes
        .windows(needle.len())
        .any(|candidate| candidate == needle)
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<Sha256Digest, OpenAiPackageAnalysisError> {
    let bytes = serde_json::to_vec(value).map_err(OpenAiPackageAnalysisError::SerializeEvidence)?;
    Ok(digest(&bytes))
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}
