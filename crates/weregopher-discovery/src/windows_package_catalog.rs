//! Read-only current-user Windows package-catalog discovery.

use weregopher_domain::{Architecture, CandidateInstallationEvidence, CandidateTarget};
use windows::{
    ApplicationModel::{Package, PackageVersion},
    Management::Deployment::PackageManager,
    System::ProcessorArchitecture,
    core::{Error as WindowsError, HSTRING},
};

use crate::{
    DiscoveryError, PackageCatalogEntry, evidence_from_package_catalog_entry,
    package_catalog::supported_package_family_names,
};

const MAX_PACKAGES_PER_FAMILY: usize = 8;
const MAX_APPLICATION_IDS: usize = 64;
const MAX_PACKAGE_TEXT_CHARS: usize = 32_768;
const MAX_CANDIDATE_RESULTS: usize = 16;

/// Discovers supported current-user MSIX/AppX packages through Windows
/// `PackageManager` rather than scraping the protected `WindowsApps` directory.
///
/// Queries are restricted to maintained package family names. At most eight
/// packages are accepted per family, 64 application IDs per package, 32,768
/// characters per text field, and 16 candidate records in total. Package state
/// must verify as healthy and framework/resource packages are ignored.
///
/// # Errors
///
/// Returns [`DiscoveryError`] when a Windows package API or installation-root
/// observation fails, or when a package-catalog bound is exceeded.
pub fn discover_windows_package_catalog()
-> Result<Vec<CandidateInstallationEvidence>, DiscoveryError> {
    let manager =
        PackageManager::new().map_err(|source| catalog_error("activate PackageManager", source))?;
    let current_user = HSTRING::new();
    let mut discovered = Vec::new();

    for family_name in supported_package_family_names() {
        let family = HSTRING::from(family_name);
        let packages = manager
            .FindPackagesByUserSecurityIdPackageFamilyName(&current_user, &family)
            .map_err(|source| {
                catalog_error(format!("query current-user family {family_name}"), source)
            })?;
        for (index, package) in packages.into_iter().enumerate() {
            if index >= MAX_PACKAGES_PER_FAMILY {
                return Err(DiscoveryError::PackageCatalogLimit {
                    field: "packages per family",
                    limit: MAX_PACKAGES_PER_FAMILY,
                });
            }
            if let Some(evidence) = evidence_from_package(&package)? {
                discovered.push(evidence);
                if discovered.len() > MAX_CANDIDATE_RESULTS {
                    return Err(DiscoveryError::PackageCatalogLimit {
                        field: "candidate results",
                        limit: MAX_CANDIDATE_RESULTS,
                    });
                }
            }
        }
    }

    discovered.sort_by_key(evidence_sort_key);
    Ok(discovered)
}

fn evidence_from_package(
    package: &Package,
) -> Result<Option<CandidateInstallationEvidence>, DiscoveryError> {
    if package
        .IsFramework()
        .map_err(|source| catalog_error("read package framework status", source))?
        || package
            .IsResourcePackage()
            .map_err(|source| catalog_error("read package resource status", source))?
        || !package
            .Status()
            .and_then(|status| status.VerifyIsOK())
            .map_err(|source| catalog_error("verify package status", source))?
    {
        return Ok(None);
    }

    let id = package
        .Id()
        .map_err(|source| catalog_error("read package identity", source))?;
    let package_name = bounded_hstring(
        &id.Name()
            .map_err(|source| catalog_error("read package name", source))?,
        "package name",
    )?;
    let package_family_name = bounded_hstring(
        &id.FamilyName()
            .map_err(|source| catalog_error("read package family name", source))?,
        "package family name",
    )?;
    let package_full_name = bounded_hstring(
        &id.FullName()
            .map_err(|source| catalog_error("read package full name", source))?,
        "package full name",
    )?;
    let publisher_id = bounded_hstring(
        &id.PublisherId()
            .map_err(|source| catalog_error("read package publisher id", source))?,
        "package publisher id",
    )?;
    let architecture = id
        .Architecture()
        .map_err(|source| catalog_error("read package architecture", source))?;
    let version = id
        .Version()
        .map_err(|source| catalog_error("read package version", source))?;
    let installed_location = package
        .InstalledLocation()
        .and_then(|folder| folder.Path())
        .map_err(|source| catalog_error("read package installation path", source))?;
    let install_location =
        bounded_hstring(&installed_location, "package installation path")?.into();
    let application_ids = application_ids(package)?;

    evidence_from_package_catalog_entry(&PackageCatalogEntry {
        package_name,
        package_family_name,
        package_full_name,
        publisher_id,
        application_ids,
        install_location,
        architecture: normalize_architecture(architecture),
        version: version_text(version),
    })
}

fn application_ids(package: &Package) -> Result<Vec<String>, DiscoveryError> {
    let entries = package
        .GetAppListEntries()
        .map_err(|source| catalog_error("read package application entries", source))?;
    let mut application_ids = Vec::new();
    for (index, entry) in entries.into_iter().enumerate() {
        if index >= MAX_APPLICATION_IDS {
            return Err(DiscoveryError::PackageCatalogLimit {
                field: "application ids",
                limit: MAX_APPLICATION_IDS,
            });
        }
        let application_id = entry
            .AppInfo()
            .and_then(|info| info.Id())
            .map_err(|source| catalog_error("read package application id", source))?;
        application_ids.push(bounded_hstring(&application_id, "application id")?);
    }
    application_ids.sort();
    application_ids.dedup();
    Ok(application_ids)
}

fn bounded_hstring(value: &HSTRING, field: &'static str) -> Result<String, DiscoveryError> {
    let value = value.to_string_lossy();
    if value.chars().count() > MAX_PACKAGE_TEXT_CHARS {
        return Err(DiscoveryError::PackageCatalogLimit {
            field,
            limit: MAX_PACKAGE_TEXT_CHARS,
        });
    }
    Ok(value)
}

const fn normalize_architecture(value: ProcessorArchitecture) -> Option<Architecture> {
    if value.0 == ProcessorArchitecture::X64.0 {
        Some(Architecture::X86_64)
    } else if value.0 == ProcessorArchitecture::Arm64.0 {
        Some(Architecture::Aarch64)
    } else {
        None
    }
}

fn version_text(version: PackageVersion) -> String {
    format!(
        "{}.{}.{}.{}",
        version.Major, version.Minor, version.Build, version.Revision
    )
}

fn catalog_error(operation: impl Into<String>, source: WindowsError) -> DiscoveryError {
    DiscoveryError::PackageCatalogRead {
        operation: operation.into(),
        source,
    }
}

fn evidence_sort_key(evidence: &CandidateInstallationEvidence) -> (u8, String, String) {
    (
        match evidence.target {
            CandidateTarget::Codex => 0,
            CandidateTarget::HermesAgent => 1,
            CandidateTarget::Discord => 2,
            CandidateTarget::VisualStudioCode => 3,
        },
        evidence
            .observed_version
            .as_ref()
            .map_or_else(String::new, |version| version.value.clone()),
        evidence.root_path.value.to_lowercase(),
    )
}
