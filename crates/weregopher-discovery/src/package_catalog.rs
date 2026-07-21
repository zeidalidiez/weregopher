//! Pure matching of read-only Windows package-catalog records.

use std::path::PathBuf;

use weregopher_domain::{
    Architecture, CandidateInstallationEvidence, CandidateTarget, DerivedValue,
    DiscoveryConfidence, DiscoverySource, InstallationKind, PackageIdentity,
};

use crate::{DiscoveryError, ExpectedKind, is_direct_kind, path_text};

/// Identity and location values read from one current-user Windows package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageCatalogEntry {
    /// Package manifest identity name.
    pub package_name: String,
    /// Stable package family name.
    pub package_family_name: String,
    /// Versioned package full name.
    pub package_full_name: String,
    /// Publisher identifier derived by Windows from the package identity.
    pub publisher_id: String,
    /// Declared application identifiers exposed by the package catalog.
    pub application_ids: Vec<String>,
    /// Package installation root returned by Windows.
    pub install_location: PathBuf,
    /// Package processor architecture when supported by the release profile.
    pub architecture: Option<Architecture>,
    /// Four-component package version text.
    pub version: String,
}

#[derive(Clone, Copy)]
struct PackageMatchRule {
    package_name: &'static str,
    package_family_name: &'static str,
    publisher_id: &'static str,
    required_application_id: &'static str,
    target: CandidateTarget,
    channel: Option<&'static str>,
}

const PACKAGE_MATCH_RULES: &[PackageMatchRule] = &[
    PackageMatchRule {
        package_name: "OpenAI.Codex",
        package_family_name: "OpenAI.Codex_2p2nqsd0c76g0",
        publisher_id: "2p2nqsd0c76g0",
        required_application_id: "App",
        target: CandidateTarget::Codex,
        channel: None,
    },
    PackageMatchRule {
        package_name: "Microsoft.VisualStudioCode",
        package_family_name: "Microsoft.VisualStudioCode_8wekyb3d8bbwe",
        publisher_id: "8wekyb3d8bbwe",
        required_application_id: "VSCode",
        target: CandidateTarget::VisualStudioCode,
        channel: Some("stable"),
    },
];

/// Converts one Windows package-catalog record into candidate evidence when
/// its complete maintained package identity and declared application ID match.
///
/// A match remains discovery evidence only; package registration does not
/// establish Electron use, transformability, or compatibility.
///
/// # Errors
///
/// Returns [`DiscoveryError`] when the matched installation root cannot be
/// inspected or represented by the evidence contract.
pub fn evidence_from_package_catalog_entry(
    entry: &PackageCatalogEntry,
) -> Result<Option<CandidateInstallationEvidence>, DiscoveryError> {
    let Some(rule) = PACKAGE_MATCH_RULES.iter().find(|rule| {
        entry.package_name == rule.package_name
            && entry.package_family_name == rule.package_family_name
            && entry.publisher_id == rule.publisher_id
            && entry
                .application_ids
                .iter()
                .any(|application_id| application_id == rule.required_application_id)
    }) else {
        return Ok(None);
    };

    let expected_full_name_suffix = format!("__{}", rule.publisher_id);
    if !entry
        .package_full_name
        .starts_with(&format!("{}_", rule.package_name))
        || !entry
            .package_full_name
            .ends_with(&expected_full_name_suffix)
        || entry.version.trim().is_empty()
        || !entry.install_location.is_absolute()
        || !is_direct_kind(&entry.install_location, ExpectedKind::Directory)?
    {
        return Ok(None);
    }

    let mut application_ids = entry.application_ids.clone();
    application_ids.sort();
    application_ids.dedup();
    let package_identity = PackageIdentity {
        package_name: entry.package_name.clone(),
        package_family_name: entry.package_family_name.clone(),
        package_full_name: entry.package_full_name.clone(),
        publisher_id: entry.publisher_id.clone(),
        application_ids,
    };
    let channel = rule.channel.map(|value| {
        DerivedValue::new(
            value.to_owned(),
            DiscoveryConfidence::Corroborated,
            DiscoverySource::PackageCatalog,
        )
    });

    Ok(Some(CandidateInstallationEvidence {
        target: rule.target,
        installation_kind: DerivedValue::new(
            InstallationKind::Msix,
            DiscoveryConfidence::DirectObservation,
            DiscoverySource::PackageCatalog,
        ),
        root_path: DerivedValue::new(
            path_text(&entry.install_location)?,
            DiscoveryConfidence::DirectObservation,
            DiscoverySource::PackageCatalog,
        ),
        primary_executable_path: None,
        package_identity: Some(DerivedValue::new(
            package_identity,
            DiscoveryConfidence::DirectObservation,
            DiscoverySource::PackageCatalog,
        )),
        architecture: entry.architecture.map(|value| {
            DerivedValue::new(
                value,
                DiscoveryConfidence::DirectObservation,
                DiscoverySource::PackageCatalog,
            )
        }),
        channel,
        observed_version: Some(DerivedValue::new(
            entry.version.trim().to_owned(),
            DiscoveryConfidence::DirectObservation,
            DiscoverySource::PackageCatalog,
        )),
    }))
}

#[cfg(windows)]
pub(crate) fn supported_package_family_names() -> impl Iterator<Item = &'static str> {
    PACKAGE_MATCH_RULES
        .iter()
        .map(|rule| rule.package_family_name)
}
