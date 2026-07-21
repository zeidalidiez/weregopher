//! Pure matching of read-only Windows uninstall-registry records.

use std::path::PathBuf;

use weregopher_domain::{
    CandidateInstallationEvidence, CandidateTarget, DerivedValue, DiscoveryConfidence,
    DiscoverySource, InstallationKind,
};

use crate::{DiscoveryError, ExpectedKind, is_direct_kind, path_text};

/// Values read from one Windows uninstall-registry subkey.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UninstallRegistryEntry {
    /// Installed-program display name.
    pub display_name: String,
    /// Installed-program publisher, when present.
    pub publisher: Option<String>,
    /// Installation root recorded by the installer.
    pub install_location: PathBuf,
    /// Installer-reported display version, when present.
    pub display_version: Option<String>,
}

#[derive(Clone, Copy)]
struct UninstallMatchRule {
    display_name: &'static str,
    publisher: &'static str,
    target: CandidateTarget,
    marker: &'static str,
    marker_is_primary_executable: bool,
    installation_kind: InstallationKind,
    channel: &'static str,
}

const UNINSTALL_MATCH_RULES: &[UninstallMatchRule] = &[
    UninstallMatchRule {
        display_name: "Discord",
        publisher: "Discord Inc.",
        target: CandidateTarget::Discord,
        marker: "Update.exe",
        marker_is_primary_executable: false,
        installation_kind: InstallationKind::Squirrel,
        channel: "stable",
    },
    UninstallMatchRule {
        display_name: "Discord PTB",
        publisher: "Discord Inc.",
        target: CandidateTarget::Discord,
        marker: "Update.exe",
        marker_is_primary_executable: false,
        installation_kind: InstallationKind::Squirrel,
        channel: "ptb",
    },
    UninstallMatchRule {
        display_name: "Discord Canary",
        publisher: "Discord Inc.",
        target: CandidateTarget::Discord,
        marker: "Update.exe",
        marker_is_primary_executable: false,
        installation_kind: InstallationKind::Squirrel,
        channel: "canary",
    },
    UninstallMatchRule {
        display_name: "Microsoft Visual Studio Code",
        publisher: "Microsoft Corporation",
        target: CandidateTarget::VisualStudioCode,
        marker: "Code.exe",
        marker_is_primary_executable: true,
        installation_kind: InstallationKind::Exe,
        channel: "stable",
    },
    UninstallMatchRule {
        display_name: "Microsoft Visual Studio Code Insiders",
        publisher: "Microsoft Corporation",
        target: CandidateTarget::VisualStudioCode,
        marker: "Code - Insiders.exe",
        marker_is_primary_executable: true,
        installation_kind: InstallationKind::Exe,
        channel: "insiders",
    },
];

#[cfg(windows)]
pub(crate) fn is_supported_uninstall_display_name(display_name: &str) -> bool {
    let display_name = display_name.trim();
    UNINSTALL_MATCH_RULES
        .iter()
        .any(|rule| display_name.eq_ignore_ascii_case(rule.display_name))
}

/// Converts one uninstall-registry entry into candidate evidence when its
/// product name, publisher, absolute installation root, and direct marker file
/// all match a maintained rule.
///
/// A match remains discovery evidence only and does not establish executable
/// authenticity, Electron use, or compatibility.
///
/// # Errors
///
/// Returns [`DiscoveryError`] when candidate filesystem metadata cannot be read
/// or a matched path cannot be represented by the evidence contract.
pub fn evidence_from_uninstall_entry(
    entry: &UninstallRegistryEntry,
) -> Result<Option<CandidateInstallationEvidence>, DiscoveryError> {
    let Some(publisher) = entry.publisher.as_deref().map(str::trim) else {
        return Ok(None);
    };
    let display_name = entry.display_name.trim();
    let Some(rule) = UNINSTALL_MATCH_RULES.iter().find(|rule| {
        display_name.eq_ignore_ascii_case(rule.display_name)
            && publisher.eq_ignore_ascii_case(rule.publisher)
    }) else {
        return Ok(None);
    };

    if !entry.install_location.is_absolute()
        || !is_direct_kind(&entry.install_location, ExpectedKind::Directory)?
    {
        return Ok(None);
    }
    let marker = entry.install_location.join(rule.marker);
    if !is_direct_kind(&marker, ExpectedKind::File)? {
        return Ok(None);
    }

    let primary_executable_path = rule
        .marker_is_primary_executable
        .then(|| path_text(&marker))
        .transpose()?
        .map(|value| {
            DerivedValue::new(
                value,
                DiscoveryConfidence::DirectObservation,
                DiscoverySource::FilesystemLayout,
            )
        });
    let observed_version = entry
        .display_version
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            DerivedValue::new(
                value.to_owned(),
                DiscoveryConfidence::DirectObservation,
                DiscoverySource::UninstallRegistry,
            )
        });

    Ok(Some(CandidateInstallationEvidence {
        target: rule.target,
        installation_kind: DerivedValue::new(
            rule.installation_kind,
            DiscoveryConfidence::Corroborated,
            DiscoverySource::FilesystemLayout,
        ),
        root_path: DerivedValue::new(
            path_text(&entry.install_location)?,
            DiscoveryConfidence::DirectObservation,
            DiscoverySource::UninstallRegistry,
        ),
        primary_executable_path,
        architecture: None,
        channel: Some(DerivedValue::new(
            rule.channel.to_owned(),
            DiscoveryConfidence::Corroborated,
            DiscoverySource::UninstallRegistry,
        )),
        observed_version,
    }))
}
