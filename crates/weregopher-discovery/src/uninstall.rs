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
enum UninstallDisplayName {
    Exact(&'static str),
    ProductOrVersioned(&'static str),
}

impl UninstallDisplayName {
    fn matches(self, value: &str) -> bool {
        match self {
            Self::Exact(expected) => value.eq_ignore_ascii_case(expected),
            Self::ProductOrVersioned(product) => {
                if value.eq_ignore_ascii_case(product) {
                    return true;
                }
                let Some((prefix, suffix)) = value.split_at_checked(product.len()) else {
                    return false;
                };
                prefix.eq_ignore_ascii_case(product)
                    && suffix.strip_prefix(' ').is_some_and(is_version_like_suffix)
            }
        }
    }
}

fn is_version_like_suffix(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let (version, build) = value
        .split_once('+')
        .map_or((value, None), |(version, build)| (version, Some(build)));
    if build.is_some_and(|build| build.contains('+') || !valid_version_identifiers(build)) {
        return false;
    }
    let (core, prerelease) = version
        .split_once('-')
        .map_or((version, None), |(core, prerelease)| {
            (core, Some(prerelease))
        });
    if prerelease.is_some_and(|value| !valid_version_identifiers(value)) {
        return false;
    }
    let mut components = core.split('.');
    let Some(major) = components.next() else {
        return false;
    };
    let Some(minor) = components.next() else {
        return false;
    };
    let Some(patch) = components.next() else {
        return false;
    };
    components.next().is_none()
        && [major, minor, patch].into_iter().all(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn valid_version_identifiers(value: &str) -> bool {
    value.split('.').all(|identifier| {
        !identifier.is_empty()
            && identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

#[derive(Clone, Copy)]
struct UninstallMatchRule {
    display_name: UninstallDisplayName,
    publisher: &'static str,
    target: CandidateTarget,
    marker: &'static str,
    marker_is_primary_executable: bool,
    installation_kind: InstallationKind,
    channel: Option<&'static str>,
}

const UNINSTALL_MATCH_RULES: &[UninstallMatchRule] = &[
    UninstallMatchRule {
        display_name: UninstallDisplayName::Exact("Discord"),
        publisher: "Discord Inc.",
        target: CandidateTarget::Discord,
        marker: "Update.exe",
        marker_is_primary_executable: false,
        installation_kind: InstallationKind::Squirrel,
        channel: Some("stable"),
    },
    UninstallMatchRule {
        display_name: UninstallDisplayName::Exact("Discord PTB"),
        publisher: "Discord Inc.",
        target: CandidateTarget::Discord,
        marker: "Update.exe",
        marker_is_primary_executable: false,
        installation_kind: InstallationKind::Squirrel,
        channel: Some("ptb"),
    },
    UninstallMatchRule {
        display_name: UninstallDisplayName::Exact("Discord Canary"),
        publisher: "Discord Inc.",
        target: CandidateTarget::Discord,
        marker: "Update.exe",
        marker_is_primary_executable: false,
        installation_kind: InstallationKind::Squirrel,
        channel: Some("canary"),
    },
    UninstallMatchRule {
        display_name: UninstallDisplayName::Exact("Microsoft Visual Studio Code"),
        publisher: "Microsoft Corporation",
        target: CandidateTarget::VisualStudioCode,
        marker: "Code.exe",
        marker_is_primary_executable: true,
        installation_kind: InstallationKind::Exe,
        channel: Some("stable"),
    },
    UninstallMatchRule {
        display_name: UninstallDisplayName::Exact("Microsoft Visual Studio Code Insiders"),
        publisher: "Microsoft Corporation",
        target: CandidateTarget::VisualStudioCode,
        marker: "Code - Insiders.exe",
        marker_is_primary_executable: true,
        installation_kind: InstallationKind::Exe,
        channel: Some("insiders"),
    },
    UninstallMatchRule {
        display_name: UninstallDisplayName::ProductOrVersioned("Hermes"),
        publisher: "Nous Research",
        target: CandidateTarget::HermesAgent,
        marker: "Hermes.exe",
        marker_is_primary_executable: true,
        installation_kind: InstallationKind::Unknown,
        channel: None,
    },
];

#[cfg(windows)]
pub(crate) fn is_supported_uninstall_display_name(display_name: &str) -> bool {
    let display_name = display_name.trim();
    UNINSTALL_MATCH_RULES
        .iter()
        .any(|rule| rule.display_name.matches(display_name))
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
        rule.display_name.matches(display_name) && publisher.eq_ignore_ascii_case(rule.publisher)
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

    let (installation_kind_confidence, installation_kind_source) =
        if rule.installation_kind == InstallationKind::Unknown {
            (
                DiscoveryConfidence::Advisory,
                DiscoverySource::UninstallRegistry,
            )
        } else {
            (
                DiscoveryConfidence::Corroborated,
                DiscoverySource::FilesystemLayout,
            )
        };

    Ok(Some(CandidateInstallationEvidence {
        target: rule.target,
        installation_kind: DerivedValue::new(
            rule.installation_kind,
            installation_kind_confidence,
            installation_kind_source,
        ),
        root_path: DerivedValue::new(
            path_text(&entry.install_location)?,
            DiscoveryConfidence::DirectObservation,
            DiscoverySource::UninstallRegistry,
        ),
        primary_executable_path,
        package_identity: None,
        architecture: None,
        channel: rule.channel.map(|value| {
            DerivedValue::new(
                value.to_owned(),
                DiscoveryConfidence::Corroborated,
                DiscoverySource::UninstallRegistry,
            )
        }),
        observed_version,
    }))
}
