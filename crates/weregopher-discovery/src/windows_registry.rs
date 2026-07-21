//! Read-only enumeration of Windows uninstall-registry views.

use std::{cmp::Ordering, io, path::PathBuf};

use weregopher_domain::{CandidateInstallationEvidence, CandidateTarget};
use winreg::{
    HKCU, HKLM, RegKey,
    enums::{KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY},
};

use crate::{
    DiscoveryError, UninstallRegistryEntry, evidence_from_uninstall_entry,
    uninstall::is_supported_uninstall_display_name,
};

const UNINSTALL_PATH: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
const MAX_KEYS_PER_VIEW: usize = 4_096;
const MAX_REGISTRY_TEXT_CHARS: usize = 32_768;
const MAX_CANDIDATE_RESULTS: usize = 20;

#[derive(Clone, Copy)]
struct RegistryView {
    label: &'static str,
    root: &'static RegKey,
    view_flag: u32,
}

/// Discovers supported installations from the current user's and local
/// machine's 32-bit and 64-bit Windows uninstall-registry views.
///
/// The source opens keys with read-only access, enumerates at most 4,096
/// uninstall subkeys per view, accepts at most 32,768 characters per relevant
/// string value, and returns at most 20 candidate records. Entries are emitted
/// only after maintained display-name and publisher rules are corroborated by
/// an absolute installation root and direct marker-file metadata.
///
/// # Errors
///
/// Returns [`DiscoveryError`] when registry enumeration or candidate metadata
/// inspection fails, or when a configured input/result bound is exceeded.
pub fn discover_windows_uninstall_registry()
-> Result<Vec<CandidateInstallationEvidence>, DiscoveryError> {
    let views = [
        RegistryView {
            label: "HKCU 64-bit uninstall view",
            root: HKCU,
            view_flag: KEY_WOW64_64KEY,
        },
        RegistryView {
            label: "HKCU 32-bit uninstall view",
            root: HKCU,
            view_flag: KEY_WOW64_32KEY,
        },
        RegistryView {
            label: "HKLM 64-bit uninstall view",
            root: HKLM,
            view_flag: KEY_WOW64_64KEY,
        },
        RegistryView {
            label: "HKLM 32-bit uninstall view",
            root: HKLM,
            view_flag: KEY_WOW64_32KEY,
        },
    ];

    let mut discovered = Vec::new();
    for view in views {
        read_view(view, &mut discovered)?;
        if discovered.len() > MAX_CANDIDATE_RESULTS {
            return Err(DiscoveryError::RegistryResultLimit {
                limit: MAX_CANDIDATE_RESULTS,
            });
        }
    }

    discovered.sort_by(compare_evidence);
    discovered.dedup_by(same_candidate);
    Ok(discovered)
}

fn read_view(
    view: RegistryView,
    discovered: &mut Vec<CandidateInstallationEvidence>,
) -> Result<(), DiscoveryError> {
    let uninstall = match view
        .root
        .open_subkey_with_flags(UNINSTALL_PATH, KEY_READ | view.view_flag)
    {
        Ok(key) => key,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(registry_read_error(view.label, source)),
    };

    for (index, subkey_name) in uninstall.enum_keys().enumerate() {
        if index >= MAX_KEYS_PER_VIEW {
            return Err(DiscoveryError::RegistryEntryLimit {
                location: view.label.to_owned(),
                limit: MAX_KEYS_PER_VIEW,
            });
        }
        let subkey_name = subkey_name.map_err(|source| registry_read_error(view.label, source))?;
        let location = format!("{}\\{}", view.label, subkey_name);
        let subkey = match uninstall.open_subkey_with_flags(&subkey_name, KEY_READ) {
            Ok(key) => key,
            Err(source) if source.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => return Err(registry_read_error(&location, source)),
        };

        let Some(display_name) = read_optional_text(&subkey, &location, "DisplayName")? else {
            continue;
        };
        if !is_supported_uninstall_display_name(&display_name) {
            continue;
        }
        let publisher = read_optional_text(&subkey, &location, "Publisher")?;
        let Some(install_location) = read_optional_text(&subkey, &location, "InstallLocation")?
        else {
            continue;
        };
        let display_version = read_optional_text(&subkey, &location, "DisplayVersion")?;
        let entry = UninstallRegistryEntry {
            display_name,
            publisher,
            install_location: PathBuf::from(install_location.trim()),
            display_version,
        };
        if let Some(evidence) = evidence_from_uninstall_entry(&entry)? {
            discovered.push(evidence);
        }
    }

    Ok(())
}

fn read_optional_text(
    key: &RegKey,
    location: &str,
    value_name: &'static str,
) -> Result<Option<String>, DiscoveryError> {
    match key.get_value::<String, _>(value_name) {
        Ok(value) => {
            if value.chars().count() > MAX_REGISTRY_TEXT_CHARS {
                return Err(DiscoveryError::RegistryTextLimit {
                    location: location.to_owned(),
                    value_name,
                    limit: MAX_REGISTRY_TEXT_CHARS,
                });
            }
            Ok(Some(value))
        }
        Err(source)
            if matches!(
                source.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::InvalidData
            ) =>
        {
            Ok(None)
        }
        Err(source) => Err(registry_read_error(
            &format!("{location} value {value_name}"),
            source,
        )),
    }
}

fn registry_read_error(location: &str, source: io::Error) -> DiscoveryError {
    DiscoveryError::RegistryRead {
        location: location.to_owned(),
        source,
    }
}

fn compare_evidence(
    left: &CandidateInstallationEvidence,
    right: &CandidateInstallationEvidence,
) -> Ordering {
    evidence_sort_key(left).cmp(&evidence_sort_key(right))
}

fn evidence_sort_key(evidence: &CandidateInstallationEvidence) -> (u8, String, String) {
    (
        target_rank(evidence.target),
        evidence
            .channel
            .as_ref()
            .map_or_else(String::new, |channel| channel.value.to_lowercase()),
        evidence.root_path.value.to_lowercase(),
    )
}

const fn target_rank(target: CandidateTarget) -> u8 {
    match target {
        CandidateTarget::Codex => 0,
        CandidateTarget::HermesAgent => 1,
        CandidateTarget::Discord => 2,
        CandidateTarget::VisualStudioCode => 3,
    }
}

fn same_candidate(
    left: &mut CandidateInstallationEvidence,
    right: &mut CandidateInstallationEvidence,
) -> bool {
    left.target == right.target
        && left
            .channel
            .as_ref()
            .map(|channel| channel.value.to_lowercase())
            == right
                .channel
                .as_ref()
                .map(|channel| channel.value.to_lowercase())
        && left.root_path.value.to_lowercase() == right.root_path.value.to_lowercase()
}
