//! Known per-user Windows installation-location discovery tests.

use std::{fs, path::Path};

use tempfile::tempdir;
use weregopher_discovery::discover_known_user_locations;
use weregopher_domain::{CandidateTarget, DiscoveryConfidence, DiscoverySource, InstallationKind};

fn create_marker(root: &Path, relative_root: &str, marker: &str) -> std::io::Result<()> {
    let installation = root.join(relative_root);
    fs::create_dir_all(&installation)?;
    fs::write(installation.join(marker), b"fixture")
}

#[test]
fn known_user_locations_discover_supported_discord_and_vscode_channels()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    create_marker(fixture.path(), "Discord", "Update.exe")?;
    create_marker(fixture.path(), "DiscordPTB", "Update.exe")?;
    create_marker(fixture.path(), "DiscordCanary", "Update.exe")?;
    create_marker(fixture.path(), "Programs/Microsoft VS Code", "Code.exe")?;
    create_marker(
        fixture.path(),
        "Programs/Microsoft VS Code Insiders",
        "Code - Insiders.exe",
    )?;

    let discovered = discover_known_user_locations(fixture.path())?;
    let identities: Vec<_> = discovered
        .iter()
        .map(|record| {
            (
                record.target,
                record
                    .channel
                    .as_ref()
                    .map(|channel| channel.value.as_str()),
                record.installation_kind.value,
            )
        })
        .collect();
    assert_eq!(
        identities,
        [
            (
                CandidateTarget::Discord,
                Some("stable"),
                InstallationKind::Squirrel,
            ),
            (
                CandidateTarget::Discord,
                Some("ptb"),
                InstallationKind::Squirrel,
            ),
            (
                CandidateTarget::Discord,
                Some("canary"),
                InstallationKind::Squirrel,
            ),
            (
                CandidateTarget::VisualStudioCode,
                Some("stable"),
                InstallationKind::Exe,
            ),
            (
                CandidateTarget::VisualStudioCode,
                Some("insiders"),
                InstallationKind::Exe,
            ),
        ]
    );

    for record in &discovered {
        assert_eq!(
            record.root_path.confidence,
            DiscoveryConfidence::DirectObservation
        );
        assert_eq!(
            record.root_path.source,
            DiscoverySource::KnownInstallLocation
        );
        assert_eq!(
            record.installation_kind.confidence,
            DiscoveryConfidence::Corroborated
        );
        assert_eq!(
            record.installation_kind.source,
            DiscoverySource::FilesystemLayout
        );
        assert!(record.architecture.is_none());
        assert!(record.observed_version.is_none());
    }
    assert!(
        discovered[..3]
            .iter()
            .all(|record| record.primary_executable_path.is_none())
    );
    assert!(
        discovered[3..]
            .iter()
            .all(|record| record.primary_executable_path.is_some())
    );
    Ok(())
}

#[test]
fn known_user_locations_ignore_incomplete_and_unrelated_directories()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    fs::create_dir_all(fixture.path().join("Discord"))?;
    fs::create_dir_all(fixture.path().join("Programs/Microsoft VS Code"))?;
    create_marker(fixture.path(), "Unrelated", "Update.exe")?;

    assert!(discover_known_user_locations(fixture.path())?.is_empty());
    Ok(())
}
