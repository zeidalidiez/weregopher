//! Uninstall-registry matching tests over isolated filesystem fixtures.

use std::{fs, path::Path};

use tempfile::tempdir;
use weregopher_discovery::{UninstallRegistryEntry, evidence_from_uninstall_entry};
use weregopher_domain::{CandidateTarget, DiscoveryConfidence, DiscoverySource, InstallationKind};

fn create_marker(root: &Path, marker: &str) -> std::io::Result<()> {
    fs::create_dir_all(root)?;
    fs::write(root.join(marker), b"fixture")
}

fn registry_entry(
    display_name: &str,
    publisher: &str,
    install_location: &Path,
    display_version: Option<&str>,
) -> UninstallRegistryEntry {
    UninstallRegistryEntry {
        display_name: display_name.to_owned(),
        publisher: Some(publisher.to_owned()),
        install_location: install_location.to_path_buf(),
        display_version: display_version.map(str::to_owned),
    }
}

#[test]
fn uninstall_entries_emit_provenance_bound_vscode_and_discord_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let code = fixture.path().join("Microsoft VS Code");
    let discord = fixture.path().join("DiscordCanary");
    create_marker(&code, "Code.exe")?;
    create_marker(&discord, "Update.exe")?;

    let code_evidence = evidence_from_uninstall_entry(&registry_entry(
        "Microsoft Visual Studio Code",
        "Microsoft Corporation",
        &code,
        Some("1.108.0"),
    ))?
    .ok_or("VS Code registry entry should match")?;
    assert_eq!(code_evidence.target, CandidateTarget::VisualStudioCode);
    assert_eq!(code_evidence.installation_kind.value, InstallationKind::Exe);
    assert_eq!(
        code_evidence.root_path.source,
        DiscoverySource::UninstallRegistry
    );
    assert_eq!(
        code_evidence.root_path.confidence,
        DiscoveryConfidence::DirectObservation
    );
    assert_eq!(
        code_evidence
            .primary_executable_path
            .as_ref()
            .map(|value| value.source),
        Some(DiscoverySource::FilesystemLayout)
    );
    assert_eq!(
        code_evidence
            .observed_version
            .as_ref()
            .map(|value| value.value.as_str()),
        Some("1.108.0")
    );

    let discord_evidence = evidence_from_uninstall_entry(&registry_entry(
        "Discord Canary",
        "Discord Inc.",
        &discord,
        None,
    ))?
    .ok_or("Discord Canary registry entry should match")?;
    assert_eq!(discord_evidence.target, CandidateTarget::Discord);
    assert_eq!(
        discord_evidence
            .channel
            .as_ref()
            .map(|value| value.value.as_str()),
        Some("canary")
    );
    assert_eq!(
        discord_evidence.installation_kind.value,
        InstallationKind::Squirrel
    );
    assert!(discord_evidence.primary_executable_path.is_none());
    Ok(())
}

#[test]
fn uninstall_entries_require_matching_publisher_location_and_marker()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let code = fixture.path().join("Microsoft VS Code");
    create_marker(&code, "Code.exe")?;

    let wrong_publisher = registry_entry(
        "Microsoft Visual Studio Code",
        "Example Corporation",
        &code,
        Some("1.0.0"),
    );
    assert!(evidence_from_uninstall_entry(&wrong_publisher)?.is_none());

    let unknown_product = registry_entry("Slack", "Slack Technologies", &code, None);
    assert!(evidence_from_uninstall_entry(&unknown_product)?.is_none());

    let incomplete = registry_entry(
        "Microsoft Visual Studio Code Insiders",
        "Microsoft Corporation",
        &fixture.path().join("missing"),
        None,
    );
    assert!(evidence_from_uninstall_entry(&incomplete)?.is_none());
    Ok(())
}
