//! Candidate-specific package-layout verification-input tests.

use std::fs;
#[cfg(windows)]
use std::{path::Path, process::Command};

use tempfile::tempdir;
use weregopher_discovery::{
    CandidateLayoutMarkerKind, CandidatePathKind, correlate_candidate_evidence,
    discover_known_user_locations, verification_inputs_for_candidate,
};
#[cfg(windows)]
use weregopher_domain::{
    CandidateInstallationEvidence, DerivedValue, DiscoveryConfidence, InstallationKind,
};
use weregopher_domain::{CandidateTarget, DiscoverySource};

#[test]
fn discord_verification_inputs_select_complete_versioned_package_roots()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let local_app_data = fixture.path().join("LocalAppData");
    let root = local_app_data.join("Discord");
    fs::create_dir_all(&root)?;
    fs::write(root.join("Update.exe"), b"updater")?;

    let complete = root.join("app-1.0.9207");
    fs::create_dir_all(complete.join("resources").join("app.asar.unpacked"))?;
    fs::write(complete.join("Discord.exe"), b"executable")?;
    fs::write(complete.join("resources").join("app.asar"), b"asar")?;
    fs::write(complete.join("resources.pak"), b"pak")?;

    let incomplete = root.join("app-1.0.9206");
    fs::create_dir_all(incomplete.join("resources"))?;
    fs::write(incomplete.join("Discord.exe"), b"executable")?;

    let evidence = discover_known_user_locations(&local_app_data)?
        .into_iter()
        .next()
        .ok_or("Discord evidence should exist")?;
    let group = correlate_candidate_evidence([evidence])?
        .into_iter()
        .next()
        .ok_or("Discord evidence group should exist")?;
    let inputs = verification_inputs_for_candidate(&group)?;

    assert_eq!(inputs.len(), 1);
    let input = &inputs[0];
    assert_eq!(input.target(), CandidateTarget::Discord);
    assert_eq!(input.package_root_path(), complete.to_string_lossy());
    assert_eq!(input.discovery_observations().len(), 1);
    assert!(input.markers().iter().any(|marker| {
        marker.kind() == CandidateLayoutMarkerKind::ApplicationArchive
            && marker.path_kind() == CandidatePathKind::File
            && marker.path().source == DiscoverySource::FilesystemLayout
    }));
    assert!(input.markers().iter().any(|marker| {
        marker.kind() == CandidateLayoutMarkerKind::UnpackedApplicationDirectory
            && marker.path_kind() == CandidatePathKind::Directory
    }));
    assert!(input.markers().iter().any(|marker| {
        marker.kind() == CandidateLayoutMarkerKind::ElectronResource
            && marker.path().value.ends_with("resources.pak")
    }));
    Ok(())
}

#[test]
fn vscode_verification_inputs_require_the_unpacked_main_process_layout()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let local_app_data = fixture.path().join("LocalAppData");
    let root = local_app_data.join("Programs").join("Microsoft VS Code");
    fs::create_dir_all(root.join("resources").join("app").join("out"))?;
    fs::write(root.join("Code.exe"), b"executable")?;
    fs::write(
        root.join("resources").join("app").join("package.json"),
        b"{}",
    )?;
    fs::write(
        root.join("resources")
            .join("app")
            .join("out")
            .join("main.js"),
        b"main",
    )?;
    fs::write(root.join("resources.pak"), b"pak")?;

    let evidence = discover_known_user_locations(&local_app_data)?
        .into_iter()
        .next()
        .ok_or("Visual Studio Code evidence should exist")?;
    let group = correlate_candidate_evidence([evidence])?
        .into_iter()
        .next()
        .ok_or("Visual Studio Code evidence group should exist")?;
    let inputs = verification_inputs_for_candidate(&group)?;

    assert_eq!(inputs.len(), 1);
    let input = &inputs[0];
    assert_eq!(input.target(), CandidateTarget::VisualStudioCode);
    assert_eq!(
        input.primary_executable_path(),
        root.join("Code.exe").to_string_lossy()
    );
    assert!(input.markers().iter().any(|marker| {
        marker.kind() == CandidateLayoutMarkerKind::ApplicationManifest
            && marker.path().value.ends_with("package.json")
    }));
    assert!(input.markers().iter().any(|marker| {
        marker.kind() == CandidateLayoutMarkerKind::MainProcessEntry
            && marker.path().value.ends_with("main.js")
    }));
    Ok(())
}

#[test]
fn verification_inputs_ignore_incomplete_or_unsupported_candidate_layouts()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let local_app_data = fixture.path().join("LocalAppData");
    let root = local_app_data.join("Programs").join("Microsoft VS Code");
    fs::create_dir_all(&root)?;
    fs::write(root.join("Code.exe"), b"executable")?;

    let evidence = discover_known_user_locations(&local_app_data)?
        .into_iter()
        .next()
        .ok_or("Visual Studio Code evidence should exist")?;
    let group = correlate_candidate_evidence([evidence])?
        .into_iter()
        .next()
        .ok_or("Visual Studio Code evidence group should exist")?;
    assert!(verification_inputs_for_candidate(&group)?.is_empty());
    Ok(())
}

#[cfg(windows)]
#[test]
fn verification_inputs_reject_a_junction_candidate_root() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = tempdir()?;
    let local_app_data = fixture.path().join("LocalAppData");
    fs::create_dir_all(local_app_data.join("Programs"))?;
    let outside = fixture.path().join("outside");
    create_vscode_layout(&outside)?;
    let root = local_app_data.join("Programs").join("Microsoft VS Code");
    create_junction(&root, &outside)?;

    let group = correlate_candidate_evidence([vscode_evidence(&root)])?
        .into_iter()
        .next()
        .ok_or("Visual Studio Code evidence group should exist")?;

    assert!(verification_inputs_for_candidate(&group)?.is_empty());
    Ok(())
}

#[cfg(windows)]
#[test]
fn verification_inputs_reject_a_junction_intermediate_directory()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let local_app_data = fixture.path().join("LocalAppData");
    let root = local_app_data.join("Programs").join("Microsoft VS Code");
    fs::create_dir_all(&root)?;
    fs::write(root.join("Code.exe"), b"executable")?;
    let outside_resources = fixture.path().join("outside-resources");
    fs::create_dir_all(outside_resources.join("app").join("out"))?;
    fs::write(outside_resources.join("app").join("package.json"), b"{}")?;
    fs::write(
        outside_resources.join("app").join("out").join("main.js"),
        b"main",
    )?;
    create_junction(&root.join("resources"), &outside_resources)?;

    let evidence = discover_known_user_locations(&local_app_data)?
        .into_iter()
        .next()
        .ok_or("Visual Studio Code evidence should exist")?;
    let group = correlate_candidate_evidence([evidence])?
        .into_iter()
        .next()
        .ok_or("Visual Studio Code evidence group should exist")?;

    assert!(verification_inputs_for_candidate(&group)?.is_empty());
    Ok(())
}

#[cfg(windows)]
fn create_vscode_layout(root: &Path) -> std::io::Result<()> {
    fs::create_dir_all(root.join("resources").join("app").join("out"))?;
    fs::write(root.join("Code.exe"), b"executable")?;
    fs::write(
        root.join("resources").join("app").join("package.json"),
        b"{}",
    )?;
    fs::write(
        root.join("resources")
            .join("app")
            .join("out")
            .join("main.js"),
        b"main",
    )?;
    Ok(())
}

#[cfg(windows)]
fn vscode_evidence(root: &Path) -> CandidateInstallationEvidence {
    CandidateInstallationEvidence {
        target: CandidateTarget::VisualStudioCode,
        installation_kind: DerivedValue::new(
            InstallationKind::Exe,
            DiscoveryConfidence::Corroborated,
            DiscoverySource::KnownInstallLocation,
        ),
        root_path: DerivedValue::new(
            root.to_string_lossy().into_owned(),
            DiscoveryConfidence::DirectObservation,
            DiscoverySource::KnownInstallLocation,
        ),
        primary_executable_path: None,
        package_identity: None,
        architecture: None,
        channel: Some(DerivedValue::new(
            "stable".to_owned(),
            DiscoveryConfidence::Corroborated,
            DiscoverySource::KnownInstallLocation,
        )),
        observed_version: None,
    }
}

#[cfg(windows)]
fn create_junction(link: &Path, target: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("cmd")
        .args(["/D", "/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .status()?;
    if !status.success() {
        return Err("mklink /J failed".into());
    }
    Ok(())
}
