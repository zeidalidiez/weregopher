//! Candidate-specific package-layout verification-input tests.

#[cfg(windows)]
use std::process::Command;
use std::{fs, path::Path};

use tempfile::tempdir;
use weregopher_discovery::{
    CandidateLayoutMarkerKind, CandidatePathKind, DiscoveryError, PackageCatalogEntry,
    correlate_candidate_evidence, discover_known_user_locations,
    evidence_from_package_catalog_entry, verification_inputs_for_candidate,
};
use weregopher_domain::{Architecture, CandidateTarget, DiscoverySource};
use weregopher_domain::{CandidateInstallationEvidence, InstallationKind};
#[cfg(windows)]
use weregopher_domain::{DerivedValue, DiscoveryConfidence};

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
fn discord_verification_rejects_a_non_squirrel_installation_kind()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let local_app_data = fixture.path().join("LocalAppData");
    create_discord_candidate(&local_app_data, &["app-1.0.0"])?;
    let mut evidence = discord_evidence(&local_app_data)?;
    evidence.installation_kind.value = InstallationKind::Exe;
    let group = correlate_candidate_evidence([evidence])?
        .into_iter()
        .next()
        .ok_or("Discord evidence group should exist")?;

    assert!(verification_inputs_for_candidate(&group)?.is_empty());
    Ok(())
}

#[test]
fn discord_verification_rejects_conflicting_installation_kinds()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let local_app_data = fixture.path().join("LocalAppData");
    create_discord_candidate(&local_app_data, &["app-1.0.0"])?;
    let squirrel = discord_evidence(&local_app_data)?;
    let mut conflicting = squirrel.clone();
    conflicting.installation_kind.value = InstallationKind::Exe;
    let group = correlate_candidate_evidence([squirrel, conflicting])?
        .into_iter()
        .next()
        .ok_or("Discord evidence group should exist")?;

    assert!(verification_inputs_for_candidate(&group)?.is_empty());
    Ok(())
}

#[test]
fn discord_verification_rejects_malformed_version_directory_names()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let local_app_data = fixture.path().join("LocalAppData");
    create_discord_candidate(&local_app_data, &["app-1..2", "app-.1", "app-"])?;
    let group = correlate_candidate_evidence([discord_evidence(&local_app_data)?])?
        .into_iter()
        .next()
        .ok_or("Discord evidence group should exist")?;

    assert!(verification_inputs_for_candidate(&group)?.is_empty());
    Ok(())
}

#[test]
fn discord_verification_enforces_the_direct_entry_limit() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = tempdir()?;
    let local_app_data = fixture.path().join("LocalAppData");
    create_discord_candidate(&local_app_data, &[])?;
    let root = local_app_data.join("Discord");
    for index in 0..127 {
        fs::write(root.join(format!("unrelated-{index}")), b"fixture")?;
    }
    let group = correlate_candidate_evidence([discord_evidence(&local_app_data)?])?
        .into_iter()
        .next()
        .ok_or("Discord evidence group should exist")?;
    assert!(verification_inputs_for_candidate(&group)?.is_empty());

    fs::write(root.join("one-too-many"), b"fixture")?;
    let Err(error) = verification_inputs_for_candidate(&group) else {
        return Err("129 direct entries must exceed the verification bound".into());
    };
    assert!(matches!(
        error,
        DiscoveryError::VerificationEntryLimit { limit: 128, .. }
    ));
    Ok(())
}

#[test]
fn discord_verification_enforces_the_package_root_limit() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = tempdir()?;
    let local_app_data = fixture.path().join("LocalAppData");
    let accepted = (0..16)
        .map(|index| format!("app-1.0.{index}"))
        .collect::<Vec<_>>();
    let accepted_refs = accepted.iter().map(String::as_str).collect::<Vec<_>>();
    create_discord_candidate(&local_app_data, &accepted_refs)?;
    let group = correlate_candidate_evidence([discord_evidence(&local_app_data)?])?
        .into_iter()
        .next()
        .ok_or("Discord evidence group should exist")?;
    assert_eq!(verification_inputs_for_candidate(&group)?.len(), 16);

    create_discord_package(&local_app_data.join("Discord"), "app-1.0.16")?;
    let Err(error) = verification_inputs_for_candidate(&group) else {
        return Err("17 package roots must exceed the verification bound".into());
    };
    assert!(matches!(
        error,
        DiscoveryError::VerificationCandidateLimit { limit: 16 }
    ));
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
fn codex_verification_inputs_require_the_observed_msix_application_layout()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let root = fixture.path().join("OpenAI.Codex");
    fs::create_dir_all(root.join("app").join("resources"))?;
    fs::write(root.join("AppxManifest.xml"), b"manifest")?;
    fs::write(root.join("app").join("ChatGPT.exe"), b"executable")?;
    fs::write(root.join("app").join("resources").join("app.asar"), b"asar")?;
    fs::write(
        root.join("app").join("resources").join("codex.exe"),
        b"helper",
    )?;

    let evidence = evidence_from_package_catalog_entry(&codex_package_entry(&root))?
        .ok_or("Codex package evidence should exist")?;
    let group = correlate_candidate_evidence([evidence])?
        .into_iter()
        .next()
        .ok_or("Codex evidence group should exist")?;
    let inputs = verification_inputs_for_candidate(&group)?;

    assert_eq!(inputs.len(), 1);
    let input = &inputs[0];
    assert_eq!(input.target(), CandidateTarget::Codex);
    assert_eq!(input.package_root_path(), root.to_string_lossy());
    assert_eq!(
        input.primary_executable_path(),
        root.join("app").join("ChatGPT.exe").to_string_lossy()
    );
    assert!(input.markers().iter().any(|marker| {
        marker.kind() == CandidateLayoutMarkerKind::ApplicationManifest
            && marker.path().value.ends_with("AppxManifest.xml")
    }));
    assert!(input.markers().iter().any(|marker| {
        marker.kind() == CandidateLayoutMarkerKind::ApplicationArchive
            && marker.path().value.ends_with("app.asar")
    }));
    assert!(input.markers().iter().any(|marker| {
        marker.kind() == CandidateLayoutMarkerKind::BundledHelper
            && marker.path().value.ends_with("codex.exe")
    }));
    Ok(())
}

#[test]
fn codex_verification_rejects_conflicting_package_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let root = fixture.path().join("OpenAI.Codex");
    fs::create_dir_all(root.join("app").join("resources"))?;
    fs::write(root.join("AppxManifest.xml"), b"manifest")?;
    fs::write(root.join("app").join("ChatGPT.exe"), b"executable")?;
    fs::write(root.join("app").join("resources").join("app.asar"), b"asar")?;
    let mut evidence = evidence_from_package_catalog_entry(&codex_package_entry(&root))?
        .ok_or("Codex package evidence should exist")?;
    evidence
        .package_identity
        .as_mut()
        .ok_or("Codex package identity should exist")?
        .value
        .application_ids = vec!["Unexpected".to_owned()];
    let group = correlate_candidate_evidence([evidence])?
        .into_iter()
        .next()
        .ok_or("Codex evidence group should exist")?;

    assert!(verification_inputs_for_candidate(&group)?.is_empty());
    Ok(())
}

#[test]
fn hermes_verification_inputs_require_the_observed_packaged_main_layout()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let local_app_data = fixture.path().join("LocalAppData");
    let root = local_app_data.join("Programs").join("Hermes");
    fs::create_dir_all(
        root.join("resources")
            .join("app.asar.unpacked")
            .join("dist"),
    )?;
    fs::write(root.join("Hermes.exe"), b"executable")?;
    fs::write(root.join("resources").join("app.asar"), b"asar")?;
    fs::write(
        root.join("resources")
            .join("app.asar.unpacked")
            .join("dist")
            .join("electron-main.mjs"),
        b"main",
    )?;
    fs::write(root.join("resources").join("install-stamp.json"), b"{}")?;

    let evidence = discover_known_user_locations(&local_app_data)?
        .into_iter()
        .find(|evidence| evidence.target == CandidateTarget::HermesAgent)
        .ok_or("Hermes evidence should exist")?;
    let group = correlate_candidate_evidence([evidence])?
        .into_iter()
        .next()
        .ok_or("Hermes evidence group should exist")?;
    let inputs = verification_inputs_for_candidate(&group)?;

    assert_eq!(inputs.len(), 1);
    let input = &inputs[0];
    assert_eq!(input.target(), CandidateTarget::HermesAgent);
    assert!(input.markers().iter().any(|marker| {
        marker.kind() == CandidateLayoutMarkerKind::MainProcessEntry
            && marker.path().value.ends_with("electron-main.mjs")
    }));
    assert!(input.markers().iter().any(|marker| {
        marker.kind() == CandidateLayoutMarkerKind::InstallationMetadata
            && marker.path().value.ends_with("install-stamp.json")
    }));

    let base_evidence = input.discovery_observations()[0].clone();
    for installation_kind in [InstallationKind::Msi, InstallationKind::Unknown] {
        let mut evidence = base_evidence.clone();
        evidence.installation_kind.value = installation_kind;
        let alternate_group = correlate_candidate_evidence([evidence])?
            .into_iter()
            .next()
            .ok_or("Hermes evidence group should exist")?;
        assert_eq!(
            verification_inputs_for_candidate(&alternate_group)?.len(),
            1
        );
    }
    let mut unsupported = base_evidence;
    unsupported.installation_kind.value = InstallationKind::Squirrel;
    let unsupported_group = correlate_candidate_evidence([unsupported])?
        .into_iter()
        .next()
        .ok_or("Hermes evidence group should exist")?;
    assert!(verification_inputs_for_candidate(&unsupported_group)?.is_empty());
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

    let codex_root = fixture.path().join("incomplete-codex");
    fs::create_dir_all(codex_root.join("app").join("resources"))?;
    fs::write(codex_root.join("AppxManifest.xml"), b"manifest")?;
    fs::write(codex_root.join("app").join("ChatGPT.exe"), b"executable")?;
    let codex_evidence = evidence_from_package_catalog_entry(&codex_package_entry(&codex_root))?
        .ok_or("Codex package evidence should exist")?;
    let codex_group = correlate_candidate_evidence([codex_evidence])?
        .into_iter()
        .next()
        .ok_or("Codex evidence group should exist")?;
    assert!(verification_inputs_for_candidate(&codex_group)?.is_empty());

    let hermes_root = local_app_data.join("Programs").join("Hermes");
    fs::create_dir_all(
        hermes_root
            .join("resources")
            .join("app.asar.unpacked")
            .join("dist"),
    )?;
    fs::write(hermes_root.join("Hermes.exe"), b"executable")?;
    fs::write(hermes_root.join("resources").join("app.asar"), b"asar")?;
    fs::write(
        hermes_root
            .join("resources")
            .join("app.asar.unpacked")
            .join("dist")
            .join("electron-main.mjs"),
        b"main",
    )?;
    let hermes_evidence = discover_known_user_locations(&local_app_data)?
        .into_iter()
        .find(|evidence| evidence.target == CandidateTarget::HermesAgent)
        .ok_or("Hermes evidence should exist")?;
    let hermes_group = correlate_candidate_evidence([hermes_evidence])?
        .into_iter()
        .next()
        .ok_or("Hermes evidence group should exist")?;
    assert!(verification_inputs_for_candidate(&hermes_group)?.is_empty());
    Ok(())
}

fn codex_package_entry(root: &Path) -> PackageCatalogEntry {
    PackageCatalogEntry {
        package_name: "OpenAI.Codex".to_owned(),
        package_family_name: "OpenAI.Codex_2p2nqsd0c76g0".to_owned(),
        package_full_name: "OpenAI.Codex_26.715.8383.0_x64__2p2nqsd0c76g0".to_owned(),
        publisher_id: "2p2nqsd0c76g0".to_owned(),
        application_ids: vec!["App".to_owned()],
        install_location: root.to_path_buf(),
        architecture: Some(Architecture::X86_64),
        version: "26.715.8383.0".to_owned(),
    }
}

fn create_discord_candidate(local_app_data: &Path, packages: &[&str]) -> std::io::Result<()> {
    let root = local_app_data.join("Discord");
    fs::create_dir_all(&root)?;
    fs::write(root.join("Update.exe"), b"updater")?;
    for package in packages {
        create_discord_package(&root, package)?;
    }
    Ok(())
}

fn create_discord_package(root: &Path, package: &str) -> std::io::Result<()> {
    let package_root = root.join(package);
    fs::create_dir_all(package_root.join("resources"))?;
    fs::write(package_root.join("Discord.exe"), b"executable")?;
    fs::write(package_root.join("resources").join("app.asar"), b"asar")
}

fn discord_evidence(
    local_app_data: &Path,
) -> Result<CandidateInstallationEvidence, Box<dyn std::error::Error>> {
    discover_known_user_locations(local_app_data)?
        .into_iter()
        .find(|evidence| evidence.target == CandidateTarget::Discord)
        .ok_or_else(|| "Discord evidence should exist".into())
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
