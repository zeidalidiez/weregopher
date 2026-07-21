//! Candidate-specific package-layout verification-input tests.

mod support;

#[cfg(windows)]
use std::process::Command;
use std::{fs, path::Path};

use support::physical_tempdir as tempdir;
use weregopher_discovery::{
    CandidateEvidenceGroup, CandidateLayoutMarkerKind, CandidatePathKind, DiscoveryError,
    PackageCatalogEntry, UninstallRegistryEntry, correlate_candidate_evidence,
    discover_known_user_locations, evidence_from_package_catalog_entry,
    evidence_from_uninstall_entry, verification_inputs_for_candidate,
};
use weregopher_domain::DerivedValue;
use weregopher_domain::{Architecture, CandidateTarget, DiscoveryConfidence, DiscoverySource};
use weregopher_domain::{CandidateInstallationEvidence, InstallationKind};

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
    create_codex_layout(&root)?;
    let valid = evidence_from_package_catalog_entry(&codex_package_entry(&root))?
        .ok_or("Codex package evidence should exist")?;
    let mut evidence = valid.clone();
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

    let mut alternate_entry = codex_package_entry(&root);
    alternate_entry.version = "27.1.2.3".to_owned();
    alternate_entry.package_full_name = "OpenAI.Codex_27.1.2.3_x64__2p2nqsd0c76g0".to_owned();
    let alternate = evidence_from_package_catalog_entry(&alternate_entry)?
        .ok_or("alternate Codex package evidence should exist")?;
    let conflicting_versions = single_group_from([valid, alternate])?;
    assert!(verification_inputs_for_candidate(&conflicting_versions)?.is_empty());
    Ok(())
}

#[test]
fn codex_verification_requires_direct_package_catalog_selection_provenance()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let root = fixture.path().join("OpenAI.Codex");
    create_codex_layout(&root)?;
    let base = evidence_from_package_catalog_entry(&codex_package_entry(&root))?
        .ok_or("Codex package evidence should exist")?;

    let mut untrusted_root = base.clone();
    untrusted_root.root_path.source = DiscoverySource::UserSelectedPath;
    assert!(verification_inputs_for_candidate(&single_group(untrusted_root)?)?.is_empty());

    let mut advisory_root = base.clone();
    advisory_root.root_path.confidence = DiscoveryConfidence::Advisory;
    assert!(verification_inputs_for_candidate(&single_group(advisory_root)?)?.is_empty());

    let mut untrusted_kind = base.clone();
    untrusted_kind.installation_kind.source = DiscoverySource::UserSelectedPath;
    assert!(verification_inputs_for_candidate(&single_group(untrusted_kind)?)?.is_empty());

    let mut advisory_kind = base;
    advisory_kind.installation_kind.confidence = DiscoveryConfidence::Advisory;
    assert!(verification_inputs_for_candidate(&single_group(advisory_kind)?)?.is_empty());
    Ok(())
}

#[test]
fn codex_verification_requires_a_coherent_unpinned_package_full_name()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let root = fixture.path().join("OpenAI.Codex");
    create_codex_layout(&root)?;

    let mut alternate_entry = codex_package_entry(&root);
    alternate_entry.version = "27.1.2.3".to_owned();
    alternate_entry.package_full_name = "OpenAI.Codex_27.1.2.3_x64__2p2nqsd0c76g0".to_owned();
    let alternate = evidence_from_package_catalog_entry(&alternate_entry)?
        .ok_or("alternate Codex package version should remain supported")?;
    assert_eq!(
        verification_inputs_for_candidate(&single_group(alternate)?)?.len(),
        1
    );

    let mut malformed = evidence_from_package_catalog_entry(&codex_package_entry(&root))?
        .ok_or("Codex package evidence should exist")?;
    malformed
        .package_identity
        .as_mut()
        .ok_or("Codex package identity should exist")?
        .value
        .package_full_name = "OpenAI.Codex_not-a-version_x64__2p2nqsd0c76g0".to_owned();
    assert!(verification_inputs_for_candidate(&single_group(malformed)?)?.is_empty());
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
    let uninstall_evidence = evidence_from_uninstall_entry(&UninstallRegistryEntry {
        display_name: "Hermes".to_owned(),
        publisher: Some("Nous Research".to_owned()),
        install_location: root.clone(),
        display_version: Some("0.17.0".to_owned()),
    })?
    .ok_or("source-backed Hermes uninstall evidence should exist")?;
    assert_eq!(
        uninstall_evidence.installation_kind.value,
        InstallationKind::Unknown
    );
    assert_eq!(
        verification_inputs_for_candidate(&single_group(uninstall_evidence.clone())?)?.len(),
        1
    );
    for normalized_away_version in ["", "   "] {
        let mut malformed = uninstall_evidence.clone();
        malformed.observed_version = Some(DerivedValue {
            value: normalized_away_version.to_owned(),
            confidence: DiscoveryConfidence::DirectObservation,
            source: DiscoverySource::UninstallRegistry,
        });
        assert!(verification_inputs_for_candidate(&single_group(malformed)?)?.is_empty());
    }
    assert_eq!(
        verification_inputs_for_candidate(&single_group_from([
            base_evidence.clone(),
            uninstall_evidence,
        ])?)?
        .len(),
        1
    );

    let mut impossible_msi = base_evidence.clone();
    impossible_msi.installation_kind.value = InstallationKind::Msi;
    assert!(verification_inputs_for_candidate(&single_group(impossible_msi.clone())?)?.is_empty());
    assert!(
        verification_inputs_for_candidate(&single_group_from([
            base_evidence.clone(),
            impossible_msi,
        ])?)?
        .is_empty()
    );

    let mut unsupported = base_evidence;
    unsupported.installation_kind.value = InstallationKind::Squirrel;
    assert!(verification_inputs_for_candidate(&single_group(unsupported)?)?.is_empty());
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

fn single_group(
    evidence: CandidateInstallationEvidence,
) -> Result<CandidateEvidenceGroup, Box<dyn std::error::Error>> {
    single_group_from([evidence])
}

fn single_group_from(
    evidence: impl IntoIterator<Item = CandidateInstallationEvidence>,
) -> Result<CandidateEvidenceGroup, Box<dyn std::error::Error>> {
    correlate_candidate_evidence(evidence)?
        .into_iter()
        .next()
        .ok_or_else(|| "candidate evidence group should exist".into())
}

fn create_codex_layout(root: &Path) -> std::io::Result<()> {
    fs::create_dir_all(root.join("app").join("resources"))?;
    fs::write(root.join("AppxManifest.xml"), b"manifest")?;
    fs::write(root.join("app").join("ChatGPT.exe"), b"executable")?;
    fs::write(root.join("app").join("resources").join("app.asar"), b"asar")
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
#[test]
fn verification_inputs_reject_a_junction_ancestor_of_the_candidate_root()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let local_app_data = fixture.path().join("LocalAppData");
    fs::create_dir_all(&local_app_data)?;
    let outside_programs = fixture.path().join("outside-programs");
    let outside_root = outside_programs.join("Microsoft VS Code");
    create_vscode_layout(&outside_root)?;
    create_junction(&local_app_data.join("Programs"), &outside_programs)?;
    let root = local_app_data.join("Programs").join("Microsoft VS Code");

    let group = single_group(vscode_evidence(&root))?;
    assert!(verification_inputs_for_candidate(&group)?.is_empty());
    Ok(())
}

#[cfg(windows)]
#[test]
fn verification_inputs_reject_an_unsafe_optional_fixed_marker()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let local_app_data = fixture.path().join("LocalAppData");
    create_discord_candidate(&local_app_data, &["app-1.0.0"])?;
    let package_root = local_app_data.join("Discord").join("app-1.0.0");
    let outside_unpacked = fixture.path().join("outside-unpacked");
    fs::create_dir_all(&outside_unpacked)?;
    create_junction(
        &package_root.join("resources").join("app.asar.unpacked"),
        &outside_unpacked,
    )?;

    let group = single_group(discord_evidence(&local_app_data)?)?;
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
