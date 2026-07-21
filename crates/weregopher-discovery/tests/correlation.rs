//! Multi-source candidate-evidence correlation tests.

mod support;

use std::fs;

use support::physical_tempdir as tempdir;
use weregopher_discovery::{
    DiscoveryError, UninstallRegistryEntry, correlate_candidate_evidence,
    discover_known_user_locations, evidence_from_uninstall_entry,
};
use weregopher_domain::{CandidateTarget, DiscoverySource};

#[test]
fn correlation_groups_the_same_root_without_collapsing_source_observations()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let local_app_data = fixture.path().join("LocalAppData");
    let root = local_app_data.join("Programs").join("Microsoft VS Code");
    fs::create_dir_all(&root)?;
    fs::write(root.join("Code.exe"), b"fixture")?;

    let known = discover_known_user_locations(&local_app_data)?
        .into_iter()
        .next()
        .ok_or("known-location evidence should exist")?;
    let uninstall = evidence_from_uninstall_entry(&UninstallRegistryEntry {
        display_name: "Microsoft Visual Studio Code".to_owned(),
        publisher: Some("Microsoft Corporation".to_owned()),
        install_location: root.clone(),
        display_version: Some("1.101.0".to_owned()),
    })?
    .ok_or("uninstall evidence should exist")?;

    let groups = correlate_candidate_evidence([known, uninstall])?;
    assert_eq!(groups.len(), 1);
    let group = &groups[0];
    assert_eq!(group.target(), CandidateTarget::VisualStudioCode);
    assert_eq!(group.observations().len(), 2);
    assert!(
        group
            .observations()
            .iter()
            .any(|evidence| evidence.root_path.source == DiscoverySource::KnownInstallLocation)
    );
    assert!(
        group
            .observations()
            .iter()
            .any(|evidence| evidence.root_path.source == DiscoverySource::UninstallRegistry)
    );
    assert!(group.observations().iter().any(|evidence| {
        evidence
            .primary_executable_path
            .as_ref()
            .is_some_and(|value| value.source == DiscoverySource::FilesystemLayout)
    }));
    assert!(group.observations().iter().any(|evidence| {
        evidence
            .observed_version
            .as_ref()
            .is_some_and(|value| value.source == DiscoverySource::UninstallRegistry)
    }));
    Ok(())
}

#[test]
fn correlation_is_order_independent_and_deduplicates_only_exact_observations()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let local_app_data = fixture.path().join("LocalAppData");
    let root = local_app_data.join("Discord");
    fs::create_dir_all(&root)?;
    fs::write(root.join("Update.exe"), b"fixture")?;

    let evidence = discover_known_user_locations(&local_app_data)?
        .into_iter()
        .next()
        .ok_or("Discord evidence should exist")?;
    let mut equivalent_path = evidence.clone();
    equivalent_path.root_path.value =
        format!("{}/", equivalent_path.root_path.value.to_ascii_uppercase());

    let forward = correlate_candidate_evidence([
        evidence.clone(),
        equivalent_path.clone(),
        evidence.clone(),
    ])?;
    let reverse = correlate_candidate_evidence([evidence, equivalent_path])?;
    assert_eq!(forward, reverse);
    assert_eq!(forward.len(), 1);
    assert_eq!(forward[0].observations().len(), 2);
    Ok(())
}

#[test]
fn correlation_rejects_unbounded_input() {
    let evidence = weregopher_domain::CandidateInstallationEvidence {
        target: CandidateTarget::Codex,
        installation_kind: weregopher_domain::DerivedValue::new(
            weregopher_domain::InstallationKind::Msix,
            weregopher_domain::DiscoveryConfidence::DirectObservation,
            DiscoverySource::PackageCatalog,
        ),
        root_path: weregopher_domain::DerivedValue::new(
            r"C:\Program Files\WindowsApps\OpenAI.Codex".to_owned(),
            weregopher_domain::DiscoveryConfidence::DirectObservation,
            DiscoverySource::PackageCatalog,
        ),
        primary_executable_path: None,
        package_identity: None,
        architecture: None,
        channel: None,
        observed_version: None,
    };

    assert!(matches!(
        correlate_candidate_evidence(std::iter::repeat_n(evidence, 65)),
        Err(DiscoveryError::CorrelationInputLimit { limit: 64 })
    ));
}

#[test]
fn correlation_does_not_equate_a_drive_root_with_a_drive_relative_path()
-> Result<(), Box<dyn std::error::Error>> {
    let drive_root = weregopher_domain::CandidateInstallationEvidence {
        target: CandidateTarget::Codex,
        installation_kind: weregopher_domain::DerivedValue::new(
            weregopher_domain::InstallationKind::Msix,
            weregopher_domain::DiscoveryConfidence::DirectObservation,
            DiscoverySource::PackageCatalog,
        ),
        root_path: weregopher_domain::DerivedValue::new(
            "C:\\".to_owned(),
            weregopher_domain::DiscoveryConfidence::DirectObservation,
            DiscoverySource::PackageCatalog,
        ),
        primary_executable_path: None,
        package_identity: None,
        architecture: None,
        channel: None,
        observed_version: None,
    };
    let drive_relative = {
        let mut evidence = drive_root.clone();
        evidence.root_path.value = "C:".to_owned();
        evidence
    };

    let groups = correlate_candidate_evidence([drive_root, drive_relative])?;
    assert_eq!(groups.len(), 2);
    Ok(())
}
