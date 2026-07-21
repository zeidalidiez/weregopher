//! Windows package-catalog matching tests over isolated roots.

use std::fs;

use tempfile::tempdir;
use weregopher_discovery::{PackageCatalogEntry, evidence_from_package_catalog_entry};
use weregopher_domain::{
    Architecture, CandidateTarget, DiscoveryConfidence, DiscoverySource, InstallationKind,
};

#[test]
fn package_catalog_entries_emit_codex_and_vscode_identity_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let codex_root = fixture.path().join("OpenAI.Codex_26.715.8383.0_x64");
    let vscode_root = fixture
        .path()
        .join("Microsoft.VisualStudioCode_1.0.129.1_neutral");
    fs::create_dir_all(&codex_root)?;
    fs::create_dir_all(&vscode_root)?;

    let codex = PackageCatalogEntry {
        package_name: "OpenAI.Codex".to_owned(),
        package_family_name: "OpenAI.Codex_2p2nqsd0c76g0".to_owned(),
        package_full_name: "OpenAI.Codex_26.715.8383.0_x64__2p2nqsd0c76g0".to_owned(),
        publisher_id: "2p2nqsd0c76g0".to_owned(),
        application_ids: vec!["App".to_owned()],
        install_location: codex_root,
        architecture: Some(Architecture::X86_64),
        version: "26.715.8383.0".to_owned(),
    };
    let codex_evidence = evidence_from_package_catalog_entry(&codex)?
        .ok_or("Codex package identity should match")?;
    assert_eq!(codex_evidence.target, CandidateTarget::Codex);
    assert_eq!(
        codex_evidence.installation_kind.value,
        InstallationKind::Msix
    );
    assert_eq!(
        codex_evidence.installation_kind.source,
        DiscoverySource::PackageCatalog
    );
    assert_eq!(
        codex_evidence.root_path.confidence,
        DiscoveryConfidence::DirectObservation
    );
    let identity = codex_evidence
        .package_identity
        .as_ref()
        .ok_or("package identity evidence should be retained")?;
    assert_eq!(identity.source, DiscoverySource::PackageCatalog);
    assert_eq!(identity.value.package_name, "OpenAI.Codex");
    assert_eq!(identity.value.application_ids, ["App"]);
    assert_eq!(
        codex_evidence
            .architecture
            .as_ref()
            .map(|value| value.value),
        Some(Architecture::X86_64)
    );

    let code = PackageCatalogEntry {
        package_name: "Microsoft.VisualStudioCode".to_owned(),
        package_family_name: "Microsoft.VisualStudioCode_8wekyb3d8bbwe".to_owned(),
        package_full_name: "Microsoft.VisualStudioCode_1.0.129.1_neutral__8wekyb3d8bbwe".to_owned(),
        publisher_id: "8wekyb3d8bbwe".to_owned(),
        application_ids: vec!["VSCode".to_owned()],
        install_location: vscode_root,
        architecture: None,
        version: "1.0.129.1".to_owned(),
    };
    let vscode_evidence = evidence_from_package_catalog_entry(&code)?
        .ok_or("Visual Studio Code package identity should match")?;
    assert_eq!(vscode_evidence.target, CandidateTarget::VisualStudioCode);
    assert_eq!(
        vscode_evidence
            .channel
            .as_ref()
            .map(|value| value.value.as_str()),
        Some("stable")
    );
    assert!(vscode_evidence.architecture.is_none());
    Ok(())
}

#[test]
fn package_catalog_entries_require_exact_family_publisher_and_absolute_root()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let root = fixture.path().join("Codex");
    fs::create_dir_all(&root)?;
    let mut entry = PackageCatalogEntry {
        package_name: "OpenAI.Codex".to_owned(),
        package_family_name: "OpenAI.Codex_example".to_owned(),
        package_full_name: "OpenAI.Codex_1.0.0.0_x64__example".to_owned(),
        publisher_id: "example".to_owned(),
        application_ids: vec!["App".to_owned()],
        install_location: root,
        architecture: Some(Architecture::X86_64),
        version: "1.0.0.0".to_owned(),
    };
    assert!(evidence_from_package_catalog_entry(&entry)?.is_none());

    entry.package_family_name = "OpenAI.Codex_2p2nqsd0c76g0".to_owned();
    entry.publisher_id = "2p2nqsd0c76g0".to_owned();
    entry.install_location = "relative-root".into();
    assert!(evidence_from_package_catalog_entry(&entry)?.is_none());
    Ok(())
}
