//! Candidate installation evidence and provenance contract tests.

use serde_json::json;
use weregopher_domain::{
    Architecture, CandidateInstallationEvidence, CandidateTarget, DerivedValue,
    DiscoveryConfidence, DiscoverySource, InstallationKind,
};

#[test]
fn candidate_installation_evidence_keeps_each_value_bound_to_provenance()
-> Result<(), Box<dyn std::error::Error>> {
    let evidence = CandidateInstallationEvidence {
        target: CandidateTarget::Discord,
        installation_kind: DerivedValue::new(
            InstallationKind::Squirrel,
            DiscoveryConfidence::Corroborated,
            DiscoverySource::FilesystemLayout,
        ),
        root_path: DerivedValue::new(
            String::from(r"C:\Users\example\AppData\Local\Discord"),
            DiscoveryConfidence::DirectObservation,
            DiscoverySource::KnownInstallLocation,
        ),
        primary_executable_path: Some(DerivedValue::new(
            String::from(r"C:\Users\example\AppData\Local\Discord\Update.exe"),
            DiscoveryConfidence::DirectObservation,
            DiscoverySource::FilesystemLayout,
        )),
        package_identity: None,
        architecture: Some(DerivedValue::new(
            Architecture::X86_64,
            DiscoveryConfidence::Corroborated,
            DiscoverySource::FilesystemLayout,
        )),
        channel: Some(DerivedValue::new(
            String::from("stable"),
            DiscoveryConfidence::Corroborated,
            DiscoverySource::KnownInstallLocation,
        )),
        observed_version: None,
    };

    assert_eq!(
        serde_json::to_value(evidence)?,
        json!({
            "target": "discord",
            "installation_kind": {
                "value": "squirrel",
                "confidence": "corroborated",
                "source": "filesystem_layout"
            },
            "root_path": {
                "value": r"C:\Users\example\AppData\Local\Discord",
                "confidence": "direct_observation",
                "source": "known_install_location"
            },
            "primary_executable_path": {
                "value": r"C:\Users\example\AppData\Local\Discord\Update.exe",
                "confidence": "direct_observation",
                "source": "filesystem_layout"
            },
            "package_identity": null,
            "architecture": {
                "value": "x86_64",
                "confidence": "corroborated",
                "source": "filesystem_layout"
            },
            "channel": {
                "value": "stable",
                "confidence": "corroborated",
                "source": "known_install_location"
            },
            "observed_version": null
        })
    );
    Ok(())
}

#[test]
fn discovery_evidence_does_not_encode_electron_or_compatibility_claims()
-> Result<(), Box<dyn std::error::Error>> {
    let value = serde_json::to_value(CandidateInstallationEvidence {
        target: CandidateTarget::Codex,
        installation_kind: DerivedValue::new(
            InstallationKind::Unknown,
            DiscoveryConfidence::Advisory,
            DiscoverySource::KnownInstallLocation,
        ),
        root_path: DerivedValue::new(
            String::from(r"C:\candidate"),
            DiscoveryConfidence::Advisory,
            DiscoverySource::KnownInstallLocation,
        ),
        primary_executable_path: None,
        package_identity: None,
        architecture: None,
        channel: None,
        observed_version: None,
    })?;
    let object = value
        .as_object()
        .ok_or("candidate evidence must serialize as an object")?;

    assert!(!object.contains_key("electron"));
    assert!(!object.contains_key("compatible"));
    assert!(!object.contains_key("package_tree"));
    Ok(())
}

#[test]
fn discovery_evidence_rejects_unregistered_provenance_values() {
    assert!(
        serde_json::from_value::<DerivedValue<String>>(json!({
            "value": "stable",
            "confidence": "guaranteed",
            "source": "filesystem_layout"
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<DerivedValue<String>>(json!({
            "value": "stable",
            "confidence": "corroborated",
            "source": "web_search"
        }))
        .is_err()
    );
}
