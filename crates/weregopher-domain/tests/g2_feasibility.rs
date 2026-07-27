//! G2 target-feasibility contract behavior.

use weregopher_domain::{
    AppServerProbeChecks, AppServerProbeReport, G2ComponentEvidence, G2ComponentSource,
    G2ContractError, G2FeasibilityDisposition, G2FeasibilityReport, G2GateEvidence, G2PackagePath,
    G2ProbeScope, OpenAiPackageInventory, PreloadBridgeChecks, PreloadBridgeProbeReport,
    Sha256Digest,
};

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn component(path: &str, byte: u8) -> Result<G2ComponentEvidence, G2ContractError> {
    let source = if path.starts_with("dist/") {
        G2ComponentSource::ApplicationArchiveMember
    } else {
        G2ComponentSource::PackageFile
    };
    G2ComponentEvidence::new(
        source,
        G2PackagePath::new(path)?,
        digest(byte),
        u64::from(byte),
    )
}

fn inventory() -> Result<OpenAiPackageInventory, G2ContractError> {
    OpenAiPackageInventory::new(
        digest(1),
        digest(2),
        component("app/ChatGPT.exe", 3)?,
        component("app/resources/app.asar", 4)?,
        component("dist/main.js", 5)?,
        [component("dist/preload.js", 6)?],
        [
            component("dist/index.html", 7)?,
            component("dist/assets/main.js", 8)?,
        ],
        component("app/resources/codex.exe", 9)?,
    )
}

#[test]
fn package_paths_are_canonical_and_bounded() {
    assert!(G2PackagePath::new("app/resources/codex.exe").is_ok());
    for path in [
        "",
        "/app/resources/codex.exe",
        "app\\resources\\codex.exe",
        "app//codex.exe",
        "app/./codex.exe",
        "app/../codex.exe",
        "app/\u{0}codex.exe",
    ] {
        assert!(G2PackagePath::new(path).is_err(), "{path:?} must fail");
    }
}

#[test]
fn package_inventory_rejects_duplicate_component_paths() -> Result<(), Box<dyn std::error::Error>> {
    let duplicate = component("dist/main.js", 6)?;
    let result = OpenAiPackageInventory::new(
        digest(1),
        digest(2),
        component("app/ChatGPT.exe", 3)?,
        component("app/resources/app.asar", 4)?,
        component("dist/main.js", 5)?,
        [duplicate],
        [component("dist/index.html", 7)?],
        component("app/resources/codex.exe", 9)?,
    );
    let Err(error) = result else {
        return Err("one package path cannot have two component roles".into());
    };
    assert_eq!(error, G2ContractError::DuplicateComponentPath);
    Ok(())
}

#[test]
fn package_inventory_is_canonical_across_input_order() -> Result<(), Box<dyn std::error::Error>> {
    let forward = inventory()?;
    let reverse = OpenAiPackageInventory::new(
        digest(1),
        digest(2),
        component("app/ChatGPT.exe", 3)?,
        component("app/resources/app.asar", 4)?,
        component("dist/main.js", 5)?,
        [component("dist/preload.js", 6)?],
        [
            component("dist/assets/main.js", 8)?,
            component("dist/index.html", 7)?,
        ],
        component("app/resources/codex.exe", 9)?,
    )?;
    assert_eq!(forward, reverse);
    assert_eq!(serde_json::to_vec(&forward)?, serde_json::to_vec(&reverse)?);
    Ok(())
}

#[test]
fn exact_probe_scope_is_required_for_a_feasible_gate() -> Result<(), Box<dyn std::error::Error>> {
    let preload = PreloadBridgeProbeReport::new(
        digest(1),
        digest(6),
        digest(10),
        "123.0.0.0",
        G2ProbeScope::SyntheticFixture,
        PreloadBridgeChecks {
            document_start: true,
            isolated_globals: true,
            prototype_isolation: true,
            frozen_projection: true,
            function_round_trip: true,
            navigation_invalidation: true,
        },
    )?;
    assert!(preload.checks_pass());
    assert!(!preload.is_exact_package_evidence());

    let app_server = AppServerProbeReport::new(
        digest(1),
        digest(9),
        digest(11),
        digest(12),
        G2ProbeScope::ExactPackage,
        AppServerProbeChecks {
            stdio_jsonl: true,
            preinitialize_rejected: true,
            initialize_succeeded: true,
            initialized_sent: true,
            clean_shutdown: true,
        },
    );
    assert!(app_server.checks_pass());
    assert!(app_server.is_exact_package_evidence());

    let report = G2FeasibilityReport::new(
        digest(1),
        G2GateEvidence::passed(digest(20)),
        G2GateEvidence::failed(digest(21)),
        G2GateEvidence::passed(digest(22)),
    );
    assert_eq!(report.disposition(), G2FeasibilityDisposition::Blocked);
    Ok(())
}

#[test]
fn incomplete_and_feasible_dispositions_are_derived_not_serialized()
-> Result<(), Box<dyn std::error::Error>> {
    let incomplete = G2FeasibilityReport::new(
        digest(1),
        G2GateEvidence::passed(digest(20)),
        G2GateEvidence::not_run(),
        G2GateEvidence::not_run(),
    );
    assert_eq!(
        incomplete.disposition(),
        G2FeasibilityDisposition::Incomplete
    );

    let feasible = G2FeasibilityReport::new(
        digest(1),
        G2GateEvidence::passed(digest(20)),
        G2GateEvidence::passed(digest(21)),
        G2GateEvidence::passed(digest(22)),
    );
    assert_eq!(feasible.disposition(), G2FeasibilityDisposition::Feasible);
    let value = serde_json::to_value(feasible)?;
    assert!(value.get("disposition").is_none());
    Ok(())
}

#[test]
fn serialized_gate_evidence_cannot_bypass_status_rules() {
    let invalid = serde_json::json!({
        "status": "passed",
        "evidence_digest": null
    });
    assert!(serde_json::from_value::<G2GateEvidence>(invalid).is_err());

    let invalid = serde_json::json!({
        "status": "not_run",
        "evidence_digest": digest(1)
    });
    assert!(serde_json::from_value::<G2GateEvidence>(invalid).is_err());
}
