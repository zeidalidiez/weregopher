//! Canonical disposable-state certification scenario contract tests.

use std::time::Duration;

use serde_json::json;
use sha2::{Digest as _, Sha256};
use weregopher_domain::{
    AdapterId, ApplicationFamilyId, DisposableCertificationScenario,
    DisposableCertificationScenarioDocumentError, DisposableCertificationScenarioReport,
    DisposableCertificationScenarioReportDocumentError, DisposableScenarioArgument,
    DisposableScenarioLimits, DisposableScenarioPackageObservation, DisposableScenarioStateRoot,
    EffectiveSecurityPosture, ExecutionArgument, ExecutionDependencyPolicy, ExecutionPackagePath,
    ExecutionResourceLimits, ExecutionStateMode, FeatureId,
    MAX_DISPOSABLE_CERTIFICATION_SCENARIO_BYTES,
    MAX_DISPOSABLE_CERTIFICATION_SCENARIO_REPORT_BYTES, ScenarioId, ScenarioStateRootId,
    Sha256Digest,
};

#[test]
fn scenario_is_canonical_bounded_and_explicitly_disposable()
-> Result<(), Box<dyn std::error::Error>> {
    let scenario = fixture_scenario()?;
    let canonical = scenario.canonical_json_bytes()?;
    let parsed = DisposableCertificationScenario::from_json_slice(&canonical)?;

    assert_eq!(parsed, scenario);
    assert_eq!(scenario.format_version(), "1");
    assert_eq!(scenario.id().as_str(), "discord.smoke-marker");
    assert_eq!(scenario.application_family().as_str(), "discord");
    assert_eq!(scenario.adapter_id().as_str(), "discord.smoke-marker.v2");
    assert_eq!(scenario.workflow().as_str(), "discord.smoke-marker");
    assert_eq!(scenario.executable().as_str(), "Discord.exe");
    assert_eq!(scenario.state_roots().len(), 2);
    assert_eq!(scenario.arguments().len(), 2);
    assert_eq!(scenario.state_mode(), ExecutionStateMode::Disposable);
    assert_eq!(
        scenario.security_posture(),
        EffectiveSecurityPosture::VendorEquivalentFullTrust
    );
    assert_eq!(
        scenario.dependency_policy(),
        ExecutionDependencyPolicy::VendorDefaultAmbient
    );
    assert_eq!(scenario.maximum_timeout(), Duration::from_mins(1));
    assert_eq!(scenario.poll_interval(), Duration::from_millis(100));
    assert_eq!(scenario.shutdown_timeout(), Duration::from_secs(5));
    assert_eq!(
        scenario.canonical_document_digest()?.as_sha256(),
        &digest(&canonical)
    );
    assert_eq!(
        canonical,
        golden_without_repository_line_ending(include_bytes!(
            "fixtures/disposable-certification-scenario-v1.golden.json"
        ))
    );
    assert_eq!(
        scenario.canonical_document_digest()?.to_string(),
        "sha256:86af3a04eb8a4474368101924854569d9e0b1ea9d155efcd4446204763114d29"
    );

    let mut unknown: serde_json::Value = serde_json::from_slice(&canonical)?;
    unknown["execution_authorized"] = json!(true);
    assert!(matches!(
        DisposableCertificationScenario::from_json_slice(&serde_json::to_vec(&unknown)?),
        Err(DisposableCertificationScenarioDocumentError::InvalidDocument(_))
    ));
    assert!(matches!(
        DisposableCertificationScenario::from_json_slice(&vec![
            b' ';
            MAX_DISPOSABLE_CERTIFICATION_SCENARIO_BYTES
                + 1
        ]),
        Err(DisposableCertificationScenarioDocumentError::DocumentTooLarge)
    ));
    Ok(())
}

#[test]
fn scenario_rejects_duplicate_unbound_and_ambient_state_roots()
-> Result<(), Box<dyn std::error::Error>> {
    let scenario = fixture_scenario()?;
    let canonical = scenario.canonical_json_bytes()?;

    let mut duplicate: serde_json::Value = serde_json::from_slice(&canonical)?;
    let roots = duplicate["state_roots"]
        .as_array_mut()
        .ok_or("state roots are not an array")?;
    roots.push(roots.first().ok_or("missing fixture state root")?.clone());
    assert!(matches!(
        DisposableCertificationScenario::from_json_slice(&serde_json::to_vec(&duplicate)?),
        Err(DisposableCertificationScenarioDocumentError::InvalidContract(_))
    ));

    let mut unbound: serde_json::Value = serde_json::from_slice(&canonical)?;
    unbound["arguments"] = json!([{
        "kind": "state_path",
        "state_root": "marker",
        "prefix": "--weregopher-smoke-marker="
    }]);
    assert!(matches!(
        DisposableCertificationScenario::from_json_slice(&serde_json::to_vec(&unbound)?),
        Err(DisposableCertificationScenarioDocumentError::InvalidContract(_))
    ));

    for (field, value) in [
        ("state_mode", json!("vendor_default")),
        ("security_posture", json!("os_contained")),
        ("dependency_policy", json!("manifest_closed")),
    ] {
        let mut broadened: serde_json::Value = serde_json::from_slice(&canonical)?;
        broadened["execution"][field] = value;
        assert!(
            DisposableCertificationScenario::from_json_slice(&serde_json::to_vec(&broadened)?)
                .is_err(),
            "scenario accepted unsupported execution field {field}"
        );
    }
    Ok(())
}

#[test]
fn successful_report_binds_the_exact_scenario_package_and_observed_file()
-> Result<(), Box<dyn std::error::Error>> {
    let scenario = fixture_scenario()?;
    let package = DisposableScenarioPackageObservation::new(
        digest(b"package"),
        digest(b"executable"),
        42,
        4_096,
    )?;
    let report = DisposableCertificationScenarioReport::successful(
        scenario.clone(),
        package,
        Duration::from_secs(20),
        b"weregopher-discord-smoke-v2\n",
    )?;
    let canonical = report.canonical_json_bytes()?;
    let parsed = DisposableCertificationScenarioReport::from_json_slice(&canonical)?;

    assert_eq!(parsed, report);
    assert_eq!(report.format_version(), "1");
    assert_eq!(report.scenario(), &scenario);
    assert_eq!(report.package().package_files(), 42);
    assert_eq!(report.package().package_bytes(), 4_096);
    assert_eq!(
        report.execution().selected_timeout(),
        Duration::from_secs(20)
    );
    assert!(report.execution().job_membership_confirmed());
    assert!(report.execution().job_tree_termination_confirmed());
    assert!(report.execution().primary_process_exit_confirmed());
    assert!(report.execution().snapshot_revalidated());
    assert_eq!(
        report.execution().success_file().state_root().as_str(),
        "marker"
    );
    assert_eq!(
        report.execution().success_file().sha256(),
        digest(b"weregopher-discord-smoke-v2\n")
    );
    assert_eq!(
        report.canonical_document_digest()?.as_sha256(),
        &digest(&canonical)
    );
    assert_eq!(
        canonical,
        golden_without_repository_line_ending(include_bytes!(
            "fixtures/disposable-certification-scenario-report-v1.golden.json"
        ))
    );
    assert_eq!(
        report.canonical_document_digest()?.to_string(),
        "sha256:1d2ff5f60a32586a47e337939dd4f7a198a436bf413e41bdae7911498e8ad21d"
    );

    let mut tampered: serde_json::Value = serde_json::from_slice(&canonical)?;
    tampered["execution"]["success_file"]["sha256"] = json!(digest(b"wrong"));
    assert!(matches!(
        DisposableCertificationScenarioReport::from_json_slice(&serde_json::to_vec(&tampered)?),
        Err(DisposableCertificationScenarioReportDocumentError::InvalidContract(_))
    ));

    let mut excessive_timeout: serde_json::Value = serde_json::from_slice(&canonical)?;
    excessive_timeout["execution"]["selected_timeout_millis"] = json!(60_001);
    assert!(matches!(
        DisposableCertificationScenarioReport::from_json_slice(&serde_json::to_vec(
            &excessive_timeout
        )?),
        Err(DisposableCertificationScenarioReportDocumentError::InvalidContract(_))
    ));

    let mut failed_check: serde_json::Value = serde_json::from_slice(&canonical)?;
    failed_check["execution"]["job_tree_termination"] = json!("failed");
    assert!(matches!(
        DisposableCertificationScenarioReport::from_json_slice(&serde_json::to_vec(&failed_check)?),
        Err(DisposableCertificationScenarioReportDocumentError::InvalidDocument(_))
    ));

    assert!(matches!(
        DisposableCertificationScenarioReport::from_json_slice(&vec![
            b' ';
            MAX_DISPOSABLE_CERTIFICATION_SCENARIO_REPORT_BYTES
                + 1
        ]),
        Err(DisposableCertificationScenarioReportDocumentError::DocumentTooLarge)
    ));
    Ok(())
}

fn fixture_scenario() -> Result<DisposableCertificationScenario, Box<dyn std::error::Error>> {
    let marker = ScenarioStateRootId::new("marker")?;
    let user_data = ScenarioStateRootId::new("user-data")?;
    DisposableCertificationScenario::new(
        ScenarioId::new("discord.smoke-marker")?,
        ApplicationFamilyId::new("discord")?,
        AdapterId::new("discord.smoke-marker.v2")?,
        FeatureId::new("discord.smoke-marker")?,
        ExecutionPackagePath::new("Discord.exe")?,
        vec![
            DisposableScenarioStateRoot::success_file(
                marker.clone(),
                digest(b"weregopher-discord-smoke-v2\n"),
                u64::try_from(b"weregopher-discord-smoke-v2\n".len())?,
                256,
            )?,
            DisposableScenarioStateRoot::empty_directory(user_data.clone()),
        ],
        vec![
            DisposableScenarioArgument::state_path(
                marker,
                ExecutionArgument::new("--weregopher-smoke-marker=")?,
            ),
            DisposableScenarioArgument::state_path(
                user_data,
                ExecutionArgument::new("--user-data-dir=")?,
            ),
        ],
        DisposableScenarioLimits::new(
            Duration::from_mins(1),
            Duration::from_millis(100),
            Duration::from_secs(5),
            8,
            8_192,
            32_767,
            ExecutionResourceLimits::new(16, 2 * 1024 * 1024 * 1024, 4 * 1024 * 1024 * 1024)?,
        )?,
    )
    .map_err(Into::into)
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn golden_without_repository_line_ending(bytes: &[u8]) -> &[u8] {
    bytes.strip_suffix(b"\n").unwrap_or(bytes)
}
