//! Execution-target and generated resolution-evidence contract regressions.

use weregopher_domain::{
    EffectiveSecurityPosture, ExecutionArgument, ExecutionArtifactLocator, ExecutionPolicyDigests,
    ExecutionResolutionDigests, ExecutionResolutionEvidence, ExecutionResourceLimits,
    ExecutionStateMode, ExecutionTargetContract, ExecutionTargetId, ExecutionTargetKind,
    MAX_EXECUTION_ARGUMENT_AGGREGATE_BYTES, MAX_EXECUTION_ARGUMENTS,
    MAX_EXECUTION_PACKAGE_PATH_COMPONENTS, Sha256Digest,
};

#[test]
fn exact_execution_target_and_resolution_contracts_are_content_addressed()
-> Result<(), Box<dyn std::error::Error>> {
    let target_id = ExecutionTargetId::new("helper.allowed")?;
    let locator = ExecutionArtifactLocator::package_snapshot("bin/helper.exe")?;
    let launch = weregopher_domain::ExecutionLaunchPolicy::new(
        vec![ExecutionArgument::new("--serve")?],
        EffectiveSecurityPosture::VendorEquivalentFullTrust,
        ExecutionStateMode::Disposable,
        ExecutionResourceLimits::new(4, 64 * 1024 * 1024, 128 * 1024 * 1024)?,
        ExecutionPolicyDigests {
            compatibility_analysis_digest: digest(0x11),
            capability_policy_digest: digest(0x12),
            state_policy_digest: digest(0x13),
            user_policy_digest: digest(0x14),
        },
    )?;
    let contract = ExecutionTargetContract::new(
        target_id.clone(),
        ExecutionTargetKind::VendorHelper,
        locator.clone(),
        launch,
    );
    let contract_digest = contract.canonical_document_digest()?;
    let round_trip: ExecutionTargetContract =
        serde_json::from_slice(&contract.canonical_json_bytes()?)?;
    assert_eq!(round_trip, contract);
    assert_eq!(round_trip.canonical_document_digest()?, contract_digest);
    assert!(!format!("{contract:?}").contains("--serve"));

    let evidence = ExecutionResolutionEvidence::new(
        target_id,
        locator,
        ExecutionResolutionDigests {
            execution_contract_digest: contract_digest,
            artifact_source_digest: digest(0x21),
            executable_digest: digest(0x22),
            artifact_trust_evidence_digest: digest(0x23),
            provenance_evidence_digest: digest(0x24),
        },
    );
    let evidence_digest = evidence.canonical_document_digest()?;
    let evidence_round_trip: ExecutionResolutionEvidence =
        serde_json::from_slice(&evidence.canonical_json_bytes()?)?;
    assert_eq!(evidence_round_trip, evidence);
    assert_eq!(
        evidence_round_trip.canonical_document_digest()?,
        evidence_digest
    );
    Ok(())
}

#[test]
fn streamed_argument_parser_rejects_a_malformed_first_excess_value()
-> Result<(), Box<dyn std::error::Error>> {
    let arguments = (0..MAX_EXECUTION_ARGUMENTS)
        .map(|index| ExecutionArgument::new(format!("argument-{index}")))
        .collect::<Result<Vec<_>, _>>()?;
    let contract = contract_with_arguments(arguments.clone())?;
    let document = String::from_utf8(contract.canonical_json_bytes()?)?;
    let exact_arguments = serde_json::to_string(&arguments)?;
    let exact_fragment = format!("\"arguments\":{exact_arguments}");
    assert!(document.contains(&exact_fragment));
    let exact: ExecutionTargetContract = serde_json::from_str(&document)?;
    assert_eq!(
        exact.launch_policy().arguments().len(),
        MAX_EXECUTION_ARGUMENTS
    );

    let mut excess_arguments = exact_arguments;
    let closing = excess_arguments
        .pop()
        .ok_or("arguments JSON must end in a bracket")?;
    assert_eq!(closing, ']');
    excess_arguments.push_str(",{\"malformed\":true}]");
    let excess_document = document.replacen(
        &exact_fragment,
        &format!("\"arguments\":{excess_arguments}"),
        1,
    );
    let error = serde_json::from_str::<ExecutionTargetContract>(&excess_document)
        .err()
        .ok_or("the first excess argument must fail")?;
    assert!(error.to_string().contains("argument count"));
    Ok(())
}

#[test]
fn execution_target_contract_limits_and_transport_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    assert!(ExecutionArtifactLocator::package_snapshot("../helper.exe").is_err());
    assert!(
        ExecutionArtifactLocator::package_snapshot(
            vec!["x"; MAX_EXECUTION_PACKAGE_PATH_COMPONENTS + 1].join("/")
        )
        .is_err()
    );
    assert!(ExecutionResourceLimits::new(0, 1, 1).is_err());
    assert!(ExecutionResourceLimits::new(1, 2, 1).is_err());

    let arguments = (0..=MAX_EXECUTION_ARGUMENTS)
        .map(|index| ExecutionArgument::new(format!("argument-{index}")))
        .collect::<Result<Vec<_>, _>>()?;
    let error = weregopher_domain::ExecutionLaunchPolicy::new(
        arguments,
        EffectiveSecurityPosture::VendorEquivalentFullTrust,
        ExecutionStateMode::Disposable,
        ExecutionResourceLimits::new(1, 1, 1)?,
        ExecutionPolicyDigests {
            compatibility_analysis_digest: digest(0x31),
            capability_policy_digest: digest(0x32),
            state_policy_digest: digest(0x33),
            user_policy_digest: digest(0x34),
        },
    )
    .err()
    .ok_or("excess arguments must fail")?;
    assert!(error.to_string().contains("argument count"));

    let aggregate_arguments = vec![
        ExecutionArgument::new("x".repeat(MAX_EXECUTION_ARGUMENT_AGGREGATE_BYTES / 2))?,
        ExecutionArgument::new("y".repeat(MAX_EXECUTION_ARGUMENT_AGGREGATE_BYTES / 2))?,
        ExecutionArgument::new("z")?,
    ];
    assert!(contract_with_arguments(aggregate_arguments).is_err());

    let contract = fixture_contract()?;
    let mut document = serde_json::to_value(&contract)?;
    document["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ExecutionTargetContract>(document).is_err());

    let mut document = serde_json::to_value(&contract)?;
    document["format_version"] = serde_json::json!(2);
    assert!(serde_json::from_value::<ExecutionTargetContract>(document).is_err());

    let resolution = ExecutionResolutionEvidence::new(
        ExecutionTargetId::new("helper.fixture")?,
        ExecutionArtifactLocator::managed_artifact(digest(0x50)),
        ExecutionResolutionDigests {
            execution_contract_digest: digest(0x51),
            artifact_source_digest: digest(0x52),
            executable_digest: digest(0x53),
            artifact_trust_evidence_digest: digest(0x54),
            provenance_evidence_digest: digest(0x55),
        },
    );
    let mut document = serde_json::to_value(resolution)?;
    document["launch_authorized"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ExecutionResolutionEvidence>(document).is_err());
    Ok(())
}

fn contract_with_arguments(
    arguments: Vec<ExecutionArgument>,
) -> Result<ExecutionTargetContract, Box<dyn std::error::Error>> {
    Ok(ExecutionTargetContract::new(
        ExecutionTargetId::new("helper.arguments")?,
        ExecutionTargetKind::VendorHelper,
        ExecutionArtifactLocator::managed_artifact(digest(0x60)),
        weregopher_domain::ExecutionLaunchPolicy::new(
            arguments,
            EffectiveSecurityPosture::VendorEquivalentFullTrust,
            ExecutionStateMode::Disposable,
            ExecutionResourceLimits::new(1, 1, 1)?,
            ExecutionPolicyDigests {
                compatibility_analysis_digest: digest(0x61),
                capability_policy_digest: digest(0x62),
                state_policy_digest: digest(0x63),
                user_policy_digest: digest(0x64),
            },
        )?,
    ))
}

fn fixture_contract() -> Result<ExecutionTargetContract, Box<dyn std::error::Error>> {
    Ok(ExecutionTargetContract::new(
        ExecutionTargetId::new("helper.fixture")?,
        ExecutionTargetKind::VendorHelper,
        ExecutionArtifactLocator::managed_artifact(digest(0x40)),
        weregopher_domain::ExecutionLaunchPolicy::new(
            Vec::new(),
            EffectiveSecurityPosture::VendorEquivalentFullTrust,
            ExecutionStateMode::Disposable,
            ExecutionResourceLimits::new(1, 1, 1)?,
            ExecutionPolicyDigests {
                compatibility_analysis_digest: digest(0x41),
                capability_policy_digest: digest(0x42),
                state_policy_digest: digest(0x43),
                user_policy_digest: digest(0x44),
            },
        )?,
    ))
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}
