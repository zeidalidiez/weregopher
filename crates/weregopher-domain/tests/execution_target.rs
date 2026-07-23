//! Execution-target and generated resolution-evidence contract regressions.

use weregopher_domain::{
    ExecutionArgument, ExecutionArtifactLocator, ExecutionContractParseError,
    ExecutionDependencyPolicy, ExecutionPolicyRequirements, ExecutionResolutionDigests,
    ExecutionResolutionEvidence, ExecutionResourceLimits, ExecutionStateMode,
    ExecutionTargetContract, ExecutionTargetContractError, ExecutionTargetId, ExecutionTargetKind,
    MAX_EXECUTION_ARGUMENT_AGGREGATE_BYTES, MAX_EXECUTION_ARGUMENT_BYTES, MAX_EXECUTION_ARGUMENTS,
    MAX_EXECUTION_PACKAGE_PATH_COMPONENTS, MAX_EXECUTION_RESOLUTION_DOCUMENT_BYTES,
    MAX_EXECUTION_TARGET_DOCUMENT_BYTES, RequiredSecurityPosture, Sha256Digest,
};

#[test]
fn exact_execution_target_and_resolution_contracts_are_content_addressed()
-> Result<(), Box<dyn std::error::Error>> {
    let target_id = ExecutionTargetId::new("helper.allowed")?;
    let locator = ExecutionArtifactLocator::package_snapshot("bin/helper.exe")?;
    let launch = weregopher_domain::ExecutionLaunchPolicy::new(
        vec![ExecutionArgument::new("--label=雪\"\\tail")?],
        ExecutionDependencyPolicy::VendorDefaultAmbient,
        RequiredSecurityPosture::VendorEquivalentFullTrust,
        ExecutionStateMode::Disposable,
        ExecutionResourceLimits::new(4, 64 * 1024 * 1024, 128 * 1024 * 1024)?,
        ExecutionPolicyRequirements {
            capability_policy_digest: digest(0x12).into(),
            state_policy_digest: digest(0x13).into(),
        },
    )?;
    let contract = ExecutionTargetContract::new(
        target_id.clone(),
        ExecutionTargetKind::VendorHelper,
        locator.clone(),
        launch,
    );
    let contract_digest = contract.canonical_document_digest()?;
    assert_eq!(
        contract.canonical_json_bytes()?,
        include_bytes!("fixtures/execution-target-v2.golden.json")
    );
    assert_eq!(
        contract_digest.to_string(),
        "sha256:df3d92da4aa4c411fa901ca8cbbe65d49eb71396d6cad94a44e33083e8a4f228"
    );
    let round_trip: ExecutionTargetContract =
        serde_json::from_slice(&contract.canonical_json_bytes()?)?;
    assert_eq!(round_trip, contract);
    assert_eq!(round_trip.canonical_document_digest()?, contract_digest);
    assert!(!format!("{contract:?}").contains("--label"));

    let evidence = ExecutionResolutionEvidence::new(
        target_id,
        locator,
        ExecutionResolutionDigests {
            execution_contract_digest: contract_digest,
            artifact_source_digest: digest(0x21).into(),
            executable_digest: digest(0x22).into(),
            artifact_trust_evidence_digest: digest(0x23).into(),
            provenance_evidence_digest: digest(0x24).into(),
        },
    )?;
    let evidence_digest = evidence.canonical_document_digest()?;
    assert_eq!(
        evidence.canonical_json_bytes()?,
        include_bytes!("fixtures/execution-resolution-v2.golden.json")
    );
    assert_eq!(
        evidence_digest.to_string(),
        "sha256:f43f834a3dc75dd7c86f747d0b939389fa7d823e6ff1d2b5a1f5582d8469ebf3"
    );
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
        ExecutionDependencyPolicy::VendorDefaultAmbient,
        RequiredSecurityPosture::VendorEquivalentFullTrust,
        ExecutionStateMode::Disposable,
        ExecutionResourceLimits::new(1, 1, 1)?,
        ExecutionPolicyRequirements {
            capability_policy_digest: digest(0x32).into(),
            state_policy_digest: digest(0x33).into(),
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

    let conflict = ExecutionResolutionEvidence::new(
        ExecutionTargetId::new("helper.fixture")?,
        ExecutionArtifactLocator::managed_artifact(digest(0x50).into()),
        ExecutionResolutionDigests {
            execution_contract_digest: digest(0x51).into(),
            artifact_source_digest: digest(0x52).into(),
            executable_digest: digest(0x53).into(),
            artifact_trust_evidence_digest: digest(0x54).into(),
            provenance_evidence_digest: digest(0x55).into(),
        },
    )
    .err()
    .ok_or("conflicting managed executable identities must fail")?;
    assert_eq!(
        conflict,
        ExecutionTargetContractError::ManagedExecutableDigestMismatch
    );

    let resolution = ExecutionResolutionEvidence::new(
        ExecutionTargetId::new("helper.fixture")?,
        ExecutionArtifactLocator::managed_artifact(digest(0x50).into()),
        ExecutionResolutionDigests {
            execution_contract_digest: digest(0x51).into(),
            artifact_source_digest: digest(0x52).into(),
            executable_digest: digest(0x50).into(),
            artifact_trust_evidence_digest: digest(0x54).into(),
            provenance_evidence_digest: digest(0x55).into(),
        },
    )?;
    let mut contradictory = serde_json::to_value(&resolution)?;
    contradictory["digests"]["executable_digest"] = serde_json::to_value(digest(0x53))?;
    assert!(serde_json::from_value::<ExecutionResolutionEvidence>(contradictory).is_err());
    let mut document = serde_json::to_value(resolution)?;
    document["launch_authorized"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ExecutionResolutionEvidence>(document).is_err());
    Ok(())
}

#[test]
fn package_locators_reject_windows_ambiguous_components() {
    for path in [
        "CON.exe",
        "bin/NUL.txt",
        "bin/NUL .txt",
        "bin/COM1 .txt",
        "bin/helper?.exe",
        "bin/helper<.exe",
        "bin/helper|.exe",
        "bin/\u{001f}helper.exe",
        "bin/COM¹.log",
        "bin/LPT²",
        "bin/CONIN$.exe",
        "bin/CONOUT$",
        "bin/CLOCK$.dll",
    ] {
        assert!(
            ExecutionArtifactLocator::package_snapshot(path).is_err(),
            "accepted Windows-ambiguous path {path:?}"
        );
    }
}

#[test]
fn bounded_document_entrypoints_reject_bytes_before_serde() -> Result<(), Box<dyn std::error::Error>>
{
    let oversized = vec![b' '; MAX_EXECUTION_TARGET_DOCUMENT_BYTES + 1];
    assert!(matches!(
        ExecutionTargetContract::from_json_slice(&oversized),
        Err(ExecutionContractParseError::DocumentTooLarge { .. })
    ));
    assert!(matches!(
        ExecutionTargetContract::from_json_reader(std::io::Cursor::new(oversized)),
        Err(ExecutionContractParseError::DocumentTooLarge { .. })
    ));
    let oversized_resolution = vec![b' '; MAX_EXECUTION_RESOLUTION_DOCUMENT_BYTES + 1];
    assert!(matches!(
        ExecutionResolutionEvidence::from_json_slice(&oversized_resolution),
        Err(ExecutionContractParseError::DocumentTooLarge { .. })
    ));

    let worst_case_arguments = vec![
        ExecutionArgument::new("\u{1}".repeat(MAX_EXECUTION_ARGUMENT_BYTES))?,
        ExecutionArgument::new("\u{1}".repeat(MAX_EXECUTION_ARGUMENT_BYTES))?,
    ];
    let maximum_path = vec!["a".repeat(255); 16].join("/");
    let largest_escaped_contract = ExecutionTargetContract::new(
        ExecutionTargetId::new("helper.maximum-escaped")?,
        ExecutionTargetKind::VendorHelper,
        ExecutionArtifactLocator::package_snapshot(maximum_path)?,
        weregopher_domain::ExecutionLaunchPolicy::new(
            worst_case_arguments,
            ExecutionDependencyPolicy::VendorDefaultAmbient,
            RequiredSecurityPosture::VendorEquivalentFullTrust,
            ExecutionStateMode::Disposable,
            ExecutionResourceLimits::new(1, 1, 1)?,
            ExecutionPolicyRequirements {
                capability_policy_digest: digest(0x71).into(),
                state_policy_digest: digest(0x72).into(),
            },
        )?,
    );
    let canonical = largest_escaped_contract.canonical_json_bytes()?;
    assert!(canonical.len() <= MAX_EXECUTION_TARGET_DOCUMENT_BYTES);
    assert_eq!(
        ExecutionTargetContract::from_json_reader(std::io::Cursor::new(canonical))?,
        largest_escaped_contract
    );

    let contract = fixture_contract()?;
    let bytes = contract.canonical_json_bytes()?;
    assert_eq!(ExecutionTargetContract::from_json_slice(&bytes)?, contract);
    let mut obsolete = serde_json::to_value(contract)?;
    obsolete["format_version"] = serde_json::json!("1");
    assert!(ExecutionTargetContract::from_json_slice(&serde_json::to_vec(&obsolete)?).is_err());
    Ok(())
}

fn contract_with_arguments(
    arguments: Vec<ExecutionArgument>,
) -> Result<ExecutionTargetContract, Box<dyn std::error::Error>> {
    Ok(ExecutionTargetContract::new(
        ExecutionTargetId::new("helper.arguments")?,
        ExecutionTargetKind::VendorHelper,
        ExecutionArtifactLocator::managed_artifact(digest(0x60).into()),
        weregopher_domain::ExecutionLaunchPolicy::new(
            arguments,
            ExecutionDependencyPolicy::VendorDefaultAmbient,
            RequiredSecurityPosture::VendorEquivalentFullTrust,
            ExecutionStateMode::Disposable,
            ExecutionResourceLimits::new(1, 1, 1)?,
            ExecutionPolicyRequirements {
                capability_policy_digest: digest(0x62).into(),
                state_policy_digest: digest(0x63).into(),
            },
        )?,
    ))
}

fn fixture_contract() -> Result<ExecutionTargetContract, Box<dyn std::error::Error>> {
    Ok(ExecutionTargetContract::new(
        ExecutionTargetId::new("helper.fixture")?,
        ExecutionTargetKind::VendorHelper,
        ExecutionArtifactLocator::managed_artifact(digest(0x40).into()),
        weregopher_domain::ExecutionLaunchPolicy::new(
            Vec::new(),
            ExecutionDependencyPolicy::VendorDefaultAmbient,
            RequiredSecurityPosture::VendorEquivalentFullTrust,
            ExecutionStateMode::Disposable,
            ExecutionResourceLimits::new(1, 1, 1)?,
            ExecutionPolicyRequirements {
                capability_policy_digest: digest(0x42).into(),
                state_policy_digest: digest(0x43).into(),
            },
        )?,
    ))
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}
