//! Fail-closed certification-evidence contract tests.

use std::collections::BTreeMap;

use serde_json::json;
use weregopher_domain::{
    CertificationArtifactDigest, CertificationArtifactKind, CertificationArtifactRef,
    CertificationCheckAssessment, CertificationCheckStatus, CertificationChecks,
    CertificationContractError, CertificationEvidence, CertificationEvidenceDisposition,
    CertificationProfileDigest, CertificationTarget, CompatibilityAnalysisDigest, ExecutableDigest,
    ExecutionArtifactSourceDigest, ExecutionContractDigest, ExecutionResolutionEvidenceDigest,
    FeatureId, MAX_CERTIFICATION_DOCUMENT_BYTES, MAX_CERTIFICATION_EVIDENCE_REFS,
    MAX_CERTIFICATION_WORKFLOWS, Sha256Digest,
};

#[test]
fn certification_disposition_is_derived_without_profile_scope_or_granting_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let passed = assessment(CertificationCheckStatus::Passed, 0x10)?;
    let fixed_checks = checks(passed.clone());
    let evidence = CertificationEvidence::new(
        target(0x20),
        CertificationProfileDigest::new(digest(0x30)),
        fixed_checks,
        BTreeMap::new(),
    )?;
    assert_eq!(
        evidence.disposition(),
        CertificationEvidenceDisposition::Complete
    );
    let value = serde_json::to_value(&evidence)?;
    assert_eq!(value["format_version"], "1");
    for forbidden in [
        "scope",
        "certification_class",
        "publication_status",
        "trust_mode",
        "transformation_authorized",
        "execution_authorized",
        "certified",
    ] {
        assert!(value.get(forbidden).is_none());
    }

    let incomplete = CertificationEvidence::new(
        target(0x21),
        CertificationProfileDigest::new(digest(0x31)),
        checks(CertificationCheckAssessment::not_run()),
        BTreeMap::new(),
    )?;
    assert_eq!(
        incomplete.disposition(),
        CertificationEvidenceDisposition::Incomplete
    );

    let mut blocked_checks = checks(passed);
    blocked_checks.security_contract = assessment(CertificationCheckStatus::Failed, 0x32)?;
    let blocked = CertificationEvidence::new(
        target(0x22),
        CertificationProfileDigest::new(digest(0x33)),
        blocked_checks,
        BTreeMap::new(),
    )?;
    assert_eq!(
        blocked.disposition(),
        CertificationEvidenceDisposition::Blocked
    );
    Ok(())
}

#[test]
fn check_evidence_is_exactly_bounded_unique_and_status_coherent()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        CertificationCheckAssessment::new(CertificationCheckStatus::Passed, []),
        Err(CertificationContractError::MissingEvidence)
    );
    assert_eq!(
        CertificationCheckAssessment::new(
            CertificationCheckStatus::NotRun,
            [artifact(CertificationArtifactKind::RuntimeProbe, 0x40)],
        ),
        Err(CertificationContractError::UnexpectedEvidence)
    );
    assert!(
        CertificationCheckAssessment::not_run()
            .evidence()
            .is_empty()
    );
    assert!(
        serde_json::from_value::<CertificationCheckAssessment>(json!({
            "status": "passed",
            "evidence": []
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<CertificationCheckAssessment>(json!({
            "status": "not_run",
            "evidence": [{
                "kind": "security_probe",
                "digest": format!("sha256:{}", "44".repeat(32))
            }]
        }))
        .is_err()
    );

    let forward = (0_u8..64).map(|byte| artifact(CertificationArtifactKind::StaticAnalysis, byte));
    let reverse = (0_u8..64)
        .rev()
        .map(|byte| artifact(CertificationArtifactKind::StaticAnalysis, byte));
    let forward = CertificationCheckAssessment::new(CertificationCheckStatus::Passed, forward)?;
    let reverse = CertificationCheckAssessment::new(CertificationCheckStatus::Passed, reverse)?;
    assert_eq!(forward.evidence().len(), MAX_CERTIFICATION_EVIDENCE_REFS);
    assert_eq!(serde_json::to_vec(&forward)?, serde_json::to_vec(&reverse)?);

    let oversized =
        (0_u8..=64).map(|byte| artifact(CertificationArtifactKind::StaticAnalysis, byte));
    assert_eq!(
        CertificationCheckAssessment::new(CertificationCheckStatus::Passed, oversized),
        Err(CertificationContractError::TooManyEvidenceReferences)
    );
    let duplicate = artifact(CertificationArtifactKind::SecurityProbe, 0x41);
    assert_eq!(
        CertificationCheckAssessment::new(
            CertificationCheckStatus::Failed,
            [duplicate.clone(), duplicate],
        ),
        Err(CertificationContractError::DuplicateEvidenceReference)
    );
    Ok(())
}

#[test]
fn workflow_scope_is_bounded_canonical_and_contributes_to_the_disposition()
-> Result<(), Box<dyn std::error::Error>> {
    let passed = assessment(CertificationCheckStatus::Passed, 0x50)?;
    let mut forward = BTreeMap::new();
    for index in 0..MAX_CERTIFICATION_WORKFLOWS {
        forward.insert(
            FeatureId::new(format!("workflow.{index:03}"))?,
            passed.clone(),
        );
    }
    let mut reverse = BTreeMap::new();
    for index in (0..MAX_CERTIFICATION_WORKFLOWS).rev() {
        reverse.insert(
            FeatureId::new(format!("workflow.{index:03}"))?,
            passed.clone(),
        );
    }
    let forward_document = CertificationEvidence::new(
        target(0x51),
        CertificationProfileDigest::new(digest(0x52)),
        checks(passed.clone()),
        forward.clone(),
    )?;
    let reverse_document = CertificationEvidence::new(
        target(0x51),
        CertificationProfileDigest::new(digest(0x52)),
        checks(passed.clone()),
        reverse,
    )?;
    assert_eq!(
        serde_json::to_vec(&forward_document)?,
        serde_json::to_vec(&reverse_document)?
    );

    forward.insert(
        FeatureId::new(format!("workflow.{MAX_CERTIFICATION_WORKFLOWS:03}"))?,
        passed,
    );
    assert_eq!(
        CertificationEvidence::new(
            target(0x51),
            CertificationProfileDigest::new(digest(0x52)),
            checks(assessment(CertificationCheckStatus::Passed, 0x53)?),
            forward,
        ),
        Err(CertificationContractError::TooManyWorkflowAssessments)
    );

    let mut failed_workflow = BTreeMap::new();
    failed_workflow.insert(
        FeatureId::new("workflow.failed")?,
        assessment(CertificationCheckStatus::Failed, 0x54)?,
    );
    let blocked = CertificationEvidence::new(
        target(0x51),
        CertificationProfileDigest::new(digest(0x52)),
        checks(assessment(CertificationCheckStatus::Passed, 0x55)?),
        failed_workflow,
    )?;
    assert_eq!(
        blocked.disposition(),
        CertificationEvidenceDisposition::Blocked
    );
    Ok(())
}

#[test]
fn certification_transport_is_exact_targeted_closed_and_byte_bounded()
-> Result<(), Box<dyn std::error::Error>> {
    let exact_target = target(0x60);
    let evidence = CertificationEvidence::new(
        exact_target.clone(),
        CertificationProfileDigest::new(digest(0x70)),
        checks(assessment(CertificationCheckStatus::NotApplicable, 0x71)?),
        BTreeMap::new(),
    )?;
    let bytes = serde_json::to_vec(&evidence)?;
    let decoded = CertificationEvidence::from_json_slice(&bytes)?;
    assert_eq!(decoded, evidence);
    assert_eq!(decoded.target(), &exact_target);

    let value = serde_json::to_value(&evidence)?;
    let mut unknown = value.clone();
    unknown
        .as_object_mut()
        .ok_or("certification document must be an object")?
        .insert("authority".to_owned(), json!(true));
    assert!(serde_json::from_value::<CertificationEvidence>(unknown).is_err());

    for malformed_version in [json!(1), json!("01"), json!("2"), serde_json::Value::Null] {
        let mut malformed = value.clone();
        malformed["format_version"] = malformed_version;
        assert!(serde_json::from_value::<CertificationEvidence>(malformed).is_err());
    }

    let mut exact_limit = bytes;
    exact_limit.resize(MAX_CERTIFICATION_DOCUMENT_BYTES, b' ');
    assert!(CertificationEvidence::from_json_slice(&exact_limit).is_ok());
    let mut oversized = exact_limit;
    oversized.push(b' ');
    assert!(CertificationEvidence::from_json_slice(&oversized).is_err());
    Ok(())
}

#[test]
fn duplicate_and_excess_workflow_transport_fails_before_domain_acceptance()
-> Result<(), Box<dyn std::error::Error>> {
    let assessment = assessment(CertificationCheckStatus::Passed, 0x80)?;
    let evidence = CertificationEvidence::new(
        target(0x81),
        CertificationProfileDigest::new(digest(0x82)),
        checks(assessment.clone()),
        BTreeMap::new(),
    )?;
    let serialized = serde_json::to_string(&evidence)?;
    let assessment_json = serde_json::to_string(&assessment)?;
    let duplicate = serialized.replacen(
        "\"workflows\":{}",
        &format!(
            "\"workflows\":{{\"workflow.duplicate\":{assessment_json},\"workflow.duplicate\":{{\"discarded\":[1,2,3]}}}}"
        ),
        1,
    );
    assert_ne!(serialized, duplicate);
    let error = serde_json::from_str::<CertificationEvidence>(&duplicate)
        .err()
        .ok_or("duplicate workflow must fail")?;
    assert!(error.to_string().contains("duplicate workflow identifiers"));

    let mut value = serde_json::to_value(evidence)?;
    let workflows = value["workflows"]
        .as_object_mut()
        .ok_or("workflows must be an object")?;
    for index in 0..=MAX_CERTIFICATION_WORKFLOWS {
        workflows.insert(
            format!("workflow.{index:03}"),
            serde_json::to_value(&assessment)?,
        );
    }
    assert!(serde_json::from_value::<CertificationEvidence>(value).is_err());
    Ok(())
}

fn target(seed: u8) -> CertificationTarget {
    CertificationTarget::new(
        CompatibilityAnalysisDigest::new(digest(seed)),
        ExecutionContractDigest::new(digest(seed.wrapping_add(1))),
        ExecutionResolutionEvidenceDigest::new(digest(seed.wrapping_add(2))),
        ExecutionArtifactSourceDigest::new(digest(seed.wrapping_add(3))),
        ExecutableDigest::new(digest(seed.wrapping_add(4))),
    )
}

fn artifact(kind: CertificationArtifactKind, seed: u8) -> CertificationArtifactRef {
    CertificationArtifactRef::new(kind, CertificationArtifactDigest::new(digest(seed)))
}

fn assessment(
    status: CertificationCheckStatus,
    seed: u8,
) -> Result<CertificationCheckAssessment, CertificationContractError> {
    if status == CertificationCheckStatus::NotRun {
        return Ok(CertificationCheckAssessment::not_run());
    }
    CertificationCheckAssessment::new(
        status,
        [artifact(CertificationArtifactKind::RuntimeProbe, seed)],
    )
}

fn checks(assessment: CertificationCheckAssessment) -> CertificationChecks {
    CertificationChecks {
        package_identity: assessment.clone(),
        entry_point_resolution: assessment.clone(),
        transform_matches: assessment.clone(),
        module_graph: assessment.clone(),
        native_dependencies: assessment.clone(),
        runtime_bootstrap: assessment.clone(),
        renderer_bootstrap: assessment.clone(),
        preload_handshake: assessment.clone(),
        state_safety: assessment.clone(),
        helper_lifecycle: assessment.clone(),
        security_contract: assessment.clone(),
        resource_scenario: assessment.clone(),
        declared_exceptions: assessment,
    }
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}
