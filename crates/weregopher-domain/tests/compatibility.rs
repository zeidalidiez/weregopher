//! Fail-closed compatibility-analysis contract tests.

use std::collections::BTreeMap;

use serde_json::json;
use weregopher_domain::{
    AnalysisDisposition, CompatibilityAnalysis, CompatibilityContractError,
    CompatibilityDimensions, CompatibilityEvidenceKind, CompatibilityEvidenceRef,
    CompatibilityTarget, DimensionAssessment, DimensionStatus, FeatureId,
    MAX_COMPATIBILITY_EVIDENCE_REFS, MAX_COMPATIBILITY_WORKFLOWS, Sha256Digest,
};

#[test]
fn analysis_disposition_requires_every_declared_dimension_to_be_resolved()
-> Result<(), Box<dyn std::error::Error>> {
    let source = digest(0x11);
    let target = target(0x12);

    let unknown_dimensions = dimensions(DimensionAssessment::unknown());
    let incomplete =
        CompatibilityAnalysis::new(source, target.clone(), unknown_dimensions, BTreeMap::new())?;
    assert_eq!(incomplete.disposition(), AnalysisDisposition::Incomplete);

    let package_evidence =
        CompatibilityEvidenceRef::new(CompatibilityEvidenceKind::PackageManifest, digest(0x22));
    let satisfied =
        DimensionAssessment::new(DimensionStatus::Satisfied, [package_evidence.clone()])?;
    let not_applicable =
        DimensionAssessment::new(DimensionStatus::NotApplicable, [package_evidence.clone()])?;
    let mut complete_dimensions = dimensions(satisfied.clone());
    complete_dimensions.helpers = not_applicable;
    let mut workflows = BTreeMap::new();
    workflows.insert(
        FeatureId::new("launch.ready")?,
        DimensionAssessment::new(
            DimensionStatus::Satisfied,
            [CompatibilityEvidenceRef::new(
                CompatibilityEvidenceKind::WorkflowProbe,
                digest(0x33),
            )],
        )?,
    );
    let complete = CompatibilityAnalysis::new(
        source,
        target.clone(),
        complete_dimensions.clone(),
        workflows.clone(),
    )?;
    assert_eq!(complete.disposition(), AnalysisDisposition::Complete);

    complete_dimensions.native_modules = DimensionAssessment::new(
        DimensionStatus::Unsatisfied,
        [CompatibilityEvidenceRef::new(
            CompatibilityEvidenceKind::StaticAnalysis,
            digest(0x44),
        )],
    )?;
    let blocked = CompatibilityAnalysis::new(source, target, complete_dimensions, workflows)?;
    assert_eq!(blocked.disposition(), AnalysisDisposition::Blocked);

    let mut contradictory_dimensions = dimensions(DimensionAssessment::unknown());
    contradictory_dimensions.security = DimensionAssessment::new(
        DimensionStatus::Unsatisfied,
        [CompatibilityEvidenceRef::new(
            CompatibilityEvidenceKind::SecurityProbe,
            digest(0x45),
        )],
    )?;
    let contradictory = CompatibilityAnalysis::new(
        *blocked.source_build_fingerprint_digest(),
        blocked.target().clone(),
        contradictory_dimensions,
        BTreeMap::new(),
    )?;
    assert_eq!(contradictory.disposition(), AnalysisDisposition::Blocked);
    Ok(())
}

#[test]
fn resolved_assessment_deserialization_requires_immutable_evidence() {
    assert!(
        serde_json::from_value::<DimensionAssessment>(json!({
            "status": "satisfied",
            "evidence": []
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<DimensionAssessment>(json!({
            "status": "not_applicable",
            "evidence": []
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<DimensionAssessment>(json!({
            "status": "unknown",
            "evidence": []
        }))
        .is_ok()
    );
}

#[test]
fn assessment_evidence_is_exactly_bounded_unique_and_canonically_ordered()
-> Result<(), Box<dyn std::error::Error>> {
    let forward = (0_u8..64).map(|byte| {
        CompatibilityEvidenceRef::new(CompatibilityEvidenceKind::StaticAnalysis, digest(byte))
    });
    let reverse = (0_u8..64).rev().map(|byte| {
        CompatibilityEvidenceRef::new(CompatibilityEvidenceKind::StaticAnalysis, digest(byte))
    });
    let forward = DimensionAssessment::new(DimensionStatus::Satisfied, forward)?;
    let reverse = DimensionAssessment::new(DimensionStatus::Satisfied, reverse)?;
    assert_eq!(forward.evidence().len(), MAX_COMPATIBILITY_EVIDENCE_REFS);
    assert_eq!(serde_json::to_vec(&forward)?, serde_json::to_vec(&reverse)?);

    let oversized = (0_u8..=64).map(|byte| {
        CompatibilityEvidenceRef::new(CompatibilityEvidenceKind::StaticAnalysis, digest(byte))
    });
    assert_eq!(
        DimensionAssessment::new(DimensionStatus::Satisfied, oversized),
        Err(CompatibilityContractError::TooManyEvidenceReferences)
    );

    let duplicate = json!({
        "kind": "runtime_probe",
        "digest": format!("sha256:{}", "55".repeat(32))
    });
    assert!(
        serde_json::from_value::<DimensionAssessment>(json!({
            "status": "satisfied",
            "evidence": [duplicate.clone(), duplicate]
        }))
        .is_err()
    );
    Ok(())
}

#[test]
fn workflow_scope_is_exactly_bounded_and_canonically_ordered()
-> Result<(), Box<dyn std::error::Error>> {
    let source = digest(0x56);
    let target = target(0x57);
    let assessment = assessment(DimensionStatus::Satisfied, 0x58)?;

    let empty = CompatibilityAnalysis::new(
        source,
        target.clone(),
        dimensions(assessment.clone()),
        BTreeMap::new(),
    )?;
    assert!(empty.workflows().is_empty());

    let mut forward = BTreeMap::new();
    for index in 0..MAX_COMPATIBILITY_WORKFLOWS {
        forward.insert(
            FeatureId::new(format!("workflow.{index:03}"))?,
            assessment.clone(),
        );
    }
    let mut reverse = BTreeMap::new();
    for index in (0..MAX_COMPATIBILITY_WORKFLOWS).rev() {
        reverse.insert(
            FeatureId::new(format!("workflow.{index:03}"))?,
            assessment.clone(),
        );
    }
    let forward_analysis = CompatibilityAnalysis::new(
        source,
        target.clone(),
        dimensions(assessment.clone()),
        forward.clone(),
    )?;
    let reverse_analysis = CompatibilityAnalysis::new(
        source,
        target.clone(),
        dimensions(assessment.clone()),
        reverse,
    )?;
    assert_eq!(
        forward_analysis.workflows().len(),
        MAX_COMPATIBILITY_WORKFLOWS
    );
    assert_eq!(
        serde_json::to_vec(&forward_analysis)?,
        serde_json::to_vec(&reverse_analysis)?
    );

    forward.insert(
        FeatureId::new(format!("workflow.{MAX_COMPATIBILITY_WORKFLOWS:03}"))?,
        assessment.clone(),
    );
    assert_eq!(
        CompatibilityAnalysis::new(source, target, dimensions(assessment), forward),
        Err(CompatibilityContractError::TooManyWorkflowAssessments)
    );
    Ok(())
}

#[test]
fn analysis_is_bound_to_exact_source_and_target_without_granting_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let source = digest(0x60);
    let exact_target = target(0x61);
    let resolved_assessment = assessment(DimensionStatus::Satisfied, 0x70)?;
    let analysis = CompatibilityAnalysis::new(
        source,
        exact_target.clone(),
        dimensions(resolved_assessment),
        BTreeMap::new(),
    )?;
    let value = serde_json::to_value(&analysis)?;

    assert_eq!(value["format_version"], "1");
    assert_eq!(
        value["source_build_fingerprint_digest"],
        serde_json::to_value(source)?
    );
    assert_eq!(value["target"], serde_json::to_value(&exact_target)?);
    assert_eq!(analysis.source_build_fingerprint_digest(), &source);
    assert_eq!(analysis.target(), &exact_target);
    assert!(value.get("disposition").is_none());
    assert!(value.get("certification_class").is_none());
    assert!(value.get("effective_security_posture").is_none());
    assert!(value.get("efficiency_status").is_none());
    assert!(value.get("transformation_authorized").is_none());
    assert!(value.get("execution_authorized").is_none());
    assert!(value.get("certified").is_none());

    let different_target = target(0x71);
    let rebound = CompatibilityAnalysis::new(
        source,
        different_target,
        dimensions(assessment(DimensionStatus::Satisfied, 0x70)?),
        BTreeMap::new(),
    )?;
    assert_ne!(analysis, rebound);
    assert_ne!(
        serde_json::to_vec(&analysis)?,
        serde_json::to_vec(&rebound)?
    );
    Ok(())
}

#[test]
fn deserialization_rejects_unknown_missing_and_unsupported_shapes()
-> Result<(), Box<dyn std::error::Error>> {
    let analysis = CompatibilityAnalysis::new(
        digest(0x80),
        target(0x81),
        dimensions(assessment(DimensionStatus::Satisfied, 0x90)?),
        BTreeMap::new(),
    )?;
    let value = serde_json::to_value(analysis)?;
    assert!(serde_json::from_value::<CompatibilityAnalysis>(value.clone()).is_ok());

    let mut unknown_top_level = value.clone();
    unknown_top_level
        .as_object_mut()
        .ok_or("analysis must serialize as an object")?
        .insert("platform".to_owned(), json!("linux"));
    assert!(serde_json::from_value::<CompatibilityAnalysis>(unknown_top_level).is_err());

    let mut unknown_target_field = value.clone();
    unknown_target_field["target"]
        .as_object_mut()
        .ok_or("target must serialize as an object")?
        .insert("capabilities".to_owned(), json!([]));
    assert!(serde_json::from_value::<CompatibilityAnalysis>(unknown_target_field).is_err());

    let mut unsupported_platform = value.clone();
    unsupported_platform["target"]["platform"] = json!("linux");
    assert!(serde_json::from_value::<CompatibilityAnalysis>(unsupported_platform).is_err());

    let mut unsupported_architecture = value.clone();
    unsupported_architecture["target"]["architecture"] = json!("aarch64");
    assert!(serde_json::from_value::<CompatibilityAnalysis>(unsupported_architecture).is_err());

    let mut missing_target_identity = value.clone();
    missing_target_identity["target"]
        .as_object_mut()
        .ok_or("target must serialize as an object")?
        .remove("execution_environment_digest");
    assert!(serde_json::from_value::<CompatibilityAnalysis>(missing_target_identity).is_err());

    let mut unknown_dimension_field = value.clone();
    unknown_dimension_field["dimensions"]
        .as_object_mut()
        .ok_or("dimensions must serialize as an object")?
        .insert("launch_authority".to_owned(), json!({}));
    assert!(serde_json::from_value::<CompatibilityAnalysis>(unknown_dimension_field).is_err());

    let mut missing_dimension = value.clone();
    missing_dimension["dimensions"]
        .as_object_mut()
        .ok_or("dimensions must serialize as an object")?
        .remove("security");
    assert!(serde_json::from_value::<CompatibilityAnalysis>(missing_dimension).is_err());

    let mut empty_dimensions = value.clone();
    empty_dimensions["dimensions"] = json!({});
    assert!(serde_json::from_value::<CompatibilityAnalysis>(empty_dimensions).is_err());

    for malformed_version in [
        json!(0),
        json!(1),
        json!(1.0),
        json!(2),
        json!("01"),
        json!("v1"),
        serde_json::Value::Null,
    ] {
        let mut malformed = value.clone();
        malformed["format_version"] = malformed_version;
        assert!(serde_json::from_value::<CompatibilityAnalysis>(malformed).is_err());
    }
    let mut missing_version = value.clone();
    missing_version
        .as_object_mut()
        .ok_or("analysis must serialize as an object")?
        .remove("format_version");
    assert!(serde_json::from_value::<CompatibilityAnalysis>(missing_version).is_err());
    Ok(())
}

#[test]
fn bounded_deserialization_discards_duplicate_and_excess_entries()
-> Result<(), Box<dyn std::error::Error>> {
    let analysis = CompatibilityAnalysis::new(
        digest(0x80),
        target(0x81),
        dimensions(assessment(DimensionStatus::Satisfied, 0x90)?),
        BTreeMap::new(),
    )?;
    let value = serde_json::to_value(analysis)?;

    let workflow_assessment =
        serde_json::to_string(&assessment(DimensionStatus::Satisfied, 0x91)?)?;
    let serialized = serde_json::to_string(&value)?;
    let duplicate_workflows = serialized.replacen(
        "\"workflows\":{}",
        &format!(
            "\"workflows\":{{\"workflow.duplicate\":{workflow_assessment},\"workflow.duplicate\":{{\"discarded\":[\"without\",\"assessment\",\"allocation\"]}}}}"
        ),
        1,
    );
    assert_ne!(serialized, duplicate_workflows);
    let duplicate_error = serde_json::from_str::<CompatibilityAnalysis>(&duplicate_workflows)
        .err()
        .ok_or("duplicate workflow key must fail")?;
    assert!(
        duplicate_error
            .to_string()
            .contains("duplicate workflow identifiers")
    );

    let evidence = json!({
        "kind": "static_analysis",
        "digest": format!("sha256:{}", "92".repeat(32))
    });
    let mut oversized_evidence = value.clone();
    oversized_evidence["dimensions"]["package"]["evidence"] =
        serde_json::Value::Array(vec![evidence; MAX_COMPATIBILITY_EVIDENCE_REFS + 1]);
    let evidence_error = serde_json::from_value::<CompatibilityAnalysis>(oversized_evidence)
        .err()
        .ok_or("oversized evidence must fail")?;
    assert!(
        evidence_error
            .to_string()
            .contains("exceeds the evidence-reference limit")
    );

    let mut oversized_workflows = value;
    let workflows = oversized_workflows["workflows"]
        .as_object_mut()
        .ok_or("workflows must serialize as an object")?;
    let workflow_assessment = serde_json::to_value(assessment(DimensionStatus::Satisfied, 0x93)?)?;
    for index in 0..=MAX_COMPATIBILITY_WORKFLOWS {
        workflows.insert(format!("workflow.{index:03}"), workflow_assessment.clone());
    }
    let workflow_error = serde_json::from_value::<CompatibilityAnalysis>(oversized_workflows)
        .err()
        .ok_or("oversized workflow map must fail")?;
    assert!(
        workflow_error
            .to_string()
            .contains("exceeds the workflow-assessment limit")
    );
    Ok(())
}

fn target(seed: u8) -> CompatibilityTarget {
    CompatibilityTarget::windows_x64(
        digest(seed),
        digest(seed.wrapping_add(1)),
        digest(seed.wrapping_add(2)),
        digest(seed.wrapping_add(3)),
    )
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn assessment(
    status: DimensionStatus,
    byte: u8,
) -> Result<DimensionAssessment, CompatibilityContractError> {
    DimensionAssessment::new(
        status,
        [CompatibilityEvidenceRef::new(
            CompatibilityEvidenceKind::StaticAnalysis,
            digest(byte),
        )],
    )
}

fn dimensions(assessment: DimensionAssessment) -> CompatibilityDimensions {
    CompatibilityDimensions {
        package: assessment.clone(),
        main_runtime: assessment.clone(),
        renderer: assessment.clone(),
        preload: assessment.clone(),
        electron_api: assessment.clone(),
        node_api: assessment.clone(),
        native_modules: assessment.clone(),
        helpers: assessment.clone(),
        state: assessment.clone(),
        security: assessment,
    }
}
