//! Schema generation contract tests.

use std::fs;

use tempfile::tempdir;
use xtask::{SCHEMA_FILENAMES, check_schemas, generate_schemas, run};

#[test]
fn schema_generation_is_complete_deterministic_and_checkable()
-> Result<(), Box<dyn std::error::Error>> {
    let first = tempdir()?;
    let second = tempdir()?;

    generate_schemas(first.path())?;
    generate_schemas(second.path())?;
    check_schemas(first.path())?;

    let expected = [
        "adapter-execution-authority.schema.json",
        "adapter-transform-authority.schema.json",
        "build-fingerprint.schema.json",
        "call-context.schema.json",
        "candidate-installation-evidence.schema.json",
        "candidate-profile.schema.json",
        "certification-class.schema.json",
        "certification-evidence.schema.json",
        "certification-profile.schema.json",
        "compatibility-analysis.schema.json",
        "effective-security-posture.schema.json",
        "execution-resolution-evidence.schema.json",
        "execution-target-contract.schema.json",
        "frame-header.schema.json",
        "generated-execution-overlay.schema.json",
        "generated-transform-overlay.schema.json",
        "package-tree-manifest.schema.json",
        "protocol-limits.schema.json",
        "publication-status.schema.json",
        "trust-mode.schema.json",
        "wire-value.schema.json",
    ];
    assert_eq!(SCHEMA_FILENAMES, expected);

    for filename in SCHEMA_FILENAMES {
        let first_bytes = fs::read(first.path().join(filename))?;
        let second_bytes = fs::read(second.path().join(filename))?;
        assert_eq!(first_bytes, second_bytes, "schema {filename} drifted");

        let document: serde_json::Value = serde_json::from_slice(&first_bytes)?;
        assert_eq!(
            document["$schema"],
            serde_json::json!("https://json-schema.org/draft/2020-12/schema")
        );
    }
    Ok(())
}

#[test]
fn certification_evidence_schema_is_exact_bounded_and_non_authorizing()
-> Result<(), Box<dyn std::error::Error>> {
    let output = tempdir()?;
    generate_schemas(output.path())?;
    let document: serde_json::Value = serde_json::from_slice(&fs::read(
        output.path().join("certification-evidence.schema.json"),
    )?)?;

    assert_eq!(document["additionalProperties"], false);
    assert_required_properties(
        &document,
        &[
            "format_version",
            "target",
            "profile_digest",
            "checks",
            "workflows",
        ],
    )?;
    assert_eq!(
        document["$defs"]["CertificationEvidenceFormatVersion"]["enum"],
        serde_json::json!(["1"])
    );
    assert_eq!(
        document["x-weregopher-maxDocumentBytes"],
        weregopher_domain::MAX_CERTIFICATION_DOCUMENT_BYTES
    );
    assert_eq!(document["properties"]["workflows"]["maxProperties"], 128);

    let target = &document["$defs"]["CertificationTarget"];
    assert_eq!(target["additionalProperties"], false);
    for (field, role) in [
        (
            "compatibility_analysis_digest",
            "CompatibilityAnalysisDigest",
        ),
        ("execution_contract_digest", "ExecutionContractDigest"),
        (
            "execution_resolution_evidence_digest",
            "ExecutionResolutionEvidenceDigest",
        ),
        ("artifact_source_digest", "ExecutionArtifactSourceDigest"),
        ("executable_digest", "ExecutableDigest"),
    ] {
        assert_eq!(
            target["properties"][field]["$ref"],
            format!("#/$defs/{role}")
        );
        assert_eq!(document["$defs"][role]["$ref"], "#/$defs/Sha256Digest");
    }
    assert_eq!(
        document["properties"]["profile_digest"]["$ref"],
        "#/$defs/CertificationProfileDigest"
    );
    assert_eq!(
        document["$defs"]["CertificationProfileDigest"]["$ref"],
        "#/$defs/Sha256Digest"
    );

    let assessment = &document["$defs"]["CertificationCheckAssessment"];
    assert_eq!(assessment["additionalProperties"], false);
    assert_eq!(assessment["properties"]["evidence"]["maxItems"], 64);
    assert_eq!(assessment["properties"]["evidence"]["uniqueItems"], true);
    assert!(assessment["allOf"].is_array());

    let checks = &document["$defs"]["CertificationChecks"];
    assert_eq!(checks["additionalProperties"], false);
    assert_required_properties(
        checks,
        &[
            "package_identity",
            "entry_point_resolution",
            "transform_matches",
            "module_graph",
            "native_dependencies",
            "runtime_bootstrap",
            "renderer_bootstrap",
            "preload_handshake",
            "state_safety",
            "helper_lifecycle",
            "security_contract",
            "resource_scenario",
            "declared_exceptions",
        ],
    )?;

    for forbidden in [
        "scope",
        "certification_class",
        "publication_status",
        "trust_mode",
        "transformation_authorized",
        "execution_authorized",
        "certified",
    ] {
        assert!(document["properties"].get(forbidden).is_none());
    }
    Ok(())
}

#[test]
fn certification_profile_schema_is_exact_bounded_and_non_authorizing()
-> Result<(), Box<dyn std::error::Error>> {
    let output = tempdir()?;
    generate_schemas(output.path())?;
    let document: serde_json::Value = serde_json::from_slice(&fs::read(
        output.path().join("certification-profile.schema.json"),
    )?)?;

    assert_eq!(document["additionalProperties"], false);
    assert_required_properties(
        &document,
        &["format_version", "class", "checks", "workflows"],
    )?;
    assert_eq!(
        document["$defs"]["CertificationProfileFormatVersion"]["enum"],
        serde_json::json!(["1"])
    );
    assert_eq!(
        document["x-weregopher-maxDocumentBytes"],
        weregopher_domain::MAX_CERTIFICATION_PROFILE_DOCUMENT_BYTES
    );
    assert_eq!(
        schema_string_constants(&document["$defs"]["CertificationProfileClass"])?,
        [
            "structural_verified",
            "smoke_verified",
            "contract_verified",
            "exact_certified"
        ]
    );
    assert_eq!(document["properties"]["workflows"]["maxItems"], 128);
    assert_eq!(document["properties"]["workflows"]["uniqueItems"], true);
    assert_eq!(
        document["properties"]["workflows"]["items"]["$ref"],
        "#/$defs/FeatureId"
    );

    let checks = &document["$defs"]["CertificationProfileChecks"];
    assert_eq!(checks["additionalProperties"], false);
    assert_required_properties(
        checks,
        &[
            "package_identity",
            "entry_point_resolution",
            "transform_matches",
            "module_graph",
            "native_dependencies",
            "runtime_bootstrap",
            "renderer_bootstrap",
            "preload_handshake",
            "state_safety",
            "helper_lifecycle",
            "security_contract",
            "resource_scenario",
            "declared_exceptions",
        ],
    )?;
    assert_eq!(
        schema_string_constants(&document["$defs"]["CertificationExpectedStatus"])?,
        ["passed", "not_applicable"]
    );

    for forbidden in [
        "profile_digest",
        "target",
        "publication_status",
        "trust_mode",
        "permissions",
        "transformation_authorized",
        "execution_authorized",
        "certified",
    ] {
        assert!(document["properties"].get(forbidden).is_none());
    }
    Ok(())
}

#[test]
fn execution_rebinding_schemas_are_exact_bounded_and_non_authorizing()
-> Result<(), Box<dyn std::error::Error>> {
    let output = tempdir()?;
    generate_schemas(output.path())?;

    let authority: serde_json::Value = serde_json::from_slice(&fs::read(
        output
            .path()
            .join("adapter-execution-authority.schema.json"),
    )?)?;
    assert_execution_authority_schema(&authority)?;

    let overlay: serde_json::Value = serde_json::from_slice(&fs::read(
        output
            .path()
            .join("generated-execution-overlay.schema.json"),
    )?)?;
    assert_generated_execution_overlay_schema(&overlay)?;
    Ok(())
}

#[test]
fn execution_target_schemas_are_exact_bounded_and_non_authorizing()
-> Result<(), Box<dyn std::error::Error>> {
    let output = tempdir()?;
    generate_schemas(output.path())?;
    let target: serde_json::Value = serde_json::from_slice(&fs::read(
        output.path().join("execution-target-contract.schema.json"),
    )?)?;
    let resolution: serde_json::Value = serde_json::from_slice(&fs::read(
        output
            .path()
            .join("execution-resolution-evidence.schema.json"),
    )?)?;

    assert_execution_target_schema(&target)?;
    assert_execution_resolution_schema(&resolution)?;
    Ok(())
}

fn assert_execution_target_schema(
    target: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(target["additionalProperties"], false);
    assert_required_properties(
        target,
        &[
            "format_version",
            "target_id",
            "kind",
            "artifact_locator",
            "launch_policy",
        ],
    )?;
    assert_eq!(
        target["$defs"]["ExecutionTargetContractFormatVersion"]["enum"],
        serde_json::json!(["2"])
    );
    let launch = &target["$defs"]["ExecutionLaunchPolicy"];
    assert_eq!(launch["additionalProperties"], false);
    assert_required_properties(
        launch,
        &[
            "arguments",
            "environment",
            "inherited_handles",
            "console",
            "working_directory",
            "dependency_policy",
            "required_security_posture",
            "state_mode",
            "resource_limits",
            "policy_requirements",
        ],
    )?;
    assert_eq!(launch["properties"]["arguments"]["maxItems"], 64);
    assert_eq!(
        launch["properties"]["arguments"]["x-weregopher-maxAggregateUtf8Bytes"],
        weregopher_domain::MAX_EXECUTION_ARGUMENT_AGGREGATE_BYTES
    );
    assert_eq!(
        launch["properties"]["arguments"]["items"]["$ref"],
        "#/$defs/ExecutionArgument"
    );
    assert_eq!(target["$defs"]["ExecutionArgument"]["maxLength"], 8192);
    assert_eq!(
        target["$defs"]["ExecutionArgument"]["x-weregopher-maxUtf8Bytes"],
        weregopher_domain::MAX_EXECUTION_ARGUMENT_BYTES
    );
    assert_eq!(
        target["x-weregopher-maxDocumentBytes"],
        weregopher_domain::MAX_EXECUTION_TARGET_DOCUMENT_BYTES
    );
    assert_execution_locator_schema(target)?;
    assert_execution_policy_schema(target)?;
    assert_no_live_authorization_fields(target);
    Ok(())
}

fn assert_execution_locator_schema(
    document: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let variants = document["$defs"]["ExecutionArtifactLocator"]["oneOf"]
        .as_array()
        .ok_or("execution artifact locator must be a closed union")?;
    assert_eq!(variants.len(), 2);
    for variant in variants {
        assert_eq!(variant["additionalProperties"], false);
        assert!(variant["properties"]["artifact_source"]["const"].is_string());
    }
    assert_eq!(
        variants[0]["properties"]["normalized_path"]["$ref"],
        "#/$defs/ExecutionPackagePath"
    );
    let package_path = &document["$defs"]["ExecutionPackagePath"];
    assert_eq!(package_path["maxLength"], 4096);
    assert_eq!(package_path["x-weregopher-maxUtf8Bytes"], 4096);
    assert_eq!(package_path["x-weregopher-maxPathComponents"], 256);
    assert_eq!(
        package_path["x-weregopher-windowsDeviceAliasesRejected"],
        true
    );
    assert_eq!(
        variants[1]["properties"]["digest"]["$ref"],
        "#/$defs/ExecutableDigest"
    );
    assert_eq!(
        document["$defs"]["ExecutableDigest"]["$ref"],
        "#/$defs/Sha256Digest"
    );
    Ok(())
}

fn assert_execution_policy_schema(
    target: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let resources = &target["$defs"]["ExecutionResourceLimits"];
    assert_eq!(resources["additionalProperties"], false);
    assert_required_properties(
        resources,
        &[
            "active_process_limit",
            "process_memory_limit_bytes",
            "job_memory_limit_bytes",
        ],
    )?;
    for field in [
        "active_process_limit",
        "process_memory_limit_bytes",
        "job_memory_limit_bytes",
    ] {
        assert_eq!(resources["properties"][field]["minimum"], 1);
    }
    assert_eq!(resources["x-weregopher-processMemoryAtMostJobMemory"], true);
    let requirements = &target["$defs"]["ExecutionPolicyRequirements"];
    assert_eq!(requirements["additionalProperties"], false);
    for (field, role) in [
        ("capability_policy_digest", "CapabilityPolicyDigest"),
        ("state_policy_digest", "StatePolicyDigest"),
    ] {
        assert_eq!(
            requirements["properties"][field]["$ref"],
            format!("#/$defs/{role}")
        );
        assert_eq!(target["$defs"][role]["$ref"], "#/$defs/Sha256Digest");
    }
    assert!(
        requirements["properties"]
            .get("compatibility_analysis_digest")
            .is_none()
    );
    assert!(
        requirements["properties"]
            .get("user_policy_digest")
            .is_none()
    );
    Ok(())
}

fn assert_execution_resolution_schema(
    resolution: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(resolution["additionalProperties"], false);
    assert_required_properties(
        resolution,
        &["format_version", "target_id", "artifact_locator", "digests"],
    )?;
    assert_eq!(
        resolution["$defs"]["ExecutionResolutionFormatVersion"]["enum"],
        serde_json::json!(["2"])
    );
    assert_eq!(
        resolution["x-weregopher-maxDocumentBytes"],
        weregopher_domain::MAX_EXECUTION_RESOLUTION_DOCUMENT_BYTES
    );
    assert_eq!(
        resolution["x-weregopher-managedLocatorDigestEqualsExecutableDigest"],
        true
    );
    let digests = &resolution["$defs"]["ExecutionResolutionDigests"];
    assert_eq!(digests["additionalProperties"], false);
    for (field, role) in [
        ("execution_contract_digest", "ExecutionContractDigest"),
        ("artifact_source_digest", "ExecutionArtifactSourceDigest"),
        ("executable_digest", "ExecutableDigest"),
        (
            "artifact_trust_evidence_digest",
            "ArtifactTrustEvidenceDigest",
        ),
        ("provenance_evidence_digest", "ProvenanceEvidenceDigest"),
    ] {
        assert_eq!(
            digests["properties"][field]["$ref"],
            format!("#/$defs/{role}")
        );
        assert_eq!(resolution["$defs"][role]["$ref"], "#/$defs/Sha256Digest");
    }
    assert_execution_locator_schema(resolution)?;
    assert_no_live_authorization_fields(resolution);
    Ok(())
}

fn assert_execution_authority_schema(
    authority: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        authority["$defs"]["ExecutionRebindingFormatVersion"]["enum"],
        serde_json::json!(["1"])
    );
    assert_required_properties(
        authority,
        &[
            "format_version",
            "adapter_id",
            "family",
            "adapter_content_digest",
            "targets",
        ],
    )?;
    let targets = &authority["properties"]["targets"];
    assert_eq!(targets["minProperties"], 1);
    assert_eq!(targets["maxProperties"], 64);
    let target_schemas = targets["patternProperties"]
        .as_object()
        .ok_or("execution authority must constrain target identifiers")?;
    assert_eq!(target_schemas.len(), 1);
    assert!(target_schemas.contains_key(stable_identifier_pattern()));
    assert_eq!(targets["additionalProperties"], false);
    assert_eq!(
        target_schemas
            .values()
            .next()
            .ok_or("execution authority target schema is missing")?["$ref"],
        "#/$defs/AuthorizedExecutionTargetRef"
    );
    assert_eq!(authority["additionalProperties"], false);
    let target = &authority["$defs"]["AuthorizedExecutionTargetRef"];
    assert_eq!(target["additionalProperties"], false);
    assert_required_properties(
        target,
        &["kind", "artifact_source", "execution_contract_digest"],
    )?;
    assert_eq!(
        schema_string_constants(&authority["$defs"]["ExecutionArtifactSource"])?,
        ["package_snapshot", "managed_artifact"]
    );
    assert_eq!(
        schema_string_constants(&authority["$defs"]["ExecutionTargetKind"])?,
        [
            "main_runtime",
            "vendor_helper",
            "abi_island",
            "specialized_helper"
        ]
    );
    assert_eq!(
        authority["properties"]["adapter_content_digest"]["$ref"],
        "#/$defs/Sha256Digest"
    );
    assert_eq!(
        authority["properties"]["adapter_id"]["$ref"],
        "#/$defs/AdapterId"
    );
    assert_eq!(
        authority["properties"]["family"]["$ref"],
        "#/$defs/ApplicationFamilyId"
    );
    assert_eq!(
        target["properties"]["execution_contract_digest"]["$ref"],
        "#/$defs/ExecutionContractDigest"
    );
    assert_eq!(
        authority["$defs"]["ExecutionContractDigest"]["$ref"],
        "#/$defs/Sha256Digest"
    );
    for forbidden in execution_authority_forbidden_fields() {
        assert!(authority["properties"].get(forbidden).is_none());
        assert!(target["properties"].get(forbidden).is_none());
    }
    Ok(())
}

fn assert_generated_execution_overlay_schema(
    overlay: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        overlay["$defs"]["ExecutionRebindingFormatVersion"]["enum"],
        serde_json::json!(["1"])
    );
    assert_required_properties(
        overlay,
        &[
            "format_version",
            "platform",
            "architecture",
            "binding",
            "bindings",
        ],
    )?;
    assert_eq!(
        schema_string_constants(&overlay["$defs"]["ExecutionPlatform"])?,
        ["windows"]
    );
    assert_eq!(
        schema_string_constants(&overlay["$defs"]["ExecutionArchitecture"])?,
        ["x86_64"]
    );
    let bindings = &overlay["properties"]["bindings"];
    assert_eq!(bindings["minProperties"], 1);
    assert_eq!(bindings["maxProperties"], 64);
    let binding_schemas = bindings["patternProperties"]
        .as_object()
        .ok_or("execution overlay must constrain target identifiers")?;
    assert_eq!(binding_schemas.len(), 1);
    assert!(binding_schemas.contains_key(stable_identifier_pattern()));
    assert_eq!(bindings["additionalProperties"], false);
    assert_eq!(
        binding_schemas
            .values()
            .next()
            .ok_or("execution overlay binding schema is missing")?["$ref"],
        "#/$defs/ExecutionArtifactBinding"
    );
    assert_eq!(overlay["additionalProperties"], false);
    assert_eq!(
        overlay["properties"]["binding"]["$ref"],
        "#/$defs/ExecutionOverlayBinding"
    );
    for definition in [
        "ExecutionArtifactBinding",
        "ExecutionAuthorityBinding",
        "ExecutionOverlayBinding",
    ] {
        assert_eq!(overlay["$defs"][definition]["additionalProperties"], false);
    }
    let artifact = &overlay["$defs"]["ExecutionArtifactBinding"];
    assert_required_properties(
        artifact,
        &[
            "execution_contract_digest",
            "artifact_source_digest",
            "executable_digest",
            "resolution_evidence_digest",
        ],
    )?;
    for (field, role) in [
        ("execution_contract_digest", "ExecutionContractDigest"),
        ("artifact_source_digest", "ExecutionArtifactSourceDigest"),
        ("executable_digest", "ExecutableDigest"),
        (
            "resolution_evidence_digest",
            "ExecutionResolutionEvidenceDigest",
        ),
    ] {
        assert_eq!(
            artifact["properties"][field]["$ref"],
            format!("#/$defs/{role}")
        );
        assert_eq!(overlay["$defs"][role]["$ref"], "#/$defs/Sha256Digest");
    }
    assert_execution_overlay_context_schema(overlay)?;
    assert_execution_overlay_is_non_authorizing(overlay);
    Ok(())
}

fn assert_execution_overlay_context_schema(
    overlay: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = &overlay["$defs"]["ExecutionAuthorityBinding"];
    assert_required_properties(
        authority,
        &[
            "family",
            "adapter_id",
            "adapter_content_digest",
            "adapter_execution_authority_digest",
        ],
    )?;
    assert_eq!(
        authority["properties"]["family"]["$ref"],
        "#/$defs/ApplicationFamilyId"
    );
    assert_eq!(
        authority["properties"]["adapter_id"]["$ref"],
        "#/$defs/AdapterId"
    );
    for field in [
        "adapter_content_digest",
        "adapter_execution_authority_digest",
    ] {
        assert_eq!(
            authority["properties"][field]["$ref"],
            "#/$defs/Sha256Digest"
        );
    }
    let context = &overlay["$defs"]["ExecutionOverlayBinding"];
    assert_required_properties(
        context,
        &[
            "source_build_fingerprint_digest",
            "package_tree_merkle",
            "execution_environment_digest",
            "authority",
            "build_descriptor_digest",
        ],
    )?;
    assert_eq!(
        context["properties"]["authority"]["$ref"],
        "#/$defs/ExecutionAuthorityBinding"
    );
    for field in [
        "source_build_fingerprint_digest",
        "package_tree_merkle",
        "execution_environment_digest",
        "build_descriptor_digest",
    ] {
        assert_eq!(context["properties"][field]["$ref"], "#/$defs/Sha256Digest");
    }
    Ok(())
}

fn assert_execution_overlay_is_non_authorizing(overlay: &serde_json::Value) {
    for forbidden in execution_authority_forbidden_fields() {
        for properties in [
            &overlay["properties"],
            &overlay["$defs"]["ExecutionArtifactBinding"]["properties"],
            &overlay["$defs"]["ExecutionAuthorityBinding"]["properties"],
            &overlay["$defs"]["ExecutionOverlayBinding"]["properties"],
        ] {
            assert!(properties.get(forbidden).is_none());
        }
    }
}

fn assert_no_live_authorization_fields(value: &serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(properties) = object.get("properties") {
                for forbidden in [
                    "authority_authenticated",
                    "authorization_token",
                    "execution_authorized",
                    "launch_authorized",
                    "process_id",
                    "revocation_current",
                    "sandboxed",
                ] {
                    assert!(properties.get(forbidden).is_none());
                }
            }
            for child in object.values() {
                assert_no_live_authorization_fields(child);
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                assert_no_live_authorization_fields(child);
            }
        }
        _ => {}
    }
}

fn stable_identifier_pattern() -> &'static str {
    r"^(?!.*\.\.)[a-z0-9](?:[a-z0-9._-]{0,253}[a-z0-9])?$"
}

fn execution_authority_forbidden_fields() -> [&'static str; 10] {
    [
        "arguments",
        "capabilities",
        "execution_authorized",
        "launch_authorized",
        "native_content",
        "privileged_operations",
        "replacement_module",
        "security_exceptions",
        "state_migrations",
        "user_consent",
    ]
}

fn assert_required_properties(
    schema: &serde_json::Value,
    expected: &[&str],
) -> Result<(), &'static str> {
    let required = schema["required"]
        .as_array()
        .ok_or("schema must declare required properties")?;
    assert_eq!(required.len(), expected.len());
    for property in expected {
        assert!(required.iter().any(|value| value == property));
    }
    Ok(())
}

#[test]
fn transform_rebinding_schemas_are_exact_bounded_and_non_authorizing()
-> Result<(), Box<dyn std::error::Error>> {
    let output = tempdir()?;
    generate_schemas(output.path())?;

    let authority: serde_json::Value = serde_json::from_slice(&fs::read(
        output
            .path()
            .join("adapter-transform-authority.schema.json"),
    )?)?;
    assert_transform_authority_schema(&authority)?;

    let overlay: serde_json::Value = serde_json::from_slice(&fs::read(
        output
            .path()
            .join("generated-transform-overlay.schema.json"),
    )?)?;
    assert_generated_overlay_shape(&overlay)?;
    assert_generated_overlay_digest_refs(&overlay);
    assert_generated_overlay_is_non_authorizing(&overlay);
    Ok(())
}

fn assert_transform_authority_schema(
    authority: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        authority["$defs"]["TransformRebindingFormatVersion"]["enum"],
        serde_json::json!(["1"])
    );
    assert_eq!(authority["properties"]["rules"]["minProperties"], 1);
    assert_eq!(authority["properties"]["rules"]["maxProperties"], 128);
    assert_eq!(authority["additionalProperties"], false);
    assert_eq!(
        authority["required"],
        serde_json::json!([
            "format_version",
            "adapter_id",
            "family",
            "adapter_content_digest",
            "rules"
        ])
    );
    let authority_rule_schemas = authority["properties"]["rules"]["patternProperties"]
        .as_object()
        .ok_or("authority rule schema must constrain map keys")?;
    assert_eq!(authority_rule_schemas.len(), 1);
    assert_eq!(
        authority_rule_schemas
            .values()
            .next()
            .ok_or("authority rule schema is missing its value type")?["$ref"],
        "#/$defs/AuthorizedTransformRuleRef"
    );
    assert_eq!(
        authority["$defs"]["AuthorizedTransformRuleRef"]["additionalProperties"],
        false
    );
    assert!(authority["properties"].get("capabilities").is_none());
    assert!(
        authority["properties"]
            .get("execution_authorized")
            .is_none()
    );
    Ok(())
}

fn assert_generated_overlay_shape(
    overlay: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        overlay["$defs"]["TransformRebindingFormatVersion"]["enum"],
        serde_json::json!(["1"])
    );
    assert_eq!(
        schema_string_constants(&overlay["$defs"]["TransformPlatform"])?,
        ["windows"]
    );
    assert_eq!(
        schema_string_constants(&overlay["$defs"]["TransformArchitecture"])?,
        ["x86_64"]
    );
    assert_eq!(overlay["properties"]["rebindings"]["minProperties"], 1);
    assert_eq!(overlay["properties"]["rebindings"]["maxProperties"], 128);
    assert_eq!(overlay["additionalProperties"], false);
    assert_eq!(
        overlay["required"],
        serde_json::json!([
            "format_version",
            "platform",
            "architecture",
            "binding",
            "rebindings"
        ])
    );
    let rebinding_schemas = overlay["properties"]["rebindings"]["patternProperties"]
        .as_object()
        .ok_or("generated rebinding schema must constrain map keys")?;
    assert_eq!(rebinding_schemas.len(), 1);
    assert_eq!(
        rebinding_schemas
            .values()
            .next()
            .ok_or("generated rebinding schema is missing its value type")?["$ref"],
        "#/$defs/TransformRebinding"
    );
    assert_eq!(
        overlay["properties"]["binding"]["$ref"],
        "#/$defs/TransformOverlayBinding"
    );
    assert_eq!(
        overlay["$defs"]["TransformOverlayBinding"]["additionalProperties"],
        false
    );
    assert_eq!(
        overlay["$defs"]["TransformRebinding"]["additionalProperties"],
        false
    );
    assert_eq!(
        overlay["$defs"]["SourceUnitRef"]["additionalProperties"],
        false
    );
    assert_eq!(
        overlay["$defs"]["SourceUnitId"]["maxLength"],
        serde_json::json!(255)
    );
    Ok(())
}

fn assert_generated_overlay_digest_refs(overlay: &serde_json::Value) {
    let binding_properties = &overlay["$defs"]["TransformOverlayBinding"]["properties"];
    assert_eq!(
        binding_properties["adapter_id"]["$ref"],
        "#/$defs/AdapterId"
    );
    assert_eq!(
        binding_properties["family"]["$ref"],
        "#/$defs/ApplicationFamilyId"
    );
    for field in [
        "adapter_content_digest",
        "adapter_transform_authority_digest",
        "build_descriptor_digest",
        "source_build_fingerprint_digest",
    ] {
        assert_eq!(binding_properties[field]["$ref"], "#/$defs/Sha256Digest");
    }
    let rebinding_properties = &overlay["$defs"]["TransformRebinding"]["properties"];
    for field in [
        "audit_log_digest",
        "match_evidence_digest",
        "rule_digest",
        "source_map_digest",
        "transformed_source_digest",
    ] {
        assert_eq!(rebinding_properties[field]["$ref"], "#/$defs/Sha256Digest");
    }
}

fn assert_generated_overlay_is_non_authorizing(overlay: &serde_json::Value) {
    for forbidden in [
        "capabilities",
        "execution_authorized",
        "launch_authorized",
        "native_content",
        "privileged_operations",
        "replacement_module",
        "security_exceptions",
        "state_migrations",
    ] {
        assert!(overlay["properties"].get(forbidden).is_none());
        assert!(
            overlay["$defs"]["TransformOverlayBinding"]["properties"]
                .get(forbidden)
                .is_none()
        );
        assert!(
            overlay["$defs"]["TransformRebinding"]["properties"]
                .get(forbidden)
                .is_none()
        );
    }
}

#[test]
fn schema_check_detects_a_stale_generated_file() -> Result<(), Box<dyn std::error::Error>> {
    let output = tempdir()?;
    generate_schemas(output.path())?;
    fs::write(output.path().join(SCHEMA_FILENAMES[0]), b"{}\n")?;

    let error = check_schemas(output.path());
    assert!(error.is_err());
    Ok(())
}

#[test]
fn xtask_schema_command_generates_then_checks_the_repository_directory()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = tempdir()?;

    run(["schema"], repository.path())?;
    run(["schema", "--check"], repository.path())?;

    assert!(
        repository
            .path()
            .join("schemas/wire-value.schema.json")
            .is_file()
    );
    assert!(run(["unknown"], repository.path()).is_err());
    Ok(())
}

#[test]
fn generated_schema_enforces_canonical_identifier_and_digest_grammars()
-> Result<(), Box<dyn std::error::Error>> {
    let output = tempdir()?;
    generate_schemas(output.path())?;
    let document: serde_json::Value = serde_json::from_slice(&fs::read(
        output.path().join("build-fingerprint.schema.json"),
    )?)?;

    let family = &document["$defs"]["ApplicationFamilyId"];
    assert_eq!(family["minLength"], 1);
    assert_eq!(family["maxLength"], 255);
    assert_eq!(
        family["pattern"],
        r"^(?!.*\.\.)[a-z0-9](?:[a-z0-9._-]{0,253}[a-z0-9])?$"
    );

    let digest = &document["$defs"]["Sha256Digest"];
    assert_eq!(digest["minLength"], 71);
    assert_eq!(digest["maxLength"], 71);
    assert_eq!(digest["pattern"], r"^sha256:[0-9a-f]{64}$");
    Ok(())
}

#[test]
fn generated_schemas_bound_every_rust_integer_format() -> Result<(), Box<dyn std::error::Error>> {
    let output = tempdir()?;
    generate_schemas(output.path())?;

    for filename in SCHEMA_FILENAMES {
        let document: serde_json::Value =
            serde_json::from_slice(&fs::read(output.path().join(filename))?)?;
        assert_integer_formats_are_bounded(&document, filename);
    }
    Ok(())
}

#[test]
fn generated_protocol_schemas_match_registered_flags_and_positive_limits()
-> Result<(), Box<dyn std::error::Error>> {
    let output = tempdir()?;
    generate_schemas(output.path())?;

    let frame: serde_json::Value =
        serde_json::from_slice(&fs::read(output.path().join("frame-header.schema.json"))?)?;
    let flags = &frame["properties"]["flags"];
    assert_eq!(flags["minimum"], 0);
    assert_eq!(flags["maximum"], 0);

    let limits: serde_json::Value = serde_json::from_slice(&fs::read(
        output.path().join("protocol-limits.schema.json"),
    )?)?;
    let properties = limits["properties"]
        .as_object()
        .ok_or("protocol limits schema properties must be an object")?;
    for (name, schema) in properties {
        assert_eq!(schema["minimum"], 1, "limit {name} accepted zero");
    }
    Ok(())
}

#[test]
fn package_manifest_schema_is_generated_with_a_fixed_format_version()
-> Result<(), Box<dyn std::error::Error>> {
    let output = tempdir()?;
    generate_schemas(output.path())?;
    let path = output.path().join("package-tree-manifest.schema.json");
    assert!(path.is_file());

    let document: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
    let version = &document["properties"]["format_version"];
    assert_eq!(version["minimum"], 1);
    assert_eq!(version["maximum"], 1);
    assert_eq!(document["additionalProperties"], false);
    assert_eq!(
        document["properties"]["files"]["maxItems"],
        weregopher_fingerprint::MAX_PACKAGE_FILE_RECORDS
    );
    assert_eq!(
        document["$defs"]["PackageFileRecord"]["additionalProperties"],
        false
    );
    let normalized_path = &document["$defs"]["PackageFileRecord"]["properties"]["normalized_path"];
    assert_eq!(normalized_path["minLength"], 1);
    assert_eq!(normalized_path["maxLength"], 32_767);
    assert!(normalized_path["pattern"].is_string());
    Ok(())
}

#[test]
fn candidate_installation_evidence_schema_preserves_provenance_without_compatibility_claims()
-> Result<(), Box<dyn std::error::Error>> {
    let output = tempdir()?;
    generate_schemas(output.path())?;
    let path = output
        .path()
        .join("candidate-installation-evidence.schema.json");
    assert!(path.is_file());

    let document: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
    assert_eq!(
        schema_string_constants(&document["$defs"]["DiscoveryConfidence"])?,
        ["advisory", "corroborated", "direct_observation"]
    );
    assert_eq!(
        schema_string_constants(&document["$defs"]["DiscoverySource"])?,
        [
            "package_catalog",
            "uninstall_registry",
            "known_install_location",
            "shortcut",
            "filesystem_layout",
            "running_process",
            "user_selected_path",
            "package_manifest",
            "executable_version_resource",
            "authenticode_signature"
        ]
    );
    assert!(document["properties"]["package_identity"].is_object());
    assert!(document["$defs"]["PackageIdentity"].is_object());
    assert!(document["properties"].get("electron").is_none());
    assert!(document["properties"].get("compatible").is_none());
    assert!(document["properties"].get("package_tree").is_none());
    Ok(())
}

#[test]
fn candidate_profile_schema_fixes_the_initial_target_and_channel_vocabularies()
-> Result<(), Box<dyn std::error::Error>> {
    let output = tempdir()?;
    generate_schemas(output.path())?;
    let path = output.path().join("candidate-profile.schema.json");
    assert!(path.is_file());

    let document: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
    let targets = schema_string_constants(&document["$defs"]["CandidateTarget"])?;
    assert_eq!(
        targets,
        ["codex", "hermes_agent", "discord", "visual_studio_code"]
    );
    let channels = schema_string_constants(&document["$defs"]["CandidateChannelHint"])?;
    assert_eq!(channels, ["stable", "ptb", "canary", "insiders"]);
    assert!(document["properties"].get("electron").is_none());
    assert!(document["properties"].get("compatibility").is_none());
    assert!(document["properties"].get("package_path").is_none());
    Ok(())
}

#[test]
fn compatibility_analysis_schema_is_versioned_bounded_and_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let output = tempdir()?;
    generate_schemas(output.path())?;
    let path = output.path().join("compatibility-analysis.schema.json");
    assert!(path.is_file());

    let document: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
    assert_eq!(
        document["$defs"]["CompatibilityAnalysisFormatVersion"]["enum"],
        serde_json::json!(["1"])
    );
    assert_eq!(
        document["properties"]["format_version"]["$ref"],
        "#/$defs/CompatibilityAnalysisFormatVersion"
    );
    assert_eq!(document["properties"]["workflows"]["maxProperties"], 128);
    assert_eq!(
        document["properties"]["source_build_fingerprint_digest"]["$ref"],
        "#/$defs/Sha256Digest"
    );
    assert_eq!(
        document["properties"]["target"]["$ref"],
        "#/$defs/CompatibilityTarget"
    );
    assert_eq!(document["additionalProperties"], false);
    assert_compatibility_target_schema(&document)?;

    let assessment = &document["$defs"]["DimensionAssessment"];
    assert_eq!(assessment["properties"]["evidence"]["maxItems"], 64);
    assert_eq!(assessment["properties"]["evidence"]["uniqueItems"], true);
    assert_eq!(
        assessment["allOf"][0]["then"]["properties"]["evidence"]["minItems"],
        1
    );
    assert_eq!(
        assessment["allOf"][0]["if"]["properties"]["status"]["enum"],
        serde_json::json!(["satisfied", "unsatisfied", "not_applicable"])
    );
    assert_eq!(
        schema_string_constants(&document["$defs"]["DimensionStatus"])?,
        ["unknown", "satisfied", "unsatisfied", "not_applicable"]
    );
    assert!(document["properties"].get("certification_class").is_none());
    assert!(
        document["properties"]
            .get("effective_security_posture")
            .is_none()
    );
    assert!(document["properties"].get("efficiency_status").is_none());
    assert!(
        document["properties"]
            .get("transformation_authorized")
            .is_none()
    );
    assert!(document["properties"].get("execution_authorized").is_none());
    assert!(document["properties"].get("certified").is_none());
    Ok(())
}

fn assert_compatibility_target_schema(document: &serde_json::Value) -> Result<(), &'static str> {
    assert_eq!(
        schema_string_constants(&document["$defs"]["CompatibilityPlatform"])?,
        ["windows"]
    );
    assert_eq!(
        schema_string_constants(&document["$defs"]["CompatibilityArchitecture"])?,
        ["x86_64"]
    );
    let root_required = document["required"]
        .as_array()
        .ok_or("analysis schema must declare required properties")?;
    for property in [
        "format_version",
        "source_build_fingerprint_digest",
        "target",
        "dimensions",
        "workflows",
    ] {
        assert!(root_required.iter().any(|value| value == property));
    }
    let target = &document["$defs"]["CompatibilityTarget"];
    assert_eq!(
        target["additionalProperties"], false,
        "target must reject undeclared environment attributes"
    );
    let target_required = target["required"]
        .as_array()
        .ok_or("target schema must declare required identities")?;
    for property in [
        "platform",
        "architecture",
        "adapter_contract_digest",
        "main_runtime_contract_digest",
        "renderer_backend_contract_digest",
        "execution_environment_digest",
    ] {
        assert!(target_required.iter().any(|value| value == property));
    }
    for property in [
        "adapter_contract_digest",
        "main_runtime_contract_digest",
        "renderer_backend_contract_digest",
        "execution_environment_digest",
    ] {
        assert_eq!(
            target["properties"][property]["$ref"],
            "#/$defs/Sha256Digest"
        );
    }
    assert!(document["$defs"].get("BuildFingerprint").is_none());
    assert!(document["$defs"].get("PackageIdentity").is_none());
    Ok(())
}

fn schema_string_constants(schema: &serde_json::Value) -> Result<Vec<&str>, &'static str> {
    schema["oneOf"]
        .as_array()
        .ok_or("enum schema must use oneOf")?
        .iter()
        .map(|variant| {
            variant["const"]
                .as_str()
                .ok_or("enum variant must have a string const")
        })
        .collect()
}

fn assert_integer_formats_are_bounded(value: &serde_json::Value, path: &str) {
    match value {
        serde_json::Value::Object(object) => {
            if object
                .get("format")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|format| {
                    matches!(
                        format,
                        "uint8"
                            | "uint16"
                            | "uint32"
                            | "uint64"
                            | "int8"
                            | "int16"
                            | "int32"
                            | "int64"
                    )
                })
            {
                assert!(object.contains_key("minimum"), "missing minimum at {path}");
                assert!(object.contains_key("maximum"), "missing maximum at {path}");
            }
            for (key, child) in object {
                assert_integer_formats_are_bounded(child, &format!("{path}/{key}"));
            }
        }
        serde_json::Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                assert_integer_formats_are_bounded(child, &format!("{path}/{index}"));
            }
        }
        _ => {}
    }
}
