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
        "adapter-transform-authority.schema.json",
        "build-fingerprint.schema.json",
        "call-context.schema.json",
        "candidate-installation-evidence.schema.json",
        "candidate-profile.schema.json",
        "certification-class.schema.json",
        "compatibility-analysis.schema.json",
        "effective-security-posture.schema.json",
        "frame-header.schema.json",
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
