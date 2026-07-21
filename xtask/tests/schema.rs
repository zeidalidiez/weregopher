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
        "build-fingerprint.schema.json",
        "call-context.schema.json",
        "candidate-profile.schema.json",
        "certification-class.schema.json",
        "effective-security-posture.schema.json",
        "frame-header.schema.json",
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
