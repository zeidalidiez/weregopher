//! Pure package-manifest construction tests.

use weregopher_domain::Sha256Digest;
use weregopher_fingerprint::{
    MAX_NORMALIZED_PACKAGE_PATH_CHARS, MAX_PACKAGE_FILE_RECORDS, MAX_PACKAGE_RECORD_PATH_BYTES,
    ManifestError, PackageEntryType, PackageFileKind, PackageFileRecord, PackageTreeManifest,
    build_package_manifest, classify_package_file,
};

#[test]
fn input_order_does_not_change_the_manifest() -> Result<(), Box<dyn std::error::Error>> {
    let first = record("resources/app.asar", 0x11, PackageFileKind::Asar);
    let second = record(
        "resources/app.asar.unpacked/native.node",
        0x22,
        PackageFileKind::NativeModule,
    );

    let forward = build_package_manifest(vec![first.clone(), second.clone()])?;
    let reverse = build_package_manifest(vec![second, first])?;

    assert_eq!(forward, reverse);
    assert_eq!(
        forward.package_tree_merkle().to_string(),
        "sha256:ce4f446dff9a29e7098d5ad729aa87aa383ad88757d59de3b097efbe1c201231"
    );
    assert_eq!(
        forward
            .files()
            .iter()
            .map(|record| record.normalized_path.as_str())
            .collect::<Vec<_>>(),
        vec![
            "resources/app.asar",
            "resources/app.asar.unpacked/native.node"
        ]
    );
    Ok(())
}

#[test]
fn noncanonical_record_paths_are_rejected() {
    for path in [
        "",
        "/absolute",
        "trailing/",
        "double//separator",
        "./relative",
        "parent/../escape",
        r"windows\separator",
        "drive:C/path",
        "control\0character",
    ] {
        let result = build_package_manifest(vec![record(path, 0x33, PackageFileKind::Regular)]);
        assert!(result.is_err(), "accepted noncanonical path {path:?}");
    }

    let too_long = "a".repeat(32_768);
    assert!(
        build_package_manifest(vec![record(&too_long, 0x33, PackageFileKind::Regular)]).is_err()
    );
}

#[test]
fn windows_case_collisions_are_rejected() {
    let result = build_package_manifest(vec![
        record("Resources/App.asar", 0x44, PackageFileKind::Asar),
        record("resources/app.asar", 0x55, PackageFileKind::Asar),
    ]);

    assert!(result.is_err());

    let prefix_result = build_package_manifest(vec![
        record("Resources/app.asar", 0x44, PackageFileKind::Asar),
        record("resources/main.js", 0x55, PackageFileKind::Regular),
    ]);
    assert!(prefix_result.is_err());
}

#[test]
fn executable_metadata_must_match_the_file_kind() {
    let mut native = record("native/addon.node", 0x66, PackageFileKind::NativeModule);
    native.executable = false;
    assert!(build_package_manifest(vec![native]).is_err());

    let mut ordinary = record("resources/app.js", 0x77, PackageFileKind::Regular);
    ordinary.executable = true;
    assert!(build_package_manifest(vec![ordinary]).is_err());
}

#[test]
fn manifest_json_rejects_unknown_format_versions() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = build_package_manifest(vec![record(
        "resources/app.js",
        0x88,
        PackageFileKind::Regular,
    )])?;
    let mut value = serde_json::to_value(manifest)?;
    value["format_version"] = serde_json::json!(2);

    assert!(serde_json::from_value::<PackageTreeManifest>(value).is_err());
    Ok(())
}

#[test]
fn manifest_json_rejects_noncanonical_or_tampered_content() -> Result<(), Box<dyn std::error::Error>>
{
    let manifest = build_package_manifest(vec![
        record("resources/app.asar", 0x99, PackageFileKind::Asar),
        record("resources/main.js", 0xaa, PackageFileKind::Regular),
    ])?;

    let mut tampered_root = serde_json::to_value(&manifest)?;
    tampered_root["package_tree_merkle"] = serde_json::json!(format!("sha256:{}", "00".repeat(32)));
    assert!(serde_json::from_value::<PackageTreeManifest>(tampered_root).is_err());

    let mut unsorted = serde_json::to_value(manifest)?;
    unsorted["files"]
        .as_array_mut()
        .ok_or_else(|| std::io::Error::other("manifest files was not an array"))?
        .reverse();
    assert!(serde_json::from_value::<PackageTreeManifest>(unsorted).is_err());
    Ok(())
}

#[test]
fn package_manifest_rejects_unknown_outer_and_record_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let manifest = build_package_manifest(vec![record(
        "resources/main.js",
        0xab,
        PackageFileKind::Regular,
    )])?;

    let mut unknown_outer = serde_json::to_value(&manifest)?;
    unknown_outer["execution_authorized"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PackageTreeManifest>(unknown_outer).is_err());

    let mut unknown_record = serde_json::to_value(manifest)?;
    unknown_record["files"][0]["trusted"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PackageTreeManifest>(unknown_record).is_err());
    Ok(())
}

#[test]
fn package_manifest_file_and_aggregate_path_limits_are_exact() {
    let mut at_file_limit = (0..MAX_PACKAGE_FILE_RECORDS)
        .map(|index| {
            record(
                &format!("files/{index:05}.bin"),
                0xac,
                PackageFileKind::Regular,
            )
        })
        .collect::<Vec<_>>();
    assert!(build_package_manifest(at_file_limit.clone()).is_ok());
    at_file_limit.push(record("files/excess.bin", 0xac, PackageFileKind::Regular));
    assert_eq!(
        build_package_manifest(at_file_limit),
        Err(ManifestError::FileLimitExceeded {
            actual: MAX_PACKAGE_FILE_RECORDS + 1,
            max: MAX_PACKAGE_FILE_RECORDS,
        })
    );

    let mut at_path_limit = records_with_aggregate_path_bytes(MAX_PACKAGE_RECORD_PATH_BYTES);
    assert!(build_package_manifest(at_path_limit.clone()).is_ok());
    let Some(last) = at_path_limit.last_mut() else {
        return;
    };
    last.normalized_path.push('b');
    assert_eq!(
        build_package_manifest(at_path_limit),
        Err(ManifestError::PathBytesExceeded {
            actual: MAX_PACKAGE_RECORD_PATH_BYTES + 1,
            max: MAX_PACKAGE_RECORD_PATH_BYTES,
        })
    );
}

#[test]
fn transport_stops_at_the_first_excess_file_before_deserializing_it()
-> Result<(), Box<dyn std::error::Error>> {
    let valid_record =
        serde_json::to_string(&record("resources/main.js", 0xae, PackageFileKind::Regular))?;
    let mut document = String::from(
        r#"{"format_version":1,"package_tree_merkle":"sha256:0000000000000000000000000000000000000000000000000000000000000000","files":["#,
    );
    for index in 0..MAX_PACKAGE_FILE_RECORDS {
        if index != 0 {
            document.push(',');
        }
        document.push_str(&valid_record);
    }
    document.push_str(
        r#",{"normalized_path":{"malformed":"must not deserialize"},"size":0,"sha256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","executable":false,"kind":"regular","signer_thumbprint":null}]}"#,
    );

    let Err(error) = serde_json::from_str::<PackageTreeManifest>(&document) else {
        return Err("oversized package manifest unexpectedly deserialized".into());
    };
    let error = error.to_string();
    assert!(error.contains("package file record limit"), "{error}");
    Ok(())
}

#[test]
fn transport_rejects_excess_aggregate_path_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let records = records_with_aggregate_path_bytes(MAX_PACKAGE_RECORD_PATH_BYTES + 1);
    let files = serde_json::to_string(&records)?;
    let document = format!(
        r#"{{"format_version":1,"package_tree_merkle":"sha256:0000000000000000000000000000000000000000000000000000000000000000","files":{files}}}"#
    );

    let Err(error) = serde_json::from_str::<PackageTreeManifest>(&document) else {
        return Err("package paths above the transport limit unexpectedly deserialized".into());
    };
    let error = error.to_string();
    assert!(error.contains("package record path bytes"), "{error}");
    Ok(())
}

#[test]
fn package_file_classification_is_case_insensitive_and_link_aware() {
    for (path, expected) in [
        ("resources/app.ASAR", PackageFileKind::Asar),
        ("native/addon.NoDe", PackageFileKind::NativeModule),
        ("bin/helper.EXE", PackageFileKind::Executable),
        ("bin/library.DlL", PackageFileKind::Executable),
        ("bin/legacy.com", PackageFileKind::Executable),
        ("bin/saver.scr", PackageFileKind::Executable),
        ("bin/control.cpl", PackageFileKind::Executable),
        ("resources/main.js", PackageFileKind::Regular),
    ] {
        assert_eq!(
            classify_package_file(path, PackageEntryType::RegularFile),
            expected
        );
    }

    assert_eq!(
        classify_package_file("resources/app.asar", PackageEntryType::SymbolicLink),
        PackageFileKind::SymbolicLink
    );
}

fn record(path: &str, digest_byte: u8, kind: PackageFileKind) -> PackageFileRecord {
    PackageFileRecord {
        normalized_path: path.to_owned(),
        size: 128,
        sha256: Sha256Digest::from_bytes([digest_byte; 32]),
        executable: matches!(
            kind,
            PackageFileKind::NativeModule | PackageFileKind::Executable
        ),
        kind,
        signer_thumbprint: None,
    }
}

fn records_with_aggregate_path_bytes(target: usize) -> Vec<PackageFileRecord> {
    let mut records = Vec::new();
    let mut retained = 0_usize;
    while retained < target {
        let prefix = format!("{:05}/", records.len());
        let path_bytes = (target - retained).min(MAX_NORMALIZED_PACKAGE_PATH_CHARS);
        let body_bytes = path_bytes.saturating_sub(prefix.len());
        if body_bytes == 0 {
            break;
        }
        let path = format!("{prefix}{}", "a".repeat(body_bytes));
        retained += path.len();
        records.push(record(&path, 0xaf, PackageFileKind::Regular));
    }
    records
}
