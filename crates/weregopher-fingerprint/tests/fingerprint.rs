//! Pure package-manifest construction tests.

use weregopher_domain::Sha256Digest;
use weregopher_fingerprint::{
    PackageFileKind, PackageFileRecord, PackageTreeManifest, build_package_manifest,
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
        forward.package_tree_merkle.to_string(),
        "sha256:ce4f446dff9a29e7098d5ad729aa87aa383ad88757d59de3b097efbe1c201231"
    );
    assert_eq!(
        forward
            .files
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
