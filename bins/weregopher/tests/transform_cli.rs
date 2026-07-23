//! Live transform command integration tests.

use std::{fs, process::Command};

use sha2::{Digest as _, Sha256};
use tempfile::tempdir;
use weregopher_adapter_discord::{DISCORD_MAIN_ENTRY, SMOKE_ADAPTER_ID};
use weregopher_asar::{AsarArchive, AsarLimits};

#[test]
fn discord_smoke_transform_rewrites_and_revalidates_the_main_asar_member()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let input = temp.path().join("app.asar");
    let output = temp.path().join("transformed.asar");
    let source = b"(()=>{console.log('discord')})();";
    let package = br#"{"name":"discord","main":"bundle.js"}"#;
    fs::write(
        &input,
        fixture_archive(&[(DISCORD_MAIN_ENTRY, source), ("package.json", package)])?,
    )?;

    let result = Command::new(env!("CARGO_BIN_EXE_weregopher"))
        .arg("transform")
        .arg("discord-smoke")
        .arg(&input)
        .arg(&output)
        .output()?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );

    let report: serde_json::Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(report["adapter_id"], SMOKE_ADAPTER_ID);
    assert_eq!(report["source_unit"], DISCORD_MAIN_ENTRY);

    let output_bytes = fs::read(output)?;
    let archive = AsarArchive::parse(&output_bytes, AsarLimits::initial())?;
    let transformed = archive
        .file(DISCORD_MAIN_ENTRY)
        .ok_or("missing transformed source")?;
    assert!(transformed.ends_with(source));
    assert!(
        transformed
            .windows(SMOKE_ADAPTER_ID.len())
            .any(|window| { window == SMOKE_ADAPTER_ID.as_bytes() })
    );
    assert_eq!(archive.file("package.json"), Some(package.as_slice()));
    Ok(())
}

fn fixture_archive(files: &[(&str, &[u8])]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut offset = 0_u64;
    let mut members = serde_json::Map::new();
    let mut body = Vec::new();
    for (path, bytes) in files {
        let hash = format!("{:x}", Sha256::digest(bytes));
        members.insert(
            (*path).to_owned(),
            serde_json::json!({
                "size": bytes.len(),
                "offset": offset.to_string(),
                "integrity": {
                    "algorithm": "SHA256",
                    "hash": hash,
                    "blockSize": 4_194_304,
                    "blocks": [hash],
                }
            }),
        );
        offset = offset
            .checked_add(u64::try_from(bytes.len())?)
            .ok_or("fixture offset overflow")?;
        body.extend_from_slice(bytes);
    }
    let mut json = serde_json::to_vec(&serde_json::json!({"files": members}))?;
    let json_size = u32::try_from(json.len())?;
    while json.len() % 4 != 0 {
        json.push(0);
    }
    let padded_size = u32::try_from(json.len())?;
    let mut archive = Vec::new();
    archive.extend_from_slice(&4_u32.to_le_bytes());
    archive.extend_from_slice(&(padded_size + 8).to_le_bytes());
    archive.extend_from_slice(&(padded_size + 4).to_le_bytes());
    archive.extend_from_slice(&json_size.to_le_bytes());
    archive.extend_from_slice(&json);
    archive.extend_from_slice(&body);
    Ok(archive)
}
