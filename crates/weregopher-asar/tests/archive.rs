//! ASAR archive behavior tests.

use sha2::{Digest as _, Sha256};
use weregopher_asar::{AsarArchive, AsarError, AsarLimits};

#[test]
fn archive_replacement_is_integrity_checked_and_deterministic()
-> Result<(), Box<dyn std::error::Error>> {
    let original_bundle = b"console.log('old');\n";
    let package = br#"{"name":"discord","main":"bundle.js"}"#;
    let fixture = fixture_archive(&[("bundle.js", original_bundle), ("package.json", package)])?;

    let mut archive = AsarArchive::parse(&fixture, AsarLimits::initial())?;
    assert_eq!(archive.file("bundle.js"), Some(original_bundle.as_slice()));
    assert_eq!(archive.file("package.json"), Some(package.as_slice()));

    let replacement = b"console.log('weregopher');\n".to_vec();
    archive.replace_file("bundle.js", replacement.clone())?;
    let first = archive.to_bytes()?;
    let second = archive.to_bytes()?;
    assert_eq!(first, second);

    let reparsed = AsarArchive::parse(&first, AsarLimits::initial())?;
    assert_eq!(reparsed.file("bundle.js"), Some(replacement.as_slice()));
    assert_eq!(reparsed.file("package.json"), Some(package.as_slice()));
    Ok(())
}

#[test]
fn archive_parser_rejects_noncanonical_member_paths() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture_archive(&[("..", b"escape")])?;
    assert!(matches!(
        AsarArchive::parse(&fixture, AsarLimits::initial()),
        Err(AsarError::InvalidMemberName)
    ));
    Ok(())
}

#[test]
fn archive_parser_rejects_tampered_file_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture_archive(&[("bundle.js", b"original")])?;
    let final_byte = fixture.last_mut().ok_or("fixture unexpectedly empty")?;
    *final_byte ^= 0xff;
    assert!(matches!(
        AsarArchive::parse(&fixture, AsarLimits::initial()),
        Err(AsarError::IntegrityMismatch)
    ));
    Ok(())
}

fn fixture_archive(files: &[(&str, &[u8])]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut offset = 0_u64;
    let mut members = serde_json::Map::new();
    let mut body = Vec::new();

    for (path, bytes) in files {
        let hash = hex_digest(bytes);
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

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
