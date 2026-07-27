//! Bounded app-server JSONL handshake behavior.

use std::io::{BufReader, Cursor};

use weregopher_adapter_openai::{
    AppServerClientInfo, AppServerProtocolError, AppServerProtocolLimits, AppServerSchemaError,
    hash_app_server_schema_bundle, probe_app_server_handshake,
};

#[test]
fn handshake_proves_preinitialize_rejection_then_initializes()
-> Result<(), Box<dyn std::error::Error>> {
    let responses = concat!(
        "{\"id\":1,\"error\":{\"code\":-32002,\"message\":\"Not initialized\"}}\n",
        "{\"method\":\"server/notice\",\"params\":{\"future\":true}}\n",
        "{\"id\":2,\"result\":{\"platformOs\":\"windows\",\"futureField\":true,\"platformFamily\":\"windows\",\"userAgent\":\"codex-fixture\"}}\n"
    );
    let mut reader = BufReader::new(Cursor::new(responses.as_bytes()));
    let mut writer = Vec::new();
    let evidence = probe_app_server_handshake(
        &mut reader,
        &mut writer,
        &AppServerClientInfo::new("weregopher_g2_probe", "Weregopher G2 probe", "0.1.0")?,
        AppServerProtocolLimits::initial(),
    )?;

    assert!(evidence.preinitialize_rejected());
    assert!(evidence.initialize_succeeded());
    assert!(evidence.initialized_sent());
    assert_eq!(evidence.observed_server_messages(), 3);

    let lines = std::str::from_utf8(&writer)?
        .lines()
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0]["method"], "thread/list");
    assert_eq!(lines[0]["id"], 1);
    assert_eq!(lines[1]["method"], "initialize");
    assert_eq!(
        lines[1]["params"]["clientInfo"]["name"],
        "weregopher_g2_probe"
    );
    assert_eq!(lines[2]["method"], "initialized");
    assert!(lines[2].get("id").is_none());
    Ok(())
}

#[test]
fn handshake_rejects_oversized_inbound_lines() -> Result<(), Box<dyn std::error::Error>> {
    let limits = AppServerProtocolLimits::new(64, 4)?;
    let responses = format!(
        "{{\"id\":1,\"error\":{{\"message\":\"{}\"}}}}\n",
        "x".repeat(80)
    );
    let mut reader = BufReader::new(Cursor::new(responses.into_bytes()));
    let mut writer = Vec::new();
    let error = probe_app_server_handshake(
        &mut reader,
        &mut writer,
        &AppServerClientInfo::new("probe", "Probe", "1")?,
        limits,
    )
    .err()
    .ok_or("an oversized line must fail")?;
    assert!(matches!(error, AppServerProtocolError::InboundLineTooLarge));
    Ok(())
}

#[test]
fn handshake_rejects_success_before_initialization() -> Result<(), Box<dyn std::error::Error>> {
    let responses = "{\"id\":1,\"result\":{}}\n";
    let mut reader = BufReader::new(Cursor::new(responses.as_bytes()));
    let mut writer = Vec::new();
    let error = probe_app_server_handshake(
        &mut reader,
        &mut writer,
        &AppServerClientInfo::new("probe", "Probe", "1")?,
        AppServerProtocolLimits::initial(),
    )
    .err()
    .ok_or("pre-initialize success must fail")?;
    assert!(matches!(
        error,
        AppServerProtocolError::PreinitializeRequestAccepted
    ));
    Ok(())
}

#[test]
fn handshake_enforces_the_observed_message_budget() -> Result<(), Box<dyn std::error::Error>> {
    let responses = concat!(
        "{\"method\":\"notice/one\",\"params\":{}}\n",
        "{\"method\":\"notice/two\",\"params\":{}}\n",
        "{\"id\":1,\"error\":{\"message\":\"Not initialized\"}}\n"
    );
    let mut reader = BufReader::new(Cursor::new(responses.as_bytes()));
    let mut writer = Vec::new();
    let error = probe_app_server_handshake(
        &mut reader,
        &mut writer,
        &AppServerClientInfo::new("probe", "Probe", "1")?,
        AppServerProtocolLimits::new(1024, 2)?,
    )
    .err()
    .ok_or("excess handshake messages must fail")?;
    assert!(matches!(
        error,
        AppServerProtocolError::MessageLimitExceeded
    ));
    Ok(())
}

#[test]
fn schema_bundle_digest_is_canonical_across_generator_file_order()
-> Result<(), Box<dyn std::error::Error>> {
    let forward = hash_app_server_schema_bundle([
        (
            "json-schema/ClientRequest.json".to_owned(),
            br#"{"type":"object"}"#.to_vec(),
        ),
        (
            "typescript/ClientRequest.ts".to_owned(),
            b"export type ClientRequest = unknown;\n".to_vec(),
        ),
    ])?;
    let reverse = hash_app_server_schema_bundle([
        (
            "typescript/ClientRequest.ts".to_owned(),
            b"export type ClientRequest = unknown;\n".to_vec(),
        ),
        (
            "json-schema/ClientRequest.json".to_owned(),
            br#"{"type":"object"}"#.to_vec(),
        ),
    ])?;

    assert_eq!(forward, reverse);
    assert_eq!(forward.file_count(), 2);
    assert_eq!(
        forward.total_bytes(),
        br#"{"type":"object"}"#.len() + b"export type ClientRequest = unknown;\n".len()
    );
    Ok(())
}

#[test]
fn schema_bundle_requires_both_exact_generator_outputs() {
    let missing_typescript = hash_app_server_schema_bundle([(
        "json-schema/ClientRequest.json".to_owned(),
        br#"{"type":"object"}"#.to_vec(),
    )]);
    assert!(matches!(
        missing_typescript,
        Err(AppServerSchemaError::MissingGeneratorOutput { .. })
    ));

    let traversal = hash_app_server_schema_bundle([
        (
            "json-schema/../escape.json".to_owned(),
            br#"{"type":"object"}"#.to_vec(),
        ),
        (
            "typescript/ClientRequest.ts".to_owned(),
            b"export type ClientRequest = unknown;\n".to_vec(),
        ),
    ]);
    assert!(matches!(
        traversal,
        Err(AppServerSchemaError::InvalidRelativePath)
    ));
}

#[test]
fn schema_bundle_rejects_duplicate_paths() {
    let duplicate = hash_app_server_schema_bundle([
        (
            "json-schema/ClientRequest.json".to_owned(),
            br#"{"type":"object"}"#.to_vec(),
        ),
        (
            "json-schema/ClientRequest.json".to_owned(),
            br#"{"type":"null"}"#.to_vec(),
        ),
        (
            "typescript/ClientRequest.ts".to_owned(),
            b"export type ClientRequest = unknown;\n".to_vec(),
        ),
    ]);
    assert!(matches!(
        duplicate,
        Err(AppServerSchemaError::DuplicatePath)
    ));
}
