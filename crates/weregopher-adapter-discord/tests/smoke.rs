//! Discord adapter smoke-transform behavior tests.

use weregopher_adapter_discord::{
    DiscordAdapterError, SMOKE_ADAPTER_ID, SMOKE_MARKER_ARGUMENT_PREFIX, SMOKE_MARKER_CONTENT,
    transform_smoke_source,
};

#[test]
fn discord_smoke_adapter_injects_an_observable_prefix_into_the_real_main_shape()
-> Result<(), Box<dyn std::error::Error>> {
    let package = br#"{"name":"discord","main":"bundle.js"}"#;
    let source = b"(()=>{console.log('discord')})();";

    let transformed = transform_smoke_source(package, source)?;
    assert!(transformed.ends_with(source));
    assert!(
        transformed
            .windows(SMOKE_ADAPTER_ID.len())
            .any(|window| { window == SMOKE_ADAPTER_ID.as_bytes() })
    );
    assert!(
        transformed
            .windows(SMOKE_MARKER_ARGUMENT_PREFIX.len())
            .any(|window| { window == SMOKE_MARKER_ARGUMENT_PREFIX.as_bytes() })
    );
    let encoded_marker = SMOKE_MARKER_CONTENT.replace('\n', "\\n");
    assert!(
        transformed
            .windows(encoded_marker.len())
            .any(|window| { window == encoded_marker.as_bytes() })
    );
    Ok(())
}

#[test]
fn discord_smoke_adapter_rejects_an_unrecognized_main_bundle() {
    let package = br#"{"name":"discord","main":"other.js"}"#;
    assert!(matches!(
        transform_smoke_source(package, b"(()=>{})();"),
        Err(DiscordAdapterError::UnsupportedPackage)
    ));
}
