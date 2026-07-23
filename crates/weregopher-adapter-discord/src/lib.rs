//! Durable Discord-family transforms used by the initial live vertical slice.

use thiserror::Error;

const MAX_PACKAGE_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_MAIN_SOURCE_BYTES: usize = 64 * 1024 * 1024;
const DISCORD_MAIN_PREFIX: &[u8] = b"(()=>{";
const SMOKE_PREFIX: &[u8] = br#";(()=>{const __weregopherAdapter="discord.smoke-marker.v1";const __weregopherMarker=process.env.WEREGOPHER_SMOKE_MARKER;if(__weregopherMarker){require("node:fs").writeFileSync(__weregopherMarker,"weregopher-discord-smoke-v1\n",{encoding:"utf8",flag:"wx"});}void __weregopherAdapter;})();
"#;

/// Stable identity of the deliberately narrow Discord smoke adapter.
pub const SMOKE_ADAPTER_ID: &str = "discord.smoke-marker.v1";
/// Exact bytes written by the adapter when `WEREGOPHER_SMOKE_MARKER` is set.
pub const SMOKE_MARKER_CONTENT: &str = "weregopher-discord-smoke-v1\n";
/// ASAR member containing Discord's packaged main process source.
pub const DISCORD_MAIN_ENTRY: &str = "bundle.js";
/// ASAR member declaring Discord's packaged main entry.
pub const DISCORD_PACKAGE_MANIFEST: &str = "package.json";

/// Injects an opt-in smoke marker before Discord's recognized packaged main bundle.
///
/// The adapter accepts only a Discord package manifest whose main entry is `bundle.js` and the
/// Rspack bootstrap shape observed for the supported family. The original source is retained
/// byte-for-byte after the injected prefix. The marker write occurs only when the launch command
/// supplies `WEREGOPHER_SMOKE_MARKER`; this function itself performs no filesystem access.
///
/// # Errors
///
/// Returns a closed [`DiscordAdapterError`] when the inputs exceed their limits, the manifest is
/// invalid, the package shape is unsupported, or the adapter was already applied.
pub fn transform_smoke_source(
    package_manifest: &[u8],
    main_source: &[u8],
) -> Result<Vec<u8>, DiscordAdapterError> {
    if package_manifest.len() > MAX_PACKAGE_MANIFEST_BYTES {
        return Err(DiscordAdapterError::ManifestTooLarge);
    }
    if main_source.len() > MAX_MAIN_SOURCE_BYTES {
        return Err(DiscordAdapterError::SourceTooLarge);
    }
    let manifest: serde_json::Value =
        serde_json::from_slice(package_manifest).map_err(DiscordAdapterError::InvalidManifest)?;
    let supported_package = manifest.get("name").and_then(serde_json::Value::as_str)
        == Some("discord")
        && manifest.get("main").and_then(serde_json::Value::as_str) == Some(DISCORD_MAIN_ENTRY);
    if !supported_package || !main_source.starts_with(DISCORD_MAIN_PREFIX) {
        return Err(DiscordAdapterError::UnsupportedPackage);
    }
    if main_source
        .windows(SMOKE_ADAPTER_ID.len())
        .any(|window| window == SMOKE_ADAPTER_ID.as_bytes())
    {
        return Err(DiscordAdapterError::AlreadyTransformed);
    }
    let output_size = SMOKE_PREFIX
        .len()
        .checked_add(main_source.len())
        .ok_or(DiscordAdapterError::SourceTooLarge)?;
    if output_size > MAX_MAIN_SOURCE_BYTES {
        return Err(DiscordAdapterError::SourceTooLarge);
    }
    let mut transformed = Vec::with_capacity(output_size);
    transformed.extend_from_slice(SMOKE_PREFIX);
    transformed.extend_from_slice(main_source);
    Ok(transformed)
}

/// Closed errors produced by the Discord family adapter.
#[derive(Debug, Error)]
pub enum DiscordAdapterError {
    /// The package manifest exceeds the adapter's input ceiling.
    #[error("Discord package manifest exceeds the configured byte limit")]
    ManifestTooLarge,
    /// The package manifest is not valid JSON.
    #[error("Discord package manifest is invalid: {0}")]
    InvalidManifest(#[source] serde_json::Error),
    /// The package identity, main entry, or source bootstrap shape is not supported.
    #[error("Discord package is not supported by this adapter")]
    UnsupportedPackage,
    /// The main-process source exceeds the adapter's input or output ceiling.
    #[error("Discord main source exceeds the configured byte limit")]
    SourceTooLarge,
    /// The source already contains this adapter's identity.
    #[error("Discord main source is already transformed by this adapter")]
    AlreadyTransformed,
}
