//! Bounded `WebView2` preload-probe program construction.

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use weregopher_domain::Sha256Digest;

use crate::MAX_OPENAI_PRELOAD_SOURCE_BYTES;

#[cfg(windows)]
pub(crate) const PRELOAD_PROBE_WORLD_NAME: &str = "weregopher.g2.exact-preload";
pub(crate) const PRELOAD_PROBE_INDEX_HTML: &[u8] = include_bytes!("preload_probe/index.html");
pub(crate) const PRELOAD_PROBE_MAIN_SOURCE: &[u8] = include_bytes!("preload_probe/main.js");
pub(crate) const PRELOAD_PROBE_MAIN_BOOTSTRAP: &str =
    include_str!("preload_probe/main-bootstrap.js");

const PRELOAD_PROBE_PROFILE: &str = "weregopher.openai.preload.webview2.v1";
const PRELOAD_PROBE_ISOLATED_PREFIX: &str = include_str!("preload_probe/isolated-prefix.js");
const PRELOAD_PROBE_ISOLATED_SUFFIX: &str = include_str!("preload_probe/isolated-suffix.js");
const PRELOAD_FILENAME_TOKEN: &str = "__WEREGOPHER_PRELOAD_FILENAME__";
const PRELOAD_DIRECTORY_TOKEN: &str = "__WEREGOPHER_PRELOAD_DIRECTORY__";
const PRELOAD_SOURCE_START: &str = "/*__WEREGOPHER_EXACT_PRELOAD_SOURCE_START__*/\n";
const PRELOAD_SOURCE_END: &str = "\n/*__WEREGOPHER_EXACT_PRELOAD_SOURCE_END__*/";

/// Matches the renderer fixture's hard document-start registration ceiling.
pub(crate) const MAX_PRELOAD_PROBE_PROGRAM_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub(crate) enum PreloadProbeProgramError {
    #[error("exact preload source must not be empty")]
    EmptySource,
    #[error("exact preload source exceeds its byte limit")]
    SourceTooLarge,
    #[error("exact preload probe program exceeds its byte limit")]
    ProgramTooLarge,
}

pub(crate) fn assemble_isolated_world_program(
    source: &str,
    archive_path: &str,
) -> Result<String, PreloadProbeProgramError> {
    if source.is_empty() {
        return Err(PreloadProbeProgramError::EmptySource);
    }
    if source.len() > MAX_OPENAI_PRELOAD_SOURCE_BYTES {
        return Err(PreloadProbeProgramError::SourceTooLarge);
    }
    let filename = format!("app.asar/{archive_path}");
    let directory = archive_path
        .rsplit_once('/')
        .map_or("app.asar", |(directory, _)| directory);
    let filename_json =
        serde_json::to_string(&filename).map_err(|_| PreloadProbeProgramError::ProgramTooLarge)?;
    let directory_json =
        serde_json::to_string(directory).map_err(|_| PreloadProbeProgramError::ProgramTooLarge)?;
    let prefix = PRELOAD_PROBE_ISOLATED_PREFIX
        .replace(PRELOAD_FILENAME_TOKEN, &filename_json)
        .replace(PRELOAD_DIRECTORY_TOKEN, &directory_json);
    let capacity = prefix
        .len()
        .checked_add(source.len())
        .and_then(|length| length.checked_add(PRELOAD_PROBE_ISOLATED_SUFFIX.len()))
        .ok_or(PreloadProbeProgramError::ProgramTooLarge)?;
    if capacity > MAX_PRELOAD_PROBE_PROGRAM_BYTES {
        return Err(PreloadProbeProgramError::ProgramTooLarge);
    }
    let mut program = String::with_capacity(capacity);
    program.push_str(&prefix);
    program.push_str(source);
    program.push_str(PRELOAD_PROBE_ISOLATED_SUFFIX);
    Ok(program)
}

pub(crate) fn renderer_backend_digest() -> Sha256Digest {
    let mut hasher = Sha256::new();
    for asset in [
        PRELOAD_PROBE_PROFILE.as_bytes(),
        PRELOAD_PROBE_INDEX_HTML,
        PRELOAD_PROBE_MAIN_SOURCE,
        PRELOAD_PROBE_MAIN_BOOTSTRAP.as_bytes(),
        PRELOAD_PROBE_ISOLATED_PREFIX.as_bytes(),
        PRELOAD_PROBE_ISOLATED_SUFFIX.as_bytes(),
    ] {
        hasher.update(u64::try_from(asset.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(asset);
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_wraps_source_without_rewriting_it() -> Result<(), Box<dyn std::error::Error>> {
        let source = "const marker = `exact-${1 + 1}`;\n//# sourceMappingURL=preload.js.map";
        let program = assemble_isolated_world_program(source, "dist/preload.js")?;
        let source_start = program
            .find(PRELOAD_SOURCE_START)
            .ok_or("preload start marker is missing")?
            + PRELOAD_SOURCE_START.len();
        let source_end = program
            .find(PRELOAD_SOURCE_END)
            .ok_or("preload end marker is missing")?;

        assert_eq!(&program[source_start..source_end], source);
        assert!(program.len() <= MAX_PRELOAD_PROBE_PROGRAM_BYTES);
        Ok(())
    }

    #[test]
    fn backend_identity_is_deterministic_and_source_independent() {
        assert_eq!(renderer_backend_digest(), renderer_backend_digest());
        assert_ne!(renderer_backend_digest().as_bytes(), &[0_u8; 32]);
    }
}
