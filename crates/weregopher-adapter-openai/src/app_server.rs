//! Bounded, forward-compatible Codex app-server initialization probing.

use std::{
    collections::BTreeMap,
    io::{self, BufRead, Write},
};

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use weregopher_domain::Sha256Digest;

const INITIAL_MAX_LINE_BYTES: usize = 1024 * 1024;
const INITIAL_MAX_MESSAGES: usize = 64;
const ABSOLUTE_MAX_LINE_BYTES: usize = 16 * 1024 * 1024;
const ABSOLUTE_MAX_MESSAGES: usize = 1024;
const MAX_CLIENT_NAME_BYTES: usize = 64;
const MAX_CLIENT_TEXT_BYTES: usize = 128;
pub(crate) const MAX_SCHEMA_FILES: usize = 1_024;
pub(crate) const MAX_SCHEMA_FILE_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_SCHEMA_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_SCHEMA_PATH_BYTES: usize = 4_096;
const MAX_SCHEMA_PATH_COMPONENTS: usize = 256;
const PREINITIALIZE_REQUEST_ID: u64 = 1;
const INITIALIZE_REQUEST_ID: u64 = 2;
const SCHEMA_BUNDLE_DIGEST_DOMAIN: &[u8] = b"weregopher.app-server-schema-bundle.v1\0";
const JSON_SCHEMA_ROOT: &str = "json-schema";
const TYPESCRIPT_ROOT: &str = "typescript";

/// Resource ceilings for one app-server initialization probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppServerProtocolLimits {
    line_bytes: usize,
    messages: usize,
}

impl AppServerProtocolLimits {
    /// Constructs bounded JSONL and handshake-message limits.
    ///
    /// # Errors
    ///
    /// Returns [`AppServerProtocolError::InvalidLimits`] for zero, unusably
    /// small, or absolute-ceiling-exceeding limits.
    pub const fn new(
        max_line_bytes: usize,
        max_messages: usize,
    ) -> Result<Self, AppServerProtocolError> {
        if max_line_bytes < 64
            || max_line_bytes > ABSOLUTE_MAX_LINE_BYTES
            || max_messages < 2
            || max_messages > ABSOLUTE_MAX_MESSAGES
        {
            return Err(AppServerProtocolError::InvalidLimits);
        }
        Ok(Self {
            line_bytes: max_line_bytes,
            messages: max_messages,
        })
    }

    /// Returns the initial conservative handshake limits.
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            line_bytes: INITIAL_MAX_LINE_BYTES,
            messages: INITIAL_MAX_MESSAGES,
        }
    }

    /// Returns the maximum JSON bytes accepted in one line.
    #[must_use]
    pub const fn max_line_bytes(self) -> usize {
        self.line_bytes
    }

    /// Returns the maximum server messages observed before initialization.
    #[must_use]
    pub const fn max_messages(self) -> usize {
        self.messages
    }
}

/// Bounded identity sent in the app-server `initialize` request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppServerClientInfo {
    name: String,
    title: String,
    version: String,
}

impl AppServerClientInfo {
    /// Validates a stable client name plus bounded display/version text.
    ///
    /// # Errors
    ///
    /// Returns [`AppServerProtocolError::InvalidClientInfo`] for empty,
    /// oversized, control-character-bearing, or noncanonical names.
    pub fn new(
        name: impl Into<String>,
        title: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self, AppServerProtocolError> {
        let name = name.into();
        let title = title.into();
        let version = version.into();
        if name.is_empty()
            || name.len() > MAX_CLIENT_NAME_BYTES
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            || !valid_client_text(&title)
            || !valid_client_text(&version)
        {
            return Err(AppServerProtocolError::InvalidClientInfo);
        }
        Ok(Self {
            name,
            title,
            version,
        })
    }
}

fn valid_client_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CLIENT_TEXT_BYTES
        && !value.chars().any(char::is_control)
}

/// Immutable observations produced by the bounded initialization exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppServerHandshakeEvidence {
    initialize_response_digest: Sha256Digest,
    preinitialize_rejected: bool,
    initialize_succeeded: bool,
    initialized_sent: bool,
    observed_server_messages: usize,
}

impl AppServerHandshakeEvidence {
    /// Returns the canonical digest of the unknown-field-preserving initialize response.
    #[must_use]
    pub const fn initialize_response_digest(&self) -> &Sha256Digest {
        &self.initialize_response_digest
    }

    /// Reports whether the server rejected a request before initialization.
    #[must_use]
    pub const fn preinitialize_rejected(&self) -> bool {
        self.preinitialize_rejected
    }

    /// Reports whether the initialize request returned a result.
    #[must_use]
    pub const fn initialize_succeeded(&self) -> bool {
        self.initialize_succeeded
    }

    /// Reports whether the required initialized notification was written.
    #[must_use]
    pub const fn initialized_sent(&self) -> bool {
        self.initialized_sent
    }

    /// Returns the number of bounded server messages observed.
    #[must_use]
    pub const fn observed_server_messages(&self) -> usize {
        self.observed_server_messages
    }
}

/// Content-only identity for both exact app-server schema generator outputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppServerSchemaBundleEvidence {
    digest: Sha256Digest,
    file_count: usize,
    total_bytes: usize,
}

impl AppServerSchemaBundleEvidence {
    /// Returns the deterministic digest of paths, sizes, and file bytes.
    #[must_use]
    pub const fn digest(&self) -> &Sha256Digest {
        &self.digest
    }

    /// Returns the number of bounded generated files in both output trees.
    #[must_use]
    pub const fn file_count(&self) -> usize {
        self.file_count
    }

    /// Returns the aggregate generated content size.
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }
}

/// Exact app-server schema bundle collection or hashing failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AppServerSchemaError {
    /// A generated path was empty, absolute, ambiguous, or exceeded its bounds.
    #[error("app-server generated schema path is invalid")]
    InvalidRelativePath,
    /// A generated output path appeared more than once.
    #[error("app-server generated schema contains a duplicate path")]
    DuplicatePath,
    /// A generated file was empty or exceeded the per-file ceiling.
    #[error("app-server generated schema file has an invalid size")]
    InvalidFileSize,
    /// The schema generators produced too many files.
    #[error("app-server generated schema exceeds its file-count limit")]
    TooManyFiles,
    /// The schema generators produced too many aggregate bytes.
    #[error("app-server generated schema exceeds its aggregate byte limit")]
    AggregateTooLarge,
    /// One required exact-binary generator output was absent.
    #[error("app-server generated schema is missing the {output} output")]
    MissingGeneratorOutput {
        /// Required output-root name.
        output: &'static str,
    },
}

/// Hashes the bounded output of both exact-binary app-server schema generators.
///
/// Input paths are canonical forward-slash paths rooted below
/// `json-schema/` or `typescript/`. Ordering is normalized before a
/// domain-separated digest binds each path, content length, and content digest.
/// Raw generated schema bytes are not retained in the returned evidence.
///
/// # Errors
///
/// Returns [`AppServerSchemaError`] for missing generator roots, malformed or
/// duplicate paths, empty/oversized files, excessive file counts, or excessive
/// aggregate bytes.
pub fn hash_app_server_schema_bundle(
    files: impl IntoIterator<Item = (String, Vec<u8>)>,
) -> Result<AppServerSchemaBundleEvidence, AppServerSchemaError> {
    let mut collected = BTreeMap::new();
    let mut total_bytes = 0_usize;
    let mut has_json_schema = false;
    let mut has_typescript = false;
    for (path, bytes) in files {
        let root = validate_schema_path(&path)?;
        let is_json_schema = root == JSON_SCHEMA_ROOT;
        let is_typescript = root == TYPESCRIPT_ROOT;
        if bytes.is_empty() || bytes.len() > MAX_SCHEMA_FILE_BYTES {
            return Err(AppServerSchemaError::InvalidFileSize);
        }
        if collected.len() == MAX_SCHEMA_FILES {
            return Err(AppServerSchemaError::TooManyFiles);
        }
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or(AppServerSchemaError::AggregateTooLarge)?;
        if total_bytes > MAX_SCHEMA_TOTAL_BYTES {
            return Err(AppServerSchemaError::AggregateTooLarge);
        }
        if collected.insert(path, bytes).is_some() {
            return Err(AppServerSchemaError::DuplicatePath);
        }
        has_json_schema |= is_json_schema;
        has_typescript |= is_typescript;
    }
    if !has_json_schema {
        return Err(AppServerSchemaError::MissingGeneratorOutput {
            output: JSON_SCHEMA_ROOT,
        });
    }
    if !has_typescript {
        return Err(AppServerSchemaError::MissingGeneratorOutput {
            output: TYPESCRIPT_ROOT,
        });
    }

    let mut hasher = Sha256::new();
    hasher.update(SCHEMA_BUNDLE_DIGEST_DOMAIN);
    for (path, bytes) in &collected {
        let path_length =
            u64::try_from(path.len()).map_err(|_| AppServerSchemaError::InvalidRelativePath)?;
        let byte_length =
            u64::try_from(bytes.len()).map_err(|_| AppServerSchemaError::InvalidFileSize)?;
        hasher.update(path_length.to_be_bytes());
        hasher.update(path.as_bytes());
        hasher.update(byte_length.to_be_bytes());
        hasher.update(Sha256::digest(bytes));
    }
    Ok(AppServerSchemaBundleEvidence {
        digest: Sha256Digest::from_bytes(hasher.finalize().into()),
        file_count: collected.len(),
        total_bytes,
    })
}

fn validate_schema_path(path: &str) -> Result<&str, AppServerSchemaError> {
    if path.is_empty()
        || path.len() > MAX_SCHEMA_PATH_BYTES
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.chars().any(char::is_control)
    {
        return Err(AppServerSchemaError::InvalidRelativePath);
    }
    let mut components = path.split('/');
    let root = components
        .next()
        .ok_or(AppServerSchemaError::InvalidRelativePath)?;
    if !matches!(root, JSON_SCHEMA_ROOT | TYPESCRIPT_ROOT) {
        return Err(AppServerSchemaError::InvalidRelativePath);
    }
    let mut component_count = 1_usize;
    let mut has_file_name = false;
    for component in components {
        component_count = component_count
            .checked_add(1)
            .ok_or(AppServerSchemaError::InvalidRelativePath)?;
        if component_count > MAX_SCHEMA_PATH_COMPONENTS
            || component.is_empty()
            || matches!(component, "." | "..")
        {
            return Err(AppServerSchemaError::InvalidRelativePath);
        }
        has_file_name = true;
    }
    if !has_file_name {
        return Err(AppServerSchemaError::InvalidRelativePath);
    }
    Ok(root)
}

/// App-server JSONL framing or initialization protocol failure.
#[derive(Debug, Error)]
pub enum AppServerProtocolError {
    /// Caller-selected limits are zero, unusably small, or exceed hard ceilings.
    #[error("invalid app-server probe limits")]
    InvalidLimits,
    /// Client identity text is invalid.
    #[error("invalid app-server client information")]
    InvalidClientInfo,
    /// Transport input/output failed.
    #[error("app-server standard-I/O transport failed: {0}")]
    Io(#[from] io::Error),
    /// One inbound JSONL message exceeded the configured byte ceiling.
    #[error("app-server inbound JSONL line exceeds its byte limit")]
    InboundLineTooLarge,
    /// One outbound JSONL message exceeded the configured byte ceiling.
    #[error("app-server outbound JSONL line exceeds its byte limit")]
    OutboundLineTooLarge,
    /// The server stream ended before the expected response.
    #[error("app-server closed output before completing initialization")]
    UnexpectedEof,
    /// The server emitted an empty JSONL record.
    #[error("app-server emitted an empty JSONL record")]
    EmptyLine,
    /// A server line was not valid JSON.
    #[error("app-server emitted invalid JSON: {0}")]
    InvalidJson(#[source] serde_json::Error),
    /// More server messages were observed than the handshake budget permits.
    #[error("app-server initialization exceeded its message limit")]
    MessageLimitExceeded,
    /// A matching response contained both/neither result and error.
    #[error("app-server emitted an invalid response shape")]
    InvalidResponseShape,
    /// The server accepted a request before initialization.
    #[error("app-server accepted a request before initialize")]
    PreinitializeRequestAccepted,
    /// The initialize request returned a protocol error.
    #[error("app-server rejected initialize")]
    InitializeRejected,
    /// Canonical response serialization failed.
    #[error("failed to serialize app-server response evidence: {0}")]
    SerializeEvidence(#[source] serde_json::Error),
}

/// Probes the documented app-server initialization state machine over bounded
/// newline-delimited JSON.
///
/// The exchange first confirms that an ordinary request is rejected before
/// initialization, then sends one `initialize` request and the required
/// `initialized` notification. Unknown notifications and response fields are
/// retained/ignored without schema rejection. Process ownership, timeouts,
/// schema generation, disposable state, and clean shutdown remain the caller's
/// responsibility.
///
/// # Errors
///
/// Returns [`AppServerProtocolError`] for transport, framing, bounds, JSON, or
/// handshake-state violations.
pub fn probe_app_server_handshake<R, W>(
    reader: &mut R,
    writer: &mut W,
    client: &AppServerClientInfo,
    limits: AppServerProtocolLimits,
) -> Result<AppServerHandshakeEvidence, AppServerProtocolError>
where
    R: BufRead,
    W: Write,
{
    write_message(
        writer,
        &json!({
            "id": PREINITIALIZE_REQUEST_ID,
            "method": "thread/list",
            "params": {}
        }),
        limits,
    )?;
    let mut observed = 0_usize;
    let preinitialize = wait_for_response(reader, PREINITIALIZE_REQUEST_ID, limits, &mut observed)?;
    if preinitialize.get("result").is_some() {
        return Err(AppServerProtocolError::PreinitializeRequestAccepted);
    }
    if !preinitialize.get("error").is_some_and(Value::is_object) {
        return Err(AppServerProtocolError::InvalidResponseShape);
    }

    write_message(
        writer,
        &json!({
            "id": INITIALIZE_REQUEST_ID,
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": client.name,
                    "title": client.title,
                    "version": client.version,
                }
            }
        }),
        limits,
    )?;
    let initialize = wait_for_response(reader, INITIALIZE_REQUEST_ID, limits, &mut observed)?;
    if initialize.get("error").is_some() {
        return Err(AppServerProtocolError::InitializeRejected);
    }
    if !initialize.get("result").is_some_and(Value::is_object) {
        return Err(AppServerProtocolError::InvalidResponseShape);
    }
    let initialize_response_digest = canonical_digest(&initialize)?;

    write_message(
        writer,
        &json!({"method": "initialized", "params": {}}),
        limits,
    )?;
    writer.flush()?;
    Ok(AppServerHandshakeEvidence {
        initialize_response_digest,
        preinitialize_rejected: true,
        initialize_succeeded: true,
        initialized_sent: true,
        observed_server_messages: observed,
    })
}

fn wait_for_response<R: BufRead>(
    reader: &mut R,
    request_id: u64,
    limits: AppServerProtocolLimits,
    observed: &mut usize,
) -> Result<Value, AppServerProtocolError> {
    loop {
        if *observed == limits.messages {
            return Err(AppServerProtocolError::MessageLimitExceeded);
        }
        let line = read_bounded_line(reader, limits.line_bytes)?;
        *observed += 1;
        let message: Value =
            serde_json::from_slice(&line).map_err(AppServerProtocolError::InvalidJson)?;
        if message.get("id").and_then(Value::as_u64) != Some(request_id) {
            continue;
        }
        let has_result = message.get("result").is_some();
        let has_error = message.get("error").is_some();
        if has_result == has_error {
            return Err(AppServerProtocolError::InvalidResponseShape);
        }
        return Ok(message);
    }
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    limit: usize,
) -> Result<Vec<u8>, AppServerProtocolError> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Err(AppServerProtocolError::UnexpectedEof);
        }
        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            extend_bounded(&mut line, &available[..newline], limit)?;
            reader.consume(newline + 1);
            break;
        }
        let consumed = available.len();
        extend_bounded(&mut line, available, limit)?;
        reader.consume(consumed);
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    if line.is_empty() {
        return Err(AppServerProtocolError::EmptyLine);
    }
    Ok(line)
}

fn extend_bounded(
    destination: &mut Vec<u8>,
    source: &[u8],
    limit: usize,
) -> Result<(), AppServerProtocolError> {
    let length = destination
        .len()
        .checked_add(source.len())
        .ok_or(AppServerProtocolError::InboundLineTooLarge)?;
    if length > limit {
        return Err(AppServerProtocolError::InboundLineTooLarge);
    }
    destination.extend_from_slice(source);
    Ok(())
}

fn write_message<W: Write>(
    writer: &mut W,
    message: &Value,
    limits: AppServerProtocolLimits,
) -> Result<(), AppServerProtocolError> {
    let bytes = serde_json::to_vec(message).map_err(AppServerProtocolError::SerializeEvidence)?;
    if bytes.len() > limits.line_bytes {
        return Err(AppServerProtocolError::OutboundLineTooLarge);
    }
    writer.write_all(&bytes)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<Sha256Digest, AppServerProtocolError> {
    let bytes = serde_json::to_vec(value).map_err(AppServerProtocolError::SerializeEvidence)?;
    Ok(Sha256Digest::from_bytes(Sha256::digest(bytes).into()))
}
