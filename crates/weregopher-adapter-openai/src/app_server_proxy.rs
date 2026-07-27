//! Bounded, payload-preserving Codex app-server proxy core.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
    time::{Duration, Instant},
};

use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const ABSOLUTE_MAX_LINE_BYTES: usize = 16 * 1024 * 1024;
const ABSOLUTE_MAX_QUEUE_MESSAGES: usize = 4_096;
const ABSOLUTE_MAX_QUEUE_BYTES: usize = 64 * 1024 * 1024;
const ABSOLUTE_MAX_JSON_DEPTH: usize = 128;
const ABSOLUTE_MAX_JSON_NODES: usize = 1_048_576;
const ABSOLUTE_MAX_ACTIVE_REQUESTS: usize = 4_096;
const ABSOLUTE_MAX_REQUEST_HISTORY: usize = 1_048_576;
const ABSOLUTE_MAX_REQUEST_TIMEOUT: Duration = Duration::from_hours(24);
const MAX_METHOD_BYTES: usize = 1_024;
const MAX_REQUEST_ID_BYTES: usize = 256;
const REQUEST_ID_DIGEST_DOMAIN: &[u8] = b"weregopher.app-server-request-id.v1\0";

/// Direction in which one app-server protocol message travels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AppServerProxyDirection {
    /// A packaged client message traveling toward the app-server.
    ClientToServer,
    /// An app-server message traveling toward the packaged client.
    ServerToClient,
}

impl AppServerProxyDirection {
    const fn opposite(self) -> Self {
        match self {
            Self::ClientToServer => Self::ServerToClient,
            Self::ServerToClient => Self::ClientToServer,
        }
    }
}

/// Structural class of one accepted app-server message.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AppServerProxyMessageKind {
    /// A method-bearing message with a request identity.
    Request,
    /// A method-bearing message without a request identity.
    Notification,
    /// A request-correlated message containing a result.
    SuccessResponse,
    /// A request-correlated message containing an error.
    ErrorResponse,
}

/// Bounded app-server request identity used only for correlation.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AppServerRequestId {
    /// Nonnegative integer identity.
    Unsigned(u64),
    /// Negative integer identity.
    Signed(i64),
    /// Nonempty bounded string identity.
    Text(String),
}

impl fmt::Debug for AppServerRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsigned(_) => formatter.write_str("Unsigned(<redacted>)"),
            Self::Signed(_) => formatter.write_str("Signed(<redacted>)"),
            Self::Text(value) => formatter
                .debug_struct("Text")
                .field("byte_length", &value.len())
                .finish_non_exhaustive(),
        }
    }
}

/// Per-direction message and byte ceilings for one in-memory proxy queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppServerQueueLimits {
    messages: usize,
    bytes: usize,
}

impl AppServerQueueLimits {
    /// Constructs nonzero queue ceilings below the hard proxy maximums.
    ///
    /// # Errors
    ///
    /// Returns [`AppServerProxyError::InvalidQueueLimits`] when either
    /// dimension is zero or exceeds its absolute ceiling.
    pub const fn new(messages: usize, bytes: usize) -> Result<Self, AppServerProxyError> {
        if messages == 0
            || messages > ABSOLUTE_MAX_QUEUE_MESSAGES
            || bytes == 0
            || bytes > ABSOLUTE_MAX_QUEUE_BYTES
        {
            return Err(AppServerProxyError::InvalidQueueLimits);
        }
        Ok(Self { messages, bytes })
    }

    /// Returns the maximum queued message count.
    #[must_use]
    pub const fn max_messages(self) -> usize {
        self.messages
    }

    /// Returns the maximum aggregate queued JSON bytes.
    #[must_use]
    pub const fn max_bytes(self) -> usize {
        self.bytes
    }
}

/// Recursive JSON structure ceilings used before protocol metadata is interpreted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppServerJsonLimits {
    depth: usize,
    nodes: usize,
}

impl AppServerJsonLimits {
    /// Constructs nonzero JSON depth and value-node ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`AppServerProxyError::InvalidJsonLimits`] when either
    /// dimension is zero or exceeds its absolute ceiling.
    pub const fn new(depth: usize, nodes: usize) -> Result<Self, AppServerProxyError> {
        if depth == 0
            || depth > ABSOLUTE_MAX_JSON_DEPTH
            || nodes == 0
            || nodes > ABSOLUTE_MAX_JSON_NODES
        {
            return Err(AppServerProxyError::InvalidJsonLimits);
        }
        Ok(Self { depth, nodes })
    }

    /// Returns the maximum recursive JSON value depth.
    #[must_use]
    pub const fn max_depth(self) -> usize {
        self.depth
    }

    /// Returns the maximum recursive JSON value count.
    #[must_use]
    pub const fn max_nodes(self) -> usize {
        self.nodes
    }
}

/// Complete resource policy for one transparent proxy session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppServerProxyLimits {
    line_bytes: usize,
    to_server: AppServerQueueLimits,
    to_client: AppServerQueueLimits,
    json: AppServerJsonLimits,
    active_requests: usize,
    request_history: usize,
    request_timeout: Duration,
}

impl AppServerProxyLimits {
    /// Constructs a bounded proxy policy.
    ///
    /// # Errors
    ///
    /// Returns an explicit limit error for a zero, incoherent, or absolute-
    /// ceiling-exceeding line, active-request count, history, or timeout.
    pub fn new(
        line_bytes: usize,
        to_server: AppServerQueueLimits,
        to_client: AppServerQueueLimits,
        json: AppServerJsonLimits,
        active_requests: usize,
        request_history: usize,
        request_timeout: Duration,
    ) -> Result<Self, AppServerProxyError> {
        if line_bytes == 0 || line_bytes > ABSOLUTE_MAX_LINE_BYTES {
            return Err(AppServerProxyError::InvalidLineLimit);
        }
        if active_requests == 0 || active_requests > ABSOLUTE_MAX_ACTIVE_REQUESTS {
            return Err(AppServerProxyError::InvalidActiveRequestLimit);
        }
        if request_history < active_requests || request_history > ABSOLUTE_MAX_REQUEST_HISTORY {
            return Err(AppServerProxyError::InvalidRequestHistoryLimit);
        }
        if request_timeout.is_zero() || request_timeout > ABSOLUTE_MAX_REQUEST_TIMEOUT {
            return Err(AppServerProxyError::InvalidRequestTimeout);
        }
        Ok(Self {
            line_bytes,
            to_server,
            to_client,
            json,
            active_requests,
            request_history,
            request_timeout,
        })
    }

    /// Returns the initial conservative proxy policy.
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            line_bytes: 1024 * 1024,
            to_server: AppServerQueueLimits {
                messages: 256,
                bytes: 8 * 1024 * 1024,
            },
            to_client: AppServerQueueLimits {
                messages: 256,
                bytes: 8 * 1024 * 1024,
            },
            json: AppServerJsonLimits {
                depth: 64,
                nodes: 65_536,
            },
            active_requests: 1_024,
            request_history: 65_536,
            request_timeout: Duration::from_mins(5),
        }
    }

    /// Returns the accepted byte ceiling for one delimiter-free JSON line.
    #[must_use]
    pub const fn max_line_bytes(self) -> usize {
        self.line_bytes
    }

    /// Returns the client-to-server queue limits.
    #[must_use]
    pub const fn to_server_queue(self) -> AppServerQueueLimits {
        self.to_server
    }

    /// Returns the server-to-client queue limits.
    #[must_use]
    pub const fn to_client_queue(self) -> AppServerQueueLimits {
        self.to_client
    }

    /// Returns the JSON structure limits.
    #[must_use]
    pub const fn json(self) -> AppServerJsonLimits {
        self.json
    }

    /// Returns the maximum unresolved requests across both directions.
    #[must_use]
    pub const fn max_active_requests(self) -> usize {
        self.active_requests
    }

    /// Returns the maximum total request identities accepted per session.
    #[must_use]
    pub const fn max_request_history(self) -> usize {
        self.request_history
    }

    /// Returns the timeout applied when a request leaves its queue.
    #[must_use]
    pub const fn request_timeout(self) -> Duration {
        self.request_timeout
    }
}

/// Immutable metadata observed without retaining a parsed message body.
#[derive(Clone, Eq, PartialEq)]
pub struct AppServerMessageObservation {
    direction: AppServerProxyDirection,
    kind: AppServerProxyMessageKind,
    method: Option<String>,
    request_id: Option<AppServerRequestId>,
    byte_length: usize,
}

impl fmt::Debug for AppServerMessageObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppServerMessageObservation")
            .field("direction", &self.direction)
            .field("kind", &self.kind)
            .field("method_byte_length", &self.method.as_ref().map(String::len))
            .field("has_request_id", &self.request_id.is_some())
            .field("byte_length", &self.byte_length)
            .finish()
    }
}

impl AppServerMessageObservation {
    /// Returns the message travel direction.
    #[must_use]
    pub const fn direction(&self) -> AppServerProxyDirection {
        self.direction
    }

    /// Returns the structural protocol-message class.
    #[must_use]
    pub const fn kind(&self) -> AppServerProxyMessageKind {
        self.kind
    }

    /// Returns the bounded method name for a request or notification.
    #[must_use]
    pub fn method(&self) -> Option<&str> {
        self.method.as_deref()
    }

    /// Returns the bounded correlation identity when one was present.
    #[must_use]
    pub const fn request_id(&self) -> Option<&AppServerRequestId> {
        self.request_id.as_ref()
    }

    /// Returns the exact delimiter-free JSON byte length.
    #[must_use]
    pub const fn byte_length(&self) -> usize {
        self.byte_length
    }
}

/// One validated proxy frame retaining exact delimiter-free JSON bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct AppServerProxyFrame {
    observation: AppServerMessageObservation,
    json_bytes: Vec<u8>,
}

impl fmt::Debug for AppServerProxyFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppServerProxyFrame")
            .field("observation", &self.observation)
            .field("payload", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl AppServerProxyFrame {
    /// Returns message metadata observed by the proxy.
    #[must_use]
    pub const fn observation(&self) -> &AppServerMessageObservation {
        &self.observation
    }

    /// Returns the exact validated JSON bytes, excluding the JSONL delimiter.
    ///
    /// The transport layer is responsible for appending one newline.
    #[must_use]
    pub fn json_bytes(&self) -> &[u8] {
        &self.json_bytes
    }
}

/// One structurally validated exact frame awaiting dynamic proxy admission.
///
/// Preparation parses and bounds the message but does not mutate queue,
/// correlation, deadline, or diagnostic state. The candidate is not an
/// authorization or interception decision. Admission rechecks all dynamic
/// session state before the exact retained bytes can enter a queue.
pub struct AppServerProxyCandidate {
    prepared_limits: AppServerProxyLimits,
    observation: AppServerMessageObservation,
    json_bytes: Vec<u8>,
}

impl fmt::Debug for AppServerProxyCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppServerProxyCandidate")
            .field("observation", &self.observation)
            .field("payload", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl AppServerProxyCandidate {
    /// Returns the bounded structural metadata available before admission.
    #[must_use]
    pub const fn observation(&self) -> &AppServerMessageObservation {
        &self.observation
    }

    /// Returns the exact validated delimiter-free JSON bytes.
    ///
    /// Access does not admit the candidate or grant authority. Callers that
    /// persist these bytes remain responsible for an explicit redaction policy.
    #[must_use]
    pub fn json_bytes(&self) -> &[u8] {
        &self.json_bytes
    }
}

/// An unresolved request removed at or after its forwarding deadline.
#[derive(Clone, Eq, PartialEq)]
pub struct AppServerExpiredRequest {
    origin: AppServerProxyDirection,
    request_id: AppServerRequestId,
}

impl fmt::Debug for AppServerExpiredRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppServerExpiredRequest")
            .field("origin", &self.origin)
            .field("request_id", &self.request_id)
            .finish()
    }
}

impl AppServerExpiredRequest {
    /// Returns the direction in which the request originated.
    #[must_use]
    pub const fn origin(&self) -> AppServerProxyDirection {
        self.origin
    }

    /// Returns the expired correlation identity.
    #[must_use]
    pub const fn request_id(&self) -> &AppServerRequestId {
        &self.request_id
    }
}

/// Lifecycle state of one in-memory proxy session.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AppServerProxyState {
    /// The proxy accepts and forwards bounded messages.
    Open,
    /// All queued frames and unresolved requests were explicitly abandoned.
    Closed,
}

/// Payload-free snapshot of bounded proxy state and counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppServerProxyDiagnostics {
    state: AppServerProxyState,
    accepted_client_messages: u64,
    accepted_server_messages: u64,
    accepted_client_bytes: u64,
    accepted_server_bytes: u64,
    forwarded_to_server_messages: u64,
    forwarded_to_client_messages: u64,
    queued_to_server_messages: usize,
    queued_to_client_messages: usize,
    queued_to_server_bytes: usize,
    queued_to_client_bytes: usize,
    peak_to_server_messages: usize,
    peak_to_client_messages: usize,
    peak_to_server_bytes: usize,
    peak_to_client_bytes: usize,
    pending_client_requests: usize,
    pending_server_requests: usize,
    client_request_history: usize,
    server_request_history: usize,
    late_responses: u64,
    unmatched_responses: u64,
    expired_requests: u64,
}

impl AppServerProxyDiagnostics {
    /// Returns the proxy lifecycle state.
    #[must_use]
    pub const fn state(self) -> AppServerProxyState {
        self.state
    }

    /// Returns successfully accepted client-message count.
    #[must_use]
    pub const fn accepted_client_messages(self) -> u64 {
        self.accepted_client_messages
    }

    /// Returns successfully accepted server-message count.
    #[must_use]
    pub const fn accepted_server_messages(self) -> u64 {
        self.accepted_server_messages
    }

    /// Returns successfully accepted client payload bytes.
    #[must_use]
    pub const fn accepted_client_bytes(self) -> u64 {
        self.accepted_client_bytes
    }

    /// Returns successfully accepted server payload bytes.
    #[must_use]
    pub const fn accepted_server_bytes(self) -> u64 {
        self.accepted_server_bytes
    }

    /// Returns frames released toward the app-server.
    #[must_use]
    pub const fn forwarded_to_server_messages(self) -> u64 {
        self.forwarded_to_server_messages
    }

    /// Returns frames released toward the client.
    #[must_use]
    pub const fn forwarded_to_client_messages(self) -> u64 {
        self.forwarded_to_client_messages
    }

    /// Returns current client-to-server queued message count.
    #[must_use]
    pub const fn queued_to_server_messages(self) -> usize {
        self.queued_to_server_messages
    }

    /// Returns current server-to-client queued message count.
    #[must_use]
    pub const fn queued_to_client_messages(self) -> usize {
        self.queued_to_client_messages
    }

    /// Returns current client-to-server queued bytes.
    #[must_use]
    pub const fn queued_to_server_bytes(self) -> usize {
        self.queued_to_server_bytes
    }

    /// Returns current server-to-client queued bytes.
    #[must_use]
    pub const fn queued_to_client_bytes(self) -> usize {
        self.queued_to_client_bytes
    }

    /// Returns peak client-to-server queued message count.
    #[must_use]
    pub const fn peak_to_server_messages(self) -> usize {
        self.peak_to_server_messages
    }

    /// Returns peak server-to-client queued message count.
    #[must_use]
    pub const fn peak_to_client_messages(self) -> usize {
        self.peak_to_client_messages
    }

    /// Returns peak client-to-server queued bytes.
    #[must_use]
    pub const fn peak_to_server_bytes(self) -> usize {
        self.peak_to_server_bytes
    }

    /// Returns peak server-to-client queued bytes.
    #[must_use]
    pub const fn peak_to_client_bytes(self) -> usize {
        self.peak_to_client_bytes
    }

    /// Returns forwarded client requests awaiting server responses.
    #[must_use]
    pub const fn pending_client_requests(self) -> usize {
        self.pending_client_requests
    }

    /// Returns forwarded server requests awaiting client responses.
    #[must_use]
    pub const fn pending_server_requests(self) -> usize {
        self.pending_server_requests
    }

    /// Returns completed or expired client identities retained as digests.
    #[must_use]
    pub const fn client_request_history(self) -> usize {
        self.client_request_history
    }

    /// Returns completed or expired server identities retained as digests.
    #[must_use]
    pub const fn server_request_history(self) -> usize {
        self.server_request_history
    }

    /// Returns responses matching a completed or expired request identity.
    #[must_use]
    pub const fn late_responses(self) -> u64 {
        self.late_responses
    }

    /// Returns responses that did not match a live forwarded request.
    #[must_use]
    pub const fn unmatched_responses(self) -> u64 {
        self.unmatched_responses
    }

    /// Returns forwarded requests removed by deadline expiry.
    #[must_use]
    pub const fn expired_requests(self) -> u64 {
        self.expired_requests
    }
}

/// Explicit accounting for state abandoned by proxy closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppServerProxyCloseReport {
    messages: usize,
    bytes: usize,
    requests: usize,
    request_history: usize,
}

impl AppServerProxyCloseReport {
    /// Returns the number of queued frames discarded by closure.
    #[must_use]
    pub const fn abandoned_messages(self) -> usize {
        self.messages
    }

    /// Returns the number of queued JSON bytes discarded by closure.
    #[must_use]
    pub const fn abandoned_bytes(self) -> usize {
        self.bytes
    }

    /// Returns the number of queued or pending requests invalidated by closure.
    #[must_use]
    pub const fn abandoned_requests(self) -> usize {
        self.requests
    }

    /// Returns completed/expired request digests cleared by closure.
    #[must_use]
    pub const fn cleared_request_history(self) -> usize {
        self.request_history
    }
}

/// Bounded proxy input, correlation, queue, or lifecycle failure.
#[derive(Debug, Error)]
pub enum AppServerProxyError {
    /// A queue limit was zero or exceeded an absolute maximum.
    #[error("invalid app-server proxy queue limits")]
    InvalidQueueLimits,
    /// The line ceiling was zero or exceeded its absolute maximum.
    #[error("invalid app-server proxy line limit")]
    InvalidLineLimit,
    /// A JSON structure limit was zero or exceeded an absolute maximum.
    #[error("invalid app-server proxy JSON limits")]
    InvalidJsonLimits,
    /// The active-request ceiling was zero or exceeded its absolute maximum.
    #[error("invalid app-server proxy active-request limit")]
    InvalidActiveRequestLimit,
    /// Request history was smaller than active capacity or exceeded its hard maximum.
    #[error("invalid app-server proxy request-history limit")]
    InvalidRequestHistoryLimit,
    /// The request timeout was zero or exceeded its absolute maximum.
    #[error("invalid app-server proxy request timeout")]
    InvalidRequestTimeout,
    /// The session was already closed.
    #[error("app-server proxy is closed")]
    Closed,
    /// A prepared frame came from a proxy with different structural limits.
    #[error("app-server proxy candidate limits do not match this session")]
    CandidateLimitsMismatch,
    /// The supplied delimiter-free line was empty or all whitespace.
    #[error("app-server proxy received an empty JSON line")]
    EmptyLine,
    /// The supplied line contained a JSONL delimiter.
    #[error("app-server proxy line contains an embedded line break")]
    EmbeddedLineBreak,
    /// One JSON line exceeded its configured byte ceiling.
    #[error("app-server proxy JSON line exceeds its byte limit")]
    LineTooLarge,
    /// A JSON line was malformed.
    #[error("app-server proxy received invalid JSON: {0}")]
    InvalidJson(#[source] serde_json::Error),
    /// The JSON line was not an object.
    #[error("app-server proxy message must be a JSON object")]
    TopLevelNotObject,
    /// An object contained a duplicate key and was ambiguous to interpret.
    #[error("app-server proxy JSON contains a duplicate object key")]
    DuplicateObjectKey,
    /// Recursive JSON depth exceeded the configured ceiling.
    #[error("app-server proxy JSON exceeds its depth limit")]
    JsonDepthLimitExceeded,
    /// Recursive JSON value count exceeded the configured ceiling.
    #[error("app-server proxy JSON exceeds its node limit")]
    JsonNodeLimitExceeded,
    /// A method was empty, oversized, non-string, or contained control text.
    #[error("app-server proxy method is invalid")]
    InvalidMethod,
    /// A request identity was empty, oversized, fractional, or otherwise unsupported.
    #[error("app-server proxy request identity is invalid")]
    InvalidRequestId,
    /// Method/result/error/id fields formed an ambiguous protocol message.
    #[error("app-server proxy message shape is ambiguous")]
    AmbiguousMessageShape,
    /// The destination queue reached its message-count ceiling.
    #[error("app-server proxy {direction:?} queue reached its message limit")]
    QueueMessageLimitExceeded {
        /// Direction of the full destination queue.
        direction: AppServerProxyDirection,
    },
    /// The destination queue reached its aggregate-byte ceiling.
    #[error("app-server proxy {direction:?} queue reached its byte limit")]
    QueueByteLimitExceeded {
        /// Direction of the full destination queue.
        direction: AppServerProxyDirection,
    },
    /// An origin reused an unresolved request identity.
    #[error("app-server proxy {direction:?} request identity is already active")]
    DuplicateRequestId {
        /// Direction in which the duplicate request originated.
        direction: AppServerProxyDirection,
    },
    /// An origin attempted to reuse an identity already retired in this session.
    #[error("app-server proxy {direction:?} request identity was already used")]
    ReusedRequestId {
        /// Direction in which the reused request originated.
        direction: AppServerProxyDirection,
    },
    /// Both origin directions together reached the active-request ceiling.
    #[error("app-server proxy reached its active-request limit")]
    ActiveRequestLimitExceeded,
    /// The session reached its bounded request-identity history.
    #[error("app-server proxy reached its request-history limit")]
    RequestHistoryLimitExceeded,
    /// A peer produced a response before the corresponding queued request was released.
    #[error("app-server proxy observed a response before its request was forwarded")]
    ResponseBeforeRequestForwarded,
    /// The request deadline could not be represented by the monotonic clock.
    #[error("app-server proxy request deadline overflowed")]
    DeadlineOverflow,
    /// A caller supplied a clock value earlier than one already observed.
    #[error("app-server proxy monotonic clock moved backward")]
    NonMonotonicClock,
    /// Internal queue/correlation state contradicted a validated transition.
    #[error("app-server proxy correlation state is inconsistent")]
    InconsistentCorrelationState,
    /// A monotonic diagnostic counter could not be advanced.
    #[error("app-server proxy diagnostic counter overflowed")]
    DiagnosticCounterOverflow,
}

#[derive(Clone, Copy, Debug)]
enum ActiveRequestState {
    Queued,
    Pending { deadline: Instant },
}

#[derive(Default)]
struct ProxyCounters {
    accepted_client_messages: u64,
    accepted_server_messages: u64,
    accepted_client_bytes: u64,
    accepted_server_bytes: u64,
    forwarded_to_server_messages: u64,
    forwarded_to_client_messages: u64,
    late_responses: u64,
    unmatched_responses: u64,
    expired_requests: u64,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct RequestIdDigest([u8; 32]);

struct ProxyQueue {
    direction: AppServerProxyDirection,
    limits: AppServerQueueLimits,
    frames: VecDeque<AppServerProxyFrame>,
    bytes: usize,
    peak_messages: usize,
    peak_bytes: usize,
}

impl ProxyQueue {
    fn new(direction: AppServerProxyDirection, limits: AppServerQueueLimits) -> Self {
        Self {
            direction,
            limits,
            frames: VecDeque::new(),
            bytes: 0,
            peak_messages: 0,
            peak_bytes: 0,
        }
    }

    fn ensure_capacity(&self, bytes: usize) -> Result<(), AppServerProxyError> {
        if self.frames.len() >= self.limits.messages {
            return Err(AppServerProxyError::QueueMessageLimitExceeded {
                direction: self.direction,
            });
        }
        let next =
            self.bytes
                .checked_add(bytes)
                .ok_or(AppServerProxyError::QueueByteLimitExceeded {
                    direction: self.direction,
                })?;
        if next > self.limits.bytes {
            return Err(AppServerProxyError::QueueByteLimitExceeded {
                direction: self.direction,
            });
        }
        Ok(())
    }

    fn push_after_capacity_check(&mut self, frame: AppServerProxyFrame) {
        self.bytes += frame.json_bytes.len();
        self.frames.push_back(frame);
        self.peak_messages = self.peak_messages.max(self.frames.len());
        self.peak_bytes = self.peak_bytes.max(self.bytes);
    }

    fn pop(&mut self) -> Result<Option<AppServerProxyFrame>, AppServerProxyError> {
        let Some(front) = self.frames.front() else {
            return Ok(None);
        };
        let remaining_bytes = self
            .bytes
            .checked_sub(front.json_bytes.len())
            .ok_or(AppServerProxyError::InconsistentCorrelationState)?;
        let frame = self
            .frames
            .pop_front()
            .ok_or(AppServerProxyError::InconsistentCorrelationState)?;
        self.bytes = remaining_bytes;
        Ok(Some(frame))
    }

    fn front(&self) -> Option<&AppServerProxyFrame> {
        self.frames.front()
    }

    fn clear(&mut self) -> (usize, usize) {
        let messages = self.frames.len();
        let bytes = self.bytes;
        self.frames.clear();
        self.bytes = 0;
        (messages, bytes)
    }
}

/// Platform-neutral exact-byte forwarding and correlation engine.
///
/// The proxy validates one delimiter-free JSON object at a time, rejects
/// ambiguous duplicate keys and bounded-resource violations, then retains the
/// original bytes for forwarding. Parsed values are discarded after metadata
/// classification so unknown methods, fields, result variants, whitespace,
/// number spellings, and key order remain unchanged on the wire.
///
/// This object does not launch a process, authorize an effect, interpret
/// application payloads, or persist traces. One external owner must serialize
/// calls and append exactly one newline when writing a returned frame.
pub struct TransparentAppServerProxy {
    limits: AppServerProxyLimits,
    state: AppServerProxyState,
    to_server: ProxyQueue,
    to_client: ProxyQueue,
    client_requests: BTreeMap<AppServerRequestId, ActiveRequestState>,
    server_requests: BTreeMap<AppServerRequestId, ActiveRequestState>,
    client_request_history: BTreeSet<RequestIdDigest>,
    server_request_history: BTreeSet<RequestIdDigest>,
    last_observed_time: Option<Instant>,
    counters: ProxyCounters,
}

impl fmt::Debug for TransparentAppServerProxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransparentAppServerProxy")
            .field("limits", &self.limits)
            .field("diagnostics", &self.diagnostics())
            .finish_non_exhaustive()
    }
}

impl TransparentAppServerProxy {
    /// Constructs an empty open proxy with validated limits.
    #[must_use]
    pub fn new(limits: AppServerProxyLimits) -> Self {
        Self {
            limits,
            state: AppServerProxyState::Open,
            to_server: ProxyQueue::new(AppServerProxyDirection::ClientToServer, limits.to_server),
            to_client: ProxyQueue::new(AppServerProxyDirection::ServerToClient, limits.to_client),
            client_requests: BTreeMap::new(),
            server_requests: BTreeMap::new(),
            client_request_history: BTreeSet::new(),
            server_request_history: BTreeSet::new(),
            last_observed_time: None,
            counters: ProxyCounters::default(),
        }
    }

    /// Validates and queues one exact client JSON line for the app-server.
    ///
    /// # Errors
    ///
    /// Returns an explicit framing, JSON, shape, correlation, queue, limit, or
    /// lifecycle error. A rejected line does not mutate proxy state.
    pub fn ingest_client(
        &mut self,
        json_line: &[u8],
    ) -> Result<AppServerMessageObservation, AppServerProxyError> {
        self.ingest(AppServerProxyDirection::ClientToServer, json_line)
    }

    /// Validates and queues one exact server JSON line for the client.
    ///
    /// # Errors
    ///
    /// Returns an explicit framing, JSON, shape, correlation, queue, limit, or
    /// lifecycle error. A rejected line does not mutate proxy state.
    pub fn ingest_server(
        &mut self,
        json_line: &[u8],
    ) -> Result<AppServerMessageObservation, AppServerProxyError> {
        self.ingest(AppServerProxyDirection::ServerToClient, json_line)
    }

    /// Structurally validates one exact client line without admitting it.
    ///
    /// This is the non-mutating preflight boundary for an outer observer or
    /// authority-reducing policy. Dynamic queue and correlation state is
    /// deliberately rechecked by [`Self::admit`].
    ///
    /// # Errors
    ///
    /// Returns an explicit lifecycle, framing, JSON, structure, method, or
    /// request-identity error.
    pub fn prepare_client(
        &self,
        json_line: &[u8],
    ) -> Result<AppServerProxyCandidate, AppServerProxyError> {
        self.prepare(AppServerProxyDirection::ClientToServer, json_line)
    }

    /// Structurally validates one exact server line without admitting it.
    ///
    /// This is the non-mutating preflight boundary for an outer observer or
    /// authority-reducing policy. Dynamic queue and correlation state is
    /// deliberately rechecked by [`Self::admit`].
    ///
    /// # Errors
    ///
    /// Returns an explicit lifecycle, framing, JSON, structure, method, or
    /// request-identity error.
    pub fn prepare_server(
        &self,
        json_line: &[u8],
    ) -> Result<AppServerProxyCandidate, AppServerProxyError> {
        self.prepare(AppServerProxyDirection::ServerToClient, json_line)
    }

    /// Atomically admits one prepared exact frame after dynamic revalidation.
    ///
    /// The candidate's original direction and validated bytes are retained.
    /// Queue capacity, request correlation, history, lifecycle state, and
    /// diagnostic arithmetic are all checked again immediately before mutation.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, candidate-limit, correlation, queue, history, or
    /// diagnostic error. A rejected candidate does not mutate proxy state.
    pub fn admit(
        &mut self,
        candidate: AppServerProxyCandidate,
    ) -> Result<AppServerMessageObservation, AppServerProxyError> {
        if self.state == AppServerProxyState::Closed {
            return Err(AppServerProxyError::Closed);
        }
        if candidate.prepared_limits != self.limits {
            return Err(AppServerProxyError::CandidateLimitsMismatch);
        }
        self.admit_candidate(candidate)
    }

    /// Releases the next exact client frame toward the app-server.
    ///
    /// A request deadline starts at this transition, not while a frame waits
    /// behind backpressure.
    ///
    /// # Errors
    ///
    /// Returns an error for a backward clock, deadline/diagnostic overflow, or
    /// an impossible internal correlation transition.
    pub fn next_for_server(
        &mut self,
        now: Instant,
    ) -> Result<Option<AppServerProxyFrame>, AppServerProxyError> {
        self.release(AppServerProxyDirection::ClientToServer, now)
    }

    /// Releases the next exact server frame toward the client.
    ///
    /// A bidirectional server request receives its deadline at this transition.
    ///
    /// # Errors
    ///
    /// Returns an error for a backward clock, deadline/diagnostic overflow, or
    /// an impossible internal correlation transition.
    pub fn next_for_client(
        &mut self,
        now: Instant,
    ) -> Result<Option<AppServerProxyFrame>, AppServerProxyError> {
        self.release(AppServerProxyDirection::ServerToClient, now)
    }

    /// Removes every forwarded request whose deadline is at or before `now`.
    ///
    /// Queued requests have no deadline and are not expired. Retired request
    /// identities remain as bounded digests so a later response is explicitly
    /// classified as late and cannot complete a reused wire identity.
    ///
    /// # Errors
    ///
    /// Returns [`AppServerProxyError::NonMonotonicClock`] for a backward clock
    /// or [`AppServerProxyError::DiagnosticCounterOverflow`] if the monotonic
    /// expiration counter cannot represent the transition.
    pub fn expire_requests(
        &mut self,
        now: Instant,
    ) -> Result<Vec<AppServerExpiredRequest>, AppServerProxyError> {
        self.ensure_monotonic_time(now)?;
        let mut expired = expired_direction(
            &self.client_requests,
            AppServerProxyDirection::ClientToServer,
            now,
        );
        expired.extend(expired_direction(
            &self.server_requests,
            AppServerProxyDirection::ServerToClient,
            now,
        ));
        let count = u64::try_from(expired.len())
            .map_err(|_| AppServerProxyError::DiagnosticCounterOverflow)?;
        let next_expired = add(self.counters.expired_requests, count)?;
        for request in &expired {
            if self
                .request_history(request.origin)
                .contains(&request_id_digest(&request.request_id))
            {
                return Err(AppServerProxyError::InconsistentCorrelationState);
            }
        }
        for request in &expired {
            let removed = self
                .requests_mut(request.origin)
                .remove(&request.request_id);
            if removed.is_none()
                || !self
                    .request_history_mut(request.origin)
                    .insert(request_id_digest(&request.request_id))
            {
                return Err(AppServerProxyError::InconsistentCorrelationState);
            }
        }
        self.counters.expired_requests = next_expired;
        self.last_observed_time = Some(now);
        Ok(expired)
    }

    /// Returns payload-free current queue, correlation, and monotonic counters.
    #[must_use]
    pub fn diagnostics(&self) -> AppServerProxyDiagnostics {
        AppServerProxyDiagnostics {
            state: self.state,
            accepted_client_messages: self.counters.accepted_client_messages,
            accepted_server_messages: self.counters.accepted_server_messages,
            accepted_client_bytes: self.counters.accepted_client_bytes,
            accepted_server_bytes: self.counters.accepted_server_bytes,
            forwarded_to_server_messages: self.counters.forwarded_to_server_messages,
            forwarded_to_client_messages: self.counters.forwarded_to_client_messages,
            queued_to_server_messages: self.to_server.frames.len(),
            queued_to_client_messages: self.to_client.frames.len(),
            queued_to_server_bytes: self.to_server.bytes,
            queued_to_client_bytes: self.to_client.bytes,
            peak_to_server_messages: self.to_server.peak_messages,
            peak_to_client_messages: self.to_client.peak_messages,
            peak_to_server_bytes: self.to_server.peak_bytes,
            peak_to_client_bytes: self.to_client.peak_bytes,
            pending_client_requests: pending_count(&self.client_requests),
            pending_server_requests: pending_count(&self.server_requests),
            client_request_history: self.client_request_history.len(),
            server_request_history: self.server_request_history.len(),
            late_responses: self.counters.late_responses,
            unmatched_responses: self.counters.unmatched_responses,
            expired_requests: self.counters.expired_requests,
        }
    }

    /// Returns the current proxy lifecycle state.
    #[must_use]
    pub const fn state(&self) -> AppServerProxyState {
        self.state
    }

    /// Explicitly closes the proxy and clears all payload/correlation state.
    ///
    /// Calling this method again is idempotent and returns zero abandonment.
    pub fn close(&mut self) -> AppServerProxyCloseReport {
        let (to_server_messages, to_server_bytes) = self.to_server.clear();
        let (to_client_messages, to_client_bytes) = self.to_client.clear();
        let abandoned_requests = self
            .client_requests
            .len()
            .saturating_add(self.server_requests.len());
        let request_history = self
            .client_request_history
            .len()
            .saturating_add(self.server_request_history.len());
        self.client_requests.clear();
        self.server_requests.clear();
        self.client_request_history.clear();
        self.server_request_history.clear();
        self.state = AppServerProxyState::Closed;
        AppServerProxyCloseReport {
            messages: to_server_messages.saturating_add(to_client_messages),
            bytes: to_server_bytes.saturating_add(to_client_bytes),
            requests: abandoned_requests,
            request_history,
        }
    }

    fn ingest(
        &mut self,
        direction: AppServerProxyDirection,
        json_line: &[u8],
    ) -> Result<AppServerMessageObservation, AppServerProxyError> {
        let candidate = self.prepare(direction, json_line)?;
        self.admit_candidate(candidate)
    }

    fn prepare(
        &self,
        direction: AppServerProxyDirection,
        json_line: &[u8],
    ) -> Result<AppServerProxyCandidate, AppServerProxyError> {
        if self.state == AppServerProxyState::Closed {
            return Err(AppServerProxyError::Closed);
        }
        let classified = parse_and_classify(json_line, self.limits)?;
        let observation = AppServerMessageObservation {
            direction,
            kind: classified.kind,
            method: classified.method,
            request_id: classified.request_id,
            byte_length: json_line.len(),
        };
        Ok(AppServerProxyCandidate {
            prepared_limits: self.limits,
            observation,
            json_bytes: json_line.to_vec(),
        })
    }

    fn admit_candidate(
        &mut self,
        candidate: AppServerProxyCandidate,
    ) -> Result<AppServerMessageObservation, AppServerProxyError> {
        if self.state == AppServerProxyState::Closed {
            return Err(AppServerProxyError::Closed);
        }
        let AppServerProxyCandidate {
            prepared_limits: _,
            observation,
            json_bytes,
        } = candidate;
        let direction = observation.direction;
        self.queue(direction).ensure_capacity(json_bytes.len())?;
        let response_action = self.preflight_correlation(&observation)?;
        let byte_length = u64::try_from(json_bytes.len())
            .map_err(|_| AppServerProxyError::DiagnosticCounterOverflow)?;
        let (next_messages, next_bytes) = match direction {
            AppServerProxyDirection::ClientToServer => (
                increment(self.counters.accepted_client_messages)?,
                add(self.counters.accepted_client_bytes, byte_length)?,
            ),
            AppServerProxyDirection::ServerToClient => (
                increment(self.counters.accepted_server_messages)?,
                add(self.counters.accepted_server_bytes, byte_length)?,
            ),
        };
        let next_unmatched = if response_action == ResponseAction::Unmatched {
            increment(self.counters.unmatched_responses)?
        } else {
            self.counters.unmatched_responses
        };
        let next_late = if response_action == ResponseAction::Late {
            increment(self.counters.late_responses)?
        } else {
            self.counters.late_responses
        };

        let frame = AppServerProxyFrame {
            observation: observation.clone(),
            json_bytes,
        };
        self.apply_correlation(&observation, response_action)?;
        self.queue_mut(direction).push_after_capacity_check(frame);
        match direction {
            AppServerProxyDirection::ClientToServer => {
                self.counters.accepted_client_messages = next_messages;
                self.counters.accepted_client_bytes = next_bytes;
            }
            AppServerProxyDirection::ServerToClient => {
                self.counters.accepted_server_messages = next_messages;
                self.counters.accepted_server_bytes = next_bytes;
            }
        }
        self.counters.late_responses = next_late;
        self.counters.unmatched_responses = next_unmatched;
        Ok(observation)
    }

    fn release(
        &mut self,
        direction: AppServerProxyDirection,
        now: Instant,
    ) -> Result<Option<AppServerProxyFrame>, AppServerProxyError> {
        self.ensure_monotonic_time(now)?;
        let Some(front) = self.queue(direction).front() else {
            self.last_observed_time = Some(now);
            return Ok(None);
        };
        let request_id = if front.observation.kind == AppServerProxyMessageKind::Request {
            front.observation.request_id.clone()
        } else {
            None
        };
        let deadline = if request_id.is_some() {
            Some(
                now.checked_add(self.limits.request_timeout)
                    .ok_or(AppServerProxyError::DeadlineOverflow)?,
            )
        } else {
            None
        };
        let next_messages = match direction {
            AppServerProxyDirection::ClientToServer => {
                increment(self.counters.forwarded_to_server_messages)?
            }
            AppServerProxyDirection::ServerToClient => {
                increment(self.counters.forwarded_to_client_messages)?
            }
        };
        if let (Some(request_id), Some(deadline)) = (request_id.as_ref(), deadline) {
            let state = self
                .requests_mut(direction)
                .get_mut(request_id)
                .ok_or(AppServerProxyError::InconsistentCorrelationState)?;
            if !matches!(state, ActiveRequestState::Queued) {
                return Err(AppServerProxyError::InconsistentCorrelationState);
            }
            *state = ActiveRequestState::Pending { deadline };
        }
        let frame = self
            .queue_mut(direction)
            .pop()?
            .ok_or(AppServerProxyError::InconsistentCorrelationState)?;
        match direction {
            AppServerProxyDirection::ClientToServer => {
                self.counters.forwarded_to_server_messages = next_messages;
            }
            AppServerProxyDirection::ServerToClient => {
                self.counters.forwarded_to_client_messages = next_messages;
            }
        }
        self.last_observed_time = Some(now);
        Ok(Some(frame))
    }

    fn preflight_correlation(
        &self,
        observation: &AppServerMessageObservation,
    ) -> Result<ResponseAction, AppServerProxyError> {
        match observation.kind {
            AppServerProxyMessageKind::Request => {
                let request_id = observation
                    .request_id
                    .as_ref()
                    .ok_or(AppServerProxyError::InconsistentCorrelationState)?;
                if self
                    .requests(observation.direction)
                    .contains_key(request_id)
                {
                    return Err(AppServerProxyError::DuplicateRequestId {
                        direction: observation.direction,
                    });
                }
                if self
                    .request_history(observation.direction)
                    .contains(&request_id_digest(request_id))
                {
                    return Err(AppServerProxyError::ReusedRequestId {
                        direction: observation.direction,
                    });
                }
                let active = self
                    .client_requests
                    .len()
                    .checked_add(self.server_requests.len())
                    .ok_or(AppServerProxyError::ActiveRequestLimitExceeded)?;
                if active >= self.limits.active_requests {
                    return Err(AppServerProxyError::ActiveRequestLimitExceeded);
                }
                let tracked = active
                    .checked_add(self.client_request_history.len())
                    .and_then(|value| value.checked_add(self.server_request_history.len()))
                    .ok_or(AppServerProxyError::RequestHistoryLimitExceeded)?;
                if tracked >= self.limits.request_history {
                    return Err(AppServerProxyError::RequestHistoryLimitExceeded);
                }
                Ok(ResponseAction::None)
            }
            AppServerProxyMessageKind::SuccessResponse
            | AppServerProxyMessageKind::ErrorResponse => {
                let Some(request_id) = observation.request_id.as_ref() else {
                    return Ok(ResponseAction::Unmatched);
                };
                let request_origin = observation.direction.opposite();
                match self.requests(request_origin).get(request_id) {
                    Some(ActiveRequestState::Pending { .. })
                        if !self
                            .request_history(request_origin)
                            .contains(&request_id_digest(request_id)) =>
                    {
                        Ok(ResponseAction::Complete)
                    }
                    Some(ActiveRequestState::Pending { .. }) => {
                        Err(AppServerProxyError::InconsistentCorrelationState)
                    }
                    Some(ActiveRequestState::Queued) => {
                        Err(AppServerProxyError::ResponseBeforeRequestForwarded)
                    }
                    None if self
                        .request_history(request_origin)
                        .contains(&request_id_digest(request_id)) =>
                    {
                        Ok(ResponseAction::Late)
                    }
                    None => Ok(ResponseAction::Unmatched),
                }
            }
            AppServerProxyMessageKind::Notification => Ok(ResponseAction::None),
        }
    }

    fn apply_correlation(
        &mut self,
        observation: &AppServerMessageObservation,
        response_action: ResponseAction,
    ) -> Result<(), AppServerProxyError> {
        match observation.kind {
            AppServerProxyMessageKind::Request => {
                let request_id = observation
                    .request_id
                    .clone()
                    .ok_or(AppServerProxyError::InconsistentCorrelationState)?;
                if self
                    .requests_mut(observation.direction)
                    .insert(request_id, ActiveRequestState::Queued)
                    .is_some()
                {
                    return Err(AppServerProxyError::InconsistentCorrelationState);
                }
            }
            AppServerProxyMessageKind::SuccessResponse
            | AppServerProxyMessageKind::ErrorResponse
                if response_action == ResponseAction::Complete =>
            {
                let request_id = observation
                    .request_id
                    .as_ref()
                    .ok_or(AppServerProxyError::InconsistentCorrelationState)?;
                if self
                    .requests_mut(observation.direction.opposite())
                    .remove(request_id)
                    .is_none()
                {
                    return Err(AppServerProxyError::InconsistentCorrelationState);
                }
                if !self
                    .request_history_mut(observation.direction.opposite())
                    .insert(request_id_digest(request_id))
                {
                    return Err(AppServerProxyError::InconsistentCorrelationState);
                }
            }
            AppServerProxyMessageKind::Notification
            | AppServerProxyMessageKind::SuccessResponse
            | AppServerProxyMessageKind::ErrorResponse => {}
        }
        Ok(())
    }

    fn queue(&self, direction: AppServerProxyDirection) -> &ProxyQueue {
        match direction {
            AppServerProxyDirection::ClientToServer => &self.to_server,
            AppServerProxyDirection::ServerToClient => &self.to_client,
        }
    }

    fn queue_mut(&mut self, direction: AppServerProxyDirection) -> &mut ProxyQueue {
        match direction {
            AppServerProxyDirection::ClientToServer => &mut self.to_server,
            AppServerProxyDirection::ServerToClient => &mut self.to_client,
        }
    }

    fn requests(
        &self,
        direction: AppServerProxyDirection,
    ) -> &BTreeMap<AppServerRequestId, ActiveRequestState> {
        match direction {
            AppServerProxyDirection::ClientToServer => &self.client_requests,
            AppServerProxyDirection::ServerToClient => &self.server_requests,
        }
    }

    fn requests_mut(
        &mut self,
        direction: AppServerProxyDirection,
    ) -> &mut BTreeMap<AppServerRequestId, ActiveRequestState> {
        match direction {
            AppServerProxyDirection::ClientToServer => &mut self.client_requests,
            AppServerProxyDirection::ServerToClient => &mut self.server_requests,
        }
    }

    fn request_history(&self, direction: AppServerProxyDirection) -> &BTreeSet<RequestIdDigest> {
        match direction {
            AppServerProxyDirection::ClientToServer => &self.client_request_history,
            AppServerProxyDirection::ServerToClient => &self.server_request_history,
        }
    }

    fn request_history_mut(
        &mut self,
        direction: AppServerProxyDirection,
    ) -> &mut BTreeSet<RequestIdDigest> {
        match direction {
            AppServerProxyDirection::ClientToServer => &mut self.client_request_history,
            AppServerProxyDirection::ServerToClient => &mut self.server_request_history,
        }
    }

    fn ensure_monotonic_time(&self, now: Instant) -> Result<(), AppServerProxyError> {
        if self
            .last_observed_time
            .is_some_and(|previous| now < previous)
        {
            Err(AppServerProxyError::NonMonotonicClock)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseAction {
    None,
    Complete,
    Late,
    Unmatched,
}

struct ClassifiedMessage {
    kind: AppServerProxyMessageKind,
    method: Option<String>,
    request_id: Option<AppServerRequestId>,
}

fn parse_and_classify(
    json_line: &[u8],
    limits: AppServerProxyLimits,
) -> Result<ClassifiedMessage, AppServerProxyError> {
    if json_line.is_empty() || json_line.iter().all(u8::is_ascii_whitespace) {
        return Err(AppServerProxyError::EmptyLine);
    }
    if json_line.iter().any(|byte| matches!(*byte, b'\r' | b'\n')) {
        return Err(AppServerProxyError::EmbeddedLineBreak);
    }
    if json_line.len() > limits.line_bytes {
        return Err(AppServerProxyError::LineTooLarge);
    }
    let value = parse_bounded_json(json_line, limits.json)?;
    let Value::Object(object) = value else {
        return Err(AppServerProxyError::TopLevelNotObject);
    };
    classify_object(&object)
}

fn classify_object(object: &Map<String, Value>) -> Result<ClassifiedMessage, AppServerProxyError> {
    let has_result = object.contains_key("result");
    let has_error = object.contains_key("error");
    let has_id = object.contains_key("id");
    if let Some(method) = object.get("method") {
        if has_result || has_error {
            return Err(AppServerProxyError::AmbiguousMessageShape);
        }
        let method = method
            .as_str()
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= MAX_METHOD_BYTES
                    && !value.chars().any(char::is_control)
            })
            .ok_or(AppServerProxyError::InvalidMethod)?
            .to_owned();
        let request_id = if has_id {
            Some(parse_request_id(
                object
                    .get("id")
                    .ok_or(AppServerProxyError::InvalidRequestId)?,
            )?)
        } else {
            None
        };
        return Ok(ClassifiedMessage {
            kind: if request_id.is_some() {
                AppServerProxyMessageKind::Request
            } else {
                AppServerProxyMessageKind::Notification
            },
            method: Some(method),
            request_id,
        });
    }

    if !has_id || has_result == has_error {
        return Err(AppServerProxyError::AmbiguousMessageShape);
    }
    let request_id = match object
        .get("id")
        .ok_or(AppServerProxyError::InvalidRequestId)?
    {
        Value::Null => None,
        value => Some(parse_request_id(value)?),
    };
    Ok(ClassifiedMessage {
        kind: if has_result {
            AppServerProxyMessageKind::SuccessResponse
        } else {
            AppServerProxyMessageKind::ErrorResponse
        },
        method: None,
        request_id,
    })
}

fn parse_request_id(value: &Value) -> Result<AppServerRequestId, AppServerProxyError> {
    match value {
        Value::Number(number) => {
            if let Some(value) = number.as_u64() {
                Ok(AppServerRequestId::Unsigned(value))
            } else if let Some(value) = number.as_i64() {
                Ok(AppServerRequestId::Signed(value))
            } else {
                Err(AppServerProxyError::InvalidRequestId)
            }
        }
        Value::String(value)
            if !value.is_empty()
                && value.len() <= MAX_REQUEST_ID_BYTES
                && !value.chars().any(char::is_control) =>
        {
            Ok(AppServerRequestId::Text(value.clone()))
        }
        _ => Err(AppServerProxyError::InvalidRequestId),
    }
}

fn increment(value: u64) -> Result<u64, AppServerProxyError> {
    value
        .checked_add(1)
        .ok_or(AppServerProxyError::DiagnosticCounterOverflow)
}

fn add(value: u64, increment: u64) -> Result<u64, AppServerProxyError> {
    value
        .checked_add(increment)
        .ok_or(AppServerProxyError::DiagnosticCounterOverflow)
}

fn request_id_digest(request_id: &AppServerRequestId) -> RequestIdDigest {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_ID_DIGEST_DOMAIN);
    match request_id {
        AppServerRequestId::Unsigned(value) => {
            hasher.update([0]);
            hasher.update(value.to_be_bytes());
        }
        AppServerRequestId::Signed(value) => {
            hasher.update([1]);
            hasher.update(value.to_be_bytes());
        }
        AppServerRequestId::Text(value) => {
            hasher.update([2]);
            match u64::try_from(value.len()) {
                Ok(length) => hasher.update(length.to_be_bytes()),
                Err(_) => hasher.update(u64::MAX.to_be_bytes()),
            }
            hasher.update(value.as_bytes());
        }
    }
    RequestIdDigest(hasher.finalize().into())
}

fn pending_count(requests: &BTreeMap<AppServerRequestId, ActiveRequestState>) -> usize {
    requests
        .values()
        .filter(|state| matches!(state, ActiveRequestState::Pending { .. }))
        .count()
}

fn expired_direction(
    requests: &BTreeMap<AppServerRequestId, ActiveRequestState>,
    origin: AppServerProxyDirection,
    now: Instant,
) -> Vec<AppServerExpiredRequest> {
    let expired: Vec<_> = requests
        .iter()
        .filter_map(|(request_id, state)| match state {
            ActiveRequestState::Pending { deadline } if *deadline <= now => {
                Some(request_id.clone())
            }
            ActiveRequestState::Queued | ActiveRequestState::Pending { .. } => None,
        })
        .collect();
    expired
        .into_iter()
        .map(|request_id| AppServerExpiredRequest { origin, request_id })
        .collect()
}

#[derive(Clone, Copy)]
enum JsonViolation {
    DuplicateKey,
    Depth,
    Nodes,
}

struct JsonBudget {
    limits: AppServerJsonLimits,
    nodes: usize,
    violation: Option<JsonViolation>,
}

impl JsonBudget {
    fn claim<E: serde::de::Error>(&mut self, depth: usize) -> Result<(), E> {
        if depth > self.limits.depth {
            self.violation = Some(JsonViolation::Depth);
            return Err(E::custom("JSON depth limit exceeded"));
        }
        if self.nodes >= self.limits.nodes {
            self.violation = Some(JsonViolation::Nodes);
            return Err(E::custom("JSON node limit exceeded"));
        }
        self.nodes += 1;
        Ok(())
    }
}

struct BoundedValueSeed<'a> {
    budget: &'a mut JsonBudget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for BoundedValueSeed<'_> {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        self.budget.claim::<D::Error>(self.depth)?;
        deserializer.deserialize_any(BoundedValueVisitor {
            budget: self.budget,
            depth: self.depth,
        })
    }
}

struct BoundedValueVisitor<'a> {
    budget: &'a mut JsonBudget,
    depth: usize,
}

impl<'de> Visitor<'de> for BoundedValueVisitor<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(BoundedValueSeed {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                self.budget.violation = Some(JsonViolation::DuplicateKey);
                return Err(A::Error::custom("duplicate JSON object key"));
            }
            let value = map.next_value_seed(BoundedValueSeed {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

fn parse_bounded_json(
    bytes: &[u8],
    limits: AppServerJsonLimits,
) -> Result<Value, AppServerProxyError> {
    let mut budget = JsonBudget {
        limits,
        nodes: 0,
        violation: None,
    };
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let result = BoundedValueSeed {
        budget: &mut budget,
        depth: 1,
    }
    .deserialize(&mut deserializer);
    let value = match result {
        Ok(value) => value,
        Err(source) => {
            return Err(match budget.violation {
                Some(JsonViolation::DuplicateKey) => AppServerProxyError::DuplicateObjectKey,
                Some(JsonViolation::Depth) => AppServerProxyError::JsonDepthLimitExceeded,
                Some(JsonViolation::Nodes) => AppServerProxyError::JsonNodeLimitExceeded,
                None => AppServerProxyError::InvalidJson(source),
            });
        }
    };
    deserializer
        .end()
        .map_err(AppServerProxyError::InvalidJson)?;
    Ok(value)
}
