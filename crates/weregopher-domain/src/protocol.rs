//! Versioned, backend-neutral protocol semantic contracts.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use thiserror::Error;

use crate::{
    AppInstanceId, CapabilityGrantId, RendererId, Sha256Digest, TraceId, UserActivationId,
};

/// Exact encoded byte length of a protocol frame header.
pub const FRAME_HEADER_LEN: usize = 28;

/// Stable numeric message tags carried by [`FrameHeader`].
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    /// Runtime connection initiation.
    Hello = 1,
    /// Successful connection negotiation.
    Welcome = 2,
    /// Rejected connection negotiation.
    Reject = 3,
    /// Request to load one application lease.
    LoadApplication = 4,
    /// Notification that application bootstrap completed.
    ApplicationReady = 5,
    /// Notification that an application runtime exited.
    ApplicationExit = 6,
    /// Remote service or object call.
    Call = 7,
    /// Successful call response.
    CallResult = 8,
    /// Failed call response.
    CallError = 9,
    /// Idempotent cancellation request.
    Cancel = 10,
    /// Remote object or service event.
    Event = 11,
    /// Event subscription request.
    Subscribe = 12,
    /// Event subscription removal.
    Unsubscribe = 13,
    /// Fire-and-forget application IPC message.
    IpcSend = 14,
    /// Request/response application IPC invocation.
    IpcInvoke = 15,
    /// Successful IPC invocation response.
    IpcReply = 16,
    /// Failed IPC invocation response.
    IpcError = 17,
    /// Credit-controlled stream creation.
    StreamOpen = 18,
    /// Additional stream credit.
    StreamWindow = 19,
    /// Stream payload.
    StreamData = 20,
    /// Successful stream termination.
    StreamEnd = 21,
    /// Failed stream termination.
    StreamError = 22,
    /// Remote-handle retention.
    RetainHandle = 23,
    /// Remote-handle release.
    ReleaseHandle = 24,
    /// Shared-buffer transfer offer.
    SharedBufferOffer = 25,
    /// Shared-buffer transfer acceptance.
    SharedBufferAccept = 26,
    /// Shared-buffer reference release.
    SharedBufferRelease = 27,
    /// Connection liveness signal.
    Heartbeat = 28,
    /// Bounded diagnostic snapshot.
    Diagnostics = 29,
    /// Graceful shutdown request.
    Shutdown = 30,
}

impl TryFrom<u8> for MessageKind {
    type Error = FrameHeaderError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Welcome),
            3 => Ok(Self::Reject),
            4 => Ok(Self::LoadApplication),
            5 => Ok(Self::ApplicationReady),
            6 => Ok(Self::ApplicationExit),
            7 => Ok(Self::Call),
            8 => Ok(Self::CallResult),
            9 => Ok(Self::CallError),
            10 => Ok(Self::Cancel),
            11 => Ok(Self::Event),
            12 => Ok(Self::Subscribe),
            13 => Ok(Self::Unsubscribe),
            14 => Ok(Self::IpcSend),
            15 => Ok(Self::IpcInvoke),
            16 => Ok(Self::IpcReply),
            17 => Ok(Self::IpcError),
            18 => Ok(Self::StreamOpen),
            19 => Ok(Self::StreamWindow),
            20 => Ok(Self::StreamData),
            21 => Ok(Self::StreamEnd),
            22 => Ok(Self::StreamError),
            23 => Ok(Self::RetainHandle),
            24 => Ok(Self::ReleaseHandle),
            25 => Ok(Self::SharedBufferOffer),
            26 => Ok(Self::SharedBufferAccept),
            27 => Ok(Self::SharedBufferRelease),
            28 => Ok(Self::Heartbeat),
            29 => Ok(Self::Diagnostics),
            30 => Ok(Self::Shutdown),
            unknown => Err(FrameHeaderError::UnknownMessageKind(unknown)),
        }
    }
}

/// Logical protocol frame header with an explicit, padding-free wire codec.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct FrameHeader {
    /// Payload length in bytes, excluding this header.
    pub frame_length: u32,
    /// Incompatible protocol generation.
    pub protocol_major: u16,
    /// Additive negotiated protocol generation.
    pub protocol_minor: u16,
    /// Payload message category.
    pub message_kind: MessageKind,
    /// Versioned frame flags.
    #[serde(deserialize_with = "deserialize_frame_flags")]
    #[schemars(range(min = 0, max = 0))]
    flags: u8,
    /// Request/response correlation ID; zero means uncorrelated.
    pub request_id: u64,
    /// Monotonically increasing sequence number for one direction.
    pub sequence: u64,
}

impl FrameHeader {
    /// Constructs a logical frame header. Reserved wire bytes are always zero.
    #[must_use]
    pub const fn new(
        frame_length: u32,
        protocol_major: u16,
        protocol_minor: u16,
        message_kind: MessageKind,
        request_id: u64,
        sequence: u64,
    ) -> Self {
        Self {
            frame_length,
            protocol_major,
            protocol_minor,
            message_kind,
            flags: 0,
            request_id,
            sequence,
        }
    }

    /// Returns registered frame flags; protocol version 1 always returns zero.
    #[must_use]
    pub const fn flags(self) -> u8 {
        self.flags
    }

    /// Encodes the header using the canonical little-endian, padding-free layout.
    #[must_use]
    pub fn encode(self) -> [u8; FRAME_HEADER_LEN] {
        let mut bytes = [0_u8; FRAME_HEADER_LEN];
        bytes[0..4].copy_from_slice(&self.frame_length.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.protocol_major.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.protocol_minor.to_le_bytes());
        bytes[8] = self.message_kind as u8;
        bytes[9] = self.flags;
        bytes[10..12].copy_from_slice(&0_u16.to_le_bytes());
        bytes[12..20].copy_from_slice(&self.request_id.to_le_bytes());
        bytes[20..28].copy_from_slice(&self.sequence.to_le_bytes());
        bytes
    }

    /// Decodes and validates one exact canonical header.
    ///
    /// # Errors
    ///
    /// Returns [`FrameHeaderError`] for an incorrect length, unknown flags,
    /// nonzero reserved bytes, or an unregistered message-kind tag.
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameHeaderError> {
        if bytes.len() != FRAME_HEADER_LEN {
            return Err(FrameHeaderError::InvalidLength {
                actual: bytes.len(),
            });
        }
        if bytes[10] != 0 || bytes[11] != 0 {
            return Err(FrameHeaderError::ReservedBitsSet);
        }
        if bytes[9] != 0 {
            return Err(FrameHeaderError::UnknownFlags(bytes[9]));
        }

        Ok(Self {
            frame_length: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            protocol_major: u16::from_le_bytes([bytes[4], bytes[5]]),
            protocol_minor: u16::from_le_bytes([bytes[6], bytes[7]]),
            message_kind: MessageKind::try_from(bytes[8])?,
            flags: bytes[9],
            request_id: u64::from_le_bytes([
                bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18],
                bytes[19],
            ]),
            sequence: u64::from_le_bytes([
                bytes[20], bytes[21], bytes[22], bytes[23], bytes[24], bytes[25], bytes[26],
                bytes[27],
            ]),
        })
    }
}

fn deserialize_frame_flags<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    let flags = u8::deserialize(deserializer)?;
    if flags == 0 {
        Ok(flags)
    } else {
        Err(D::Error::custom("no frame flags are registered"))
    }
}

/// A malformed or unsupported frame header.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FrameHeaderError {
    /// The transport supplied fewer or more than the exact header bytes.
    #[error("frame header must be {FRAME_HEADER_LEN} bytes, got {actual}")]
    InvalidLength {
        /// Observed byte length.
        actual: usize,
    },
    /// Reserved bytes were nonzero.
    #[error("frame header reserved bits must be zero")]
    ReservedBitsSet,
    /// No flag bits are registered in protocol version 1.
    #[error("unknown frame flags {0:#04x}")]
    UnknownFlags(u8),
    /// No registered semantic message uses the numeric tag.
    #[error("unknown message kind {0}")]
    UnknownMessageKind(u8),
}

/// Negotiated allocation and concurrency limits for one authenticated connection.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct ProtocolLimits {
    /// Maximum encoded payload bytes in one frame.
    #[schemars(range(min = 1))]
    pub max_frame_bytes: u32,
    /// Maximum nodes in one serialized object graph.
    #[schemars(range(min = 1))]
    pub max_graph_nodes: u32,
    /// Maximum nested object/array depth.
    #[schemars(range(min = 1))]
    pub max_object_depth: u16,
    /// Maximum UTF-8 bytes in one string.
    #[schemars(range(min = 1))]
    pub max_string_bytes: u32,
    /// Maximum bytes carried inline rather than streamed or shared.
    #[schemars(range(min = 1))]
    pub max_inline_buffer_bytes: u32,
    /// Maximum unresolved request/response operations.
    #[schemars(range(min = 1))]
    pub max_pending_requests: u32,
    /// Maximum live remote handles.
    #[schemars(range(min = 1))]
    pub max_remote_handles: u32,
    /// Maximum concurrently open streams.
    #[schemars(range(min = 1))]
    pub max_open_streams: u16,
    /// Maximum connection-owned event listeners.
    #[schemars(range(min = 1))]
    pub max_listener_count: u32,
}

impl ProtocolLimits {
    /// Conservative local defaults that remain subject to process-level policy.
    #[must_use]
    pub const fn secure_default() -> Self {
        Self {
            max_frame_bytes: 4 * 1024 * 1024,
            max_graph_nodes: 50_000,
            max_object_depth: 64,
            max_string_bytes: 2 * 1024 * 1024,
            max_inline_buffer_bytes: 256 * 1024,
            max_pending_requests: 1_024,
            max_remote_handles: 10_000,
            max_open_streams: 256,
            max_listener_count: 2_048,
        }
    }

    /// Rejects limits that would disable every valid value while retaining an enabled feature.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolLimitError`] when any required limit is zero.
    pub fn validate(&self) -> Result<(), ProtocolLimitError> {
        validate_nonzero("max_frame_bytes", self.max_frame_bytes.into())?;
        validate_nonzero("max_graph_nodes", self.max_graph_nodes.into())?;
        validate_nonzero("max_object_depth", self.max_object_depth.into())?;
        validate_nonzero("max_string_bytes", self.max_string_bytes.into())?;
        validate_nonzero(
            "max_inline_buffer_bytes",
            self.max_inline_buffer_bytes.into(),
        )?;
        validate_nonzero("max_pending_requests", self.max_pending_requests.into())?;
        validate_nonzero("max_remote_handles", self.max_remote_handles.into())?;
        validate_nonzero("max_open_streams", self.max_open_streams.into())?;
        validate_nonzero("max_listener_count", self.max_listener_count.into())
    }

    /// Negotiates each dimension to the lower of the requested value and host hard cap.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolLimitError`] when either input contains a zero limit.
    pub fn negotiate(&self, hard_cap: &Self) -> Result<Self, ProtocolLimitError> {
        self.validate()?;
        hard_cap.validate()?;
        Ok(Self {
            max_frame_bytes: self.max_frame_bytes.min(hard_cap.max_frame_bytes),
            max_graph_nodes: self.max_graph_nodes.min(hard_cap.max_graph_nodes),
            max_object_depth: self.max_object_depth.min(hard_cap.max_object_depth),
            max_string_bytes: self.max_string_bytes.min(hard_cap.max_string_bytes),
            max_inline_buffer_bytes: self
                .max_inline_buffer_bytes
                .min(hard_cap.max_inline_buffer_bytes),
            max_pending_requests: self.max_pending_requests.min(hard_cap.max_pending_requests),
            max_remote_handles: self.max_remote_handles.min(hard_cap.max_remote_handles),
            max_open_streams: self.max_open_streams.min(hard_cap.max_open_streams),
            max_listener_count: self.max_listener_count.min(hard_cap.max_listener_count),
        })
    }
}

impl Default for ProtocolLimits {
    fn default() -> Self {
        Self::secure_default()
    }
}

fn validate_nonzero(field: &'static str, value: u64) -> Result<(), ProtocolLimitError> {
    if value == 0 {
        Err(ProtocolLimitError::Zero { field })
    } else {
        Ok(())
    }
}

/// An invalid protocol allocation/concurrency limit.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProtocolLimitError {
    /// A required positive limit was zero.
    #[error("protocol limit `{field}` must be greater than zero")]
    Zero {
        /// Invalid field name.
        field: &'static str,
    },
}

/// Host-issued authority references attached to a call.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct CallAuthority {
    /// Capability grant selected and validated by the receiving host.
    pub capability: Option<CapabilityGrantId>,
    /// Short-lived, one-shot user-activation record selected by the host.
    pub user_activation: Option<UserActivationId>,
}

/// Authoritative context attached to a worker-to-host operation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct CallContext {
    /// Owning application launch.
    pub app: AppInstanceId,
    /// Originating renderer, when applicable.
    pub renderer: Option<RendererId>,
    /// Authoritative renderer frame, when applicable.
    pub frame: Option<FrameIdentity>,
    /// Authoritative script world, when applicable.
    pub world: Option<WorldIdentity>,
    /// Host-issued authority references rather than caller assertions.
    pub authority: CallAuthority,
    /// Relative call deadline in milliseconds.
    pub deadline_ms: Option<u32>,
    /// Optional causal trace identity.
    pub trace_parent: Option<TraceId>,
}

/// Origin identity observed by the renderer backend rather than supplied by page code.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct OriginIdentity {
    /// Canonical serialized origin, or an implementation-assigned opaque identifier.
    pub serialized: String,
    /// Whether the origin is opaque under browser origin rules.
    pub opaque: bool,
}

/// Renderer frame identity, including navigation generation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct FrameIdentity {
    /// Owning renderer.
    pub renderer: RendererId,
    /// Backend frame identifier.
    pub frame_id: u64,
    /// Generation incremented when the backend reuses a frame identifier.
    pub generation: u32,
    /// Parent frame identifier in the same renderer generation.
    pub parent_frame_id: Option<u64>,
    /// Backend-authoritative origin.
    pub origin: OriginIdentity,
    /// Whether this is the renderer's main frame.
    pub is_main_frame: bool,
}

/// Script world category within a renderer frame.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptWorldKind {
    /// Page main world.
    Main,
    /// Vendor preload isolated world.
    PreloadIsolated,
    /// Weregopher adapter isolated world.
    AdapterIsolated,
    /// Renderer-backend-specific world category.
    BackendSpecific(String),
}

/// Identity of a script world and its destruction/recreation generation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct WorldIdentity {
    /// Owning frame identity.
    pub frame: FrameIdentity,
    /// Backend world identifier.
    pub world_id: u64,
    /// Generation incremented when the backend reuses a world identifier.
    pub generation: u32,
    /// Semantic world category.
    pub kind: ScriptWorldKind,
}

/// Type discriminator for a remote Electron-compatible object.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    /// Application singleton.
    App,
    /// Browser-window compatible object.
    BrowserWindow,
    /// Renderer/web-contents compatible object.
    WebContents,
    /// Browser-session compatible object.
    Session,
    /// Web-request compatible object.
    WebRequest,
    /// Native menu.
    Menu,
    /// Native menu item.
    MenuItem,
    /// Notification-area icon.
    Tray,
    /// Native image.
    NativeImage,
    /// Native notification.
    Notification,
    /// Download operation.
    DownloadItem,
    /// Message port.
    MessagePort,
    /// Utility process.
    UtilityProcess,
    /// Adapter-defined object type in a signed namespace.
    AdapterDefined(u16),
}

/// Generation-protected, application-scoped remote object reference.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct ObjectHandle {
    /// Owning application launch.
    pub app: AppInstanceId,
    /// Application-scoped object number.
    pub id: u64,
    /// Reuse generation.
    pub generation: u32,
    /// Object type.
    pub kind: ObjectKind,
}

/// Generation-protected opaque protocol handle.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct OpaqueHandle {
    /// Owning application launch.
    pub app: AppInstanceId,
    /// Application-scoped handle number.
    pub id: u64,
    /// Reuse generation.
    pub generation: u32,
}

/// Remote callable-function handle.
pub type RemoteFunctionHandle = OpaqueHandle;
/// Remote promise handle.
pub type RemotePromiseHandle = OpaqueHandle;
/// Remote message-port handle.
pub type MessagePortHandle = OpaqueHandle;
/// Shared-buffer authority handle; it is not a raw operating-system handle.
pub type SharedBufferHandle = OpaqueHandle;
/// Credit-controlled stream handle.
pub type StreamHandle = OpaqueHandle;

/// Content-addressed immutable blob reference.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct ContentBlobId {
    /// Blob content digest.
    pub sha256: Sha256Digest,
    /// Exact byte length.
    pub byte_len: u64,
}

/// Storage backing for bytes or a typed array.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BufferStorage {
    /// Bounded bytes carried in the containing message.
    Inline {
        /// Inline byte content.
        value: Vec<u8>,
    },
    /// Authenticated broker-created shared mapping.
    Shared {
        /// Abstract shared-buffer handle.
        handle: SharedBufferHandle,
    },
    /// Credit-controlled stream.
    Stream {
        /// Stream handle.
        handle: StreamHandle,
    },
    /// Content-addressed file/blob transport.
    Blob {
        /// Immutable blob identity.
        id: ContentBlobId,
    },
}

/// JavaScript typed-array element interpretation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypedArrayKind {
    /// Signed 8-bit integers.
    Int8,
    /// Unsigned 8-bit integers.
    Uint8,
    /// Clamped unsigned 8-bit integers.
    Uint8Clamped,
    /// Signed 16-bit integers.
    Int16,
    /// Unsigned 16-bit integers.
    Uint16,
    /// Signed 32-bit integers.
    Int32,
    /// Unsigned 32-bit integers.
    Uint32,
    /// 32-bit IEEE floating point.
    Float32,
    /// 64-bit IEEE floating point.
    Float64,
    /// Signed 64-bit big integers.
    BigInt64,
    /// Unsigned 64-bit big integers.
    BigUint64,
}

/// One ordered JavaScript object property in a serialized graph.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WireObjectEntry {
    /// Property key.
    pub key: String,
    /// Property value.
    pub value: WireValue,
}

/// JavaScript-visible error shape plus an internal classification.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WireError {
    /// JavaScript error constructor/name.
    pub name: String,
    /// Human-visible message.
    pub message: String,
    /// Redacted or full stack according to trace policy.
    pub stack: Option<String>,
    /// Application-visible error code.
    pub code: Option<String>,
    /// Weregopher internal error category.
    pub kind: Option<String>,
    /// Optional causal error/value.
    pub cause: Option<Box<WireValue>>,
    /// Additional structured data.
    pub data: BTreeMap<String, WireValue>,
}

/// Backend-neutral semantic value model for worker, host, helper, and renderer bridges.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WireValue {
    /// JavaScript `undefined`.
    Undefined,
    /// JavaScript `null`.
    Null,
    /// Boolean primitive.
    Bool {
        /// Primitive value.
        value: bool,
    },
    /// Integer representable as signed 64 bits.
    Integer {
        /// Primitive value.
        value: i64,
    },
    /// Finite non-integer IEEE-754 value.
    Float {
        /// Primitive value.
        value: f64,
    },
    /// IEEE-754 negative zero.
    NegativeZero,
    /// IEEE-754 not-a-number.
    #[serde(rename = "nan")]
    NaN,
    /// Positive infinity.
    PositiveInfinity,
    /// Negative infinity.
    NegativeInfinity,
    /// Arbitrary-precision integer.
    BigInt {
        /// Whether the mathematical integer is negative.
        negative: bool,
        /// Unsigned magnitude encoded most-significant byte first.
        magnitude_be: Vec<u8>,
    },
    /// UTF-8 string.
    String {
        /// String value.
        value: String,
    },
    /// Bounded inline byte sequence.
    Bytes {
        /// Byte content.
        value: Vec<u8>,
    },
    /// Ordered array values.
    Array {
        /// Element values.
        values: Vec<WireValue>,
    },
    /// Ordered own string-keyed properties.
    Object {
        /// Ordered entries.
        entries: Vec<WireObjectEntry>,
    },
    /// Message-local reference used for cycles and repeated identity.
    Reference {
        /// Message-local graph-node number.
        id: u32,
    },
    /// JavaScript date milliseconds since the Unix epoch.
    DateMillis {
        /// Signed epoch milliseconds.
        value: i64,
    },
    /// JavaScript regular expression.
    RegExp {
        /// Pattern source.
        source: String,
        /// Canonically ordered JavaScript flags.
        flags: String,
    },
    /// JavaScript-compatible error.
    Error {
        /// Error value.
        value: WireError,
    },
    /// Remote Electron-compatible object.
    Handle {
        /// Object handle.
        value: ObjectHandle,
    },
    /// Remote callable function.
    Function {
        /// Function handle.
        value: RemoteFunctionHandle,
    },
    /// Remote promise.
    Promise {
        /// Promise handle.
        value: RemotePromiseHandle,
    },
    /// Remote message port.
    MessagePort {
        /// Port handle.
        value: MessagePortHandle,
    },
    /// Typed-array view over bounded storage.
    TypedArray {
        /// Element interpretation.
        array_kind: TypedArrayKind,
        /// Byte offset within storage.
        byte_offset: u64,
        /// Number of elements, not bytes.
        element_count: u64,
        /// Backing storage.
        storage: BufferStorage,
    },
}
