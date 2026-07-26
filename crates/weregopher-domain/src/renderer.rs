//! Closed contracts crossing the packaged-renderer bridge boundary.

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use thiserror::Error;

use crate::{
    AppInstanceId, FrameIdentity, ProtocolLimits, RendererId, RuntimeProtocolContractError,
    WireValue, WorldIdentity, validate_wire_value_graph, validate_wire_value_graph_for_app,
};

/// Exact byte length of a per-navigation renderer bridge nonce.
pub const RENDERER_BRIDGE_NONCE_BYTES: usize = 16;
/// Maximum UTF-8 bytes in one renderer bridge method or error code.
pub const MAX_RENDERER_BRIDGE_NAME_BYTES: usize = 255;
/// Maximum UTF-8 bytes in one renderer bridge failure diagnostic.
pub const MAX_RENDERER_BRIDGE_ERROR_BYTES: usize = 512;

/// Host-issued one-navigation challenge captured by the document-start bridge.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RendererBridgeNonce([u8; RENDERER_BRIDGE_NONCE_BYTES]);

impl RendererBridgeNonce {
    /// Constructs a nonzero per-navigation bridge nonce.
    ///
    /// # Errors
    ///
    /// Returns [`RendererContractError::ZeroBridgeNonce`] for the all-zero value.
    pub const fn new(
        bytes: [u8; RENDERER_BRIDGE_NONCE_BYTES],
    ) -> Result<Self, RendererContractError> {
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] != 0 {
                return Ok(Self(bytes));
            }
            index += 1;
        }
        Err(RendererContractError::ZeroBridgeNonce)
    }

    /// Returns the exact nonce bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; RENDERER_BRIDGE_NONCE_BYTES] {
        self.0
    }
}

impl<'de> Deserialize<'de> for RendererBridgeNonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <[u8; RENDERER_BRIDGE_NONCE_BYTES]>::deserialize(deserializer)?;
        Self::new(bytes).map_err(D::Error::custom)
    }
}

/// Backend-authoritative wrapper attached before a renderer value enters a privileged boundary.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RendererEnvelope {
    app: AppInstanceId,
    renderer: RendererId,
    frame: FrameIdentity,
    world: WorldIdentity,
    #[schemars(range(min = 1))]
    navigation_generation: u32,
    nonce: RendererBridgeNonce,
    payload: WireValue,
}

impl RendererEnvelope {
    /// Constructs a renderer envelope after validating every ownership relationship.
    ///
    /// # Errors
    ///
    /// Returns a closed renderer or wire-contract error when an identity is inconsistent, the
    /// generation is zero, or the payload contains an invalid/cross-application graph.
    #[allow(
        clippy::too_many_arguments,
        reason = "every explicit argument is an independently authoritative renderer identity"
    )]
    pub fn new(
        app: AppInstanceId,
        renderer: RendererId,
        frame: FrameIdentity,
        world: WorldIdentity,
        navigation_generation: u32,
        nonce: RendererBridgeNonce,
        payload: WireValue,
        limits: &ProtocolLimits,
    ) -> Result<Self, RendererContractError> {
        validate_renderer_authority(renderer, &frame, &world, navigation_generation, limits)?;
        validate_wire_value_graph_for_app(std::slice::from_ref(&payload), limits, app)?;
        Ok(Self {
            app,
            renderer,
            frame,
            world,
            navigation_generation,
            nonce,
            payload,
        })
    }

    /// Owning application launch.
    #[must_use]
    pub const fn app(&self) -> AppInstanceId {
        self.app
    }

    /// Backend-issued renderer identity.
    #[must_use]
    pub const fn renderer(&self) -> RendererId {
        self.renderer
    }

    /// Backend-authoritative frame identity.
    #[must_use]
    pub const fn frame(&self) -> &FrameIdentity {
        &self.frame
    }

    /// Backend-authoritative script-world identity.
    #[must_use]
    pub const fn world(&self) -> &WorldIdentity {
        &self.world
    }

    /// Navigation generation active when the backend observed the message.
    #[must_use]
    pub const fn navigation_generation(&self) -> u32 {
        self.navigation_generation
    }

    /// Host-issued per-navigation nonce.
    #[must_use]
    pub const fn nonce(&self) -> RendererBridgeNonce {
        self.nonce
    }

    /// Bounded renderer payload.
    #[must_use]
    pub const fn payload(&self) -> &WireValue {
        &self.payload
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRendererEnvelope {
    app: AppInstanceId,
    renderer: RendererId,
    frame: FrameIdentity,
    world: WorldIdentity,
    navigation_generation: u32,
    nonce: RendererBridgeNonce,
    payload: WireValue,
}

impl<'de> Deserialize<'de> for RendererEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRendererEnvelope::deserialize(deserializer)?;
        Self::new(
            raw.app,
            raw.renderer,
            raw.frame,
            raw.world,
            raw.navigation_generation,
            raw.nonce,
            raw.payload,
            &ProtocolLimits::secure_default(),
        )
        .map_err(D::Error::custom)
    }
}

/// Untrusted page-to-host invocation emitted through the document-start bridge.
///
/// Application, renderer, frame, world, origin, service target, deadline, and capability
/// authority are deliberately absent. The host derives those values from backend state.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RendererBridgeInvocation {
    nonce: RendererBridgeNonce,
    #[schemars(range(min = 1))]
    request_id: u64,
    #[schemars(length(min = 1, max = 255))]
    #[schemars(extend("x-weregopher-maxUtf8Bytes" = 255))]
    method: String,
    args: Vec<WireValue>,
}

impl RendererBridgeInvocation {
    /// Constructs one bounded renderer invocation without assigning host authority.
    ///
    /// # Errors
    ///
    /// Returns a closed renderer or wire-contract error for request zero, invalid method text, or
    /// an over-budget argument graph.
    pub fn new(
        nonce: RendererBridgeNonce,
        request_id: u64,
        method: impl Into<String>,
        args: Vec<WireValue>,
        limits: &ProtocolLimits,
    ) -> Result<Self, RendererContractError> {
        if request_id == 0 {
            return Err(RendererContractError::ZeroBridgeRequestId);
        }
        let method = method.into();
        validate_text(
            "renderer bridge method",
            &method,
            MAX_RENDERER_BRIDGE_NAME_BYTES,
        )?;
        validate_wire_value_graph(&args, limits)?;
        Ok(Self {
            nonce,
            request_id,
            method,
            args,
        })
    }

    /// Per-navigation challenge copied by the document-start bridge.
    #[must_use]
    pub const fn nonce(&self) -> RendererBridgeNonce {
        self.nonce
    }

    /// Renderer-local request correlation identity.
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    /// Adapter-routed method name.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Bounded semantic arguments.
    #[must_use]
    pub fn args(&self) -> &[WireValue] {
        &self.args
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRendererBridgeInvocation {
    nonce: RendererBridgeNonce,
    request_id: u64,
    method: String,
    args: Vec<WireValue>,
}

impl<'de> Deserialize<'de> for RendererBridgeInvocation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRendererBridgeInvocation::deserialize(deserializer)?;
        Self::new(
            raw.nonce,
            raw.request_id,
            raw.method,
            raw.args,
            &ProtocolLimits::secure_default(),
        )
        .map_err(D::Error::custom)
    }
}

/// Sanitized renderer-facing failure without host authority or raw diagnostics.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RendererBridgeFailure {
    #[schemars(length(min = 1, max = 255))]
    #[schemars(extend("x-weregopher-maxUtf8Bytes" = 255))]
    code: String,
    #[schemars(length(min = 1, max = 512))]
    #[schemars(extend("x-weregopher-maxUtf8Bytes" = 512))]
    message: String,
}

impl RendererBridgeFailure {
    /// Constructs one bounded sanitized renderer-facing failure.
    ///
    /// # Errors
    ///
    /// Returns [`RendererContractError`] for empty or oversized code/message text.
    pub fn new(
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<Self, RendererContractError> {
        let code = code.into();
        let message = message.into();
        validate_text(
            "renderer bridge error code",
            &code,
            MAX_RENDERER_BRIDGE_NAME_BYTES,
        )?;
        validate_text(
            "renderer bridge error message",
            &message,
            MAX_RENDERER_BRIDGE_ERROR_BYTES,
        )?;
        Ok(Self { code, message })
    }

    /// Stable failure code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Sanitized renderer-facing diagnostic.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRendererBridgeFailure {
    code: String,
    message: String,
}

impl<'de> Deserialize<'de> for RendererBridgeFailure {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRendererBridgeFailure::deserialize(deserializer)?;
        Self::new(raw.code, raw.message).map_err(D::Error::custom)
    }
}

/// Host-to-page completion for one renderer bridge invocation.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RendererBridgeReply {
    #[schemars(range(min = 1))]
    request_id: u64,
    result: Option<WireValue>,
    error: Option<RendererBridgeFailure>,
}

impl RendererBridgeReply {
    /// Constructs a successful bounded reply.
    ///
    /// # Errors
    ///
    /// Returns a closed renderer or wire error for request zero or an invalid value graph.
    pub fn success(
        request_id: u64,
        value: WireValue,
        limits: &ProtocolLimits,
    ) -> Result<Self, RendererContractError> {
        if request_id == 0 {
            return Err(RendererContractError::ZeroBridgeRequestId);
        }
        validate_wire_value_graph(std::slice::from_ref(&value), limits)?;
        Ok(Self {
            request_id,
            result: Some(value),
            error: None,
        })
    }

    /// Constructs a sanitized failed reply.
    ///
    /// # Errors
    ///
    /// Returns a closed renderer error for request zero or invalid/oversized text.
    pub fn failure(
        request_id: u64,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<Self, RendererContractError> {
        if request_id == 0 {
            return Err(RendererContractError::ZeroBridgeRequestId);
        }
        let error = RendererBridgeFailure::new(code, message)?;
        Ok(Self {
            request_id,
            result: None,
            error: Some(error),
        })
    }

    /// Renderer-local request correlation identity.
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    /// Successful semantic value, when present.
    #[must_use]
    pub const fn result(&self) -> Option<&WireValue> {
        self.result.as_ref()
    }

    /// Sanitized failure, when present.
    #[must_use]
    pub const fn error(&self) -> Option<&RendererBridgeFailure> {
        self.error.as_ref()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRendererBridgeReply {
    request_id: u64,
    result: Option<WireValue>,
    error: Option<RendererBridgeFailure>,
}

impl<'de> Deserialize<'de> for RendererBridgeReply {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRendererBridgeReply::deserialize(deserializer)?;
        match (raw.result, raw.error) {
            (Some(value), None) => {
                Self::success(raw.request_id, value, &ProtocolLimits::secure_default())
                    .map_err(D::Error::custom)
            }
            (None, Some(error)) => {
                Self::failure(raw.request_id, error.code, error.message).map_err(D::Error::custom)
            }
            _ => Err(D::Error::custom(
                RendererContractError::InvalidBridgeReplyShape,
            )),
        }
    }
}

fn validate_renderer_authority(
    renderer: RendererId,
    frame: &FrameIdentity,
    world: &WorldIdentity,
    navigation_generation: u32,
    limits: &ProtocolLimits,
) -> Result<(), RendererContractError> {
    if navigation_generation == 0 {
        return Err(RendererContractError::ZeroNavigationGeneration);
    }
    if frame.renderer != renderer {
        return Err(RendererContractError::FrameRendererMismatch);
    }
    if frame.generation != navigation_generation {
        return Err(RendererContractError::FrameNavigationMismatch);
    }
    if &world.frame != frame {
        return Err(RendererContractError::WorldFrameMismatch);
    }
    if world.generation != navigation_generation {
        return Err(RendererContractError::WorldNavigationMismatch);
    }
    validate_text(
        "renderer origin",
        &frame.origin.serialized,
        usize::try_from(limits.max_string_bytes).unwrap_or(usize::MAX),
    )
}

fn validate_text(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), RendererContractError> {
    if value.is_empty() {
        return Err(RendererContractError::EmptyText { field });
    }
    if value.len() > maximum {
        return Err(RendererContractError::TextExceeded {
            field,
            maximum,
            actual: value.len(),
        });
    }
    Ok(())
}

/// Invalid packaged-renderer bridge message or authority relationship.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RendererContractError {
    /// The document-start bridge challenge was all zero.
    #[error("renderer bridge nonce must not be all zero")]
    ZeroBridgeNonce,
    /// Navigation generation zero is reserved.
    #[error("renderer navigation generation must be nonzero")]
    ZeroNavigationGeneration,
    /// The frame belonged to a different renderer.
    #[error("renderer envelope frame does not belong to its renderer")]
    FrameRendererMismatch,
    /// The frame generation did not match the active navigation.
    #[error("renderer envelope frame generation does not match its navigation")]
    FrameNavigationMismatch,
    /// The script world belonged to a different frame.
    #[error("renderer envelope world does not belong to its frame")]
    WorldFrameMismatch,
    /// The script world generation did not match the active navigation.
    #[error("renderer envelope world generation does not match its navigation")]
    WorldNavigationMismatch,
    /// Renderer-local request zero has no correlation semantics.
    #[error("renderer bridge request ID must be nonzero")]
    ZeroBridgeRequestId,
    /// A required text field was empty.
    #[error("{field} must not be empty")]
    EmptyText {
        /// Invalid field.
        field: &'static str,
    },
    /// A text field exceeded its UTF-8 ceiling.
    #[error("{field} exceeds {maximum} UTF-8 bytes: {actual}")]
    TextExceeded {
        /// Invalid field.
        field: &'static str,
        /// Allowed bytes.
        maximum: usize,
        /// Observed bytes.
        actual: usize,
    },
    /// A reply contained neither or both of result/error.
    #[error("renderer bridge reply must contain exactly one of result or error")]
    InvalidBridgeReplyShape,
    /// The nested semantic value graph was invalid.
    #[error(transparent)]
    Wire(#[from] RuntimeProtocolContractError),
}
