//! Closed contracts for the first authenticated worker/host control protocol.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use thiserror::Error;

use crate::{
    AppInstanceId, CallContext, CompatibilityAnalysisDigest, ObjectHandle, ProtocolLimitError,
    ProtocolLimits, ProtocolSessionId, RuntimeBackendId, RuntimeId, StreamHandle, WireError,
    WireObjectEntry, WireValue,
};

/// Protocol major implemented by the G1 synthetic control slice.
pub const G1_PROTOCOL_MAJOR: u16 = 1;
/// Highest additive protocol minor implemented by the G1 synthetic control slice.
pub const G1_PROTOCOL_MINOR: u16 = 0;
/// Maximum UTF-8 bytes in one runtime-backend version string.
pub const MAX_PROTOCOL_BACKEND_VERSION_BYTES: usize = 128;
/// Maximum UTF-8 bytes in one connection-rejection diagnostic.
pub const MAX_PROTOCOL_REJECT_DETAIL_BYTES: usize = 512;
const MAX_PROTOCOL_HEARTBEAT_MILLIS: u32 = 60_000;
const MAX_PROTOCOL_CALL_DEADLINE_MILLIS: u32 = 10 * 60 * 1_000;
const MAX_PROTOCOL_SERVICE_NAME_BYTES: usize = 255;

/// One negotiated protocol version.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolVersion {
    #[schemars(range(min = 1))]
    major: u16,
    minor: u16,
}

impl ProtocolVersion {
    /// Constructs a protocol version with a nonzero major generation.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeProtocolContractError::ZeroProtocolMajor`] for major zero.
    pub const fn new(major: u16, minor: u16) -> Result<Self, RuntimeProtocolContractError> {
        if major == 0 {
            return Err(RuntimeProtocolContractError::ZeroProtocolMajor);
        }
        Ok(Self { major, minor })
    }

    /// Incompatible protocol generation.
    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    /// Additive protocol generation.
    #[must_use]
    pub const fn minor(self) -> u16 {
        self.minor
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProtocolVersion {
    major: u16,
    minor: u16,
}

impl<'de> Deserialize<'de> for ProtocolVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawProtocolVersion::deserialize(deserializer)?;
        Self::new(raw.major, raw.minor).map_err(D::Error::custom)
    }
}

/// Inclusive range of protocol versions supported by one endpoint.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolVersionRange {
    minimum: ProtocolVersion,
    maximum: ProtocolVersion,
}

impl ProtocolVersionRange {
    /// Constructs a single-major, monotonically ordered version range.
    ///
    /// # Errors
    ///
    /// Returns a relationship error for mixed majors or an inverted minor range.
    pub const fn new(
        minimum: ProtocolVersion,
        maximum: ProtocolVersion,
    ) -> Result<Self, RuntimeProtocolContractError> {
        if minimum.major != maximum.major {
            return Err(RuntimeProtocolContractError::VersionRangeMajorMismatch);
        }
        if minimum.minor > maximum.minor {
            return Err(RuntimeProtocolContractError::InvertedVersionRange);
        }
        Ok(Self { minimum, maximum })
    }

    /// Lowest supported version.
    #[must_use]
    pub const fn minimum(self) -> ProtocolVersion {
        self.minimum
    }

    /// Highest supported version.
    #[must_use]
    pub const fn maximum(self) -> ProtocolVersion {
        self.maximum
    }

    /// Chooses the highest version present in both ranges.
    #[must_use]
    pub const fn negotiate(self, other: &Self) -> Option<ProtocolVersion> {
        if self.minimum.major != other.minimum.major {
            return None;
        }
        let minimum_minor = if self.minimum.minor > other.minimum.minor {
            self.minimum.minor
        } else {
            other.minimum.minor
        };
        let maximum_minor = if self.maximum.minor < other.maximum.minor {
            self.maximum.minor
        } else {
            other.maximum.minor
        };
        if minimum_minor > maximum_minor {
            None
        } else {
            Some(ProtocolVersion {
                major: self.minimum.major,
                minor: maximum_minor,
            })
        }
    }

    /// Version range implemented by the initial synthetic control slice.
    ///
    /// # Errors
    ///
    /// Returns only if the compile-time constants violate version invariants.
    pub fn g1() -> Result<Self, RuntimeProtocolContractError> {
        let version = ProtocolVersion::new(G1_PROTOCOL_MAJOR, G1_PROTOCOL_MINOR)?;
        Self::new(version, version)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProtocolVersionRange {
    minimum: ProtocolVersion,
    maximum: ProtocolVersion,
}

impl<'de> Deserialize<'de> for ProtocolVersionRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawProtocolVersionRange::deserialize(deserializer)?;
        Self::new(raw.minimum, raw.maximum).map_err(D::Error::custom)
    }
}

/// Exact worker backend identity presented during connection setup.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBackendIdentity {
    id: RuntimeBackendId,
    #[schemars(length(min = 1, max = 128))]
    #[schemars(extend("x-weregopher-maxUtf8Bytes" = 128))]
    version: String,
}

impl RuntimeBackendIdentity {
    /// Constructs a bounded backend identity.
    ///
    /// # Errors
    ///
    /// Returns a text-boundary error for an empty or oversized version.
    pub fn new(
        id: RuntimeBackendId,
        version: impl Into<String>,
    ) -> Result<Self, RuntimeProtocolContractError> {
        let version = version.into();
        validate_text(
            "runtime backend version",
            &version,
            MAX_PROTOCOL_BACKEND_VERSION_BYTES,
        )?;
        Ok(Self { id, version })
    }

    /// Durable backend identifier.
    #[must_use]
    pub const fn id(&self) -> &RuntimeBackendId {
        &self.id
    }

    /// Exact backend version text.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuntimeBackendIdentity {
    id: RuntimeBackendId,
    version: String,
}

impl<'de> Deserialize<'de> for RuntimeBackendIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRuntimeBackendIdentity::deserialize(deserializer)?;
        Self::new(raw.id, raw.version).map_err(D::Error::custom)
    }
}

/// Additive features negotiated for one protocol session.
#[allow(
    clippy::struct_excessive_bools,
    reason = "each serialized boolean is an independently negotiated additive wire feature"
)]
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolFeatures {
    /// Asynchronous calls and results.
    pub calls: bool,
    /// Idempotent request cancellation.
    pub cancellation: bool,
    /// Ordered connection events.
    pub events: bool,
    /// Credit-controlled byte streams.
    pub credit_streams: bool,
    /// Strict single-outstanding-call synchronous lane.
    pub sync_lane: bool,
    /// Authenticated duplicated shared-buffer handles.
    pub shared_buffers: bool,
}

impl ProtocolFeatures {
    /// Features exercised by the first worker/host control fixture.
    #[must_use]
    pub const fn g1_control() -> Self {
        Self {
            calls: true,
            cancellation: true,
            events: true,
            credit_streams: true,
            sync_lane: false,
            shared_buffers: false,
        }
    }

    /// Intersects producer-requested and host-supported features.
    #[must_use]
    pub const fn negotiate(self, supported: Self) -> Self {
        Self {
            calls: self.calls && supported.calls,
            cancellation: self.cancellation && supported.cancellation,
            events: self.events && supported.events,
            credit_streams: self.credit_streams && supported.credit_streams,
            sync_lane: self.sync_lane && supported.sync_lane,
            shared_buffers: self.shared_buffers && supported.shared_buffers,
        }
    }
}

/// Worker-to-host connection initiation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeHello {
    runtime: RuntimeId,
    app: AppInstanceId,
    backend: RuntimeBackendIdentity,
    protocol_range: ProtocolVersionRange,
    nonce_proof: [u8; 32],
    capabilities: ProtocolFeatures,
    requested_limits: ProtocolLimits,
}

impl RuntimeHello {
    /// Constructs a closed connection-initiation message.
    ///
    /// # Errors
    ///
    /// Returns a contract error for an all-zero proof or invalid limits.
    #[allow(
        clippy::too_many_arguments,
        reason = "the handshake binds every independent endpoint identity and negotiation input"
    )]
    pub fn new(
        runtime: RuntimeId,
        app: AppInstanceId,
        backend: RuntimeBackendIdentity,
        protocol_range: ProtocolVersionRange,
        nonce_proof: [u8; 32],
        capabilities: ProtocolFeatures,
        requested_limits: ProtocolLimits,
    ) -> Result<Self, RuntimeProtocolContractError> {
        if nonce_proof == [0_u8; 32] {
            return Err(RuntimeProtocolContractError::ZeroNonceProof);
        }
        requested_limits.validate()?;
        Ok(Self {
            runtime,
            app,
            backend,
            protocol_range,
            nonce_proof,
            capabilities,
            requested_limits,
        })
    }

    /// Worker-runtime identity.
    #[must_use]
    pub const fn runtime(&self) -> RuntimeId {
        self.runtime
    }

    /// Owning application launch.
    #[must_use]
    pub const fn app(&self) -> AppInstanceId {
        self.app
    }

    /// Worker backend identity.
    #[must_use]
    pub const fn backend(&self) -> &RuntimeBackendIdentity {
        &self.backend
    }

    /// Supported protocol range.
    #[must_use]
    pub const fn protocol_range(&self) -> ProtocolVersionRange {
        self.protocol_range
    }

    /// Nonce-possession proof.
    #[must_use]
    pub const fn nonce_proof(&self) -> &[u8; 32] {
        &self.nonce_proof
    }

    /// Requested additive capabilities.
    #[must_use]
    pub const fn capabilities(&self) -> ProtocolFeatures {
        self.capabilities
    }

    /// Requested connection bounds.
    #[must_use]
    pub const fn requested_limits(&self) -> ProtocolLimits {
        self.requested_limits
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuntimeHello {
    runtime: RuntimeId,
    app: AppInstanceId,
    backend: RuntimeBackendIdentity,
    protocol_range: ProtocolVersionRange,
    nonce_proof: [u8; 32],
    capabilities: ProtocolFeatures,
    requested_limits: ProtocolLimits,
}

impl<'de> Deserialize<'de> for RuntimeHello {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRuntimeHello::deserialize(deserializer)?;
        Self::new(
            raw.runtime,
            raw.app,
            raw.backend,
            raw.protocol_range,
            raw.nonce_proof,
            raw.capabilities,
            raw.requested_limits,
        )
        .map_err(D::Error::custom)
    }
}

/// Negotiated heartbeat bounds for one session.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatPolicy {
    #[schemars(range(min = 1, max = 60_000))]
    interval_millis: u32,
    #[schemars(range(min = 1, max = 60_000))]
    timeout_millis: u32,
}

impl HeartbeatPolicy {
    /// Constructs a bounded heartbeat policy.
    ///
    /// # Errors
    ///
    /// Returns a duration relationship error for zero, inverted, or excessive values.
    pub const fn new(
        interval_millis: u32,
        timeout_millis: u32,
    ) -> Result<Self, RuntimeProtocolContractError> {
        if interval_millis == 0 || timeout_millis == 0 {
            return Err(RuntimeProtocolContractError::ZeroHeartbeatDuration);
        }
        if interval_millis > timeout_millis {
            return Err(RuntimeProtocolContractError::InvertedHeartbeatPolicy);
        }
        if timeout_millis > MAX_PROTOCOL_HEARTBEAT_MILLIS {
            return Err(RuntimeProtocolContractError::HeartbeatTimeoutExceeded);
        }
        Ok(Self {
            interval_millis,
            timeout_millis,
        })
    }

    /// Expected heartbeat interval.
    #[must_use]
    pub const fn interval_millis(self) -> u32 {
        self.interval_millis
    }

    /// Missing-heartbeat timeout.
    #[must_use]
    pub const fn timeout_millis(self) -> u32 {
        self.timeout_millis
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHeartbeatPolicy {
    interval_millis: u32,
    timeout_millis: u32,
}

impl<'de> Deserialize<'de> for HeartbeatPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawHeartbeatPolicy::deserialize(deserializer)?;
        Self::new(raw.interval_millis, raw.timeout_millis).map_err(D::Error::custom)
    }
}

/// Host-to-worker successful connection negotiation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeWelcome {
    session: ProtocolSessionId,
    version: ProtocolVersion,
    limits: ProtocolLimits,
    compatibility: CompatibilityAnalysisDigest,
    heartbeat: HeartbeatPolicy,
    features: ProtocolFeatures,
}

impl RuntimeWelcome {
    /// Constructs a validated welcome message.
    ///
    /// # Errors
    ///
    /// Returns a contract error when negotiated limits are invalid.
    pub fn new(
        session: ProtocolSessionId,
        version: ProtocolVersion,
        limits: ProtocolLimits,
        compatibility: CompatibilityAnalysisDigest,
        heartbeat: HeartbeatPolicy,
        features: ProtocolFeatures,
    ) -> Result<Self, RuntimeProtocolContractError> {
        limits.validate()?;
        Ok(Self {
            session,
            version,
            limits,
            compatibility,
            heartbeat,
            features,
        })
    }

    /// Authenticated session identity.
    #[must_use]
    pub const fn session(&self) -> ProtocolSessionId {
        self.session
    }

    /// Negotiated protocol version.
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Negotiated connection limits.
    #[must_use]
    pub const fn limits(&self) -> ProtocolLimits {
        self.limits
    }

    /// Compatibility identity selected by the host.
    #[must_use]
    pub const fn compatibility(&self) -> CompatibilityAnalysisDigest {
        self.compatibility
    }

    /// Negotiated heartbeat policy.
    #[must_use]
    pub const fn heartbeat(&self) -> HeartbeatPolicy {
        self.heartbeat
    }

    /// Negotiated additive feature set.
    #[must_use]
    pub const fn features(&self) -> ProtocolFeatures {
        self.features
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuntimeWelcome {
    session: ProtocolSessionId,
    version: ProtocolVersion,
    limits: ProtocolLimits,
    compatibility: CompatibilityAnalysisDigest,
    heartbeat: HeartbeatPolicy,
    features: ProtocolFeatures,
}

impl<'de> Deserialize<'de> for RuntimeWelcome {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRuntimeWelcome::deserialize(deserializer)?;
        Self::new(
            raw.session,
            raw.version,
            raw.limits,
            raw.compatibility,
            raw.heartbeat,
            raw.features,
        )
        .map_err(D::Error::custom)
    }
}

/// Stable connection-rejection category.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolRejectCode {
    /// No protocol version overlaps.
    VersionMismatch,
    /// Runtime, application, backend, or process identity mismatched.
    IdentityMismatch,
    /// Peer process or user validation failed.
    PeerRejected,
    /// Nonce-possession proof failed.
    NonceRejected,
    /// Requested limits were invalid.
    LimitsRejected,
    /// Required additive features were unavailable.
    FeaturesRejected,
    /// The encoded handshake was malformed.
    MalformedHandshake,
}

/// Bounded non-secret connection rejection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolReject {
    code: ProtocolRejectCode,
    #[schemars(length(min = 1, max = 512))]
    #[schemars(extend("x-weregopher-maxUtf8Bytes" = 512))]
    detail: String,
}

impl ProtocolReject {
    /// Constructs a bounded rejection diagnostic.
    ///
    /// # Errors
    ///
    /// Returns a text-boundary error for an empty or oversized detail.
    pub fn new(
        code: ProtocolRejectCode,
        detail: impl Into<String>,
    ) -> Result<Self, RuntimeProtocolContractError> {
        let detail = detail.into();
        validate_text(
            "protocol rejection detail",
            &detail,
            MAX_PROTOCOL_REJECT_DETAIL_BYTES,
        )?;
        Ok(Self { code, detail })
    }

    /// Stable rejection category.
    #[must_use]
    pub const fn code(&self) -> ProtocolRejectCode {
        self.code
    }

    /// Bounded non-secret diagnostic.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProtocolReject {
    code: ProtocolRejectCode,
    detail: String,
}

impl<'de> Deserialize<'de> for ProtocolReject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawProtocolReject::deserialize(deserializer)?;
        Self::new(raw.code, raw.detail).map_err(D::Error::custom)
    }
}

/// Host service, remote object, or runtime selected by one call.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CallTarget {
    /// Named host service.
    Service {
        /// Stable service name.
        #[schemars(length(min = 1, max = 255))]
        #[schemars(extend("x-weregopher-maxUtf8Bytes" = 255))]
        name: String,
    },
    /// Generation-protected remote object.
    Object {
        /// Remote object handle.
        handle: ObjectHandle,
    },
    /// One exact worker runtime.
    Runtime {
        /// Runtime identity.
        runtime: RuntimeId,
    },
}

impl CallTarget {
    /// Constructs a bounded service target.
    ///
    /// # Errors
    ///
    /// Returns a text-boundary error for an empty or oversized service name.
    pub fn service(name: impl Into<String>) -> Result<Self, RuntimeProtocolContractError> {
        let name = name.into();
        validate_text("call service", &name, MAX_PROTOCOL_SERVICE_NAME_BYTES)?;
        Ok(Self::Service { name })
    }

    fn validate(
        &self,
        limits: &ProtocolLimits,
        expected_app: AppInstanceId,
    ) -> Result<(), RuntimeProtocolContractError> {
        match self {
            Self::Service { name } => {
                let negotiated_maximum =
                    usize::try_from(limits.max_string_bytes).unwrap_or(usize::MAX);
                validate_text(
                    "call service",
                    name,
                    negotiated_maximum.min(MAX_PROTOCOL_SERVICE_NAME_BYTES),
                )?;
            }
            Self::Object { handle } if handle.app != expected_app => {
                return Err(RuntimeProtocolContractError::CrossApplicationHandle);
            }
            Self::Object { .. } | Self::Runtime { .. } => {}
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RawCallTarget {
    Service { name: String },
    Object { handle: ObjectHandle },
    Runtime { runtime: RuntimeId },
}

impl<'de> Deserialize<'de> for CallTarget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match RawCallTarget::deserialize(deserializer)? {
            RawCallTarget::Service { name } => Self::service(name).map_err(D::Error::custom),
            RawCallTarget::Object { handle } => Ok(Self::Object { handle }),
            RawCallTarget::Runtime { runtime } => Ok(Self::Runtime { runtime }),
        }
    }
}

/// One bounded worker-to-host or host-to-worker call.
#[derive(Clone, Debug, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCall {
    target: CallTarget,
    #[schemars(length(min = 1))]
    method: String,
    args: Vec<WireValue>,
    context: CallContext,
}

impl RuntimeCall {
    /// Constructs and validates one call against negotiated limits.
    ///
    /// # Errors
    ///
    /// Returns a text, deadline, or wire-graph budget error.
    pub fn new(
        target: CallTarget,
        method: impl Into<String>,
        args: Vec<WireValue>,
        context: CallContext,
        limits: &ProtocolLimits,
    ) -> Result<Self, RuntimeProtocolContractError> {
        let call = Self {
            target,
            method: method.into(),
            args,
            context,
        };
        call.validate(limits)?;
        Ok(call)
    }

    /// Revalidates this call against negotiated limits.
    ///
    /// # Errors
    ///
    /// Returns a text, deadline, or wire-graph budget error.
    pub fn validate(&self, limits: &ProtocolLimits) -> Result<(), RuntimeProtocolContractError> {
        limits.validate()?;
        self.target.validate(limits, self.context.app)?;
        validate_text(
            "call method",
            &self.method,
            usize::try_from(limits.max_string_bytes).unwrap_or(usize::MAX),
        )?;
        validate_call_context(&self.context, limits)?;
        validate_wire_value_graph_for_app(&self.args, limits, self.context.app)?;
        Ok(())
    }

    /// Call target.
    #[must_use]
    pub const fn target(&self) -> &CallTarget {
        &self.target
    }

    /// Method name.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Ordered call arguments.
    #[must_use]
    pub fn args(&self) -> &[WireValue] {
        &self.args
    }

    /// Authoritative call context.
    #[must_use]
    pub const fn context(&self) -> &CallContext {
        &self.context
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuntimeCall {
    target: CallTarget,
    method: String,
    args: Vec<WireValue>,
    context: CallContext,
}

impl<'de> Deserialize<'de> for RuntimeCall {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRuntimeCall::deserialize(deserializer)?;
        Self::new(
            raw.target,
            raw.method,
            raw.args,
            raw.context,
            &ProtocolLimits::secure_default(),
        )
        .map_err(D::Error::custom)
    }
}

/// Successful call payload.
#[derive(Clone, Debug, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCallResult {
    value: WireValue,
}

impl RuntimeCallResult {
    /// Constructs a bounded call result.
    ///
    /// # Errors
    ///
    /// Returns a wire-graph budget error.
    pub fn new(
        value: WireValue,
        limits: &ProtocolLimits,
    ) -> Result<Self, RuntimeProtocolContractError> {
        validate_wire_value_graph(std::slice::from_ref(&value), limits)?;
        Ok(Self { value })
    }

    /// Returned value.
    #[must_use]
    pub const fn value(&self) -> &WireValue {
        &self.value
    }

    /// Revalidates this result under negotiated limits.
    ///
    /// # Errors
    ///
    /// Returns a wire-graph budget error.
    pub fn validate(&self, limits: &ProtocolLimits) -> Result<(), RuntimeProtocolContractError> {
        validate_wire_value_graph(std::slice::from_ref(&self.value), limits).map(|_| ())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuntimeCallResult {
    value: WireValue,
}

impl<'de> Deserialize<'de> for RuntimeCallResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRuntimeCallResult::deserialize(deserializer)?;
        Self::new(raw.value, &ProtocolLimits::secure_default()).map_err(D::Error::custom)
    }
}

/// Failed call payload retaining JavaScript-visible error shape.
#[derive(Clone, Debug, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCallError {
    error: WireError,
}

impl RuntimeCallError {
    /// Constructs a bounded call failure.
    ///
    /// # Errors
    ///
    /// Returns a wire-graph budget error.
    pub fn new(
        error: WireError,
        limits: &ProtocolLimits,
    ) -> Result<Self, RuntimeProtocolContractError> {
        let wrapped = WireValue::Error {
            value: error.clone(),
        };
        validate_wire_value_graph(std::slice::from_ref(&wrapped), limits)?;
        Ok(Self { error })
    }

    /// JavaScript-visible error.
    #[must_use]
    pub const fn error(&self) -> &WireError {
        &self.error
    }

    /// Revalidates this failure under negotiated limits.
    ///
    /// # Errors
    ///
    /// Returns a wire-graph budget error.
    pub fn validate(&self, limits: &ProtocolLimits) -> Result<(), RuntimeProtocolContractError> {
        let wrapped = WireValue::Error {
            value: self.error.clone(),
        };
        validate_wire_value_graph(std::slice::from_ref(&wrapped), limits).map(|_| ())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuntimeCallError {
    error: WireError,
}

impl<'de> Deserialize<'de> for RuntimeCallError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRuntimeCallError::deserialize(deserializer)?;
        Self::new(raw.error, &ProtocolLimits::secure_default()).map_err(D::Error::custom)
    }
}

/// Idempotent cancellation of one nonzero request identity.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCancel {
    #[schemars(range(min = 1))]
    request_id: u64,
}

impl RuntimeCancel {
    /// Constructs a cancellation target.
    ///
    /// # Errors
    ///
    /// Returns a zero-request error because zero is uncorrelated.
    pub const fn new(request_id: u64) -> Result<Self, RuntimeProtocolContractError> {
        if request_id == 0 {
            Err(RuntimeProtocolContractError::ZeroRequestId)
        } else {
            Ok(Self { request_id })
        }
    }

    /// Request being cancelled.
    #[must_use]
    pub const fn request_id(self) -> u64 {
        self.request_id
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuntimeCancel {
    request_id: u64,
}

impl<'de> Deserialize<'de> for RuntimeCancel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRuntimeCancel::deserialize(deserializer)?;
        Self::new(raw.request_id).map_err(D::Error::custom)
    }
}

/// Ordered connection event.
#[derive(Clone, Debug, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeEvent {
    #[schemars(length(min = 1))]
    name: String,
    args: Vec<WireValue>,
}

impl RuntimeEvent {
    /// Constructs a bounded event.
    ///
    /// # Errors
    ///
    /// Returns a text or wire-graph budget error.
    pub fn new(
        name: impl Into<String>,
        args: Vec<WireValue>,
        limits: &ProtocolLimits,
    ) -> Result<Self, RuntimeProtocolContractError> {
        let event = Self {
            name: name.into(),
            args,
        };
        event.validate(limits)?;
        Ok(event)
    }

    /// Event name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Ordered event values.
    #[must_use]
    pub fn args(&self) -> &[WireValue] {
        &self.args
    }

    /// Revalidates this event under negotiated limits.
    ///
    /// # Errors
    ///
    /// Returns a text or wire-graph budget error.
    pub fn validate(&self, limits: &ProtocolLimits) -> Result<(), RuntimeProtocolContractError> {
        validate_text(
            "event name",
            &self.name,
            usize::try_from(limits.max_string_bytes).unwrap_or(usize::MAX),
        )?;
        validate_wire_value_graph(&self.args, limits).map(|_| ())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuntimeEvent {
    name: String,
    args: Vec<WireValue>,
}

impl<'de> Deserialize<'de> for RuntimeEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRuntimeEvent::deserialize(deserializer)?;
        Self::new(raw.name, raw.args, &ProtocolLimits::secure_default()).map_err(D::Error::custom)
    }
}

/// Opens a credit-controlled byte stream.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeStreamOpen {
    stream: StreamHandle,
    #[schemars(range(min = 1))]
    initial_credit: u64,
}

impl RuntimeStreamOpen {
    /// Constructs a stream open with nonzero initial credit.
    ///
    /// # Errors
    ///
    /// Returns a zero-credit error.
    pub const fn new(
        stream: StreamHandle,
        initial_credit: u64,
    ) -> Result<Self, RuntimeProtocolContractError> {
        if initial_credit == 0 {
            Err(RuntimeProtocolContractError::ZeroStreamCredit)
        } else {
            Ok(Self {
                stream,
                initial_credit,
            })
        }
    }

    /// Stream identity.
    #[must_use]
    pub const fn stream(&self) -> &StreamHandle {
        &self.stream
    }

    /// Initial receiver-granted bytes.
    #[must_use]
    pub const fn initial_credit(&self) -> u64 {
        self.initial_credit
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuntimeStreamOpen {
    stream: StreamHandle,
    initial_credit: u64,
}

impl<'de> Deserialize<'de> for RuntimeStreamOpen {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRuntimeStreamOpen::deserialize(deserializer)?;
        Self::new(raw.stream, raw.initial_credit).map_err(D::Error::custom)
    }
}

/// Grants additional byte credit to one stream.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeStreamWindow {
    stream: StreamHandle,
    #[schemars(range(min = 1))]
    additional_credit: u64,
}

impl RuntimeStreamWindow {
    /// Constructs a nonzero stream-credit grant.
    ///
    /// # Errors
    ///
    /// Returns a zero-credit error.
    pub const fn new(
        stream: StreamHandle,
        additional_credit: u64,
    ) -> Result<Self, RuntimeProtocolContractError> {
        if additional_credit == 0 {
            Err(RuntimeProtocolContractError::ZeroStreamCredit)
        } else {
            Ok(Self {
                stream,
                additional_credit,
            })
        }
    }

    /// Stream identity.
    #[must_use]
    pub const fn stream(&self) -> &StreamHandle {
        &self.stream
    }

    /// Additional receiver-granted bytes.
    #[must_use]
    pub const fn additional_credit(&self) -> u64 {
        self.additional_credit
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuntimeStreamWindow {
    stream: StreamHandle,
    additional_credit: u64,
}

impl<'de> Deserialize<'de> for RuntimeStreamWindow {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRuntimeStreamWindow::deserialize(deserializer)?;
        Self::new(raw.stream, raw.additional_credit).map_err(D::Error::custom)
    }
}

/// Ordered, credit-consuming stream bytes.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeStreamData {
    stream: StreamHandle,
    #[schemars(range(min = 1))]
    sequence: u64,
    #[schemars(length(min = 1))]
    #[schemars(with = "Vec<u8>")]
    #[serde(with = "serde_bytes")]
    bytes: Vec<u8>,
}

impl RuntimeStreamData {
    /// Constructs one bounded, nonempty stream-data message.
    ///
    /// # Errors
    ///
    /// Returns a sequence or inline-byte budget error.
    pub fn new(
        stream: StreamHandle,
        sequence: u64,
        bytes: Vec<u8>,
        limits: &ProtocolLimits,
    ) -> Result<Self, RuntimeProtocolContractError> {
        validate_stream_data(sequence, &bytes, limits)?;
        Ok(Self {
            stream,
            sequence,
            bytes,
        })
    }

    /// Stream identity.
    #[must_use]
    pub const fn stream(&self) -> &StreamHandle {
        &self.stream
    }

    /// One-based stream-data sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Credit-consuming bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Revalidates this data under negotiated limits.
    ///
    /// # Errors
    ///
    /// Returns a sequence or inline-byte budget error.
    pub fn validate(&self, limits: &ProtocolLimits) -> Result<(), RuntimeProtocolContractError> {
        validate_stream_data(self.sequence, &self.bytes, limits)
    }
}

fn validate_stream_data(
    sequence: u64,
    bytes: &[u8],
    limits: &ProtocolLimits,
) -> Result<(), RuntimeProtocolContractError> {
    limits.validate()?;
    if sequence == 0 {
        return Err(RuntimeProtocolContractError::ZeroStreamSequence);
    }
    if bytes.is_empty() {
        return Err(RuntimeProtocolContractError::EmptyStreamData);
    }
    validate_inline_bytes(
        bytes,
        usize::try_from(limits.max_inline_buffer_bytes).unwrap_or(usize::MAX),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuntimeStreamData {
    stream: StreamHandle,
    sequence: u64,
    #[serde(with = "serde_bytes")]
    bytes: Vec<u8>,
}

impl<'de> Deserialize<'de> for RuntimeStreamData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRuntimeStreamData::deserialize(deserializer)?;
        Self::new(
            raw.stream,
            raw.sequence,
            raw.bytes,
            &ProtocolLimits::secure_default(),
        )
        .map_err(D::Error::custom)
    }
}

/// Reason for a graceful protocol shutdown.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeShutdownReason {
    /// Normal application lifecycle completion.
    ApplicationExit,
    /// Host is shutting down the runtime.
    HostShutdown,
    /// Worker requested orderly termination.
    WorkerShutdown,
    /// Negotiated policy was revoked.
    PolicyRevoked,
}

/// Graceful shutdown request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeShutdown {
    /// Stable shutdown category.
    pub reason: RuntimeShutdownReason,
}

/// Observed budget usage in one decoded wire-value graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireValueBudget {
    nodes: u32,
    maximum_depth: u16,
    remote_handles: u32,
}

impl WireValueBudget {
    /// Total semantic graph nodes.
    #[must_use]
    pub const fn nodes(self) -> u32 {
        self.nodes
    }

    /// Deepest value nesting.
    #[must_use]
    pub const fn maximum_depth(self) -> u16 {
        self.maximum_depth
    }

    /// Remote handles referenced by the graph.
    #[must_use]
    pub const fn remote_handles(self) -> u32 {
        self.remote_handles
    }
}

/// Validates one or more wire values without recursive Rust calls.
///
/// # Errors
///
/// Returns a graph, text, byte, handle, duplicate-key, or semantic-canonicality error.
pub fn validate_wire_value_graph(
    roots: &[WireValue],
    limits: &ProtocolLimits,
) -> Result<WireValueBudget, RuntimeProtocolContractError> {
    validate_wire_value_graph_with_app(roots, limits, None)
}

/// Validates wire values and rejects every remote handle owned by another application.
///
/// # Errors
///
/// Returns the same errors as [`validate_wire_value_graph`] plus
/// [`RuntimeProtocolContractError::CrossApplicationHandle`].
pub fn validate_wire_value_graph_for_app(
    roots: &[WireValue],
    limits: &ProtocolLimits,
    app: AppInstanceId,
) -> Result<WireValueBudget, RuntimeProtocolContractError> {
    validate_wire_value_graph_with_app(roots, limits, Some(app))
}

fn validate_wire_value_graph_with_app(
    roots: &[WireValue],
    limits: &ProtocolLimits,
    expected_app: Option<AppInstanceId>,
) -> Result<WireValueBudget, RuntimeProtocolContractError> {
    limits.validate()?;
    let root_count = u32::try_from(roots.len())
        .map_err(|_| RuntimeProtocolContractError::GraphNodeCountOverflow)?;
    if root_count > limits.max_graph_nodes {
        return Err(RuntimeProtocolContractError::GraphNodesExceeded {
            maximum: limits.max_graph_nodes,
            actual: root_count,
        });
    }
    let mut pending = Vec::new();
    pending
        .try_reserve_exact(roots.len())
        .map_err(|_| RuntimeProtocolContractError::BudgetAllocationFailed)?;
    for value in roots.iter().rev() {
        pending.push((value, 1_u16));
    }

    let mut nodes = 0_u32;
    let mut maximum_depth = 0_u16;
    let mut remote_handles = 0_u32;
    while let Some((value, depth)) = pending.pop() {
        nodes = nodes
            .checked_add(1)
            .ok_or(RuntimeProtocolContractError::GraphNodeCountOverflow)?;
        if nodes > limits.max_graph_nodes {
            return Err(RuntimeProtocolContractError::GraphNodesExceeded {
                maximum: limits.max_graph_nodes,
                actual: nodes,
            });
        }
        if depth > limits.max_object_depth {
            return Err(RuntimeProtocolContractError::GraphDepthExceeded {
                maximum: limits.max_object_depth,
                actual: depth,
            });
        }
        maximum_depth = maximum_depth.max(depth);

        validate_wire_value(
            value,
            depth,
            limits,
            &mut pending,
            &mut remote_handles,
            limits.max_graph_nodes - nodes,
            expected_app,
        )?;
    }

    Ok(WireValueBudget {
        nodes,
        maximum_depth,
        remote_handles,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "one exhaustive match keeps every closed WireValue variant in the same trust-boundary audit"
)]
fn validate_wire_value<'a>(
    value: &'a WireValue,
    depth: u16,
    limits: &ProtocolLimits,
    pending: &mut Vec<(&'a WireValue, u16)>,
    remote_handles: &mut u32,
    remaining_nodes: u32,
    expected_app: Option<AppInstanceId>,
) -> Result<(), RuntimeProtocolContractError> {
    let maximum_string = usize::try_from(limits.max_string_bytes).unwrap_or(usize::MAX);
    let maximum_inline = usize::try_from(limits.max_inline_buffer_bytes).unwrap_or(usize::MAX);
    match value {
        WireValue::Undefined
        | WireValue::Null
        | WireValue::Bool { .. }
        | WireValue::Integer { .. }
        | WireValue::NegativeZero
        | WireValue::NaN
        | WireValue::PositiveInfinity
        | WireValue::NegativeInfinity
        | WireValue::Reference { .. }
        | WireValue::DateMillis { .. } => {}
        WireValue::Float { value } if value.is_finite() && value.fract() != 0.0 => {}
        WireValue::Float { .. } => {
            return Err(RuntimeProtocolContractError::NonCanonicalFloat);
        }
        WireValue::BigInt {
            negative,
            magnitude_be,
        } => {
            if magnitude_be.is_empty()
                || magnitude_be.first() == Some(&0)
                || (*negative && magnitude_be.iter().all(|byte| *byte == 0))
            {
                return Err(RuntimeProtocolContractError::NonCanonicalBigInt);
            }
            validate_inline_bytes(magnitude_be, maximum_inline)?;
        }
        WireValue::String { value } => {
            validate_bounded_text("wire string", value, maximum_string)?;
        }
        WireValue::Bytes { value } => validate_inline_bytes(value, maximum_inline)?,
        WireValue::Array { values } => {
            reserve_pending(
                pending,
                values.len(),
                remaining_nodes,
                limits.max_graph_nodes,
            )?;
            let child_depth = child_depth(depth, limits, values.is_empty())?;
            for child in values.iter().rev() {
                pending.push((child, child_depth));
            }
        }
        WireValue::Object { entries } => {
            validate_object_entries(entries, maximum_string)?;
            reserve_pending(
                pending,
                entries.len(),
                remaining_nodes,
                limits.max_graph_nodes,
            )?;
            let child_depth = child_depth(depth, limits, entries.is_empty())?;
            for entry in entries.iter().rev() {
                pending.push((&entry.value, child_depth));
            }
        }
        WireValue::RegExp { source, flags } => {
            validate_bounded_text("regular expression source", source, maximum_string)?;
            if flags.len() > maximum_string {
                return Err(RuntimeProtocolContractError::TextExceeded {
                    field: "regular expression flags",
                    maximum: maximum_string,
                    actual: flags.len(),
                });
            }
            let mut previous_position = None;
            let mut unicode = false;
            let mut unicode_sets = false;
            for flag in flags.bytes() {
                let Some(position) = b"dgimsuvy".iter().position(|candidate| *candidate == flag)
                else {
                    return Err(RuntimeProtocolContractError::InvalidRegularExpressionFlags);
                };
                if previous_position.is_some_and(|previous| position <= previous) {
                    return Err(RuntimeProtocolContractError::InvalidRegularExpressionFlags);
                }
                previous_position = Some(position);
                unicode |= flag == b'u';
                unicode_sets |= flag == b'v';
            }
            if unicode && unicode_sets {
                return Err(RuntimeProtocolContractError::InvalidRegularExpressionFlags);
            }
        }
        WireValue::Error { value } => {
            validate_wire_error(
                value,
                maximum_string,
                pending,
                depth,
                limits,
                remaining_nodes,
            )?;
        }
        WireValue::Handle { value } => {
            validate_remote_handle(value.app, expected_app, remote_handles, limits)?;
        }
        WireValue::Function { value }
        | WireValue::Promise { value }
        | WireValue::MessagePort { value } => {
            validate_remote_handle(value.app, expected_app, remote_handles, limits)?;
        }
        WireValue::TypedArray {
            array_kind,
            byte_offset,
            element_count,
            storage,
        } => {
            let element_bytes = match array_kind {
                crate::TypedArrayKind::Int8
                | crate::TypedArrayKind::Uint8
                | crate::TypedArrayKind::Uint8Clamped => 1_u64,
                crate::TypedArrayKind::Int16 | crate::TypedArrayKind::Uint16 => 2,
                crate::TypedArrayKind::Int32
                | crate::TypedArrayKind::Uint32
                | crate::TypedArrayKind::Float32 => 4,
                crate::TypedArrayKind::Float64
                | crate::TypedArrayKind::BigInt64
                | crate::TypedArrayKind::BigUint64 => 8,
            };
            let byte_len = element_count
                .checked_mul(element_bytes)
                .and_then(|length| byte_offset.checked_add(length))
                .ok_or(RuntimeProtocolContractError::TypedArrayRangeOverflow)?;
            match storage {
                crate::BufferStorage::Inline { value } => {
                    validate_inline_bytes(value, maximum_inline)?;
                    if byte_len > u64::try_from(value.len()).unwrap_or(u64::MAX) {
                        return Err(RuntimeProtocolContractError::TypedArrayRangeExceeded);
                    }
                }
                crate::BufferStorage::Shared { handle }
                | crate::BufferStorage::Stream { handle } => {
                    validate_remote_handle(handle.app, expected_app, remote_handles, limits)?;
                }
                crate::BufferStorage::Blob { .. } => {}
            }
        }
    }
    Ok(())
}

fn validate_wire_error<'a>(
    error: &'a WireError,
    maximum_string: usize,
    pending: &mut Vec<(&'a WireValue, u16)>,
    depth: u16,
    limits: &ProtocolLimits,
    remaining_nodes: u32,
) -> Result<(), RuntimeProtocolContractError> {
    validate_bounded_text("wire error name", &error.name, maximum_string)?;
    validate_bounded_text("wire error message", &error.message, maximum_string)?;
    for (field, value) in [
        ("wire error stack", error.stack.as_deref()),
        ("wire error code", error.code.as_deref()),
        ("wire error kind", error.kind.as_deref()),
    ] {
        if let Some(value) = value {
            validate_bounded_text(field, value, maximum_string)?;
        }
    }
    let children = error
        .data
        .len()
        .checked_add(usize::from(error.cause.is_some()))
        .ok_or(RuntimeProtocolContractError::GraphNodeCountOverflow)?;
    reserve_pending(pending, children, remaining_nodes, limits.max_graph_nodes)?;
    let child_depth = child_depth(depth, limits, children == 0)?;
    for (key, value) in error.data.iter().rev() {
        validate_bounded_text("wire error data key", key, maximum_string)?;
        pending.push((value, child_depth));
    }
    if let Some(cause) = &error.cause {
        pending.push((cause, child_depth));
    }
    Ok(())
}

fn validate_remote_handle(
    actual_app: AppInstanceId,
    expected_app: Option<AppInstanceId>,
    remote_handles: &mut u32,
    limits: &ProtocolLimits,
) -> Result<(), RuntimeProtocolContractError> {
    if expected_app.is_some_and(|expected| actual_app != expected) {
        return Err(RuntimeProtocolContractError::CrossApplicationHandle);
    }
    *remote_handles = remote_handles
        .checked_add(1)
        .ok_or(RuntimeProtocolContractError::RemoteHandleCountOverflow)?;
    if *remote_handles > limits.max_remote_handles {
        return Err(RuntimeProtocolContractError::RemoteHandlesExceeded {
            maximum: limits.max_remote_handles,
            actual: *remote_handles,
        });
    }
    Ok(())
}

fn validate_object_entries(
    entries: &[WireObjectEntry],
    maximum_string: usize,
) -> Result<(), RuntimeProtocolContractError> {
    let mut keys = BTreeSet::new();
    for entry in entries {
        validate_bounded_text("wire object key", &entry.key, maximum_string)?;
        if !keys.insert(entry.key.as_str()) {
            return Err(RuntimeProtocolContractError::DuplicateObjectKey {
                key: entry.key.clone(),
            });
        }
    }
    Ok(())
}

fn reserve_pending<T>(
    pending: &mut Vec<T>,
    additional: usize,
    remaining_nodes: u32,
    maximum_nodes: u32,
) -> Result<(), RuntimeProtocolContractError> {
    let required = pending
        .len()
        .checked_add(additional)
        .ok_or(RuntimeProtocolContractError::GraphNodeCountOverflow)?;
    if required > usize::try_from(remaining_nodes).unwrap_or(usize::MAX) {
        let actual = maximum_nodes
            .checked_add(1)
            .ok_or(RuntimeProtocolContractError::GraphNodeCountOverflow)?;
        return Err(RuntimeProtocolContractError::GraphNodesExceeded {
            maximum: maximum_nodes,
            actual,
        });
    }
    pending
        .try_reserve(additional)
        .map_err(|_| RuntimeProtocolContractError::BudgetAllocationFailed)
}

fn child_depth(
    depth: u16,
    limits: &ProtocolLimits,
    has_no_children: bool,
) -> Result<u16, RuntimeProtocolContractError> {
    if has_no_children {
        return Ok(depth);
    }
    let child_depth = depth
        .checked_add(1)
        .ok_or(RuntimeProtocolContractError::GraphDepthOverflow)?;
    if child_depth > limits.max_object_depth {
        return Err(RuntimeProtocolContractError::GraphDepthExceeded {
            maximum: limits.max_object_depth,
            actual: child_depth,
        });
    }
    Ok(child_depth)
}

fn validate_call_context(
    context: &CallContext,
    limits: &ProtocolLimits,
) -> Result<(), RuntimeProtocolContractError> {
    if let Some(deadline) = context.deadline_ms {
        if deadline == 0 {
            return Err(RuntimeProtocolContractError::ZeroCallDeadline);
        }
        if deadline > MAX_PROTOCOL_CALL_DEADLINE_MILLIS {
            return Err(RuntimeProtocolContractError::CallDeadlineExceeded);
        }
    }
    match (&context.renderer, &context.frame) {
        (None, Some(_)) => return Err(RuntimeProtocolContractError::FrameWithoutRenderer),
        (Some(renderer), Some(frame)) if renderer != &frame.renderer => {
            return Err(RuntimeProtocolContractError::FrameRendererMismatch);
        }
        _ => {}
    }
    if let Some(frame) = &context.frame {
        validate_text(
            "frame origin",
            &frame.origin.serialized,
            usize::try_from(limits.max_string_bytes).unwrap_or(usize::MAX),
        )?;
    }
    if let Some(world) = &context.world {
        let frame = context
            .frame
            .as_ref()
            .ok_or(RuntimeProtocolContractError::WorldWithoutFrame)?;
        if &world.frame != frame {
            return Err(RuntimeProtocolContractError::WorldFrameMismatch);
        }
        if let crate::ScriptWorldKind::BackendSpecific(kind) = &world.kind {
            validate_text(
                "backend-specific world kind",
                kind,
                usize::try_from(limits.max_string_bytes).unwrap_or(usize::MAX),
            )?;
        }
    }
    Ok(())
}

fn validate_inline_bytes(bytes: &[u8], maximum: usize) -> Result<(), RuntimeProtocolContractError> {
    if bytes.len() > maximum {
        Err(RuntimeProtocolContractError::InlineBytesExceeded {
            maximum,
            actual: bytes.len(),
        })
    } else {
        Ok(())
    }
}

fn validate_text(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), RuntimeProtocolContractError> {
    if value.is_empty() {
        return Err(RuntimeProtocolContractError::EmptyText { field });
    }
    validate_bounded_text(field, value, maximum)
}

fn validate_bounded_text(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), RuntimeProtocolContractError> {
    if value.len() > maximum {
        return Err(RuntimeProtocolContractError::TextExceeded {
            field,
            maximum,
            actual: value.len(),
        });
    }
    Ok(())
}

/// Invalid runtime protocol message or semantic graph.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RuntimeProtocolContractError {
    /// Protocol major zero is reserved.
    #[error("protocol major must be nonzero")]
    ZeroProtocolMajor,
    /// One range attempted to span incompatible major generations.
    #[error("protocol version range must use one major generation")]
    VersionRangeMajorMismatch,
    /// Minimum minor exceeded maximum minor.
    #[error("protocol version range is inverted")]
    InvertedVersionRange,
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
    /// All-zero nonce proofs are never issued.
    #[error("nonce-possession proof must not be all zero")]
    ZeroNonceProof,
    /// Negotiated protocol limits were invalid.
    #[error(transparent)]
    Limits(#[from] ProtocolLimitError),
    /// Heartbeat duration was zero.
    #[error("heartbeat durations must be nonzero")]
    ZeroHeartbeatDuration,
    /// Heartbeat interval exceeded its timeout.
    #[error("heartbeat interval must not exceed its timeout")]
    InvertedHeartbeatPolicy,
    /// Heartbeat timeout exceeded the implementation ceiling.
    #[error("heartbeat timeout exceeds the implementation ceiling")]
    HeartbeatTimeoutExceeded,
    /// Request zero has no correlation semantics.
    #[error("request ID zero cannot be cancelled")]
    ZeroRequestId,
    /// Relative call deadline was zero.
    #[error("call deadline must be nonzero when present")]
    ZeroCallDeadline,
    /// Relative call deadline exceeded the implementation ceiling.
    #[error("call deadline exceeds the implementation ceiling")]
    CallDeadlineExceeded,
    /// A frame was supplied without its owning renderer.
    #[error("call context frame requires an owning renderer")]
    FrameWithoutRenderer,
    /// The frame belonged to a different renderer than the call context.
    #[error("call context frame does not belong to its renderer")]
    FrameRendererMismatch,
    /// A script world was supplied without its owning frame.
    #[error("call context world requires an owning frame")]
    WorldWithoutFrame,
    /// The world belonged to a different frame generation than the call context.
    #[error("call context world does not belong to its frame")]
    WorldFrameMismatch,
    /// Wire graph exceeded its node ceiling.
    #[error("wire graph exceeds {maximum} nodes: {actual}")]
    GraphNodesExceeded {
        /// Allowed nodes.
        maximum: u32,
        /// Observed nodes.
        actual: u32,
    },
    /// Wire graph node counting overflowed.
    #[error("wire graph node count overflowed")]
    GraphNodeCountOverflow,
    /// Wire graph exceeded its nesting ceiling.
    #[error("wire graph exceeds depth {maximum}: {actual}")]
    GraphDepthExceeded {
        /// Allowed depth.
        maximum: u16,
        /// Observed depth.
        actual: u16,
    },
    /// Wire graph depth arithmetic overflowed.
    #[error("wire graph depth overflowed")]
    GraphDepthOverflow,
    /// Traversal storage could not be reserved.
    #[error("wire graph traversal allocation failed")]
    BudgetAllocationFailed,
    /// Inline byte content exceeded its ceiling.
    #[error("inline bytes exceed {maximum}: {actual}")]
    InlineBytesExceeded {
        /// Allowed bytes.
        maximum: usize,
        /// Observed bytes.
        actual: usize,
    },
    /// Object keys must be unique.
    #[error("wire object contains duplicate key `{key}`")]
    DuplicateObjectKey {
        /// Duplicate key.
        key: String,
    },
    /// Float used a representation with a dedicated semantic variant.
    #[error("wire float must be finite, nonintegral, and not negative zero")]
    NonCanonicalFloat,
    /// Big integer magnitude was empty, padded, or negative zero.
    #[error("wire bigint magnitude is noncanonical")]
    NonCanonicalBigInt,
    /// Regular-expression flags were unknown or repeated.
    #[error("regular-expression flags are invalid")]
    InvalidRegularExpressionFlags,
    /// A remote handle belonged to a different application launch.
    #[error("remote handle belongs to a different application")]
    CrossApplicationHandle,
    /// Remote handle count overflowed.
    #[error("remote handle count overflowed")]
    RemoteHandleCountOverflow,
    /// Remote handles exceeded the negotiated ceiling.
    #[error("wire graph exceeds {maximum} remote handles: {actual}")]
    RemoteHandlesExceeded {
        /// Allowed handles.
        maximum: u32,
        /// Observed handles.
        actual: u32,
    },
    /// Typed-array offset/length arithmetic overflowed.
    #[error("typed-array byte range overflowed")]
    TypedArrayRangeOverflow,
    /// Typed-array range exceeded inline storage.
    #[error("typed-array range exceeds inline storage")]
    TypedArrayRangeExceeded,
    /// Stream credit must be nonzero.
    #[error("stream credit must be nonzero")]
    ZeroStreamCredit,
    /// Stream-data sequence zero is reserved.
    #[error("stream-data sequence must be nonzero")]
    ZeroStreamSequence,
    /// Stream data must consume at least one byte of credit.
    #[error("stream data must not be empty")]
    EmptyStreamData,
}
