//! Backend-authoritative conversion from untrusted page messages to runtime calls.

use std::collections::BTreeSet;

use thiserror::Error;
use weregopher_domain::{
    AppInstanceId, CallAuthority, CallContext, CallTarget, FrameIdentity, ProtocolLimits,
    RendererBridgeInvocation, RendererBridgeNonce, RendererContractError, RendererEnvelope,
    RendererId, RuntimeCall, RuntimeProtocolContractError, ScriptWorldKind, WireValue,
    WorldIdentity,
};

use crate::{PackageOriginError, PrivateOrigin};

const G1_RENDERER_CALL_DEADLINE_MILLIS: u32 = 5_000;
const G1_MAIN_FRAME_ID: u64 = 1;
const G1_MAIN_WORLD_ID: u64 = 1;

/// One page invocation after backend source and identity authority were attached.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthorizedRendererCall {
    page_request_id: u64,
    envelope: RendererEnvelope,
    call: RuntimeCall,
}

impl AuthorizedRendererCall {
    /// Page-local request identity used for the renderer reply.
    #[must_use]
    pub const fn page_request_id(&self) -> u64 {
        self.page_request_id
    }

    /// Backend-authoritative renderer envelope retained as evidence.
    #[must_use]
    pub const fn envelope(&self) -> &RendererEnvelope {
        &self.envelope
    }

    /// Runtime call with host-derived application/frame/world context.
    #[must_use]
    pub const fn call(&self) -> &RuntimeCall {
        &self.call
    }
}

/// Per-navigation authority that validates page messages and prevents request replay.
#[derive(Clone, Debug)]
pub struct RendererBridgeAuthority {
    app: AppInstanceId,
    renderer: RendererId,
    origin: PrivateOrigin,
    navigation_generation: u32,
    nonce: RendererBridgeNonce,
    service: String,
    limits: ProtocolLimits,
    accepted_requests: BTreeSet<u64>,
}

impl RendererBridgeAuthority {
    /// Constructs authority for one exact backend navigation.
    ///
    /// # Errors
    ///
    /// Returns a closed bridge error for generation zero or an invalid service target.
    #[allow(
        clippy::too_many_arguments,
        reason = "each argument binds one independent backend or negotiated protocol identity"
    )]
    pub fn new(
        app: AppInstanceId,
        renderer: RendererId,
        origin: PrivateOrigin,
        navigation_generation: u32,
        nonce: RendererBridgeNonce,
        service: impl Into<String>,
        limits: ProtocolLimits,
    ) -> Result<Self, RendererBridgeError> {
        if navigation_generation == 0 {
            return Err(RendererBridgeError::ZeroNavigationGeneration);
        }
        limits.validate()?;
        let service = service.into();
        CallTarget::service(service.clone())?;
        Ok(Self {
            app,
            renderer,
            origin,
            navigation_generation,
            nonce,
            service,
            limits,
            accepted_requests: BTreeSet::new(),
        })
    }

    /// Validates one backend-observed source and untrusted invocation, then derives the runtime
    /// call authority.
    ///
    /// The message cannot supply its own application, frame, world, origin, target service,
    /// deadline, capabilities, or user activation.
    ///
    /// # Errors
    ///
    /// Returns a closed error for wrong source/nonce, replay, budget exhaustion, or invalid nested
    /// contracts.
    pub fn authorize(
        &mut self,
        observed_source: &str,
        invocation: &RendererBridgeInvocation,
    ) -> Result<AuthorizedRendererCall, RendererBridgeError> {
        self.origin
            .request_path(observed_source, crate::PackageOriginLimits::g1_fixture())
            .map_err(|_| RendererBridgeError::SourceMismatch)?;
        if invocation.nonce() != self.nonce {
            return Err(RendererBridgeError::NonceMismatch);
        }
        if self.accepted_requests.contains(&invocation.request_id()) {
            return Err(RendererBridgeError::RequestReplay {
                request_id: invocation.request_id(),
            });
        }
        let maximum = usize::try_from(self.limits.max_pending_requests).unwrap_or(usize::MAX);
        if self.accepted_requests.len() >= maximum {
            return Err(RendererBridgeError::RequestBudgetExceeded {
                maximum: self.limits.max_pending_requests,
            });
        }

        let frame = FrameIdentity {
            renderer: self.renderer,
            frame_id: G1_MAIN_FRAME_ID,
            generation: self.navigation_generation,
            parent_frame_id: None,
            origin: self.origin.identity(),
            is_main_frame: true,
        };
        let world = WorldIdentity {
            frame: frame.clone(),
            world_id: G1_MAIN_WORLD_ID,
            generation: self.navigation_generation,
            kind: ScriptWorldKind::Main,
        };
        let envelope = RendererEnvelope::new(
            self.app,
            self.renderer,
            frame.clone(),
            world.clone(),
            self.navigation_generation,
            self.nonce,
            WireValue::Array {
                values: invocation.args().to_vec(),
            },
            &self.limits,
        )?;
        let call = RuntimeCall::new(
            CallTarget::service(self.service.clone())?,
            invocation.method(),
            invocation.args().to_vec(),
            CallContext {
                app: self.app,
                renderer: Some(self.renderer),
                frame: Some(frame),
                world: Some(world),
                authority: CallAuthority::default(),
                deadline_ms: Some(G1_RENDERER_CALL_DEADLINE_MILLIS),
                trace_parent: None,
            },
            &self.limits,
        )?;
        self.accepted_requests.insert(invocation.request_id());
        Ok(AuthorizedRendererCall {
            page_request_id: invocation.request_id(),
            envelope,
            call,
        })
    }
}

/// Rejected renderer message or failed host-authority derivation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RendererBridgeError {
    /// Navigation generation zero is reserved.
    #[error("renderer bridge navigation generation must be nonzero")]
    ZeroNavigationGeneration,
    /// The backend-observed document source was outside the bound private origin.
    #[error("renderer message source does not match the active private origin")]
    SourceMismatch,
    /// The page message did not carry the active document-start challenge.
    #[error("renderer bridge nonce does not match the active navigation")]
    NonceMismatch,
    /// One page-local request identity was reused within a navigation.
    #[error("renderer bridge request {request_id} was replayed")]
    RequestReplay {
        /// Replayed request.
        request_id: u64,
    },
    /// Accepted request identities exhausted the negotiated request budget.
    #[error("renderer bridge exceeds {maximum} accepted requests")]
    RequestBudgetExceeded {
        /// Negotiated ceiling.
        maximum: u32,
    },
    /// Origin parsing failed while deriving source authority.
    #[error(transparent)]
    Origin(#[from] PackageOriginError),
    /// Renderer envelope validation failed.
    #[error(transparent)]
    Renderer(#[from] RendererContractError),
    /// Runtime-call construction or protocol-limit validation failed.
    #[error(transparent)]
    Runtime(#[from] RuntimeProtocolContractError),
    /// Negotiated protocol limits were invalid.
    #[error(transparent)]
    Limits(#[from] weregopher_domain::ProtocolLimitError),
}
