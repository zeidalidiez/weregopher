//! Authenticated handshake and bounded per-session state machines.

use std::{
    collections::BTreeMap,
    fmt,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use thiserror::Error;
use weregopher_domain::{
    AppInstanceId, CompatibilityAnalysisDigest, HeartbeatPolicy, ProtocolFeatures, ProtocolLimits,
    ProtocolSessionId, ProtocolVersionRange, RuntimeBackendIdentity, RuntimeHello, RuntimeId,
    RuntimeProtocolContractError, RuntimeWelcome,
};

const NONCE_PROOF_DOMAIN: &[u8] = b"weregopher.runtime-protocol.nonce-proof.v1\0";

/// A one-use, nonzero 256-bit host challenge delivered outside the protocol transport.
#[derive(Eq, PartialEq)]
pub struct NonceChallenge([u8; 32]);

impl NonceChallenge {
    /// Constructs a challenge from cryptographically random bytes supplied by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`NonceChallengeError::AllZero`] for the sentinel all-zero value.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, NonceChallengeError> {
        if bytes == [0_u8; 32] {
            Err(NonceChallengeError::AllZero)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Returns challenge bytes for protected delivery or proof construction.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for NonceChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NonceChallenge([REDACTED])")
    }
}

/// An invalid out-of-band handshake challenge.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NonceChallengeError {
    /// The all-zero sentinel is never issued.
    #[error("nonce challenge must not be all zero")]
    AllZero,
}

/// Derives the protocol's domain-separated proof of nonce possession and peer identity.
#[must_use]
pub fn nonce_possession_proof(
    nonce: &NonceChallenge,
    runtime: RuntimeId,
    app: AppInstanceId,
    backend: &RuntimeBackendIdentity,
    peer_pid: u32,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(NONCE_PROOF_DOMAIN);
    digest.update(nonce.as_bytes());
    digest.update(runtime.as_uuid().as_bytes());
    digest.update(app.as_uuid().as_bytes());
    update_length_prefixed(&mut digest, backend.id().as_str().as_bytes());
    update_length_prefixed(&mut digest, backend.version().as_bytes());
    digest.update(peer_pid.to_le_bytes());
    digest.finalize().into()
}

fn update_length_prefixed(digest: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
    digest.update(length.to_le_bytes());
    digest.update(value);
}

/// One-use host-side handshake verifier and negotiation policy.
pub struct HostHandshake {
    nonce: NonceChallenge,
    expected_peer_pid: u32,
    runtime: RuntimeId,
    app: AppInstanceId,
    backend: RuntimeBackendIdentity,
    versions: ProtocolVersionRange,
    features: ProtocolFeatures,
    hard_limits: ProtocolLimits,
    session: ProtocolSessionId,
    compatibility: CompatibilityAnalysisDigest,
    heartbeat: HeartbeatPolicy,
}

impl HostHandshake {
    /// Creates one verifier bound to the expected process and runtime identity.
    ///
    /// # Errors
    ///
    /// Returns an error for PID zero or invalid host limits.
    #[allow(
        clippy::too_many_arguments,
        reason = "the verifier explicitly binds every independent handshake input"
    )]
    pub fn new(
        nonce: NonceChallenge,
        expected_peer_pid: u32,
        runtime: RuntimeId,
        app: AppInstanceId,
        backend: RuntimeBackendIdentity,
        versions: ProtocolVersionRange,
        features: ProtocolFeatures,
        hard_limits: ProtocolLimits,
        session: ProtocolSessionId,
        compatibility: CompatibilityAnalysisDigest,
        heartbeat: HeartbeatPolicy,
    ) -> Result<Self, HandshakeError> {
        if expected_peer_pid == 0 {
            return Err(HandshakeError::ZeroPeerPid);
        }
        hard_limits.validate()?;
        Ok(Self {
            nonce,
            expected_peer_pid,
            runtime,
            app,
            backend,
            versions,
            features,
            hard_limits,
            session,
            compatibility,
            heartbeat,
        })
    }

    /// Authenticates a hello and returns the exact negotiated welcome.
    ///
    /// Consuming `self` makes each nonce verifier single-use.
    ///
    /// # Errors
    ///
    /// Returns an error for any observed/expected process or runtime identity
    /// mismatch, a bad nonce proof, incompatible version, or invalid limits.
    pub fn negotiate(
        self,
        hello: &RuntimeHello,
        observed_peer_pid: u32,
    ) -> Result<RuntimeWelcome, HandshakeError> {
        if observed_peer_pid != self.expected_peer_pid {
            return Err(HandshakeError::ObservedPeerPidMismatch {
                expected: self.expected_peer_pid,
                actual: observed_peer_pid,
            });
        }
        if hello.runtime() != self.runtime
            || hello.app() != self.app
            || hello.backend() != &self.backend
        {
            return Err(HandshakeError::RuntimeIdentityMismatch);
        }
        let expected_proof = nonce_possession_proof(
            &self.nonce,
            self.runtime,
            self.app,
            &self.backend,
            observed_peer_pid,
        );
        if hello.nonce_proof() != &expected_proof {
            return Err(HandshakeError::NonceProofMismatch);
        }
        let version = self
            .versions
            .negotiate(&hello.protocol_range())
            .ok_or(HandshakeError::NoCompatibleVersion)?;
        let limits = hello.requested_limits().negotiate(&self.hard_limits)?;
        let features = hello.capabilities().negotiate(self.features);
        RuntimeWelcome::new(
            self.session,
            version,
            limits,
            self.compatibility,
            self.heartbeat,
            features,
        )
        .map_err(HandshakeError::InvalidWelcome)
    }
}

/// One-use worker-side verifier for the host's selected protocol parameters.
pub struct WorkerHandshake {
    versions: ProtocolVersionRange,
    offered_features: ProtocolFeatures,
    requested_limits: ProtocolLimits,
}

impl WorkerHandshake {
    /// Captures the exact negotiation offer from a validated hello.
    #[must_use]
    pub fn from_hello(hello: &RuntimeHello) -> Self {
        Self {
            versions: hello.protocol_range(),
            offered_features: hello.capabilities(),
            requested_limits: hello.requested_limits(),
        }
    }

    /// Verifies that a welcome only narrows the worker's original offer.
    ///
    /// Consuming `self` prevents accidentally applying one offer verifier to
    /// multiple sessions.
    ///
    /// # Errors
    ///
    /// Returns an error when the host selects an unsupported version, enables
    /// an unoffered feature, or raises any requested limit.
    pub fn accept(self, welcome: &RuntimeWelcome) -> Result<(), WorkerHandshakeError> {
        let selected = welcome.version();
        if selected.major() != self.versions.minimum().major()
            || selected.minor() < self.versions.minimum().minor()
            || selected.minor() > self.versions.maximum().minor()
        {
            return Err(WorkerHandshakeError::UnsupportedVersion);
        }
        if !features_are_subset(welcome.features(), self.offered_features) {
            return Err(WorkerHandshakeError::FeaturesExpanded);
        }
        let bounded = welcome.limits().negotiate(&self.requested_limits)?;
        if bounded != welcome.limits() {
            return Err(WorkerHandshakeError::LimitsExpanded);
        }
        Ok(())
    }
}

fn features_are_subset(selected: ProtocolFeatures, offered: ProtocolFeatures) -> bool {
    (!selected.calls || offered.calls)
        && (!selected.cancellation || offered.cancellation)
        && (!selected.events || offered.events)
        && (!selected.credit_streams || offered.credit_streams)
        && (!selected.sync_lane || offered.sync_lane)
        && (!selected.shared_buffers || offered.shared_buffers)
}

/// A host welcome that expanded or escaped the worker's hello offer.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkerHandshakeError {
    /// The selected version was outside the offered inclusive range.
    #[error("host selected a protocol version outside the worker offer")]
    UnsupportedVersion,
    /// The host enabled at least one feature the worker did not offer.
    #[error("host enabled a protocol feature the worker did not offer")]
    FeaturesExpanded,
    /// At least one selected limit exceeded the worker request.
    #[error("host selected a protocol limit above the worker request")]
    LimitsExpanded,
    /// The selected or requested limits contained a zero dimension.
    #[error(transparent)]
    InvalidLimits(#[from] weregopher_domain::ProtocolLimitError),
}

/// A failed host-side authenticated handshake.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HandshakeError {
    /// PID zero cannot identify a live Windows peer.
    #[error("expected peer PID must be nonzero")]
    ZeroPeerPid,
    /// The transport-reported peer process differed from the launched worker.
    #[error("transport peer PID {actual} does not match expected PID {expected}")]
    ObservedPeerPidMismatch {
        /// Launched worker PID.
        expected: u32,
        /// Transport-observed PID.
        actual: u32,
    },
    /// Runtime, app, or backend identity differed.
    #[error("runtime handshake identity does not match the launched worker")]
    RuntimeIdentityMismatch,
    /// No supported protocol version overlapped.
    #[error("runtime and host have no compatible protocol version")]
    NoCompatibleVersion,
    /// The nonce proof did not bind this exact identity and PID.
    #[error("runtime nonce-possession proof does not match")]
    NonceProofMismatch,
    /// A requested or host limit was zero.
    #[error(transparent)]
    InvalidLimits(#[from] weregopher_domain::ProtocolLimitError),
    /// Negotiated welcome construction failed.
    #[error("negotiated welcome is invalid: {0}")]
    InvalidWelcome(#[source] RuntimeProtocolContractError),
}

#[derive(Clone, Copy, Debug)]
struct PendingRequest {
    deadline: Instant,
    cancelled: bool,
}

/// Result of an idempotent cancellation transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestCancellation {
    /// The request transitioned from active to cancelled.
    NewlyCancelled,
    /// The request was already cancelled.
    AlreadyCancelled,
}

/// Disposition of a response for a tracked request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallCompletion {
    /// The response can be delivered to the caller.
    Delivered,
    /// Cancellation won and the late response must be discarded.
    DiscardedAfterCancellation,
}

/// Bounded request IDs, deadlines, cancellation, and late-result disposition.
pub struct PendingRequests {
    maximum: u32,
    next_request_id: u64,
    requests: BTreeMap<u64, PendingRequest>,
}

impl PendingRequests {
    /// Constructs an empty request set.
    ///
    /// # Errors
    ///
    /// Returns [`PendingRequestError::ZeroMaximum`] when no request could be added.
    pub const fn new(maximum: u32) -> Result<Self, PendingRequestError> {
        if maximum == 0 {
            return Err(PendingRequestError::ZeroMaximum);
        }
        Ok(Self {
            maximum,
            next_request_id: 1,
            requests: BTreeMap::new(),
        })
    }

    /// Allocates a new nonzero request ID with a relative deadline.
    ///
    /// # Errors
    ///
    /// Returns an error when full, the timeout is zero, deadline arithmetic
    /// overflows, or request ID space is exhausted.
    pub fn begin(&mut self, now: Instant, timeout: Duration) -> Result<u64, PendingRequestError> {
        if timeout.is_zero() {
            return Err(PendingRequestError::ZeroTimeout);
        }
        if self.requests.len() >= usize::try_from(self.maximum).unwrap_or(usize::MAX) {
            return Err(PendingRequestError::CapacityExceeded {
                maximum: self.maximum,
            });
        }
        let deadline = now
            .checked_add(timeout)
            .ok_or(PendingRequestError::DeadlineOverflow)?;
        let next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(PendingRequestError::RequestIdExhausted)?;
        let request_id = self.next_request_id;
        self.requests.insert(
            request_id,
            PendingRequest {
                deadline,
                cancelled: false,
            },
        );
        self.next_request_id = next_request_id;
        Ok(request_id)
    }

    /// Idempotently marks a live request cancelled.
    ///
    /// # Errors
    ///
    /// Returns [`PendingRequestError::UnknownRequest`] after completion or expiry.
    pub fn cancel(&mut self, request_id: u64) -> Result<RequestCancellation, PendingRequestError> {
        let request = self
            .requests
            .get_mut(&request_id)
            .ok_or(PendingRequestError::UnknownRequest { request_id })?;
        if request.cancelled {
            Ok(RequestCancellation::AlreadyCancelled)
        } else {
            request.cancelled = true;
            Ok(RequestCancellation::NewlyCancelled)
        }
    }

    /// Removes a completed request and determines whether to deliver its response.
    ///
    /// # Errors
    ///
    /// Returns [`PendingRequestError::UnknownRequest`] after prior completion or expiry.
    pub fn complete(&mut self, request_id: u64) -> Result<CallCompletion, PendingRequestError> {
        let request = self
            .requests
            .remove(&request_id)
            .ok_or(PendingRequestError::UnknownRequest { request_id })?;
        if request.cancelled {
            Ok(CallCompletion::DiscardedAfterCancellation)
        } else {
            Ok(CallCompletion::Delivered)
        }
    }

    /// Removes and returns every request whose deadline is at or before `now`.
    #[must_use]
    pub fn expire(&mut self, now: Instant) -> Vec<u64> {
        let expired: Vec<_> = self
            .requests
            .iter()
            .filter_map(|(request_id, request)| (request.deadline <= now).then_some(*request_id))
            .collect();
        for request_id in &expired {
            self.requests.remove(request_id);
        }
        expired
    }

    /// Whether no unresolved request remains.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    /// Number of unresolved requests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.requests.len()
    }
}

/// An invalid pending-request state transition.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PendingRequestError {
    /// At least one pending request must be permitted.
    #[error("pending-request maximum must be nonzero")]
    ZeroMaximum,
    /// Relative request timeout must be positive.
    #[error("pending-request timeout must be nonzero")]
    ZeroTimeout,
    /// The deadline could not be represented by [`Instant`].
    #[error("pending-request deadline overflowed")]
    DeadlineOverflow,
    /// All configured request slots are occupied.
    #[error("pending requests reached configured maximum {maximum}")]
    CapacityExceeded {
        /// Configured maximum.
        maximum: u32,
    },
    /// The monotonic nonzero request ID space was exhausted.
    #[error("request ID space is exhausted")]
    RequestIdExhausted,
    /// The request is not live.
    #[error("request {request_id} is not pending")]
    UnknownRequest {
        /// Requested identity.
        request_id: u64,
    },
}

/// Receiver-granted byte credit and exact per-stream sequencing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamCredit {
    available: u64,
    next_sequence: u64,
}

impl StreamCredit {
    /// Starts a stream with nonzero byte credit and expected sequence one.
    ///
    /// # Errors
    ///
    /// Returns [`StreamCreditError::ZeroCredit`] for zero initial credit.
    pub const fn new(initial_credit: u64) -> Result<Self, StreamCreditError> {
        if initial_credit == 0 {
            Err(StreamCreditError::ZeroCredit)
        } else {
            Ok(Self {
                available: initial_credit,
                next_sequence: 1,
            })
        }
    }

    /// Remaining sender allowance in bytes.
    #[must_use]
    pub const fn available(self) -> u64 {
        self.available
    }

    /// Adds a nonzero receiver window grant.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or overflowing credit.
    pub fn grant(&mut self, additional: u64) -> Result<(), StreamCreditError> {
        if additional == 0 {
            return Err(StreamCreditError::ZeroCredit);
        }
        self.available = self
            .available
            .checked_add(additional)
            .ok_or(StreamCreditError::CreditOverflow)?;
        Ok(())
    }

    /// Consumes bytes at the next exact one-based stream sequence.
    ///
    /// Failed transitions leave both sequence and credit unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error for replay/gaps, empty data, credit overrun, or sequence
    /// exhaustion.
    pub fn consume(&mut self, sequence: u64, bytes: u64) -> Result<(), StreamCreditError> {
        if sequence != self.next_sequence {
            return Err(StreamCreditError::UnexpectedSequence {
                expected: self.next_sequence,
                actual: sequence,
            });
        }
        if bytes == 0 {
            return Err(StreamCreditError::EmptyData);
        }
        if bytes > self.available {
            return Err(StreamCreditError::CreditExceeded {
                available: self.available,
                requested: bytes,
            });
        }
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(StreamCreditError::SequenceExhausted)?;
        self.available -= bytes;
        self.next_sequence = next_sequence;
        Ok(())
    }
}

/// An invalid byte-credit or stream-sequence transition.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StreamCreditError {
    /// Credit grants must be nonzero.
    #[error("stream credit must be nonzero")]
    ZeroCredit,
    /// Stream data must consume at least one byte.
    #[error("stream data must not be empty")]
    EmptyData,
    /// A stream sequence was replayed or skipped.
    #[error("unexpected stream sequence {actual}; expected {expected}")]
    UnexpectedSequence {
        /// Next required sequence.
        expected: u64,
        /// Received sequence.
        actual: u64,
    },
    /// Sender attempted to exceed receiver-granted credit.
    #[error("stream requested {requested} bytes with only {available} credit")]
    CreditExceeded {
        /// Remaining credit.
        available: u64,
        /// Attempted byte count.
        requested: u64,
    },
    /// A grant overflowed the credit counter.
    #[error("stream credit overflowed")]
    CreditOverflow,
    /// Exact stream sequence space was exhausted.
    #[error("stream sequence space is exhausted")]
    SequenceExhausted,
}
