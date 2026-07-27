//! Bounded pull observation and authority-reducing app-server interception.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
    hash::{Hash, Hasher},
    sync::Arc,
};

use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    AppServerExpiredRequest, AppServerMessageObservation, AppServerProxyDirection,
    AppServerProxyMessageKind, AppServerRequestId,
};

const ABSOLUTE_MAX_EVENTS: usize = 65_536;
const ABSOLUTE_MAX_RULES: usize = 256;
const ABSOLUTE_MAX_RULE_METHOD_BYTES: usize = 64 * 1_024;
const MAX_METHOD_BYTES: usize = 1_024;
const METHOD_FINGERPRINT_DOMAIN: &[u8] = b"weregopher.app-server-observed-method.v1\0";
const REQUEST_CORRELATION_DOMAIN: &[u8] = b"weregopher.app-server-observed-request.v1\0";

/// Resource ceiling for one in-memory redacted event journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppServerEventLimits {
    events: usize,
}

impl AppServerEventLimits {
    /// Constructs a nonzero event ceiling below the fixed hard maximum.
    ///
    /// # Errors
    ///
    /// Returns [`AppServerControlError::InvalidEventLimits`] for zero or more
    /// than 65,536 retained events.
    pub const fn new(events: usize) -> Result<Self, AppServerControlError> {
        if events == 0 || events > ABSOLUTE_MAX_EVENTS {
            return Err(AppServerControlError::InvalidEventLimits);
        }
        Ok(Self { events })
    }

    /// Returns the conservative initial retained-event ceiling.
    #[must_use]
    pub const fn initial() -> Self {
        Self { events: 2_048 }
    }

    /// Returns the maximum number of queued redacted events.
    #[must_use]
    pub const fn max_events(self) -> usize {
        self.events
    }
}

/// Content identity for a bounded method name without retaining that name.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AppServerMethodFingerprint {
    digest: [u8; 32],
    byte_length: usize,
}

impl fmt::Debug for AppServerMethodFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppServerMethodFingerprint")
            .field("byte_length", &self.byte_length)
            .finish_non_exhaustive()
    }
}

impl AppServerMethodFingerprint {
    /// Fingerprints one valid bounded method name for redacted comparison.
    ///
    /// # Errors
    ///
    /// Returns [`AppServerControlError::InvalidMethod`] when the name is empty,
    /// exceeds 1,024 bytes, or contains control text.
    pub fn for_method(method: &str) -> Result<Self, AppServerControlError> {
        validate_method(method)?;
        let mut digest = Sha256::new();
        digest.update(METHOD_FINGERPRINT_DOMAIN);
        digest.update(method.as_bytes());
        Ok(Self {
            digest: digest.finalize().into(),
            byte_length: method.len(),
        })
    }

    /// Returns the domain-separated method digest.
    ///
    /// The digest is pseudonymous comparison data, not proof that the method
    /// was safe, supported, authorized, or secret.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Returns the original method-name byte length.
    #[must_use]
    pub const fn byte_length(&self) -> usize {
        self.byte_length
    }
}

/// Journal-local request lifecycle identity unrelated to the wire request ID.
#[derive(Clone)]
pub struct AppServerCorrelationToken {
    journal: Arc<JournalIdentity>,
    sequence: u64,
}

impl AppServerCorrelationToken {
    /// Returns the journal-local monotonic token.
    #[must_use]
    pub const fn get(&self) -> u64 {
        self.sequence
    }

    /// Reports whether two tokens came from the same in-process journal.
    pub(crate) fn belongs_to_same_journal(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.journal, &other.journal)
    }
}

impl fmt::Debug for AppServerCorrelationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AppServerCorrelationToken")
            .field(&self.sequence)
            .finish()
    }
}

impl PartialEq for AppServerCorrelationToken {
    fn eq(&self, other: &Self) -> bool {
        self.sequence == other.sequence && Arc::ptr_eq(&self.journal, &other.journal)
    }
}

impl Eq for AppServerCorrelationToken {}

impl PartialOrd for AppServerCorrelationToken {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AppServerCorrelationToken {
    fn cmp(&self, other: &Self) -> Ordering {
        Arc::as_ptr(&self.journal)
            .cmp(&Arc::as_ptr(&other.journal))
            .then_with(|| self.sequence.cmp(&other.sequence))
    }
}

impl Hash for AppServerCorrelationToken {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::ptr::hash(Arc::as_ptr(&self.journal), state);
        self.sequence.hash(state);
    }
}

struct JournalIdentity {
    _marker: u8,
}

/// Stage at which one structurally valid message was observed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AppServerEventStage {
    /// The exact frame entered a transparent proxy queue.
    Accepted,
    /// The exact frame left its transparent proxy queue toward its peer.
    Forwarded,
    /// An exact authority-reducing rule denied admission.
    Blocked,
}

/// Redacted fixed-shape metadata for one app-server protocol message.
#[derive(Clone, Eq, PartialEq)]
pub struct AppServerRedactedMessage {
    stage: AppServerEventStage,
    direction: AppServerProxyDirection,
    kind: AppServerProxyMessageKind,
    method: Option<AppServerMethodFingerprint>,
    correlation: Option<AppServerCorrelationToken>,
    byte_length: usize,
    block_rule: Option<AppServerInterceptRuleId>,
}

impl fmt::Debug for AppServerRedactedMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppServerRedactedMessage")
            .field("stage", &self.stage)
            .field("direction", &self.direction)
            .field("kind", &self.kind)
            .field("method", &self.method)
            .field("correlation", &self.correlation)
            .field("byte_length", &self.byte_length)
            .field("block_rule", &self.block_rule)
            .finish()
    }
}

impl AppServerRedactedMessage {
    /// Returns the observation stage.
    #[must_use]
    pub const fn stage(&self) -> AppServerEventStage {
        self.stage
    }

    /// Returns the message travel direction.
    #[must_use]
    pub const fn direction(&self) -> AppServerProxyDirection {
        self.direction
    }

    /// Returns the structural message class.
    #[must_use]
    pub const fn kind(&self) -> AppServerProxyMessageKind {
        self.kind
    }

    /// Returns the pseudonymous method fingerprint for method-bearing messages.
    #[must_use]
    pub const fn method(&self) -> Option<&AppServerMethodFingerprint> {
        self.method.as_ref()
    }

    /// Returns the journal-local lifecycle token for a correlated request.
    #[must_use]
    pub fn correlation(&self) -> Option<AppServerCorrelationToken> {
        self.correlation.clone()
    }

    /// Returns the exact delimiter-free message byte length.
    #[must_use]
    pub const fn byte_length(&self) -> usize {
        self.byte_length
    }

    /// Returns the exact rule that blocked this candidate, when applicable.
    #[must_use]
    pub const fn block_rule(&self) -> Option<AppServerInterceptRuleId> {
        self.block_rule
    }
}

/// Redacted expiration of one previously forwarded request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppServerRequestExpiredEvent {
    origin: AppServerProxyDirection,
    correlation: AppServerCorrelationToken,
}

impl AppServerRequestExpiredEvent {
    /// Returns the direction in which the request originated.
    #[must_use]
    pub const fn origin(&self) -> AppServerProxyDirection {
        self.origin
    }

    /// Returns the journal-local request lifecycle token.
    #[must_use]
    pub fn correlation(&self) -> AppServerCorrelationToken {
        self.correlation.clone()
    }
}

/// Payload-free detail retained by one bounded session event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppServerEventDetail {
    /// A structurally valid accepted, forwarded, or blocked message.
    Message(AppServerRedactedMessage),
    /// A forwarded request reached its response deadline.
    RequestExpired(AppServerRequestExpiredEvent),
}

/// One monotonically ordered redacted session event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppServerSessionEvent {
    sequence: u64,
    detail: AppServerEventDetail,
}

impl AppServerSessionEvent {
    /// Returns the journal-local monotonic sequence, beginning at one.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the payload-free event detail.
    #[must_use]
    pub const fn detail(&self) -> &AppServerEventDetail {
        &self.detail
    }
}

/// Current bounded event and correlation accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppServerEventDiagnostics {
    queued_events: usize,
    max_events: usize,
    evicted_events: u64,
    active_correlations: usize,
    pending_response_correlations: usize,
}

impl AppServerEventDiagnostics {
    /// Returns events currently available through the pull interface.
    #[must_use]
    pub const fn queued_events(self) -> usize {
        self.queued_events
    }

    /// Returns the configured retained-event ceiling.
    #[must_use]
    pub const fn max_events(self) -> usize {
        self.max_events
    }

    /// Returns oldest events explicitly evicted at the bounded ceiling.
    #[must_use]
    pub const fn evicted_events(self) -> u64 {
        self.evicted_events
    }

    /// Returns request correlations awaiting a response or expiration.
    #[must_use]
    pub const fn active_correlations(self) -> usize {
        self.active_correlations
    }

    /// Returns completed responses admitted but not yet forwarded.
    #[must_use]
    pub const fn pending_response_correlations(self) -> usize {
        self.pending_response_correlations
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct RequestCorrelationKey {
    origin: AppServerProxyDirection,
    digest: [u8; 32],
}

/// Bounded pull journal for redacted proxy lifecycle observations.
///
/// No callback or caller code executes on the transport path. At capacity the
/// oldest fixed-shape event is evicted and an exact loss counter advances;
/// protocol frames are never dropped or altered by journal pressure.
pub struct AppServerSessionEventJournal {
    limits: AppServerEventLimits,
    identity: Arc<JournalIdentity>,
    events: VecDeque<AppServerSessionEvent>,
    evicted_events: u64,
    last_sequence: u64,
    last_correlation: u64,
    active_correlations: BTreeMap<RequestCorrelationKey, AppServerCorrelationToken>,
    pending_responses: BTreeMap<RequestCorrelationKey, AppServerCorrelationToken>,
}

impl fmt::Debug for AppServerSessionEventJournal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppServerSessionEventJournal")
            .field("diagnostics", &self.diagnostics())
            .finish_non_exhaustive()
    }
}

impl AppServerSessionEventJournal {
    /// Constructs an empty journal from validated limits.
    #[must_use]
    pub fn new(limits: AppServerEventLimits) -> Self {
        Self {
            limits,
            identity: Arc::new(JournalIdentity { _marker: 0 }),
            events: VecDeque::new(),
            evicted_events: 0,
            last_sequence: 0,
            last_correlation: 0,
            active_correlations: BTreeMap::new(),
            pending_responses: BTreeMap::new(),
        }
    }

    /// Records one frame after successful proxy admission.
    ///
    /// # Errors
    ///
    /// Returns an overflow or lifecycle-consistency error. Callers must invoke
    /// this exactly once for every successful proxy admission.
    pub fn record_accepted(
        &mut self,
        observation: &AppServerMessageObservation,
    ) -> Result<(), AppServerControlError> {
        let method = fingerprint_observed_method(observation)?;
        let sequence = self.preflight_event_sequence()?;
        let correlation = match observation.kind() {
            AppServerProxyMessageKind::Request => {
                let key = request_key(observation)
                    .ok_or(AppServerControlError::InconsistentCorrelationState)?;
                if self.active_correlations.contains_key(&key)
                    || self.pending_responses.contains_key(&key)
                {
                    return Err(AppServerControlError::InconsistentCorrelationState);
                }
                let token = AppServerCorrelationToken {
                    journal: Arc::clone(&self.identity),
                    sequence: self
                        .last_correlation
                        .checked_add(1)
                        .ok_or(AppServerControlError::CorrelationSequenceOverflow)?,
                };
                self.active_correlations.insert(key, token.clone());
                self.last_correlation = token.sequence;
                Some(token)
            }
            AppServerProxyMessageKind::SuccessResponse
            | AppServerProxyMessageKind::ErrorResponse => {
                let Some(key) = request_key(observation) else {
                    self.push_message(
                        sequence,
                        AppServerEventStage::Accepted,
                        observation,
                        method,
                        None,
                        None,
                    )?;
                    return Ok(());
                };
                let Some(token) = self.active_correlations.remove(&key) else {
                    self.push_message(
                        sequence,
                        AppServerEventStage::Accepted,
                        observation,
                        method,
                        None,
                        None,
                    )?;
                    return Ok(());
                };
                if self.pending_responses.insert(key, token.clone()).is_some() {
                    return Err(AppServerControlError::InconsistentCorrelationState);
                }
                Some(token)
            }
            AppServerProxyMessageKind::Notification => None,
        };
        self.push_message(
            sequence,
            AppServerEventStage::Accepted,
            observation,
            method,
            correlation,
            None,
        )
    }

    /// Records one frame after it leaves its proxy queue.
    ///
    /// # Errors
    ///
    /// Returns an overflow or lifecycle-consistency error. Callers must invoke
    /// this exactly once for every frame released by the proxy.
    pub fn record_forwarded(
        &mut self,
        observation: &AppServerMessageObservation,
    ) -> Result<(), AppServerControlError> {
        let method = fingerprint_observed_method(observation)?;
        let sequence = self.preflight_event_sequence()?;
        let correlation = match observation.kind() {
            AppServerProxyMessageKind::Request => {
                let key = request_key(observation)
                    .ok_or(AppServerControlError::InconsistentCorrelationState)?;
                Some(
                    self.active_correlations
                        .get(&key)
                        .cloned()
                        .ok_or(AppServerControlError::InconsistentCorrelationState)?,
                )
            }
            AppServerProxyMessageKind::SuccessResponse
            | AppServerProxyMessageKind::ErrorResponse => {
                request_key(observation).and_then(|key| self.pending_responses.remove(&key))
            }
            AppServerProxyMessageKind::Notification => None,
        };
        self.push_message(
            sequence,
            AppServerEventStage::Forwarded,
            observation,
            method,
            correlation,
            None,
        )
    }

    /// Records one structurally valid candidate denied before proxy admission.
    ///
    /// A blocked candidate cannot create or complete a request correlation.
    ///
    /// # Errors
    ///
    /// Returns an event-sequence or eviction-counter overflow.
    pub fn record_blocked(
        &mut self,
        observation: &AppServerMessageObservation,
        rule: AppServerInterceptRuleId,
    ) -> Result<(), AppServerControlError> {
        let method = fingerprint_observed_method(observation)?;
        let sequence = self.preflight_event_sequence()?;
        self.push_message(
            sequence,
            AppServerEventStage::Blocked,
            observation,
            method,
            None,
            Some(rule),
        )
    }

    /// Records one request returned by proxy deadline expiration.
    ///
    /// # Errors
    ///
    /// Returns an overflow or lifecycle-consistency error.
    pub fn record_expired(
        &mut self,
        expired: &AppServerExpiredRequest,
    ) -> Result<(), AppServerControlError> {
        let sequence = self.preflight_event_sequence()?;
        let key = request_key_from_parts(expired.origin(), expired.request_id());
        let correlation = self
            .active_correlations
            .remove(&key)
            .ok_or(AppServerControlError::InconsistentCorrelationState)?;
        self.push_event(
            sequence,
            AppServerEventDetail::RequestExpired(AppServerRequestExpiredEvent {
                origin: expired.origin(),
                correlation,
            }),
        )
    }

    /// Returns and removes the oldest retained redacted event.
    pub fn next_event(&mut self) -> Option<AppServerSessionEvent> {
        self.events.pop_front()
    }

    /// Clears transient request-correlation state without discarding events.
    ///
    /// A process/session owner calls this when the proxy closes or is replaced.
    pub fn clear_correlations(&mut self) {
        self.active_correlations.clear();
        self.pending_responses.clear();
    }

    /// Returns bounded event and private-correlation accounting.
    #[must_use]
    pub fn diagnostics(&self) -> AppServerEventDiagnostics {
        AppServerEventDiagnostics {
            queued_events: self.events.len(),
            max_events: self.limits.events,
            evicted_events: self.evicted_events,
            active_correlations: self.active_correlations.len(),
            pending_response_correlations: self.pending_responses.len(),
        }
    }

    fn preflight_event_sequence(&self) -> Result<u64, AppServerControlError> {
        let sequence = self
            .last_sequence
            .checked_add(1)
            .ok_or(AppServerControlError::EventSequenceOverflow)?;
        if self.events.len() == self.limits.events {
            self.evicted_events
                .checked_add(1)
                .ok_or(AppServerControlError::EventEvictionOverflow)?;
        }
        Ok(sequence)
    }

    fn push_message(
        &mut self,
        sequence: u64,
        stage: AppServerEventStage,
        observation: &AppServerMessageObservation,
        method: Option<AppServerMethodFingerprint>,
        correlation: Option<AppServerCorrelationToken>,
        block_rule: Option<AppServerInterceptRuleId>,
    ) -> Result<(), AppServerControlError> {
        self.push_event(
            sequence,
            AppServerEventDetail::Message(AppServerRedactedMessage {
                stage,
                direction: observation.direction(),
                kind: observation.kind(),
                method,
                correlation,
                byte_length: observation.byte_length(),
                block_rule,
            }),
        )
    }

    fn push_event(
        &mut self,
        sequence: u64,
        detail: AppServerEventDetail,
    ) -> Result<(), AppServerControlError> {
        if self.events.len() == self.limits.events {
            let removed = self.events.pop_front();
            if removed.is_none() {
                return Err(AppServerControlError::InconsistentEventState);
            }
            self.evicted_events = self
                .evicted_events
                .checked_add(1)
                .ok_or(AppServerControlError::EventEvictionOverflow)?;
        }
        self.events
            .push_back(AppServerSessionEvent { sequence, detail });
        self.last_sequence = sequence;
        Ok(())
    }
}

/// Stable caller-chosen identity for one authority-reducing rule.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AppServerInterceptRuleId(u32);

impl AppServerInterceptRuleId {
    /// Constructs a nonzero local rule identity.
    ///
    /// # Errors
    ///
    /// Returns [`AppServerControlError::InvalidRuleId`] for zero.
    pub const fn new(value: u32) -> Result<Self, AppServerControlError> {
        if value == 0 {
            return Err(AppServerControlError::InvalidRuleId);
        }
        Ok(Self(value))
    }

    /// Returns the caller-chosen numeric identity.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// One exact method-bearing candidate that must be blocked before admission.
#[derive(Clone, Eq, PartialEq)]
pub struct AppServerBlockRule {
    id: AppServerInterceptRuleId,
    direction: AppServerProxyDirection,
    kind: AppServerProxyMessageKind,
    method: String,
}

impl fmt::Debug for AppServerBlockRule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppServerBlockRule")
            .field("id", &self.id)
            .field("direction", &self.direction)
            .field("kind", &self.kind)
            .field("method_byte_length", &self.method.len())
            .finish_non_exhaustive()
    }
}

impl AppServerBlockRule {
    /// Constructs one exact request or notification block rule.
    ///
    /// # Errors
    ///
    /// Returns an invalid-method or non-method-message-kind error.
    pub fn new(
        id: AppServerInterceptRuleId,
        direction: AppServerProxyDirection,
        kind: AppServerProxyMessageKind,
        method: impl Into<String>,
    ) -> Result<Self, AppServerControlError> {
        if !matches!(
            kind,
            AppServerProxyMessageKind::Request | AppServerProxyMessageKind::Notification
        ) {
            return Err(AppServerControlError::InvalidRuleMessageKind);
        }
        let method = method.into();
        validate_method(&method)?;
        Ok(Self {
            id,
            direction,
            kind,
            method,
        })
    }

    /// Returns the local rule identity.
    #[must_use]
    pub const fn id(&self) -> AppServerInterceptRuleId {
        self.id
    }
}

/// Result of evaluating a structurally valid candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppServerInterceptionDecision {
    /// Preserve and admit the original exact bytes.
    Forward,
    /// Deny admission under one exact authority-reducing rule.
    Block(AppServerInterceptRuleId),
}

/// Bounded exact-match policy that can only preserve or reduce authority.
pub struct AppServerInterceptionPolicy {
    rules: Vec<AppServerBlockRule>,
    method_bytes: usize,
}

impl fmt::Debug for AppServerInterceptionPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppServerInterceptionPolicy")
            .field("rule_count", &self.rules.len())
            .field("method_bytes", &self.method_bytes)
            .finish_non_exhaustive()
    }
}

impl AppServerInterceptionPolicy {
    /// Validates unique rule identities and exact selectors under fixed bounds.
    ///
    /// # Errors
    ///
    /// Returns an explicit rule-count, aggregate-byte, or duplicate error.
    pub fn new(rules: Vec<AppServerBlockRule>) -> Result<Self, AppServerControlError> {
        if rules.len() > ABSOLUTE_MAX_RULES {
            return Err(AppServerControlError::TooManyRules);
        }
        let mut ids = BTreeSet::new();
        let mut selectors = BTreeSet::new();
        let mut method_bytes = 0_usize;
        for rule in &rules {
            if !ids.insert(rule.id) {
                return Err(AppServerControlError::DuplicateRuleId);
            }
            method_bytes = method_bytes
                .checked_add(rule.method.len())
                .ok_or(AppServerControlError::RuleMethodBytesExceeded)?;
            if method_bytes > ABSOLUTE_MAX_RULE_METHOD_BYTES {
                return Err(AppServerControlError::RuleMethodBytesExceeded);
            }
            if !selectors.insert((
                rule.direction,
                message_kind_code(rule.kind),
                rule.method.clone(),
            )) {
                return Err(AppServerControlError::DuplicateRuleSelector);
            }
        }
        Ok(Self {
            rules,
            method_bytes,
        })
    }

    /// Returns an empty pass-through policy.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            rules: Vec::new(),
            method_bytes: 0,
        }
    }

    /// Evaluates exact structural metadata without inspecting message payloads.
    #[must_use]
    pub fn evaluate(
        &self,
        observation: &AppServerMessageObservation,
    ) -> AppServerInterceptionDecision {
        let Some(method) = observation.method() else {
            return AppServerInterceptionDecision::Forward;
        };
        self.rules
            .iter()
            .find(|rule| {
                rule.direction == observation.direction()
                    && rule.kind == observation.kind()
                    && rule.method == method
            })
            .map_or(AppServerInterceptionDecision::Forward, |rule| {
                AppServerInterceptionDecision::Block(rule.id)
            })
    }

    /// Returns the number of exact block rules.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

/// Bounded observation or authority-reducing policy construction failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AppServerControlError {
    /// The retained event ceiling was zero or above its hard maximum.
    #[error("invalid app-server event limits")]
    InvalidEventLimits,
    /// A method was empty, oversized, or contained control text.
    #[error("invalid app-server control method")]
    InvalidMethod,
    /// A rule identity was zero.
    #[error("invalid app-server interception rule identity")]
    InvalidRuleId,
    /// A block rule selected a response, which has no method.
    #[error("app-server block rules require a request or notification")]
    InvalidRuleMessageKind,
    /// More than the fixed rule-count maximum was supplied.
    #[error("app-server interception policy exceeds its rule limit")]
    TooManyRules,
    /// Exact rule methods exceeded their aggregate byte ceiling.
    #[error("app-server interception policy exceeds its method-byte limit")]
    RuleMethodBytesExceeded,
    /// Two rules used the same local identity.
    #[error("app-server interception policy contains a duplicate rule identity")]
    DuplicateRuleId,
    /// Two rules selected the same direction, kind, and exact method.
    #[error("app-server interception policy contains a duplicate selector")]
    DuplicateRuleSelector,
    /// Event ordering exceeded its numeric representation.
    #[error("app-server event sequence overflowed")]
    EventSequenceOverflow,
    /// Journal-local request correlation exceeded its numeric representation.
    #[error("app-server correlation sequence overflowed")]
    CorrelationSequenceOverflow,
    /// Explicit oldest-event eviction accounting overflowed.
    #[error("app-server event eviction counter overflowed")]
    EventEvictionOverflow,
    /// Observer request transitions contradicted proxy lifecycle ordering.
    #[error("app-server observer correlation state is inconsistent")]
    InconsistentCorrelationState,
    /// Event capacity accounting contradicted the journal queue.
    #[error("app-server observer event state is inconsistent")]
    InconsistentEventState,
}

fn fingerprint_observed_method(
    observation: &AppServerMessageObservation,
) -> Result<Option<AppServerMethodFingerprint>, AppServerControlError> {
    observation
        .method()
        .map(AppServerMethodFingerprint::for_method)
        .transpose()
}

fn validate_method(method: &str) -> Result<(), AppServerControlError> {
    if method.is_empty() || method.len() > MAX_METHOD_BYTES || method.chars().any(char::is_control)
    {
        Err(AppServerControlError::InvalidMethod)
    } else {
        Ok(())
    }
}

fn request_key(observation: &AppServerMessageObservation) -> Option<RequestCorrelationKey> {
    let request_id = observation.request_id()?;
    let origin = match observation.kind() {
        AppServerProxyMessageKind::Request => observation.direction(),
        AppServerProxyMessageKind::SuccessResponse | AppServerProxyMessageKind::ErrorResponse => {
            opposite(observation.direction())
        }
        AppServerProxyMessageKind::Notification => return None,
    };
    Some(request_key_from_parts(origin, request_id))
}

fn request_key_from_parts(
    origin: AppServerProxyDirection,
    request_id: &AppServerRequestId,
) -> RequestCorrelationKey {
    let mut digest = Sha256::new();
    digest.update(REQUEST_CORRELATION_DOMAIN);
    digest.update([direction_code(origin)]);
    match request_id {
        AppServerRequestId::Unsigned(value) => {
            digest.update([0]);
            digest.update(value.to_be_bytes());
        }
        AppServerRequestId::Signed(value) => {
            digest.update([1]);
            digest.update(value.to_be_bytes());
        }
        AppServerRequestId::Text(value) => {
            digest.update([2]);
            digest.update(value.len().to_be_bytes());
            digest.update(value.as_bytes());
        }
    }
    RequestCorrelationKey {
        origin,
        digest: digest.finalize().into(),
    }
}

const fn opposite(direction: AppServerProxyDirection) -> AppServerProxyDirection {
    match direction {
        AppServerProxyDirection::ClientToServer => AppServerProxyDirection::ServerToClient,
        AppServerProxyDirection::ServerToClient => AppServerProxyDirection::ClientToServer,
    }
}

const fn direction_code(direction: AppServerProxyDirection) -> u8 {
    match direction {
        AppServerProxyDirection::ClientToServer => 0,
        AppServerProxyDirection::ServerToClient => 1,
    }
}

const fn message_kind_code(kind: AppServerProxyMessageKind) -> u8 {
    match kind {
        AppServerProxyMessageKind::Request => 0,
        AppServerProxyMessageKind::Notification => 1,
        AppServerProxyMessageKind::SuccessResponse => 2,
        AppServerProxyMessageKind::ErrorResponse => 3,
    }
}
