//! Non-authorizing Codex execution and owned-resource correlation.

use std::{collections::BTreeMap, fmt, mem};

use thiserror::Error;

use crate::AppServerCorrelationToken;

const ABSOLUTE_MAX_CORRELATIONS: usize = 65_536;
const ABSOLUTE_MAX_RESOURCES: usize = 65_536;
const MAX_EXECUTION_ID_BYTES: usize = 256;

/// Bounded thread, turn, and item identity derived by a semantic adapter.
///
/// Construction validates only shape and hierarchy. It does not prove that the
/// values came from a supported app-server schema, identify a live execution,
/// authorize an effect, or grant process ownership.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CodexExecutionIdentity {
    thread: Option<String>,
    turn: Option<String>,
    item: Option<String>,
}

impl fmt::Debug for CodexExecutionIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexExecutionIdentity")
            .field(
                "thread_id_byte_length",
                &self.thread.as_ref().map(String::len),
            )
            .field("turn_id_byte_length", &self.turn.as_ref().map(String::len))
            .field("item_id_byte_length", &self.item.as_ref().map(String::len))
            .finish()
    }
}

impl CodexExecutionIdentity {
    /// Constructs one app-, thread-, turn-, or item-scoped identity.
    ///
    /// A turn requires a thread and an item requires both a thread and turn.
    /// Each present identifier is nonempty, at most 256 bytes, and contains no
    /// control text.
    ///
    /// # Errors
    ///
    /// Returns an explicit identifier or hierarchy error.
    pub fn new(
        thread_id: Option<String>,
        turn_id: Option<String>,
        item_id: Option<String>,
    ) -> Result<Self, AppServerOwnershipError> {
        for value in [&thread_id, &turn_id, &item_id].into_iter().flatten() {
            validate_execution_id(value)?;
        }
        if turn_id.is_some() && thread_id.is_none()
            || item_id.is_some() && (thread_id.is_none() || turn_id.is_none())
        {
            return Err(AppServerOwnershipError::InvalidIdentityHierarchy);
        }
        Ok(Self {
            thread: thread_id,
            turn: turn_id,
            item: item_id,
        })
    }

    /// Returns the exact bounded thread identity, when present.
    #[must_use]
    pub fn thread_id(&self) -> Option<&str> {
        self.thread.as_deref()
    }

    /// Returns the exact bounded turn identity, when present.
    #[must_use]
    pub fn turn_id(&self) -> Option<&str> {
        self.turn.as_deref()
    }

    /// Returns the exact bounded item identity, when present.
    #[must_use]
    pub fn item_id(&self) -> Option<&str> {
        self.item.as_deref()
    }

    /// Reports whether the identity is application-scoped.
    #[must_use]
    pub const fn is_app_scoped(&self) -> bool {
        self.thread.is_none()
    }
}

/// Registry ceilings for live semantic correlations and resource labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppServerOwnershipLimits {
    correlations: usize,
    resources: usize,
}

impl AppServerOwnershipLimits {
    /// Constructs nonzero limits below the fixed hard ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`AppServerOwnershipError::InvalidLimits`] for zero or more
    /// than 65,536 correlations or resources.
    pub const fn new(
        correlations: usize,
        resources: usize,
    ) -> Result<Self, AppServerOwnershipError> {
        if correlations == 0
            || correlations > ABSOLUTE_MAX_CORRELATIONS
            || resources == 0
            || resources > ABSOLUTE_MAX_RESOURCES
        {
            return Err(AppServerOwnershipError::InvalidLimits);
        }
        Ok(Self {
            correlations,
            resources,
        })
    }

    /// Returns conservative initial ownership-label ceilings.
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            correlations: 4_096,
            resources: 4_096,
        }
    }

    /// Returns the maximum live semantic correlation bindings.
    #[must_use]
    pub const fn max_correlations(self) -> usize {
        self.correlations
    }

    /// Returns the maximum live owned-resource labels.
    #[must_use]
    pub const fn max_resources(self) -> usize {
        self.resources
    }
}

/// Caller-local opaque identity for one externally owned resource.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AppServerOwnedResourceId(u64);

impl AppServerOwnedResourceId {
    /// Constructs a nonzero caller-local resource identity.
    ///
    /// The value is a correlation label, not an operating-system process ID or
    /// handle and not authority to inspect, terminate, or mutate a resource.
    ///
    /// # Errors
    ///
    /// Returns [`AppServerOwnershipError::InvalidResourceId`] for zero.
    pub const fn new(value: u64) -> Result<Self, AppServerOwnershipError> {
        if value == 0 {
            return Err(AppServerOwnershipError::InvalidResourceId);
        }
        Ok(Self(value))
    }

    /// Returns the caller-local numeric label.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Semantic class of one externally owned resource.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AppServerOwnedResourceKind {
    /// A vendor or adapter helper process.
    HelperProcess,
    /// A local Model Context Protocol server process.
    McpProcess,
    /// A command process attributed by a semantic adapter.
    CommandProcess,
    /// A worktree or other transient filesystem workspace.
    Worktree,
    /// A browser automation or interactive browser session.
    BrowserSession,
    /// A remote Model Context Protocol connection.
    RemoteMcpConnection,
}

/// One semantic resource label without an operating-system handle or effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppServerOwnedResource {
    id: AppServerOwnedResourceId,
    kind: AppServerOwnedResourceKind,
    identity: CodexExecutionIdentity,
}

impl AppServerOwnedResource {
    /// Returns the caller-local resource identity.
    #[must_use]
    pub const fn id(&self) -> AppServerOwnedResourceId {
        self.id
    }

    /// Returns the semantic resource class.
    #[must_use]
    pub const fn kind(&self) -> AppServerOwnedResourceKind {
        self.kind
    }

    /// Returns the bounded semantic execution identity.
    #[must_use]
    pub const fn identity(&self) -> &CodexExecutionIdentity {
        &self.identity
    }
}

/// Resources and correlations removed from one completed semantic scope.
#[derive(Debug, Eq, PartialEq)]
pub struct AppServerOwnershipRelease {
    resources: Vec<AppServerOwnedResource>,
    released_correlations: usize,
}

impl AppServerOwnershipRelease {
    /// Returns resource labels that were inside the completed scope.
    ///
    /// These are cleanup candidates only. The result contains no process
    /// handle, authorization, sandbox proof, or termination authority.
    #[must_use]
    pub fn resources(&self) -> &[AppServerOwnedResource] {
        &self.resources
    }

    /// Returns semantic request bindings removed with the scope.
    #[must_use]
    pub const fn released_correlations(&self) -> usize {
        self.released_correlations
    }
}

/// Current non-authorizing ownership-label accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppServerOwnershipDiagnostics {
    correlations: usize,
    resources: usize,
    max_correlations: usize,
    max_resources: usize,
}

impl AppServerOwnershipDiagnostics {
    /// Returns live semantic request bindings.
    #[must_use]
    pub const fn correlations(self) -> usize {
        self.correlations
    }

    /// Returns live resource labels.
    #[must_use]
    pub const fn resources(self) -> usize {
        self.resources
    }

    /// Returns the semantic request-binding ceiling.
    #[must_use]
    pub const fn max_correlations(self) -> usize {
        self.max_correlations
    }

    /// Returns the resource-label ceiling.
    #[must_use]
    pub const fn max_resources(self) -> usize {
        self.max_resources
    }
}

/// Bounded non-authorizing semantic ownership registry.
///
/// This registry intentionally does not parse app-server payloads. A
/// schema-aware family adapter must derive and validate
/// [`CodexExecutionIdentity`] before binding it to a journal-local correlation.
/// Unknown transport data cannot create a binding. Registered resources are
/// labels only; the registry owns no process, filesystem, browser, or network
/// capability and performs no cleanup effect.
pub struct AppServerOwnershipRegistry {
    limits: AppServerOwnershipLimits,
    journal_anchor: Option<AppServerCorrelationToken>,
    correlations: BTreeMap<AppServerCorrelationToken, CodexExecutionIdentity>,
    resources: BTreeMap<AppServerOwnedResourceId, AppServerOwnedResource>,
}

impl fmt::Debug for AppServerOwnershipRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppServerOwnershipRegistry")
            .field("diagnostics", &self.diagnostics())
            .finish_non_exhaustive()
    }
}

impl AppServerOwnershipRegistry {
    /// Constructs an empty registry from validated limits.
    #[must_use]
    pub fn new(limits: AppServerOwnershipLimits) -> Self {
        Self {
            limits,
            journal_anchor: None,
            correlations: BTreeMap::new(),
            resources: BTreeMap::new(),
        }
    }

    /// Binds one journal-local request token to explicit semantic evidence.
    ///
    /// The first binding permanently pins this registry to that event journal;
    /// a new registry is required for another app-server session.
    ///
    /// # Errors
    ///
    /// Returns a duplicate or capacity error. Existing bindings are never
    /// replaced, including by byte-equal identity.
    pub fn bind_correlation(
        &mut self,
        token: &AppServerCorrelationToken,
        identity: CodexExecutionIdentity,
    ) -> Result<(), AppServerOwnershipError> {
        if self.correlations.contains_key(token) {
            return Err(AppServerOwnershipError::DuplicateCorrelation);
        }
        if self
            .journal_anchor
            .as_ref()
            .is_some_and(|anchor| !anchor.belongs_to_same_journal(token))
        {
            return Err(AppServerOwnershipError::ForeignJournal);
        }
        if self.correlations.len() >= self.limits.correlations {
            return Err(AppServerOwnershipError::CorrelationLimitExceeded);
        }
        if self.journal_anchor.is_none() {
            self.journal_anchor = Some(token.clone());
        }
        self.correlations.insert(token.clone(), identity);
        Ok(())
    }

    /// Registers one resource label with explicit semantic identity.
    ///
    /// # Errors
    ///
    /// Returns a duplicate or capacity error.
    pub fn register(
        &mut self,
        id: AppServerOwnedResourceId,
        kind: AppServerOwnedResourceKind,
        identity: CodexExecutionIdentity,
    ) -> Result<(), AppServerOwnershipError> {
        if self.resources.contains_key(&id) {
            return Err(AppServerOwnershipError::DuplicateResource);
        }
        if self.resources.len() >= self.limits.resources {
            return Err(AppServerOwnershipError::ResourceLimitExceeded);
        }
        self.resources
            .insert(id, AppServerOwnedResource { id, kind, identity });
        Ok(())
    }

    /// Registers one resource from an existing semantic request binding.
    ///
    /// # Errors
    ///
    /// Returns unknown-correlation, duplicate-resource, or capacity errors.
    pub fn register_from_correlation(
        &mut self,
        id: AppServerOwnedResourceId,
        kind: AppServerOwnedResourceKind,
        token: &AppServerCorrelationToken,
    ) -> Result<(), AppServerOwnershipError> {
        let identity = self
            .correlations
            .get(token)
            .cloned()
            .ok_or(AppServerOwnershipError::UnknownCorrelation)?;
        self.register(id, kind, identity)
    }

    /// Returns semantic evidence currently bound to a local request token.
    #[must_use]
    pub fn correlation(
        &self,
        token: &AppServerCorrelationToken,
    ) -> Option<&CodexExecutionIdentity> {
        self.correlations.get(token)
    }

    /// Releases labels within one completed thread, turn, or item scope.
    ///
    /// Thread completion includes descendant turns/items; turn completion
    /// includes descendant items; item completion is exact. Application scope
    /// requires the more explicit [`Self::close_session`].
    ///
    /// # Errors
    ///
    /// Returns [`AppServerOwnershipError::AppScopeRequiresSessionClose`] for an
    /// application-scoped identity.
    pub fn release_scope(
        &mut self,
        scope: &CodexExecutionIdentity,
    ) -> Result<AppServerOwnershipRelease, AppServerOwnershipError> {
        if scope.is_app_scoped() {
            return Err(AppServerOwnershipError::AppScopeRequiresSessionClose);
        }
        let correlation_keys = self
            .correlations
            .iter()
            .filter_map(|(token, identity)| is_within(identity, scope).then_some(token.clone()))
            .collect::<Vec<_>>();
        for token in &correlation_keys {
            self.correlations.remove(token);
        }
        let resource_ids = self
            .resources
            .iter()
            .filter_map(|(id, resource)| is_within(&resource.identity, scope).then_some(*id))
            .collect::<Vec<_>>();
        let mut resources = Vec::with_capacity(resource_ids.len());
        for id in resource_ids {
            if let Some(resource) = self.resources.remove(&id) {
                resources.push(resource);
            }
        }
        Ok(AppServerOwnershipRelease {
            resources,
            released_correlations: correlation_keys.len(),
        })
    }

    /// Clears all application-scoped and descendant labels at session close.
    ///
    /// Returned resources remain non-authorizing cleanup candidates. The
    /// registry stays pinned to its original journal and must not be reused for
    /// another app-server session.
    pub fn close_session(&mut self) -> AppServerOwnershipRelease {
        let released_correlations = self.correlations.len();
        self.correlations.clear();
        let resources = mem::take(&mut self.resources).into_values().collect();
        AppServerOwnershipRelease {
            resources,
            released_correlations,
        }
    }

    /// Returns bounded registry accounting without semantic identifiers.
    #[must_use]
    pub fn diagnostics(&self) -> AppServerOwnershipDiagnostics {
        AppServerOwnershipDiagnostics {
            correlations: self.correlations.len(),
            resources: self.resources.len(),
            max_correlations: self.limits.correlations,
            max_resources: self.limits.resources,
        }
    }
}

/// Semantic identity or bounded registry failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AppServerOwnershipError {
    /// A registry limit was zero or above its hard maximum.
    #[error("invalid app-server ownership limits")]
    InvalidLimits,
    /// A semantic identifier was empty, oversized, or contained control text.
    #[error("invalid Codex execution identity")]
    InvalidExecutionId,
    /// A turn lacked a thread or an item lacked a turn.
    #[error("invalid Codex execution identity hierarchy")]
    InvalidIdentityHierarchy,
    /// A caller-local resource identity was zero.
    #[error("invalid app-server owned-resource identity")]
    InvalidResourceId,
    /// A local request token already had semantic evidence.
    #[error("app-server request correlation is already bound")]
    DuplicateCorrelation,
    /// A request token came from a different session journal.
    #[error("app-server request correlation belongs to another event journal")]
    ForeignJournal,
    /// The live semantic request-binding ceiling was reached.
    #[error("app-server ownership correlation limit reached")]
    CorrelationLimitExceeded,
    /// A resource label already existed.
    #[error("app-server owned-resource identity is already registered")]
    DuplicateResource,
    /// The live resource-label ceiling was reached.
    #[error("app-server owned-resource limit reached")]
    ResourceLimitExceeded,
    /// A resource referenced a request token without semantic evidence.
    #[error("app-server request correlation has no semantic binding")]
    UnknownCorrelation,
    /// Application scope requires explicit complete-session cleanup.
    #[error("application-scoped ownership release requires session close")]
    AppScopeRequiresSessionClose,
}

fn validate_execution_id(value: &str) -> Result<(), AppServerOwnershipError> {
    if value.is_empty()
        || value.len() > MAX_EXECUTION_ID_BYTES
        || value.chars().any(char::is_control)
    {
        Err(AppServerOwnershipError::InvalidExecutionId)
    } else {
        Ok(())
    }
}

fn is_within(identity: &CodexExecutionIdentity, scope: &CodexExecutionIdentity) -> bool {
    if identity.thread != scope.thread {
        return false;
    }
    if let Some(scope_turn) = scope.turn.as_ref()
        && identity.turn.as_ref() != Some(scope_turn)
    {
        return false;
    }
    if let Some(scope_item) = scope.item.as_ref()
        && identity.item.as_ref() != Some(scope_item)
    {
        return false;
    }
    true
}
