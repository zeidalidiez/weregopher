//! Canonical evidence contracts for the G2 `OpenAI` target-feasibility gate.

use std::{collections::BTreeSet, fmt};

use schemars::JsonSchema;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, IgnoredAny, SeqAccess, Visitor},
};
use thiserror::Error;

use crate::Sha256Digest;

/// Current serialized G2 feasibility-report contract version.
pub const G2_FEASIBILITY_FORMAT_VERSION: &str = "1";
/// Maximum bytes in one normalized package-relative component path.
pub const MAX_G2_PACKAGE_PATH_BYTES: usize = 4_096;
/// Maximum path components in one normalized package-relative path.
pub const MAX_G2_PACKAGE_PATH_COMPONENTS: usize = 256;
/// Maximum exact preload entries retained by one package inventory.
pub const MAX_G2_PRELOAD_ENTRIES: usize = 32;
/// Maximum exact renderer entries retained by one package inventory.
pub const MAX_G2_RENDERER_ENTRIES: usize = 128;
/// Maximum bytes in one observed renderer-backend version string.
pub const MAX_G2_BACKEND_VERSION_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
enum G2FormatVersion {
    #[serde(rename = "1")]
    V1,
}

/// Construction or semantic-validation failure for a G2 evidence contract.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum G2ContractError {
    /// A package-relative path is empty.
    #[error("G2 package path must not be empty")]
    EmptyPackagePath,
    /// A package-relative path exceeds its byte ceiling.
    #[error("G2 package path exceeds its byte limit")]
    PackagePathTooLong,
    /// A package-relative path is absolute, ambiguous, or uses unsupported characters.
    #[error("G2 package path is not canonical")]
    InvalidPackagePath,
    /// A package-relative path exceeds its component ceiling.
    #[error("G2 package path exceeds its component limit")]
    TooManyPackagePathComponents,
    /// A component was recorded with an impossible zero-byte length.
    #[error("G2 package component length must be nonzero")]
    EmptyComponent,
    /// No preload candidate was retained by a package inventory.
    #[error("G2 package inventory requires at least one preload candidate")]
    MissingPreloadCandidate,
    /// No renderer candidate was retained by a package inventory.
    #[error("G2 package inventory requires at least one renderer candidate")]
    MissingRendererCandidate,
    /// Too many preload candidates were supplied.
    #[error("G2 package inventory exceeds its preload-candidate limit")]
    TooManyPreloadCandidates,
    /// Too many renderer candidates were supplied.
    #[error("G2 package inventory exceeds its renderer-candidate limit")]
    TooManyRendererCandidates,
    /// One package path was assigned to more than one component role.
    #[error("G2 package inventory contains a duplicate component path")]
    DuplicateComponentPath,
    /// A renderer-backend version is empty, oversized, or contains a control character.
    #[error("G2 renderer-backend version is invalid")]
    InvalidBackendVersion,
    /// A completed gate status omitted its evidence identity.
    #[error("completed G2 gate evidence requires an artifact digest")]
    MissingGateEvidence,
    /// A not-run gate status incorrectly supplied evidence.
    #[error("not-run G2 gate evidence must not contain an artifact digest")]
    UnexpectedGateEvidence,
}

/// Canonical forward-slash package-relative path used by G2 evidence.
#[derive(Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct G2PackagePath(#[schemars(length(min = 1, max = 4096))] String);

impl<'de> Deserialize<'de> for G2PackagePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

impl G2PackagePath {
    /// Validates one normalized package-relative path.
    ///
    /// # Errors
    ///
    /// Returns [`G2ContractError`] for empty, absolute, backslash-separated,
    /// dot-segment, control-character, oversized, or over-deep paths.
    pub fn new(value: impl Into<String>) -> Result<Self, G2ContractError> {
        let value = value.into();
        if value.is_empty() {
            return Err(G2ContractError::EmptyPackagePath);
        }
        if value.len() > MAX_G2_PACKAGE_PATH_BYTES {
            return Err(G2ContractError::PackagePathTooLong);
        }
        if value.starts_with('/')
            || value.ends_with('/')
            || value.contains('\\')
            || value.chars().any(char::is_control)
        {
            return Err(G2ContractError::InvalidPackagePath);
        }
        let mut component_count = 0_usize;
        for component in value.split('/') {
            component_count = component_count
                .checked_add(1)
                .ok_or(G2ContractError::TooManyPackagePathComponents)?;
            if component_count > MAX_G2_PACKAGE_PATH_COMPONENTS {
                return Err(G2ContractError::TooManyPackagePathComponents);
            }
            if component.is_empty() || matches!(component, "." | "..") {
                return Err(G2ContractError::InvalidPackagePath);
            }
        }
        Ok(Self(value))
    }

    /// Returns the normalized package-relative path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Storage boundary containing one exact G2 package component.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum G2ComponentSource {
    /// Direct file in the observed package tree.
    PackageFile,
    /// Packed member of the exact application archive.
    ApplicationArchiveMember,
}

/// Exact content identity and size of one package component.
#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct G2ComponentEvidence {
    source: G2ComponentSource,
    path: G2PackagePath,
    sha256: Sha256Digest,
    byte_length: u64,
}

impl<'de> Deserialize<'de> for G2ComponentEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = UncheckedG2ComponentEvidence::deserialize(deserializer)?;
        Self::new(value.source, value.path, value.sha256, value.byte_length)
            .map_err(D::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedG2ComponentEvidence {
    source: G2ComponentSource,
    path: G2PackagePath,
    sha256: Sha256Digest,
    byte_length: u64,
}

impl G2ComponentEvidence {
    /// Constructs one exact package-component observation.
    ///
    /// # Errors
    ///
    /// Returns [`G2ContractError::EmptyComponent`] when `byte_length` is zero.
    pub fn new(
        source: G2ComponentSource,
        path: G2PackagePath,
        sha256: Sha256Digest,
        byte_length: u64,
    ) -> Result<Self, G2ContractError> {
        if byte_length == 0 {
            return Err(G2ContractError::EmptyComponent);
        }
        Ok(Self {
            source,
            path,
            sha256,
            byte_length,
        })
    }

    /// Returns the component storage boundary.
    #[must_use]
    pub const fn source(&self) -> G2ComponentSource {
        self.source
    }

    /// Returns the package-relative component path.
    #[must_use]
    pub const fn path(&self) -> &G2PackagePath {
        &self.path
    }

    /// Returns the exact component-byte digest.
    #[must_use]
    pub const fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }

    /// Returns the observed component length.
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }
}

/// Exact package-derived component inventory for one `OpenAI` Windows build.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpenAiPackageInventory {
    format_version: G2FormatVersion,
    source_build_fingerprint_digest: Sha256Digest,
    package_identity_digest: Sha256Digest,
    desktop_entry: G2ComponentEvidence,
    application_archive: G2ComponentEvidence,
    main_entry: G2ComponentEvidence,
    #[schemars(length(min = 1, max = 32))]
    preload_candidates: BTreeSet<G2ComponentEvidence>,
    #[schemars(length(min = 1, max = 128))]
    renderer_candidates: BTreeSet<G2ComponentEvidence>,
    app_server: G2ComponentEvidence,
}

impl<'de> Deserialize<'de> for OpenAiPackageInventory {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let UncheckedOpenAiPackageInventory {
            format_version: G2FormatVersion::V1,
            source_build_fingerprint_digest,
            package_identity_digest,
            desktop_entry,
            application_archive,
            main_entry,
            preload_candidates,
            renderer_candidates,
            app_server,
        } = UncheckedOpenAiPackageInventory::deserialize(deserializer)?;
        Self::new(
            source_build_fingerprint_digest,
            package_identity_digest,
            desktop_entry,
            application_archive,
            main_entry,
            preload_candidates,
            renderer_candidates,
            app_server,
        )
        .map_err(D::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedOpenAiPackageInventory {
    format_version: G2FormatVersion,
    source_build_fingerprint_digest: Sha256Digest,
    package_identity_digest: Sha256Digest,
    desktop_entry: G2ComponentEvidence,
    application_archive: G2ComponentEvidence,
    main_entry: G2ComponentEvidence,
    #[serde(deserialize_with = "deserialize_preload_candidates")]
    preload_candidates: Vec<G2ComponentEvidence>,
    #[serde(deserialize_with = "deserialize_renderer_candidates")]
    renderer_candidates: Vec<G2ComponentEvidence>,
    app_server: G2ComponentEvidence,
}

#[allow(
    clippy::too_many_arguments,
    reason = "the constructor mirrors the fixed G2 package evidence roles"
)]
impl OpenAiPackageInventory {
    /// Constructs a complete exact-component package inventory.
    ///
    /// # Errors
    ///
    /// Returns [`G2ContractError`] when either variable component set is empty
    /// or oversized, or when any path is assigned more than once.
    pub fn new(
        source_build_fingerprint_digest: Sha256Digest,
        package_identity_digest: Sha256Digest,
        desktop_entry: G2ComponentEvidence,
        application_archive: G2ComponentEvidence,
        main_entry: G2ComponentEvidence,
        preload_candidates: impl IntoIterator<Item = G2ComponentEvidence>,
        renderer_candidates: impl IntoIterator<Item = G2ComponentEvidence>,
        app_server: G2ComponentEvidence,
    ) -> Result<Self, G2ContractError> {
        let preload_candidates =
            collect_components(preload_candidates, MAX_G2_PRELOAD_ENTRIES, true)?;
        let renderer_candidates =
            collect_components(renderer_candidates, MAX_G2_RENDERER_ENTRIES, false)?;
        let mut locations = BTreeSet::new();
        for component in [
            &desktop_entry,
            &application_archive,
            &main_entry,
            &app_server,
        ]
        .into_iter()
        .chain(preload_candidates.iter())
        .chain(renderer_candidates.iter())
        {
            if !locations.insert((component.source, component.path.clone())) {
                return Err(G2ContractError::DuplicateComponentPath);
            }
        }
        Ok(Self {
            format_version: G2FormatVersion::V1,
            source_build_fingerprint_digest,
            package_identity_digest,
            desktop_entry,
            application_archive,
            main_entry,
            preload_candidates,
            renderer_candidates,
            app_server,
        })
    }

    /// Returns the exact source build-fingerprint document identity.
    #[must_use]
    pub const fn source_build_fingerprint_digest(&self) -> &Sha256Digest {
        &self.source_build_fingerprint_digest
    }

    /// Returns the canonical package-identity artifact digest.
    #[must_use]
    pub const fn package_identity_digest(&self) -> &Sha256Digest {
        &self.package_identity_digest
    }

    /// Returns the exact desktop executable observation.
    #[must_use]
    pub const fn desktop_entry(&self) -> &G2ComponentEvidence {
        &self.desktop_entry
    }

    /// Returns the exact application-archive observation.
    #[must_use]
    pub const fn application_archive(&self) -> &G2ComponentEvidence {
        &self.application_archive
    }

    /// Returns the package-derived main entry.
    #[must_use]
    pub const fn main_entry(&self) -> &G2ComponentEvidence {
        &self.main_entry
    }

    /// Returns exact package-derived preload candidates.
    #[must_use]
    pub const fn preload_candidates(&self) -> &BTreeSet<G2ComponentEvidence> {
        &self.preload_candidates
    }

    /// Returns exact package-derived renderer candidates.
    #[must_use]
    pub const fn renderer_candidates(&self) -> &BTreeSet<G2ComponentEvidence> {
        &self.renderer_candidates
    }

    /// Returns the exact bundled app-server executable observation.
    #[must_use]
    pub const fn app_server(&self) -> &G2ComponentEvidence {
        &self.app_server
    }
}

fn collect_components(
    values: impl IntoIterator<Item = G2ComponentEvidence>,
    limit: usize,
    preloads: bool,
) -> Result<BTreeSet<G2ComponentEvidence>, G2ContractError> {
    let mut collected = Vec::with_capacity(limit);
    for value in values {
        if collected.len() == limit {
            return Err(if preloads {
                G2ContractError::TooManyPreloadCandidates
            } else {
                G2ContractError::TooManyRendererCandidates
            });
        }
        collected.push(value);
    }
    if collected.is_empty() {
        return Err(if preloads {
            G2ContractError::MissingPreloadCandidate
        } else {
            G2ContractError::MissingRendererCandidate
        });
    }
    Ok(collected.into_iter().collect())
}

fn deserialize_preload_candidates<'de, D>(
    deserializer: D,
) -> Result<Vec<G2ComponentEvidence>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_component_sequence::<D, MAX_G2_PRELOAD_ENTRIES>(deserializer)
}

fn deserialize_renderer_candidates<'de, D>(
    deserializer: D,
) -> Result<Vec<G2ComponentEvidence>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_component_sequence::<D, MAX_G2_RENDERER_ENTRIES>(deserializer)
}

fn deserialize_component_sequence<'de, D, const LIMIT: usize>(
    deserializer: D,
) -> Result<Vec<G2ComponentEvidence>, D::Error>
where
    D: Deserializer<'de>,
{
    struct ComponentVisitor<const LIMIT: usize>;

    impl<'de, const LIMIT: usize> Visitor<'de> for ComponentVisitor<LIMIT> {
        type Value = Vec<G2ComponentEvidence>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded sequence of exact G2 package components")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence.size_hint().is_some_and(|length| length > LIMIT) {
                return Err(A::Error::custom("G2 component sequence exceeds its limit"));
            }
            let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(LIMIT));
            while values.len() < LIMIT {
                match sequence.next_element()? {
                    Some(value) => values.push(value),
                    None => return Ok(values),
                }
            }
            if sequence.next_element::<IgnoredAny>()?.is_some() {
                return Err(A::Error::custom("G2 component sequence exceeds its limit"));
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(ComponentVisitor::<LIMIT>)
}

/// Scope of the package bytes exercised by one G2 runtime probe.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum G2ProbeScope {
    /// Public synthetic fixture proving only the Weregopher mechanism.
    SyntheticFixture,
    /// Exact content-addressed installed-package component.
    ExactPackage,
}

/// Required preload/`contextBridge` fidelity checks.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each independently observed fidelity property must remain explicit evidence"
)]
pub struct PreloadBridgeChecks {
    /// Preload bootstrap ran before packaged page scripts.
    pub document_start: bool,
    /// Preload and page global objects were distinct.
    pub isolated_globals: bool,
    /// Page prototype mutation did not affect the preload world.
    pub prototype_isolation: bool,
    /// Values projected into the page were immutable.
    pub frozen_projection: bool,
    /// A projected function completed a host round trip.
    pub function_round_trip: bool,
    /// Navigation invalidated the prior world and its handles.
    pub navigation_invalidation: bool,
}

impl PreloadBridgeChecks {
    const fn all_pass(self) -> bool {
        self.document_start
            && self.isolated_globals
            && self.prototype_isolation
            && self.frozen_projection
            && self.function_round_trip
            && self.navigation_invalidation
    }
}

/// Content-addressed preload and renderer-isolation probe evidence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreloadBridgeProbeReport {
    format_version: G2FormatVersion,
    source_build_fingerprint_digest: Sha256Digest,
    preload_digest: Sha256Digest,
    renderer_backend_digest: Sha256Digest,
    #[schemars(length(min = 1, max = 128))]
    backend_version: String,
    scope: G2ProbeScope,
    checks: PreloadBridgeChecks,
}

impl<'de> Deserialize<'de> for PreloadBridgeProbeReport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let UncheckedPreloadBridgeProbeReport {
            format_version: G2FormatVersion::V1,
            source_build_fingerprint_digest,
            preload_digest,
            renderer_backend_digest,
            backend_version,
            scope,
            checks,
        } = UncheckedPreloadBridgeProbeReport::deserialize(deserializer)?;
        Self::new(
            source_build_fingerprint_digest,
            preload_digest,
            renderer_backend_digest,
            backend_version,
            scope,
            checks,
        )
        .map_err(D::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedPreloadBridgeProbeReport {
    format_version: G2FormatVersion,
    source_build_fingerprint_digest: Sha256Digest,
    preload_digest: Sha256Digest,
    renderer_backend_digest: Sha256Digest,
    backend_version: String,
    scope: G2ProbeScope,
    checks: PreloadBridgeChecks,
}

impl PreloadBridgeProbeReport {
    /// Constructs one preload/bridge probe report.
    ///
    /// # Errors
    ///
    /// Returns [`G2ContractError::InvalidBackendVersion`] for empty, oversized,
    /// or control-character-bearing version evidence.
    pub fn new(
        source_build_fingerprint_digest: Sha256Digest,
        preload_digest: Sha256Digest,
        renderer_backend_digest: Sha256Digest,
        backend_version: impl Into<String>,
        scope: G2ProbeScope,
        checks: PreloadBridgeChecks,
    ) -> Result<Self, G2ContractError> {
        let backend_version = backend_version.into();
        if backend_version.is_empty()
            || backend_version.len() > MAX_G2_BACKEND_VERSION_BYTES
            || backend_version.chars().any(char::is_control)
        {
            return Err(G2ContractError::InvalidBackendVersion);
        }
        Ok(Self {
            format_version: G2FormatVersion::V1,
            source_build_fingerprint_digest,
            preload_digest,
            renderer_backend_digest,
            backend_version,
            scope,
            checks,
        })
    }

    /// Reports whether every declared fidelity check passed.
    #[must_use]
    pub const fn checks_pass(&self) -> bool {
        self.checks.all_pass()
    }

    /// Reports whether this probe exercised the exact installed-package preload.
    #[must_use]
    pub const fn is_exact_package_evidence(&self) -> bool {
        matches!(self.scope, G2ProbeScope::ExactPackage)
    }
}

/// Required exact app-server protocol checks.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each independently observed protocol property must remain explicit evidence"
)]
pub struct AppServerProbeChecks {
    /// The process exchanged bounded newline-delimited JSON over standard I/O.
    pub stdio_jsonl: bool,
    /// A request before initialization was rejected.
    pub preinitialize_rejected: bool,
    /// The single `initialize` request succeeded.
    pub initialize_succeeded: bool,
    /// The client sent the required `initialized` notification.
    pub initialized_sent: bool,
    /// The supervised process tree exited cleanly.
    pub clean_shutdown: bool,
}

impl AppServerProbeChecks {
    const fn all_pass(self) -> bool {
        self.stdio_jsonl
            && self.preinitialize_rejected
            && self.initialize_succeeded
            && self.initialized_sent
            && self.clean_shutdown
    }
}

/// Content-addressed exact-version app-server schema and handshake evidence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppServerProbeReport {
    format_version: G2FormatVersion,
    source_build_fingerprint_digest: Sha256Digest,
    executable_digest: Sha256Digest,
    schema_bundle_digest: Sha256Digest,
    initialize_response_digest: Sha256Digest,
    scope: G2ProbeScope,
    checks: AppServerProbeChecks,
}

impl AppServerProbeReport {
    /// Constructs one exact-version schema and initialization probe report.
    #[must_use]
    pub const fn new(
        source_build_fingerprint_digest: Sha256Digest,
        executable_digest: Sha256Digest,
        schema_bundle_digest: Sha256Digest,
        initialize_response_digest: Sha256Digest,
        scope: G2ProbeScope,
        checks: AppServerProbeChecks,
    ) -> Self {
        Self {
            format_version: G2FormatVersion::V1,
            source_build_fingerprint_digest,
            executable_digest,
            schema_bundle_digest,
            initialize_response_digest,
            scope,
            checks,
        }
    }

    /// Reports whether every declared schema/handshake check passed.
    #[must_use]
    pub const fn checks_pass(&self) -> bool {
        self.checks.all_pass()
    }

    /// Reports whether this probe exercised the exact installed-package binary.
    #[must_use]
    pub const fn is_exact_package_evidence(&self) -> bool {
        matches!(self.scope, G2ProbeScope::ExactPackage)
    }
}

/// Status of one required G2 evidence lane.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum G2GateStatus {
    /// The lane has not run against the exact target.
    NotRun,
    /// The lane ran and failed its declared checks.
    Failed,
    /// The lane ran and passed its declared checks.
    Passed,
}

/// Status and exact immutable artifact identity for one G2 evidence lane.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct G2GateEvidence {
    status: G2GateStatus,
    evidence_digest: Option<Sha256Digest>,
}

impl<'de> Deserialize<'de> for G2GateEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = UncheckedG2GateEvidence::deserialize(deserializer)?;
        Self::from_parts(value.status, value.evidence_digest).map_err(D::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedG2GateEvidence {
    status: G2GateStatus,
    evidence_digest: Option<Sha256Digest>,
}

impl G2GateEvidence {
    /// Constructs a not-yet-run lane without invented evidence.
    #[must_use]
    pub const fn not_run() -> Self {
        Self {
            status: G2GateStatus::NotRun,
            evidence_digest: None,
        }
    }

    /// Constructs a failed lane bound to its evidence artifact.
    #[must_use]
    pub const fn failed(evidence_digest: Sha256Digest) -> Self {
        Self {
            status: G2GateStatus::Failed,
            evidence_digest: Some(evidence_digest),
        }
    }

    /// Constructs a passed lane bound to its evidence artifact.
    #[must_use]
    pub const fn passed(evidence_digest: Sha256Digest) -> Self {
        Self {
            status: G2GateStatus::Passed,
            evidence_digest: Some(evidence_digest),
        }
    }

    fn from_parts(
        status: G2GateStatus,
        evidence_digest: Option<Sha256Digest>,
    ) -> Result<Self, G2ContractError> {
        match (status, evidence_digest) {
            (G2GateStatus::NotRun, None) => Ok(Self::not_run()),
            (G2GateStatus::Failed, Some(digest)) => Ok(Self::failed(digest)),
            (G2GateStatus::Passed, Some(digest)) => Ok(Self::passed(digest)),
            (G2GateStatus::NotRun, Some(_)) => Err(G2ContractError::UnexpectedGateEvidence),
            (G2GateStatus::Failed | G2GateStatus::Passed, None) => {
                Err(G2ContractError::MissingGateEvidence)
            }
        }
    }

    /// Returns the lane status.
    #[must_use]
    pub const fn status(&self) -> G2GateStatus {
        self.status
    }

    /// Returns the exact evidence artifact identity, when the lane ran.
    #[must_use]
    pub const fn evidence_digest(&self) -> Option<&Sha256Digest> {
        self.evidence_digest.as_ref()
    }
}

/// Aggregate fail-closed G2 target-feasibility disposition.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum G2FeasibilityDisposition {
    /// One or more exact-target evidence lanes have not run.
    Incomplete,
    /// One or more exact-target evidence lanes failed.
    Blocked,
    /// Every required exact-target evidence lane passed.
    ///
    /// This is not application compatibility, certification, execution
    /// authorization, a security-posture claim, or an efficiency claim.
    Feasible,
}

/// Fixed target represented by the initial G2 feasibility contract.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum G2Target {
    /// Installed OpenAI-family desktop package on Windows x64.
    OpenAiWindowsX64,
}

/// Aggregate evidence-only result for the G2 `OpenAI` target-feasibility gate.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct G2FeasibilityReport {
    format_version: G2FormatVersion,
    target: G2Target,
    source_build_fingerprint_digest: Sha256Digest,
    package: G2GateEvidence,
    preload_bridge: G2GateEvidence,
    app_server: G2GateEvidence,
}

impl G2FeasibilityReport {
    /// Constructs an evidence-only G2 report for the fixed Windows x64 target.
    #[must_use]
    pub const fn new(
        source_build_fingerprint_digest: Sha256Digest,
        package: G2GateEvidence,
        preload_bridge: G2GateEvidence,
        app_server: G2GateEvidence,
    ) -> Self {
        Self {
            format_version: G2FormatVersion::V1,
            target: G2Target::OpenAiWindowsX64,
            source_build_fingerprint_digest,
            package,
            preload_bridge,
            app_server,
        }
    }

    /// Returns the aggregate fail-closed disposition.
    #[must_use]
    pub const fn disposition(&self) -> G2FeasibilityDisposition {
        let statuses = [
            self.package.status,
            self.preload_bridge.status,
            self.app_server.status,
        ];
        let mut index = 0;
        let mut incomplete = false;
        while index < statuses.len() {
            match statuses[index] {
                G2GateStatus::Failed => return G2FeasibilityDisposition::Blocked,
                G2GateStatus::NotRun => incomplete = true,
                G2GateStatus::Passed => {}
            }
            index += 1;
        }
        if incomplete {
            G2FeasibilityDisposition::Incomplete
        } else {
            G2FeasibilityDisposition::Feasible
        }
    }

    /// Returns the exact source build-fingerprint identity.
    #[must_use]
    pub const fn source_build_fingerprint_digest(&self) -> &Sha256Digest {
        &self.source_build_fingerprint_digest
    }

    /// Returns the package inventory lane.
    #[must_use]
    pub const fn package(&self) -> &G2GateEvidence {
        &self.package
    }

    /// Returns the preload/bridge fidelity lane.
    #[must_use]
    pub const fn preload_bridge(&self) -> &G2GateEvidence {
        &self.preload_bridge
    }

    /// Returns the app-server lane.
    #[must_use]
    pub const fn app_server(&self) -> &G2GateEvidence {
        &self.app_server
    }
}
