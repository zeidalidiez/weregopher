//! Exact-target, bounded, non-authorizing certification evidence.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use schemars::JsonSchema;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, IgnoredAny, MapAccess, SeqAccess, Visitor},
};
use thiserror::Error;

use crate::{
    CompatibilityAnalysisDigest, ExecutableDigest, ExecutionArtifactSourceDigest,
    ExecutionContractDigest, ExecutionResolutionEvidenceDigest, FeatureId, Sha256Digest,
};

/// Current serialized certification-evidence contract version.
pub const CERTIFICATION_EVIDENCE_FORMAT_VERSION: &str = "1";
/// Maximum immutable evidence references retained for one certification check.
pub const MAX_CERTIFICATION_EVIDENCE_REFS: usize = 64;
/// Maximum application workflow checks retained in one certification document.
pub const MAX_CERTIFICATION_WORKFLOWS: usize = 128;
/// Maximum accepted serialized certification document size.
pub const MAX_CERTIFICATION_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;

macro_rules! certification_digest_role {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Clone,
            Copy,
            Debug,
            Eq,
            Hash,
            JsonSchema,
            Ord,
            PartialEq,
            PartialOrd,
            Serialize,
            Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Sha256Digest);

        impl $name {
            /// Creates this role-specific identity from a canonical SHA-256 digest.
            #[must_use]
            pub const fn new(digest: Sha256Digest) -> Self {
                Self(digest)
            }

            /// Returns the wire-compatible SHA-256 value at a hashing or transport boundary.
            #[must_use]
            pub const fn as_sha256(&self) -> &Sha256Digest {
                &self.0
            }

            /// Consumes this role-specific identity at a hashing or transport boundary.
            #[must_use]
            pub const fn into_sha256(self) -> Sha256Digest {
                self.0
            }
        }

        impl From<Sha256Digest> for $name {
            fn from(value: Sha256Digest) -> Self {
                Self::new(value)
            }
        }

        impl From<$name> for Sha256Digest {
            fn from(value: $name) -> Self {
                value.into_sha256()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

certification_digest_role!(
    /// Immutable identity of the exact certification profile and mandatory-suite definition.
    CertificationProfileDigest
);
certification_digest_role!(
    /// Immutable identity of one certification probe, trace, fixture result, or report artifact.
    CertificationArtifactDigest
);

#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
enum CertificationEvidenceFormatVersion {
    #[serde(rename = "1")]
    V1,
}

/// Fail-closed aggregate of fixed and workflow certification checks.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CertificationEvidenceDisposition {
    /// One or more configured checks did not run.
    Incomplete,
    /// One or more configured checks failed.
    Blocked,
    /// Every configured check passed or was proven not applicable.
    Complete,
}

/// Outcome of one certification check.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CertificationCheckStatus {
    /// The configured profile did not run or resolve this check.
    NotRun,
    /// The declared requirement passed.
    Passed,
    /// The declared requirement failed.
    Failed,
    /// The exact profile proves this check does not apply.
    NotApplicable,
}

/// Kind of immutable artifact supporting one certification check.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CertificationArtifactKind {
    /// Package identity, signature, or exact package-layout evidence.
    PackageIdentity,
    /// Deterministic static-analysis evidence.
    StaticAnalysis,
    /// Main-runtime launch or bootstrap probe evidence.
    RuntimeProbe,
    /// Renderer or preload probe evidence.
    RendererProbe,
    /// State safety or migration-dry-run evidence.
    StateProbe,
    /// Security-contract probe evidence.
    SecurityProbe,
    /// Application workflow evidence.
    WorkflowProbe,
    /// Resource and process-tree scenario evidence.
    ResourceProbe,
    /// Vendor-helper lifecycle evidence.
    HelperProbe,
    /// Verification of a declared exception or known gap.
    ExceptionVerification,
}

/// Content-addressed immutable artifact supporting one certification check.
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct CertificationArtifactRef {
    /// Evidence category.
    pub kind: CertificationArtifactKind,
    /// Role-specific content identity of the evidence artifact.
    pub digest: CertificationArtifactDigest,
}

impl CertificationArtifactRef {
    /// Constructs one immutable certification evidence reference.
    #[must_use]
    pub const fn new(kind: CertificationArtifactKind, digest: CertificationArtifactDigest) -> Self {
        Self { kind, digest }
    }
}

/// Error constructing a certification-evidence contract.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CertificationContractError {
    /// A resolved check omitted supporting evidence.
    #[error("resolved certification checks require evidence")]
    MissingEvidence,
    /// A not-run check claimed immutable result evidence.
    #[error("not-run certification checks cannot contain evidence")]
    UnexpectedEvidence,
    /// One check supplied more evidence references than the contract permits.
    #[error("certification check exceeds the evidence-reference limit")]
    TooManyEvidenceReferences,
    /// One check supplied the same immutable evidence reference more than once.
    #[error("certification check contains duplicate evidence references")]
    DuplicateEvidenceReference,
    /// The document declared more application workflows than the contract permits.
    #[error("certification evidence exceeds the workflow-assessment limit")]
    TooManyWorkflowAssessments,
}

/// Error parsing a byte-bounded certification document.
#[derive(Debug, Error)]
pub enum CertificationDocumentError {
    /// Input exceeded the non-configurable serialized-document ceiling.
    #[error("certification document exceeds the byte limit")]
    DocumentTooLarge,
    /// Input was not one canonical certification-evidence transport shape.
    #[error("invalid certification document")]
    InvalidJson(#[source] serde_json::Error),
}

/// One certification check's status and immutable supporting evidence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationCheckAssessment {
    status: CertificationCheckStatus,
    #[schemars(length(max = 64))]
    evidence: BTreeSet<CertificationArtifactRef>,
}

impl<'de> Deserialize<'de> for CertificationCheckAssessment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedCertificationCheckAssessment::deserialize(deserializer)?;
        Self::new(unchecked.status, unchecked.evidence).map_err(D::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedCertificationCheckAssessment {
    status: CertificationCheckStatus,
    #[serde(deserialize_with = "deserialize_certification_artifacts")]
    evidence: Vec<CertificationArtifactRef>,
}

fn deserialize_certification_artifacts<'de, D>(
    deserializer: D,
) -> Result<Vec<CertificationArtifactRef>, D::Error>
where
    D: Deserializer<'de>,
{
    struct EvidenceVisitor;

    impl<'de> Visitor<'de> for EvidenceVisitor {
        type Value = Vec<CertificationArtifactRef>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded sequence of certification artifact references")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence
                .size_hint()
                .is_some_and(|length| length > MAX_CERTIFICATION_EVIDENCE_REFS)
            {
                return Err(A::Error::custom(
                    CertificationContractError::TooManyEvidenceReferences,
                ));
            }

            let mut values = Vec::with_capacity(
                sequence
                    .size_hint()
                    .unwrap_or(0)
                    .min(MAX_CERTIFICATION_EVIDENCE_REFS),
            );
            while values.len() < MAX_CERTIFICATION_EVIDENCE_REFS {
                match sequence.next_element()? {
                    Some(reference) => values.push(reference),
                    None => return Ok(values),
                }
            }
            if sequence.next_element::<IgnoredAny>()?.is_some() {
                return Err(A::Error::custom(
                    CertificationContractError::TooManyEvidenceReferences,
                ));
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(EvidenceVisitor)
}

impl CertificationCheckAssessment {
    /// Constructs a status-coherent, unique, bounded certification assessment.
    ///
    /// # Errors
    ///
    /// Returns [`CertificationContractError`] when resolved evidence is absent, not-run evidence is
    /// present, or references are duplicated or exceed the fixed bound.
    pub fn new(
        status: CertificationCheckStatus,
        evidence: impl IntoIterator<Item = CertificationArtifactRef>,
    ) -> Result<Self, CertificationContractError> {
        let mut values = Vec::with_capacity(MAX_CERTIFICATION_EVIDENCE_REFS);
        for reference in evidence {
            if values.len() == MAX_CERTIFICATION_EVIDENCE_REFS {
                return Err(CertificationContractError::TooManyEvidenceReferences);
            }
            values.push(reference);
        }
        let value_count = values.len();
        let evidence: BTreeSet<CertificationArtifactRef> = values.into_iter().collect();
        if evidence.len() != value_count {
            return Err(CertificationContractError::DuplicateEvidenceReference);
        }
        match status {
            CertificationCheckStatus::NotRun if !evidence.is_empty() => {
                return Err(CertificationContractError::UnexpectedEvidence);
            }
            CertificationCheckStatus::Passed
            | CertificationCheckStatus::Failed
            | CertificationCheckStatus::NotApplicable
                if evidence.is_empty() =>
            {
                return Err(CertificationContractError::MissingEvidence);
            }
            CertificationCheckStatus::NotRun
            | CertificationCheckStatus::Passed
            | CertificationCheckStatus::Failed
            | CertificationCheckStatus::NotApplicable => {}
        }
        Ok(Self { status, evidence })
    }

    /// Constructs an unresolved check without inventing evidence.
    #[must_use]
    pub fn not_run() -> Self {
        Self {
            status: CertificationCheckStatus::NotRun,
            evidence: BTreeSet::new(),
        }
    }

    /// Returns the declared check status.
    #[must_use]
    pub const fn status(&self) -> CertificationCheckStatus {
        self.status
    }

    /// Returns the canonically ordered immutable evidence references.
    #[must_use]
    pub const fn evidence(&self) -> &BTreeSet<CertificationArtifactRef> {
        &self.evidence
    }
}

/// Fixed mandatory check dimensions for one certification profile.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationChecks {
    /// Package identity, signature, and expected package layout.
    pub package_identity: CertificationCheckAssessment,
    /// Main entry-point resolution.
    pub entry_point_resolution: CertificationCheckAssessment,
    /// Deterministic transform match cardinality and output identity.
    pub transform_matches: CertificationCheckAssessment,
    /// Main module-graph load.
    pub module_graph: CertificationCheckAssessment,
    /// Native dependency recognition and strategy.
    pub native_dependencies: CertificationCheckAssessment,
    /// Main-runtime bootstrap.
    pub runtime_bootstrap: CertificationCheckAssessment,
    /// Renderer backend bootstrap.
    pub renderer_bootstrap: CertificationCheckAssessment,
    /// Preload and bridge handshake.
    pub preload_handshake: CertificationCheckAssessment,
    /// State read, migration dry run, and rollback safety.
    pub state_safety: CertificationCheckAssessment,
    /// Vendor-helper launch, exit, and cleanup.
    pub helper_lifecycle: CertificationCheckAssessment,
    /// Critical security-contract regression probes.
    pub security_contract: CertificationCheckAssessment,
    /// Process-tree and resource-limit scenarios.
    pub resource_scenario: CertificationCheckAssessment,
    /// Verification of every exception declared by the exact profile.
    pub declared_exceptions: CertificationCheckAssessment,
}

impl CertificationChecks {
    fn assessments(&self) -> [&CertificationCheckAssessment; 13] {
        [
            &self.package_identity,
            &self.entry_point_resolution,
            &self.transform_matches,
            &self.module_graph,
            &self.native_dependencies,
            &self.runtime_bootstrap,
            &self.renderer_bootstrap,
            &self.preload_handshake,
            &self.state_safety,
            &self.helper_lifecycle,
            &self.security_contract,
            &self.resource_scenario,
            &self.declared_exceptions,
        ]
    }
}

/// Exact immutable inputs against which certification evidence was produced.
///
/// Role-specific identities prevent transposing semantically distinct hashes:
///
/// ```compile_fail
/// use weregopher_domain::{
///     CertificationTarget, CompatibilityAnalysisDigest, ExecutableDigest,
///     ExecutionArtifactSourceDigest, ExecutionContractDigest,
///     ExecutionResolutionEvidenceDigest, Sha256Digest,
/// };
/// let raw = Sha256Digest::from_bytes([0x11; 32]);
/// let compatibility = CompatibilityAnalysisDigest::new(raw);
/// let contract = ExecutionContractDigest::new(raw);
/// let resolution = ExecutionResolutionEvidenceDigest::new(raw);
/// let source = ExecutionArtifactSourceDigest::new(raw);
/// let executable = ExecutableDigest::new(raw);
/// let _ = CertificationTarget::new(
///     contract,
///     compatibility,
///     resolution,
///     source,
///     executable,
/// );
/// ```
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_field_names,
    reason = "the digest suffix is part of the role-explicit wire contract"
)]
pub struct CertificationTarget {
    compatibility_analysis_digest: CompatibilityAnalysisDigest,
    execution_contract_digest: ExecutionContractDigest,
    execution_resolution_evidence_digest: ExecutionResolutionEvidenceDigest,
    artifact_source_digest: ExecutionArtifactSourceDigest,
    executable_digest: ExecutableDigest,
}

impl CertificationTarget {
    /// Constructs one exact compatibility, execution, and artifact target.
    #[must_use]
    pub const fn new(
        compatibility_analysis_digest: CompatibilityAnalysisDigest,
        execution_contract_digest: ExecutionContractDigest,
        execution_resolution_evidence_digest: ExecutionResolutionEvidenceDigest,
        artifact_source_digest: ExecutionArtifactSourceDigest,
        executable_digest: ExecutableDigest,
    ) -> Self {
        Self {
            compatibility_analysis_digest,
            execution_contract_digest,
            execution_resolution_evidence_digest,
            artifact_source_digest,
            executable_digest,
        }
    }

    /// Returns the exact compatibility-analysis identity.
    #[must_use]
    pub const fn compatibility_analysis_digest(&self) -> &CompatibilityAnalysisDigest {
        &self.compatibility_analysis_digest
    }

    /// Returns the exact static execution-contract identity.
    #[must_use]
    pub const fn execution_contract_digest(&self) -> &ExecutionContractDigest {
        &self.execution_contract_digest
    }

    /// Returns the exact generated execution-resolution identity.
    #[must_use]
    pub const fn execution_resolution_evidence_digest(&self) -> &ExecutionResolutionEvidenceDigest {
        &self.execution_resolution_evidence_digest
    }

    /// Returns the exact artifact-source identity.
    #[must_use]
    pub const fn artifact_source_digest(&self) -> &ExecutionArtifactSourceDigest {
        &self.artifact_source_digest
    }

    /// Returns the exact executable-byte identity.
    #[must_use]
    pub const fn executable_digest(&self) -> &ExecutableDigest {
        &self.executable_digest
    }
}

/// Canonical certification evidence for one exact target and one exact profile.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationEvidence {
    format_version: CertificationEvidenceFormatVersion,
    target: CertificationTarget,
    profile_digest: CertificationProfileDigest,
    checks: CertificationChecks,
    #[schemars(extend("maxProperties" = 128))]
    workflows: BTreeMap<FeatureId, CertificationCheckAssessment>,
}

impl<'de> Deserialize<'de> for CertificationEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let UncheckedCertificationEvidence {
            format_version: CertificationEvidenceFormatVersion::V1,
            target,
            profile_digest,
            checks,
            workflows,
        } = UncheckedCertificationEvidence::deserialize(deserializer)?;
        Self::new(target, profile_digest, checks, workflows).map_err(D::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedCertificationEvidence {
    format_version: CertificationEvidenceFormatVersion,
    target: CertificationTarget,
    profile_digest: CertificationProfileDigest,
    checks: CertificationChecks,
    #[serde(deserialize_with = "deserialize_certification_workflows")]
    workflows: BTreeMap<FeatureId, CertificationCheckAssessment>,
}

fn deserialize_certification_workflows<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<FeatureId, CertificationCheckAssessment>, D::Error>
where
    D: Deserializer<'de>,
{
    struct WorkflowsVisitor;

    impl<'de> Visitor<'de> for WorkflowsVisitor {
        type Value = BTreeMap<FeatureId, CertificationCheckAssessment>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded map of certification workflow assessments")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            if map
                .size_hint()
                .is_some_and(|length| length > MAX_CERTIFICATION_WORKFLOWS)
            {
                return Err(A::Error::custom(
                    CertificationContractError::TooManyWorkflowAssessments,
                ));
            }

            let mut values = BTreeMap::new();
            while values.len() < MAX_CERTIFICATION_WORKFLOWS {
                let Some(feature) = map.next_key()? else {
                    return Ok(values);
                };
                if values.contains_key(&feature) {
                    let _: IgnoredAny = map.next_value()?;
                    return Err(A::Error::custom(
                        "certification evidence contains duplicate workflow identifiers",
                    ));
                }
                let assessment = map.next_value()?;
                values.insert(feature, assessment);
            }
            if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
                return Err(A::Error::custom(
                    CertificationContractError::TooManyWorkflowAssessments,
                ));
            }
            Ok(values)
        }
    }

    deserializer.deserialize_map(WorkflowsVisitor)
}

impl CertificationEvidence {
    /// Constructs exact-target evidence without granting trust, publication, or execution authority.
    ///
    /// # Errors
    ///
    /// Returns [`CertificationContractError::TooManyWorkflowAssessments`] when the declared
    /// workflow set exceeds the fixed bound.
    pub fn new(
        target: CertificationTarget,
        profile_digest: CertificationProfileDigest,
        checks: CertificationChecks,
        workflows: BTreeMap<FeatureId, CertificationCheckAssessment>,
    ) -> Result<Self, CertificationContractError> {
        if workflows.len() > MAX_CERTIFICATION_WORKFLOWS {
            return Err(CertificationContractError::TooManyWorkflowAssessments);
        }
        Ok(Self {
            format_version: CertificationEvidenceFormatVersion::V1,
            target,
            profile_digest,
            checks,
            workflows,
        })
    }

    /// Parses one document only after enforcing the non-configurable byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`CertificationDocumentError`] when the input exceeds the byte ceiling or is not a
    /// valid canonical certification-evidence transport.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, CertificationDocumentError> {
        if bytes.len() > MAX_CERTIFICATION_DOCUMENT_BYTES {
            return Err(CertificationDocumentError::DocumentTooLarge);
        }
        serde_json::from_slice(bytes).map_err(CertificationDocumentError::InvalidJson)
    }

    /// Returns the exact serialized format version.
    #[must_use]
    pub const fn format_version(&self) -> &'static str {
        CERTIFICATION_EVIDENCE_FORMAT_VERSION
    }

    /// Returns the exact compatibility, execution, and artifact target.
    #[must_use]
    pub const fn target(&self) -> &CertificationTarget {
        &self.target
    }

    /// Returns the exact immutable certification-profile identity.
    #[must_use]
    pub const fn profile_digest(&self) -> &CertificationProfileDigest {
        &self.profile_digest
    }

    /// Returns the fixed mandatory check results.
    #[must_use]
    pub const fn checks(&self) -> &CertificationChecks {
        &self.checks
    }

    /// Returns the canonically ordered application workflow results.
    #[must_use]
    pub const fn workflows(&self) -> &BTreeMap<FeatureId, CertificationCheckAssessment> {
        &self.workflows
    }

    /// Derives a fail-closed evidence disposition without assigning a certification class.
    ///
    /// Mapping complete evidence to a certification class requires separately trusted resolution
    /// of [`Self::profile_digest`]; an untrusted producer cannot select that class in this document.
    #[must_use]
    pub fn disposition(&self) -> CertificationEvidenceDisposition {
        let mut has_failure = false;
        let mut has_gap = false;
        for assessment in self
            .checks
            .assessments()
            .into_iter()
            .chain(self.workflows.values())
        {
            match assessment.status() {
                CertificationCheckStatus::Failed => has_failure = true,
                CertificationCheckStatus::NotRun => has_gap = true,
                CertificationCheckStatus::Passed | CertificationCheckStatus::NotApplicable => {}
            }
        }
        if has_failure {
            return CertificationEvidenceDisposition::Blocked;
        }
        if has_gap {
            return CertificationEvidenceDisposition::Incomplete;
        }
        CertificationEvidenceDisposition::Complete
    }
}
