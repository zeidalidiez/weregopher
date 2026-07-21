//! Environment-bound compatibility-analysis contracts.

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

use crate::{FeatureId, Sha256Digest};

/// Maximum immutable evidence references retained for one compatibility dimension.
pub const MAX_COMPATIBILITY_EVIDENCE_REFS: usize = 64;
/// Current serialized compatibility-analysis contract version.
pub const COMPATIBILITY_ANALYSIS_FORMAT_VERSION: &str = "1";
/// Maximum application-specific workflow assessments in one analysis.
pub const MAX_COMPATIBILITY_WORKFLOWS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
enum CompatibilityAnalysisFormatVersion {
    #[serde(rename = "1")]
    V1,
}

/// Platform accepted by compatibility-analysis format version 1.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityPlatform {
    /// Microsoft Windows under the initial release profile.
    Windows,
}

/// Architecture accepted by compatibility-analysis format version 1.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityArchitecture {
    /// AMD64/x86-64 under the initial release profile.
    X86_64,
}

/// Immutable identity of the exact compatibility target that was analyzed.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityTarget {
    platform: CompatibilityPlatform,
    architecture: CompatibilityArchitecture,
    /// Digest of the resolved static adapter contract.
    adapter_contract_digest: Sha256Digest,
    /// Digest of the selected main-runtime contract and artifact descriptor.
    main_runtime_contract_digest: Sha256Digest,
    /// Digest of the selected renderer-backend contract and artifact descriptor.
    renderer_backend_contract_digest: Sha256Digest,
    /// Digest of the canonical execution-environment descriptor.
    execution_environment_digest: Sha256Digest,
}

impl CompatibilityTarget {
    /// Constructs the only target profile accepted by format version 1.
    #[must_use]
    pub const fn windows_x64(
        adapter_contract_digest: Sha256Digest,
        main_runtime_contract_digest: Sha256Digest,
        renderer_backend_contract_digest: Sha256Digest,
        execution_environment_digest: Sha256Digest,
    ) -> Self {
        Self {
            platform: CompatibilityPlatform::Windows,
            architecture: CompatibilityArchitecture::X86_64,
            adapter_contract_digest,
            main_runtime_contract_digest,
            renderer_backend_contract_digest,
            execution_environment_digest,
        }
    }

    /// Returns the fixed target platform.
    #[must_use]
    pub const fn platform(&self) -> CompatibilityPlatform {
        self.platform
    }

    /// Returns the fixed target architecture.
    #[must_use]
    pub const fn architecture(&self) -> CompatibilityArchitecture {
        self.architecture
    }

    /// Returns the resolved static adapter-contract identity.
    #[must_use]
    pub const fn adapter_contract_digest(&self) -> &Sha256Digest {
        &self.adapter_contract_digest
    }

    /// Returns the selected main-runtime contract identity.
    #[must_use]
    pub const fn main_runtime_contract_digest(&self) -> &Sha256Digest {
        &self.main_runtime_contract_digest
    }

    /// Returns the selected renderer-backend contract identity.
    #[must_use]
    pub const fn renderer_backend_contract_digest(&self) -> &Sha256Digest {
        &self.renderer_backend_contract_digest
    }

    /// Returns the canonical execution-environment identity.
    #[must_use]
    pub const fn execution_environment_digest(&self) -> &Sha256Digest {
        &self.execution_environment_digest
    }
}

/// Outcome of resolving every declared compatibility dimension.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisDisposition {
    /// One or more declared dimensions remain unresolved.
    Incomplete,
    /// One or more declared dimensions are known to be unsatisfied.
    Blocked,
    /// Every declared dimension is satisfied or explicitly not applicable.
    ///
    /// This is not a launch authorization or certification class.
    Complete,
}

/// Result of evaluating one compatibility dimension against a declared contract.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DimensionStatus {
    /// The dimension has not been resolved by sufficient evidence.
    Unknown,
    /// The declared compatibility requirement is satisfied.
    Satisfied,
    /// The declared compatibility requirement is not satisfied.
    Unsatisfied,
    /// The declared contract proves that this dimension does not apply.
    NotApplicable,
}

/// Kind of immutable evidence supporting one compatibility assessment.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityEvidenceKind {
    /// Canonical package-tree or package-layout evidence.
    PackageManifest,
    /// Deterministic static-analysis evidence.
    StaticAnalysis,
    /// Main-runtime probe evidence.
    RuntimeProbe,
    /// Renderer or preload probe evidence.
    RendererProbe,
    /// State-safety probe evidence.
    StateProbe,
    /// Security-contract probe evidence.
    SecurityProbe,
    /// Application-workflow probe evidence.
    WorkflowProbe,
    /// Signed or locally trusted adapter-contract evidence.
    AdapterContract,
}

/// Content-addressed evidence supporting one compatibility assessment.
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityEvidenceRef {
    /// Class of analysis or probe that produced the evidence.
    pub kind: CompatibilityEvidenceKind,
    /// Digest of the immutable evidence artifact.
    pub digest: Sha256Digest,
}

impl CompatibilityEvidenceRef {
    /// Constructs a content-addressed evidence reference.
    #[must_use]
    pub const fn new(kind: CompatibilityEvidenceKind, digest: Sha256Digest) -> Self {
        Self { kind, digest }
    }
}

/// Error constructing a compatibility-analysis contract.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CompatibilityContractError {
    /// A resolved status was supplied without supporting evidence.
    #[error("resolved compatibility assessments require evidence")]
    MissingEvidence,
    /// One dimension supplied more evidence references than the contract permits.
    #[error("compatibility assessment exceeds the evidence-reference limit")]
    TooManyEvidenceReferences,
    /// One dimension supplied the same immutable evidence reference more than once.
    #[error("compatibility assessment contains duplicate evidence references")]
    DuplicateEvidenceReference,
    /// The analysis declared more application workflows than the contract permits.
    #[error("compatibility analysis exceeds the workflow-assessment limit")]
    TooManyWorkflowAssessments,
}

/// One dimension's status and immutable supporting evidence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DimensionAssessment {
    status: DimensionStatus,
    #[schemars(length(max = 64))]
    evidence: BTreeSet<CompatibilityEvidenceRef>,
}

impl<'de> Deserialize<'de> for DimensionAssessment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedDimensionAssessment::deserialize(deserializer)?;
        Self::new(unchecked.status, unchecked.evidence).map_err(D::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedDimensionAssessment {
    status: DimensionStatus,
    #[serde(deserialize_with = "deserialize_evidence_references")]
    evidence: Vec<CompatibilityEvidenceRef>,
}

fn deserialize_evidence_references<'de, D>(
    deserializer: D,
) -> Result<Vec<CompatibilityEvidenceRef>, D::Error>
where
    D: Deserializer<'de>,
{
    struct EvidenceVisitor;

    impl<'de> Visitor<'de> for EvidenceVisitor {
        type Value = Vec<CompatibilityEvidenceRef>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded sequence of compatibility evidence references")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence
                .size_hint()
                .is_some_and(|length| length > MAX_COMPATIBILITY_EVIDENCE_REFS)
            {
                return Err(A::Error::custom(
                    CompatibilityContractError::TooManyEvidenceReferences,
                ));
            }

            let mut values = Vec::with_capacity(
                sequence
                    .size_hint()
                    .unwrap_or(0)
                    .min(MAX_COMPATIBILITY_EVIDENCE_REFS),
            );
            while values.len() < MAX_COMPATIBILITY_EVIDENCE_REFS {
                match sequence.next_element()? {
                    Some(reference) => values.push(reference),
                    None => return Ok(values),
                }
            }
            if sequence.next_element::<IgnoredAny>()?.is_some() {
                return Err(A::Error::custom(
                    CompatibilityContractError::TooManyEvidenceReferences,
                ));
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(EvidenceVisitor)
}

impl DimensionAssessment {
    /// Constructs an assessment and rejects unsupported resolved claims.
    ///
    /// # Errors
    ///
    /// Returns [`CompatibilityContractError`] when evidence is missing,
    /// duplicated, or exceeds the fixed per-dimension bound.
    pub fn new(
        status: DimensionStatus,
        evidence: impl IntoIterator<Item = CompatibilityEvidenceRef>,
    ) -> Result<Self, CompatibilityContractError> {
        let mut values = Vec::with_capacity(MAX_COMPATIBILITY_EVIDENCE_REFS);
        for reference in evidence {
            if values.len() == MAX_COMPATIBILITY_EVIDENCE_REFS {
                return Err(CompatibilityContractError::TooManyEvidenceReferences);
            }
            values.push(reference);
        }
        let value_count = values.len();
        let evidence: BTreeSet<CompatibilityEvidenceRef> = values.into_iter().collect();
        if evidence.len() != value_count {
            return Err(CompatibilityContractError::DuplicateEvidenceReference);
        }
        if status != DimensionStatus::Unknown && evidence.is_empty() {
            return Err(CompatibilityContractError::MissingEvidence);
        }
        Ok(Self { status, evidence })
    }

    /// Constructs an unresolved assessment without inventing evidence.
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            status: DimensionStatus::Unknown,
            evidence: BTreeSet::new(),
        }
    }

    /// Returns the declared status.
    #[must_use]
    pub const fn status(&self) -> DimensionStatus {
        self.status
    }

    /// Returns the canonically ordered supporting evidence.
    #[must_use]
    pub const fn evidence(&self) -> &BTreeSet<CompatibilityEvidenceRef> {
        &self.evidence
    }
}

/// Required compatibility dimensions for one exact build and target environment.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityDimensions {
    /// Package identity and layout contract.
    pub package: DimensionAssessment,
    /// Selected main-process runtime contract.
    pub main_runtime: DimensionAssessment,
    /// Renderer backend contract.
    pub renderer: DimensionAssessment,
    /// Preload and context-isolation contract.
    pub preload: DimensionAssessment,
    /// Used Electron API surface contract.
    pub electron_api: DimensionAssessment,
    /// Used Node API surface contract.
    pub node_api: DimensionAssessment,
    /// Native-module strategy contract.
    pub native_modules: DimensionAssessment,
    /// Vendor-helper strategy contract.
    pub helpers: DimensionAssessment,
    /// State safety and migration contract.
    pub state: DimensionAssessment,
    /// Declared security-contract probes.
    pub security: DimensionAssessment,
}

impl CompatibilityDimensions {
    fn assessments(&self) -> [&DimensionAssessment; 10] {
        [
            &self.package,
            &self.main_runtime,
            &self.renderer,
            &self.preload,
            &self.electron_api,
            &self.node_api,
            &self.native_modules,
            &self.helpers,
            &self.state,
            &self.security,
        ]
    }
}

/// Compatibility analysis for one immutable build and exact target environment.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityAnalysis {
    format_version: CompatibilityAnalysisFormatVersion,
    source_build_fingerprint_digest: Sha256Digest,
    target: CompatibilityTarget,
    dimensions: CompatibilityDimensions,
    #[schemars(extend("maxProperties" = 128))]
    workflows: BTreeMap<FeatureId, DimensionAssessment>,
}

impl<'de> Deserialize<'de> for CompatibilityAnalysis {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let UncheckedCompatibilityAnalysis {
            format_version: CompatibilityAnalysisFormatVersion::V1,
            source_build_fingerprint_digest,
            target,
            dimensions,
            workflows,
        } = UncheckedCompatibilityAnalysis::deserialize(deserializer)?;
        Self::new(
            source_build_fingerprint_digest,
            target,
            dimensions,
            workflows,
        )
        .map_err(D::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedCompatibilityAnalysis {
    format_version: CompatibilityAnalysisFormatVersion,
    source_build_fingerprint_digest: Sha256Digest,
    target: CompatibilityTarget,
    dimensions: CompatibilityDimensions,
    #[serde(deserialize_with = "deserialize_workflow_assessments")]
    workflows: BTreeMap<FeatureId, DimensionAssessment>,
}

fn deserialize_workflow_assessments<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<FeatureId, DimensionAssessment>, D::Error>
where
    D: Deserializer<'de>,
{
    struct WorkflowsVisitor;

    impl<'de> Visitor<'de> for WorkflowsVisitor {
        type Value = BTreeMap<FeatureId, DimensionAssessment>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded map of compatibility workflow assessments")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            if map
                .size_hint()
                .is_some_and(|length| length > MAX_COMPATIBILITY_WORKFLOWS)
            {
                return Err(A::Error::custom(
                    CompatibilityContractError::TooManyWorkflowAssessments,
                ));
            }

            let mut values = BTreeMap::new();
            while values.len() < MAX_COMPATIBILITY_WORKFLOWS {
                let Some(feature) = map.next_key()? else {
                    return Ok(values);
                };
                if values.contains_key(&feature) {
                    let _: IgnoredAny = map.next_value()?;
                    return Err(A::Error::custom(
                        "compatibility analysis contains duplicate workflow identifiers",
                    ));
                }
                let assessment = map.next_value()?;
                values.insert(feature, assessment);
            }
            if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
                return Err(A::Error::custom(
                    CompatibilityContractError::TooManyWorkflowAssessments,
                ));
            }
            Ok(values)
        }
    }

    deserializer.deserialize_map(WorkflowsVisitor)
}

impl CompatibilityAnalysis {
    /// Constructs an exact-target analysis without elevating it to certification.
    ///
    /// # Errors
    ///
    /// Returns [`CompatibilityContractError::TooManyWorkflowAssessments`] when
    /// the declared application workflow set exceeds the fixed bound.
    pub fn new(
        source_build_fingerprint_digest: Sha256Digest,
        target: CompatibilityTarget,
        dimensions: CompatibilityDimensions,
        workflows: BTreeMap<FeatureId, DimensionAssessment>,
    ) -> Result<Self, CompatibilityContractError> {
        if workflows.len() > MAX_COMPATIBILITY_WORKFLOWS {
            return Err(CompatibilityContractError::TooManyWorkflowAssessments);
        }
        Ok(Self {
            format_version: CompatibilityAnalysisFormatVersion::V1,
            source_build_fingerprint_digest,
            target,
            dimensions,
            workflows,
        })
    }

    /// Returns the serialized compatibility-analysis contract version.
    #[must_use]
    pub const fn format_version(&self) -> &'static str {
        COMPATIBILITY_ANALYSIS_FORMAT_VERSION
    }

    /// Returns the fail-closed aggregate of every fixed and workflow dimension.
    #[must_use]
    pub fn disposition(&self) -> AnalysisDisposition {
        let statuses = self
            .dimensions
            .assessments()
            .into_iter()
            .chain(self.workflows.values())
            .map(DimensionAssessment::status);
        aggregate_statuses(statuses)
    }

    /// Returns the immutable source build-fingerprint artifact identity.
    #[must_use]
    pub const fn source_build_fingerprint_digest(&self) -> &Sha256Digest {
        &self.source_build_fingerprint_digest
    }

    /// Returns the exact compatibility target identity.
    #[must_use]
    pub const fn target(&self) -> &CompatibilityTarget {
        &self.target
    }

    /// Returns the required compatibility dimensions.
    #[must_use]
    pub const fn dimensions(&self) -> &CompatibilityDimensions {
        &self.dimensions
    }

    /// Returns application-specific workflow assessments in canonical order.
    #[must_use]
    pub const fn workflows(&self) -> &BTreeMap<FeatureId, DimensionAssessment> {
        &self.workflows
    }
}

fn aggregate_statuses(statuses: impl IntoIterator<Item = DimensionStatus>) -> AnalysisDisposition {
    let mut incomplete = false;
    for status in statuses {
        match status {
            DimensionStatus::Unsatisfied => return AnalysisDisposition::Blocked,
            DimensionStatus::Unknown => incomplete = true,
            DimensionStatus::Satisfied | DimensionStatus::NotApplicable => {}
        }
    }
    if incomplete {
        AnalysisDisposition::Incomplete
    } else {
        AnalysisDisposition::Complete
    }
}
