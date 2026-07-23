//! Build-bound execution-artifact rebinding contracts.
//!
//! Custom map visitors bound retained domain entries. Callers that parse hostile transport bytes
//! must also impose an outer byte/read limit before invoking Serde.

use std::{collections::BTreeMap, fmt};

use schemars::JsonSchema;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, IgnoredAny, MapAccess, Visitor},
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{AdapterId, ApplicationFamilyId, ExecutionTargetId, Sha256Digest};

/// Current serialized execution-rebinding contract version.
pub const EXECUTION_REBINDING_FORMAT_VERSION: &str = "1";
/// Maximum signed execution targets in one adapter authority contract.
pub const MAX_AUTHORIZED_EXECUTION_TARGETS: usize = 64;
/// Maximum generated execution-artifact bindings in one build overlay.
pub const MAX_GENERATED_EXECUTION_BINDINGS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
enum ExecutionRebindingFormatVersion {
    #[serde(rename = "1")]
    V1,
}

/// Platform accepted by execution-rebinding format version 1.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPlatform {
    /// Microsoft Windows under the initial release profile.
    Windows,
}

/// Architecture accepted by execution-rebinding format version 1.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionArchitecture {
    /// AMD64/x86-64 under the initial release profile.
    X86_64,
}

/// Supervisor-visible role of one statically declared execution target.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionTargetKind {
    /// Weregopher-owned main runtime selected for one application.
    MainRuntime,
    /// Vendor executable designed to run independently from the desktop Electron entry point.
    VendorHelper,
    /// Minimal process retaining one bounded native ABI dependency set.
    AbiIsland,
    /// Purpose-specific media, overlay, or integration helper.
    SpecializedHelper,
}

/// Managed source from which an exact executable is resolved.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionArtifactSource {
    /// A package-tree snapshot whose identity is its canonical package-tree Merkle digest.
    PackageSnapshot,
    /// A managed content-addressed artifact manifest outside the package snapshot.
    ManagedArtifact,
}

/// One execution target declared by a static adapter artifact.
///
/// `execution_contract_digest` commits to the signed static target descriptor, including artifact
/// selection rules and launch policy. This reference does not authenticate or interpret that
/// descriptor by itself.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedExecutionTargetRef {
    kind: ExecutionTargetKind,
    artifact_source: ExecutionArtifactSource,
    execution_contract_digest: Sha256Digest,
}

impl AuthorizedExecutionTargetRef {
    /// Constructs an immutable static execution-target reference.
    #[must_use]
    pub const fn new(
        kind: ExecutionTargetKind,
        artifact_source: ExecutionArtifactSource,
        execution_contract_digest: Sha256Digest,
    ) -> Self {
        Self {
            kind,
            artifact_source,
            execution_contract_digest,
        }
    }

    /// Returns the supervisor-visible process role.
    #[must_use]
    pub const fn kind(&self) -> ExecutionTargetKind {
        self.kind
    }

    /// Returns the only managed artifact source this target may use.
    #[must_use]
    pub const fn artifact_source(&self) -> ExecutionArtifactSource {
        self.artifact_source
    }

    /// Returns the exact static target-contract identity.
    #[must_use]
    pub const fn execution_contract_digest(&self) -> &Sha256Digest {
        &self.execution_contract_digest
    }
}

/// Static execution-target authority declared by one adapter artifact.
///
/// This transport describes what an authenticated adapter may authorize, but does not authenticate
/// itself. Consumers must retrieve, hash, authenticate, and revocation-check the exact authority and
/// every referenced target contract before using them in a launch decision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterExecutionAuthority {
    format_version: ExecutionRebindingFormatVersion,
    adapter_id: AdapterId,
    family: ApplicationFamilyId,
    adapter_content_digest: Sha256Digest,
    #[schemars(extend("minProperties" = 1, "maxProperties" = 64))]
    targets: BTreeMap<ExecutionTargetId, AuthorizedExecutionTargetRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterExecutionAuthorityTransport {
    format_version: ExecutionRebindingFormatVersion,
    adapter_id: AdapterId,
    family: ApplicationFamilyId,
    adapter_content_digest: Sha256Digest,
    #[serde(deserialize_with = "deserialize_authorized_execution_targets")]
    targets: BTreeMap<ExecutionTargetId, AuthorizedExecutionTargetRef>,
}

fn deserialize_authorized_execution_targets<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<ExecutionTargetId, AuthorizedExecutionTargetRef>, D::Error>
where
    D: Deserializer<'de>,
{
    struct TargetsVisitor;

    impl<'de> Visitor<'de> for TargetsVisitor {
        type Value = BTreeMap<ExecutionTargetId, AuthorizedExecutionTargetRef>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded map of static execution targets")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            if map
                .size_hint()
                .is_some_and(|length| length > MAX_AUTHORIZED_EXECUTION_TARGETS)
            {
                return Err(A::Error::custom(
                    ExecutionContractError::TooManyExecutionTargets,
                ));
            }
            let mut targets = BTreeMap::new();
            while targets.len() < MAX_AUTHORIZED_EXECUTION_TARGETS {
                let Some(target_id) = map.next_key()? else {
                    return Ok(targets);
                };
                if targets.contains_key(&target_id) {
                    let _: IgnoredAny = map.next_value()?;
                    return Err(A::Error::custom(
                        "adapter execution authority contains duplicate execution target identifiers",
                    ));
                }
                let target = map.next_value()?;
                targets.insert(target_id, target);
            }
            if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
                return Err(A::Error::custom(
                    ExecutionContractError::TooManyExecutionTargets,
                ));
            }
            Ok(targets)
        }
    }

    deserializer.deserialize_map(TargetsVisitor)
}

impl<'de> Deserialize<'de> for AdapterExecutionAuthority {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let AdapterExecutionAuthorityTransport {
            format_version,
            adapter_id,
            family,
            adapter_content_digest,
            targets,
        } = AdapterExecutionAuthorityTransport::deserialize(deserializer)?;
        match format_version {
            ExecutionRebindingFormatVersion::V1 => {
                Self::new(adapter_id, family, adapter_content_digest, targets)
                    .map_err(D::Error::custom)
            }
        }
    }
}

impl AdapterExecutionAuthority {
    /// Constructs one static execution-target authority contract.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionContractError`] when the target map is empty or exceeds its bound.
    pub fn new(
        adapter_id: AdapterId,
        family: ApplicationFamilyId,
        adapter_content_digest: Sha256Digest,
        targets: BTreeMap<ExecutionTargetId, AuthorizedExecutionTargetRef>,
    ) -> Result<Self, ExecutionContractError> {
        if targets.is_empty() {
            return Err(ExecutionContractError::EmptyExecutionAuthority);
        }
        if targets.len() > MAX_AUTHORIZED_EXECUTION_TARGETS {
            return Err(ExecutionContractError::TooManyExecutionTargets);
        }
        Ok(Self {
            format_version: ExecutionRebindingFormatVersion::V1,
            adapter_id,
            family,
            adapter_content_digest,
            targets,
        })
    }

    /// Returns the durable adapter identifier.
    #[must_use]
    pub const fn adapter_id(&self) -> &AdapterId {
        &self.adapter_id
    }

    /// Returns the application family covered by this authority.
    #[must_use]
    pub const fn family(&self) -> &ApplicationFamilyId {
        &self.family
    }

    /// Returns the exact adapter artifact identity.
    #[must_use]
    pub const fn adapter_content_digest(&self) -> &Sha256Digest {
        &self.adapter_content_digest
    }

    /// Returns statically authorized execution targets in canonical order.
    #[must_use]
    pub const fn targets(&self) -> &BTreeMap<ExecutionTargetId, AuthorizedExecutionTargetRef> {
        &self.targets
    }

    /// Computes the SHA-256 digest of this format-v1 authority's canonical JSON bytes.
    ///
    /// The digest binds one exact parsed object but does not authenticate it.
    #[must_use]
    pub fn canonical_document_digest(&self) -> Sha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(b"{\"format_version\":\"");
        hasher.update(EXECUTION_REBINDING_FORMAT_VERSION.as_bytes());
        hasher.update(b"\",\"adapter_id\":\"");
        hasher.update(self.adapter_id.as_str().as_bytes());
        hasher.update(b"\",\"family\":\"");
        hasher.update(self.family.as_str().as_bytes());
        hasher.update(b"\",\"adapter_content_digest\":\"");
        update_canonical_digest_text(&mut hasher, &self.adapter_content_digest);
        hasher.update(b"\",\"targets\":{");
        let mut first = true;
        for (target_id, target) in &self.targets {
            if first {
                first = false;
            } else {
                hasher.update(b",");
            }
            hasher.update(b"\"");
            hasher.update(target_id.as_str().as_bytes());
            hasher.update(b"\":{\"kind\":\"");
            hasher.update(execution_target_kind_text(target.kind).as_bytes());
            hasher.update(b"\",\"artifact_source\":\"");
            hasher.update(execution_artifact_source_text(target.artifact_source).as_bytes());
            hasher.update(b"\",\"execution_contract_digest\":\"");
            update_canonical_digest_text(&mut hasher, &target.execution_contract_digest);
            hasher.update(b"\"}");
        }
        hasher.update(b"}}");
        Sha256Digest::from_bytes(hasher.finalize().into())
    }
}

fn execution_target_kind_text(kind: ExecutionTargetKind) -> &'static str {
    match kind {
        ExecutionTargetKind::MainRuntime => "main_runtime",
        ExecutionTargetKind::VendorHelper => "vendor_helper",
        ExecutionTargetKind::AbiIsland => "abi_island",
        ExecutionTargetKind::SpecializedHelper => "specialized_helper",
    }
}

fn execution_artifact_source_text(source: ExecutionArtifactSource) -> &'static str {
    match source {
        ExecutionArtifactSource::PackageSnapshot => "package_snapshot",
        ExecutionArtifactSource::ManagedArtifact => "managed_artifact",
    }
}

fn update_canonical_digest_text(hasher: &mut Sha256, digest: &Sha256Digest) {
    hasher.update(b"sha256:");
    hasher.update(hex::encode(digest.as_bytes()).as_bytes());
}

/// Role-named content identities used to construct one generated execution-artifact binding.
///
/// This constructor input is not independently serialized. Named fields prevent same-type digest
/// arguments from being silently transposed while preserving the canonical binding transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionArtifactDigests {
    /// Exact signed static target-contract identity.
    pub execution_contract_digest: Sha256Digest,
    /// Exact package-tree or managed-manifest identity containing the executable.
    pub artifact_source_digest: Sha256Digest,
    /// Exact executable byte identity.
    pub executable_digest: Sha256Digest,
    /// Exact generated resolution-evidence identity.
    pub resolution_evidence_digest: Sha256Digest,
}

/// Generated evidence binding one static execution target to exact resolved artifacts.
///
/// The resolution-evidence artifact is expected to describe the resolved executable path, signer or
/// provenance checks, launch-policy resolution, and any other target-contract evidence. This record
/// binds its digest but does not interpret or trust those bytes.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionArtifactBinding {
    #[serde(rename = "execution_contract_digest")]
    execution_contract: Sha256Digest,
    #[serde(rename = "artifact_source_digest")]
    artifact_source: Sha256Digest,
    #[serde(rename = "executable_digest")]
    executable: Sha256Digest,
    #[serde(rename = "resolution_evidence_digest")]
    resolution_evidence: Sha256Digest,
}

impl ExecutionArtifactBinding {
    /// Constructs one content-addressed generated execution-artifact binding from role-named
    /// digests, preventing positional digest transposition at the call site.
    #[must_use]
    pub const fn new(digests: ExecutionArtifactDigests) -> Self {
        Self {
            execution_contract: digests.execution_contract_digest,
            artifact_source: digests.artifact_source_digest,
            executable: digests.executable_digest,
            resolution_evidence: digests.resolution_evidence_digest,
        }
    }

    /// Returns the exact signed static target-contract identity.
    #[must_use]
    pub const fn execution_contract_digest(&self) -> &Sha256Digest {
        &self.execution_contract
    }

    /// Returns the exact package-tree or managed-manifest identity containing the executable.
    #[must_use]
    pub const fn artifact_source_digest(&self) -> &Sha256Digest {
        &self.artifact_source
    }

    /// Returns the exact executable byte identity.
    #[must_use]
    pub const fn executable_digest(&self) -> &Sha256Digest {
        &self.executable
    }

    /// Returns the exact generated resolution-evidence identity.
    #[must_use]
    pub const fn resolution_evidence_digest(&self) -> &Sha256Digest {
        &self.resolution_evidence
    }
}

/// Immutable adapter-authority identities carried by one generated execution overlay.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAuthorityBinding {
    family: ApplicationFamilyId,
    adapter_id: AdapterId,
    adapter_content_digest: Sha256Digest,
    adapter_execution_authority_digest: Sha256Digest,
}

impl ExecutionAuthorityBinding {
    fn from_authority(authority: &AdapterExecutionAuthority) -> Self {
        Self {
            family: authority.family.clone(),
            adapter_id: authority.adapter_id.clone(),
            adapter_content_digest: authority.adapter_content_digest,
            adapter_execution_authority_digest: authority.canonical_document_digest(),
        }
    }

    /// Returns the application family.
    #[must_use]
    pub const fn family(&self) -> &ApplicationFamilyId {
        &self.family
    }

    /// Returns the adapter identifier.
    #[must_use]
    pub const fn adapter_id(&self) -> &AdapterId {
        &self.adapter_id
    }

    /// Returns the exact adapter artifact identity.
    #[must_use]
    pub const fn adapter_content_digest(&self) -> &Sha256Digest {
        &self.adapter_content_digest
    }

    /// Returns the exact static execution-authority document identity.
    #[must_use]
    pub const fn adapter_execution_authority_digest(&self) -> &Sha256Digest {
        &self.adapter_execution_authority_digest
    }
}

/// Role-named immutable environment identities used to construct and validate one execution overlay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionOverlayContext {
    /// Exact source build-fingerprint identity.
    pub source_build_fingerprint_digest: Sha256Digest,
    /// Exact package-tree identity.
    pub package_tree_merkle: Sha256Digest,
    /// Exact execution-environment descriptor identity.
    pub execution_environment_digest: Sha256Digest,
    /// Exact build-descriptor identity.
    pub build_descriptor_digest: Sha256Digest,
}

/// Immutable identities binding generated execution evidence to one exact environment.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionOverlayBinding {
    source_build_fingerprint_digest: Sha256Digest,
    package_tree_merkle: Sha256Digest,
    execution_environment_digest: Sha256Digest,
    authority: ExecutionAuthorityBinding,
    build_descriptor_digest: Sha256Digest,
}

impl ExecutionOverlayBinding {
    /// Constructs exact immutable identities for one generated execution overlay.
    ///
    /// Adapter and authority digests are derived from the supplied authority object rather than
    /// accepted as independently positioned arguments.
    #[must_use]
    pub fn new(context: ExecutionOverlayContext, authority: &AdapterExecutionAuthority) -> Self {
        Self {
            source_build_fingerprint_digest: context.source_build_fingerprint_digest,
            package_tree_merkle: context.package_tree_merkle,
            execution_environment_digest: context.execution_environment_digest,
            authority: ExecutionAuthorityBinding::from_authority(authority),
            build_descriptor_digest: context.build_descriptor_digest,
        }
    }

    /// Returns the exact source build-fingerprint identity.
    #[must_use]
    pub const fn source_build_fingerprint_digest(&self) -> &Sha256Digest {
        &self.source_build_fingerprint_digest
    }

    /// Returns the exact package-tree identity.
    #[must_use]
    pub const fn package_tree_merkle(&self) -> &Sha256Digest {
        &self.package_tree_merkle
    }

    /// Returns the exact execution-environment descriptor identity.
    #[must_use]
    pub const fn execution_environment_digest(&self) -> &Sha256Digest {
        &self.execution_environment_digest
    }

    /// Returns the exact adapter-authority identities.
    #[must_use]
    pub const fn authority(&self) -> &ExecutionAuthorityBinding {
        &self.authority
    }

    /// Returns the exact build-descriptor identity.
    #[must_use]
    pub const fn build_descriptor_digest(&self) -> &Sha256Digest {
        &self.build_descriptor_digest
    }
}

/// Generated per-build execution-artifact resolution evidence.
///
/// This is structural, content-addressed evidence. It does not authenticate authority, prove that
/// referenced artifacts exist, grant capabilities, authorize execution, or authorize process launch.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedExecutionOverlay {
    format_version: ExecutionRebindingFormatVersion,
    platform: ExecutionPlatform,
    architecture: ExecutionArchitecture,
    binding: ExecutionOverlayBinding,
    #[schemars(extend("minProperties" = 1, "maxProperties" = 64))]
    bindings: BTreeMap<ExecutionTargetId, ExecutionArtifactBinding>,
}

/// Opaque proof that generated execution evidence structurally conforms to an exact supplied
/// authority object and caller-supplied environment identities.
///
/// This is not an authenticated authority, launch token, executable lease, compatibility result,
/// security-posture claim, or sandbox proof.
#[derive(Eq, PartialEq)]
pub struct StructurallyValidatedExecutionOverlay<'overlay, 'authority> {
    overlay: &'overlay GeneratedExecutionOverlay,
    authority: &'authority AdapterExecutionAuthority,
}

impl fmt::Debug for StructurallyValidatedExecutionOverlay<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StructurallyValidatedExecutionOverlay")
            .field("binding", self.overlay.binding())
            .field("target_count", &self.overlay.bindings().len())
            .finish_non_exhaustive()
    }
}

impl<'overlay, 'authority> StructurallyValidatedExecutionOverlay<'overlay, 'authority> {
    /// Returns the exact generated overlay covered by this structural proof.
    #[must_use]
    pub const fn overlay(&self) -> &'overlay GeneratedExecutionOverlay {
        self.overlay
    }

    /// Returns the exact supplied authority object covered by this structural proof.
    #[must_use]
    pub const fn authority(&self) -> &'authority AdapterExecutionAuthority {
        self.authority
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneratedExecutionOverlayTransport {
    format_version: ExecutionRebindingFormatVersion,
    platform: ExecutionPlatform,
    architecture: ExecutionArchitecture,
    binding: ExecutionOverlayBinding,
    #[serde(deserialize_with = "deserialize_execution_bindings")]
    bindings: BTreeMap<ExecutionTargetId, ExecutionArtifactBinding>,
}

fn deserialize_execution_bindings<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<ExecutionTargetId, ExecutionArtifactBinding>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BindingsVisitor;

    impl<'de> Visitor<'de> for BindingsVisitor {
        type Value = BTreeMap<ExecutionTargetId, ExecutionArtifactBinding>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded map of generated execution-artifact bindings")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            if map
                .size_hint()
                .is_some_and(|length| length > MAX_GENERATED_EXECUTION_BINDINGS)
            {
                return Err(A::Error::custom(
                    ExecutionContractError::TooManyExecutionBindings,
                ));
            }
            let mut bindings = BTreeMap::new();
            while bindings.len() < MAX_GENERATED_EXECUTION_BINDINGS {
                let Some(target_id) = map.next_key()? else {
                    return Ok(bindings);
                };
                if bindings.contains_key(&target_id) {
                    let _: IgnoredAny = map.next_value()?;
                    return Err(A::Error::custom(
                        "generated execution overlay contains duplicate execution target identifiers",
                    ));
                }
                let binding = map.next_value()?;
                bindings.insert(target_id, binding);
            }
            if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
                return Err(A::Error::custom(
                    ExecutionContractError::TooManyExecutionBindings,
                ));
            }
            Ok(bindings)
        }
    }

    deserializer.deserialize_map(BindingsVisitor)
}

impl<'de> Deserialize<'de> for GeneratedExecutionOverlay {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let GeneratedExecutionOverlayTransport {
            format_version,
            platform,
            architecture,
            binding,
            bindings,
        } = GeneratedExecutionOverlayTransport::deserialize(deserializer)?;
        match (format_version, platform, architecture) {
            (
                ExecutionRebindingFormatVersion::V1,
                ExecutionPlatform::Windows,
                ExecutionArchitecture::X86_64,
            ) => Self::windows_x64(binding, bindings).map_err(D::Error::custom),
        }
    }
}

impl GeneratedExecutionOverlay {
    /// Constructs the only generated execution target accepted by format version 1.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionContractError`] when the binding map is empty or exceeds its bound.
    pub fn windows_x64(
        binding: ExecutionOverlayBinding,
        bindings: BTreeMap<ExecutionTargetId, ExecutionArtifactBinding>,
    ) -> Result<Self, ExecutionContractError> {
        if bindings.is_empty() {
            return Err(ExecutionContractError::EmptyExecutionOverlay);
        }
        if bindings.len() > MAX_GENERATED_EXECUTION_BINDINGS {
            return Err(ExecutionContractError::TooManyExecutionBindings);
        }
        Ok(Self {
            format_version: ExecutionRebindingFormatVersion::V1,
            platform: ExecutionPlatform::Windows,
            architecture: ExecutionArchitecture::X86_64,
            binding,
            bindings,
        })
    }

    /// Structurally verifies authority non-expansion and exact environment identity bindings.
    ///
    /// The supplied authority remains unauthenticated. This operation does not retrieve target
    /// contracts, resolution evidence, manifests, snapshots, or executable bytes and therefore does
    /// not authorize process launch.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionContractError`] when an identity, target, contract, or source binding does
    /// not match.
    pub fn validate_against<'overlay, 'authority>(
        &'overlay self,
        authority: &'authority AdapterExecutionAuthority,
        context: ExecutionOverlayContext,
    ) -> Result<StructurallyValidatedExecutionOverlay<'overlay, 'authority>, ExecutionContractError>
    {
        if self.binding.source_build_fingerprint_digest != context.source_build_fingerprint_digest {
            return Err(ExecutionContractError::SourceBuildMismatch);
        }
        if self.binding.package_tree_merkle != context.package_tree_merkle {
            return Err(ExecutionContractError::PackageTreeMismatch);
        }
        if self.binding.execution_environment_digest != context.execution_environment_digest {
            return Err(ExecutionContractError::ExecutionEnvironmentMismatch);
        }
        if self.binding.build_descriptor_digest != context.build_descriptor_digest {
            return Err(ExecutionContractError::BuildDescriptorMismatch);
        }
        if self.binding.authority.adapter_id != authority.adapter_id
            || self.binding.authority.family != authority.family
            || self.binding.authority.adapter_content_digest != authority.adapter_content_digest
        {
            return Err(ExecutionContractError::AuthorityIdentityMismatch);
        }
        if self.binding.authority.adapter_execution_authority_digest
            != authority.canonical_document_digest()
        {
            return Err(ExecutionContractError::AuthorityDigestMismatch);
        }
        for (target_id, binding) in &self.bindings {
            let authorized = authority
                .targets
                .get(target_id)
                .ok_or(ExecutionContractError::UnknownExecutionTarget)?;
            if authorized.execution_contract_digest != binding.execution_contract {
                return Err(ExecutionContractError::ExecutionContractDigestMismatch);
            }
            if authorized.artifact_source == ExecutionArtifactSource::PackageSnapshot
                && binding.artifact_source != self.binding.package_tree_merkle
            {
                return Err(ExecutionContractError::PackageSnapshotDigestMismatch);
            }
        }
        Ok(StructurallyValidatedExecutionOverlay {
            overlay: self,
            authority,
        })
    }

    /// Returns generated execution-artifact bindings in canonical order.
    #[must_use]
    pub const fn bindings(&self) -> &BTreeMap<ExecutionTargetId, ExecutionArtifactBinding> {
        &self.bindings
    }

    /// Returns exact source, adapter, and environment identities for this overlay.
    #[must_use]
    pub const fn binding(&self) -> &ExecutionOverlayBinding {
        &self.binding
    }
}

/// Error constructing or structurally validating execution-rebinding contracts.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ExecutionContractError {
    /// The static authority did not declare any execution targets.
    #[error("adapter execution authority must declare at least one target")]
    EmptyExecutionAuthority,
    /// The static authority exceeded its target limit.
    #[error("adapter execution authority exceeds the target limit")]
    TooManyExecutionTargets,
    /// The generated overlay did not contain any execution bindings.
    #[error("generated execution overlay must contain at least one binding")]
    EmptyExecutionOverlay,
    /// The generated overlay exceeded its binding limit.
    #[error("generated execution overlay exceeds the binding limit")]
    TooManyExecutionBindings,
    /// The overlay referenced a different source build.
    #[error("generated execution overlay references a different source build")]
    SourceBuildMismatch,
    /// The overlay referenced a different package tree.
    #[error("generated execution overlay references a different package tree")]
    PackageTreeMismatch,
    /// The overlay referenced a different execution environment.
    #[error("generated execution overlay references a different execution environment")]
    ExecutionEnvironmentMismatch,
    /// The overlay referenced a different build descriptor.
    #[error("generated execution overlay references a different build descriptor")]
    BuildDescriptorMismatch,
    /// Adapter or family identity differed from the supplied authority.
    #[error("generated execution overlay identity does not match adapter authority")]
    AuthorityIdentityMismatch,
    /// The exact authority document differed from the supplied authority.
    #[error("generated execution overlay references a different authority artifact")]
    AuthorityDigestMismatch,
    /// The overlay referenced a target absent from static authority.
    #[error("generated execution overlay references an unknown execution target")]
    UnknownExecutionTarget,
    /// The overlay substituted a known target's static contract.
    #[error("generated execution overlay target contract does not match static authority")]
    ExecutionContractDigestMismatch,
    /// A package-snapshot target referenced a different package-tree manifest.
    #[error("package-snapshot execution target references a different package tree")]
    PackageSnapshotDigestMismatch,
}
