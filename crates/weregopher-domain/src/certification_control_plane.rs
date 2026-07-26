//! Canonical contracts for verified runner components, fresh local run attestations, and ledgers.

use std::{
    collections::BTreeSet,
    fmt,
    io::{self, Read},
};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    CertificationArtifactRef, CertificationClass, CertificationEvidenceDigest,
    CertificationProfileDigest, CertificationRunnerIdentityDigest, CertificationTarget,
    PublicationStatus, Sha256Digest,
};

/// Current serialized runner-component descriptor format.
pub const CERTIFICATION_RUNNER_COMPONENT_DESCRIPTOR_FORMAT_VERSION: &str = "1";
/// Maximum serialized bytes accepted for one runner-component descriptor.
pub const MAX_CERTIFICATION_RUNNER_COMPONENT_DESCRIPTOR_BYTES: usize = 256 * 1024;
/// Maximum exact artifacts named by one runner-component descriptor.
pub const MAX_CERTIFICATION_RUNNER_COMPONENT_ARTIFACTS: usize = 64;
/// Maximum UTF-8 bytes in one component identifier, version, or artifact name.
pub const MAX_CERTIFICATION_RUNNER_COMPONENT_TEXT_BYTES: usize = 256;
/// Maximum aggregate UTF-8 bytes across artifact names in one descriptor.
pub const MAX_CERTIFICATION_RUNNER_COMPONENT_ARTIFACT_NAME_BYTES: usize = 16 * 1024;
/// Maximum byte length representable by one runner-component artifact.
pub const MAX_CERTIFICATION_RUNNER_COMPONENT_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;

/// Current serialized local certification-run attestation format.
pub const LOCAL_CERTIFICATION_RUN_ATTESTATION_FORMAT_VERSION: &str = "1";
/// Maximum serialized bytes accepted for one local certification-run attestation.
pub const MAX_LOCAL_CERTIFICATION_RUN_ATTESTATION_BYTES: usize = 128 * 1024;
/// Maximum freshness interval accepted for a local certification run.
pub const MAX_LOCAL_CERTIFICATION_RUN_FRESHNESS_MILLIS: u64 = 10 * 60 * 1_000;

/// Current serialized local certification-ledger record format.
pub const LOCAL_CERTIFICATION_LEDGER_RECORD_FORMAT_VERSION: &str = "1";
/// Maximum serialized bytes accepted for one local certification-ledger record.
pub const MAX_LOCAL_CERTIFICATION_LEDGER_RECORD_BYTES: usize = 256 * 1024;
/// Maximum records accepted in one local certification ledger.
pub const MAX_LOCAL_CERTIFICATION_LEDGER_RECORDS: usize = 4_096;
/// Maximum aggregate serialized record bytes accepted in one local certification ledger.
pub const MAX_LOCAL_CERTIFICATION_LEDGER_BYTES: usize = 256 * 1024 * 1024;

macro_rules! certification_control_digest_role {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Clone,
            Copy,
            Debug,
            Deserialize,
            Eq,
            Hash,
            JsonSchema,
            Ord,
            PartialEq,
            PartialOrd,
            Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(Sha256Digest);

        impl $name {
            /// Creates this role-specific identity from canonical SHA-256 bytes.
            #[must_use]
            pub const fn new(digest: Sha256Digest) -> Self {
                Self(digest)
            }

            /// Returns the wire-compatible SHA-256 value.
            #[must_use]
            pub const fn as_sha256(&self) -> &Sha256Digest {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

certification_control_digest_role!(
    /// Identity of canonical runner-component provenance bytes.
    CertificationRunnerComponentProvenanceDigest
);
certification_control_digest_role!(
    /// Identity of one canonical runner-component descriptor.
    CertificationRunnerComponentDescriptorDigest
);
certification_control_digest_role!(
    /// Identity of the complete verified runner-component descriptor set.
    CertificationRunnerDescriptorSetDigest
);
certification_control_digest_role!(
    /// Identity of one local certification policy revision.
    CertificationPolicyRevisionDigest
);
certification_control_digest_role!(
    /// Identity of evidence revoking one local certification policy.
    CertificationPolicyRevocationDigest
);
certification_control_digest_role!(
    /// Identity of one local certification-runner policy revision.
    CertificationRunnerPolicyRevisionDigest
);
certification_control_digest_role!(
    /// Identity of evidence revoking one local certification-runner policy.
    CertificationRunnerPolicyRevocationDigest
);
certification_control_digest_role!(
    /// Identity of the exact verified certification artifact-reference set.
    CertificationArtifactSetDigest
);
certification_control_digest_role!(
    /// Identity of one canonical local certification-run attestation.
    LocalCertificationRunAttestationDigest
);
certification_control_digest_role!(
    /// Identity of one canonical local certification-ledger record.
    LocalCertificationLedgerRecordDigest
);

/// Exact role occupied by one certification-runner component descriptor.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CertificationRunnerComponentRole {
    /// Immutable certification runner image or executable closure.
    RunnerImage,
    /// Host operating-system image and build evidence.
    HostImage,
    /// Exact host patch-set evidence.
    HostPatchSet,
    /// Exact Electron runtime.
    ElectronRuntime,
    /// Exact language-runtime set.
    LanguageRuntimeSet,
    /// Exact compiler and toolchain set.
    ToolchainSet,
    /// Exact host-agent implementation.
    HostAgent,
    /// Exact semantic verifier implementation.
    Verifier,
    /// Complete exact probe-asset set.
    ProbeAssetSet,
    /// Exact certification source revision.
    SourceRevision,
    /// Complete approved exception-provenance set.
    ExceptionProvenance,
}

macro_rules! bounded_component_text {
    ($(#[$meta:meta])* $name:ident, $kind:literal) => {
        $(#[$meta])*
        #[derive(
            Clone,
            Debug,
            Eq,
            Hash,
            JsonSchema,
            Ord,
            PartialEq,
            PartialOrd,
            Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
            }
        }

        impl $name {
            /// Validates and retains one bounded canonical text value.
            ///
            /// # Errors
            ///
            /// Returns [`CertificationRunnerComponentTextError`] for empty, oversized, or unsafe
            /// text.
            pub fn new(value: impl Into<String>) -> Result<Self, CertificationRunnerComponentTextError> {
                let value = value.into();
                validate_component_text(&value, $kind)?;
                Ok(Self(value))
            }

            /// Returns the validated string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

bounded_component_text!(
    /// Bounded stable identifier for one runner component.
    CertificationRunnerComponentId,
    "component identifier"
);
bounded_component_text!(
    /// Bounded exact version spelling for one runner component.
    CertificationRunnerComponentVersion,
    "component version"
);
bounded_component_text!(
    /// Bounded normalized logical artifact name within one runner component.
    CertificationRunnerArtifactName,
    "artifact name"
);

fn validate_component_text(
    value: &str,
    kind: &'static str,
) -> Result<(), CertificationRunnerComponentTextError> {
    if value.is_empty() {
        return Err(CertificationRunnerComponentTextError::Empty { kind });
    }
    if value.len() > MAX_CERTIFICATION_RUNNER_COMPONENT_TEXT_BYTES {
        return Err(CertificationRunnerComponentTextError::TooLong { kind });
    }
    if value.starts_with('/') || value.ends_with('/') || value.contains('\\') {
        return Err(CertificationRunnerComponentTextError::NonCanonical { kind });
    }
    if value.split('/').any(|component| {
        component.is_empty()
            || matches!(component, "." | "..")
            || component.ends_with('.')
            || component.ends_with(' ')
    }) {
        return Err(CertificationRunnerComponentTextError::NonCanonical { kind });
    }
    if value
        .chars()
        .any(|character| character.is_control() || character == '\u{7f}')
    {
        return Err(CertificationRunnerComponentTextError::UnsafeCharacter { kind });
    }
    Ok(())
}

/// Invalid bounded runner-component text.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CertificationRunnerComponentTextError {
    /// Text was empty.
    #[error("{kind} is empty")]
    Empty {
        /// Text role.
        kind: &'static str,
    },
    /// Text exceeded its fixed UTF-8 byte ceiling.
    #[error("{kind} exceeds its UTF-8 byte ceiling")]
    TooLong {
        /// Text role.
        kind: &'static str,
    },
    /// Text used a noncanonical path-like spelling.
    #[error("{kind} is not canonical")]
    NonCanonical {
        /// Text role.
        kind: &'static str,
    },
    /// Text contained a control character.
    #[error("{kind} contains an unsafe character")]
    UnsafeCharacter {
        /// Text role.
        kind: &'static str,
    },
}

/// One exact artifact named by a runner-component descriptor.
#[derive(Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationRunnerComponentArtifact {
    name: CertificationRunnerArtifactName,
    #[serde(rename = "sha256")]
    digest: Sha256Digest,
    size_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedCertificationRunnerComponentArtifact {
    name: CertificationRunnerArtifactName,
    #[serde(rename = "sha256")]
    digest: Sha256Digest,
    size_bytes: u64,
}

impl<'de> Deserialize<'de> for CertificationRunnerComponentArtifact {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedCertificationRunnerComponentArtifact::deserialize(deserializer)?;
        Self::new(unchecked.name, unchecked.digest, unchecked.size_bytes).map_err(D::Error::custom)
    }
}

impl CertificationRunnerComponentArtifact {
    /// Constructs one exact nonempty runner-component artifact.
    ///
    /// # Errors
    ///
    /// Returns [`CertificationRunnerComponentDescriptorError::InvalidArtifactSize`] when the byte
    /// length is zero or exceeds the implementation ceiling.
    pub fn new(
        name: CertificationRunnerArtifactName,
        digest: Sha256Digest,
        size_bytes: u64,
    ) -> Result<Self, CertificationRunnerComponentDescriptorError> {
        if size_bytes == 0 || size_bytes > MAX_CERTIFICATION_RUNNER_COMPONENT_ARTIFACT_BYTES {
            return Err(CertificationRunnerComponentDescriptorError::InvalidArtifactSize);
        }
        Ok(Self {
            name,
            digest,
            size_bytes,
        })
    }

    /// Returns the exact logical artifact name.
    #[must_use]
    pub const fn name(&self) -> &CertificationRunnerArtifactName {
        &self.name
    }

    /// Returns the exact artifact-byte identity.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Returns the exact artifact byte length.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
enum CertificationRunnerComponentDescriptorFormatVersion {
    #[serde(rename = "1")]
    V1,
}

/// Canonical descriptor for one exact certification-runner component role.
///
/// Generic deserialization is deliberately unavailable. Use
/// [`CertificationRunnerComponentDescriptor::from_json_slice`] or
/// [`CertificationRunnerComponentDescriptor::from_json_reader`].
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationRunnerComponentDescriptor {
    format_version: CertificationRunnerComponentDescriptorFormatVersion,
    role: CertificationRunnerComponentRole,
    component_id: CertificationRunnerComponentId,
    version: CertificationRunnerComponentVersion,
    provenance_digest: CertificationRunnerComponentProvenanceDigest,
    #[schemars(length(min = 1, max = 64))]
    artifacts: BTreeSet<CertificationRunnerComponentArtifact>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedCertificationRunnerComponentDescriptor {
    format_version: CertificationRunnerComponentDescriptorFormatVersion,
    role: CertificationRunnerComponentRole,
    component_id: CertificationRunnerComponentId,
    version: CertificationRunnerComponentVersion,
    provenance_digest: CertificationRunnerComponentProvenanceDigest,
    artifacts: Vec<CertificationRunnerComponentArtifact>,
}

impl CertificationRunnerComponentDescriptor {
    /// Constructs one bounded canonical runner-component descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`CertificationRunnerComponentDescriptorError`] for empty, excessive, duplicate, or
    /// aggregate-oversized artifacts.
    pub fn new(
        role: CertificationRunnerComponentRole,
        component_id: CertificationRunnerComponentId,
        version: CertificationRunnerComponentVersion,
        provenance_digest: CertificationRunnerComponentProvenanceDigest,
        artifacts: BTreeSet<CertificationRunnerComponentArtifact>,
    ) -> Result<Self, CertificationRunnerComponentDescriptorError> {
        validate_component_text(component_id.as_str(), "component identifier")
            .map_err(CertificationRunnerComponentDescriptorError::InvalidText)?;
        validate_component_text(version.as_str(), "component version")
            .map_err(CertificationRunnerComponentDescriptorError::InvalidText)?;
        validate_component_artifacts(&artifacts)?;
        Ok(Self {
            format_version: CertificationRunnerComponentDescriptorFormatVersion::V1,
            role,
            component_id,
            version,
            provenance_digest,
            artifacts,
        })
    }

    /// Parses one descriptor after enforcing its serialized-byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`CertificationRunnerComponentDocumentError`] for oversized, malformed, or
    /// semantically invalid input.
    pub fn from_json_slice(
        bytes: &[u8],
    ) -> Result<Self, CertificationRunnerComponentDocumentError> {
        if bytes.len() > MAX_CERTIFICATION_RUNNER_COMPONENT_DESCRIPTOR_BYTES {
            return Err(CertificationRunnerComponentDocumentError::DocumentTooLarge);
        }
        let unchecked: UncheckedCertificationRunnerComponentDescriptor =
            serde_json::from_slice(bytes)
                .map_err(CertificationRunnerComponentDocumentError::InvalidDocument)?;
        if unchecked.format_version != CertificationRunnerComponentDescriptorFormatVersion::V1 {
            return Err(CertificationRunnerComponentDocumentError::UnsupportedVersion);
        }
        let mut artifacts = BTreeSet::new();
        for artifact in unchecked.artifacts {
            if artifacts
                .iter()
                .any(|existing: &CertificationRunnerComponentArtifact| {
                    existing.name == artifact.name
                })
            {
                return Err(CertificationRunnerComponentDocumentError::InvalidContract(
                    CertificationRunnerComponentDescriptorError::DuplicateArtifactName,
                ));
            }
            artifacts.insert(artifact);
        }
        Self::new(
            unchecked.role,
            unchecked.component_id,
            unchecked.version,
            unchecked.provenance_digest,
            artifacts,
        )
        .map_err(CertificationRunnerComponentDocumentError::InvalidContract)
    }

    /// Reads one descriptor through its fixed input ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`CertificationRunnerComponentDocumentError`] for read, allocation, size, syntax, or
    /// contract failures.
    pub fn from_json_reader(
        reader: impl Read,
    ) -> Result<Self, CertificationRunnerComponentDocumentError> {
        let bytes = read_bounded(reader, MAX_CERTIFICATION_RUNNER_COMPONENT_DESCRIPTOR_BYTES)
            .map_err(CertificationRunnerComponentDocumentError::BoundedRead)?;
        Self::from_json_slice(&bytes)
    }

    /// Returns canonical compact JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns a serializer error if canonical bytes cannot be produced.
    pub fn canonical_json_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

    /// Returns the role-specific identity of canonical descriptor bytes.
    ///
    /// # Errors
    ///
    /// Returns a serializer error if canonical bytes cannot be produced.
    pub fn canonical_document_digest(
        &self,
    ) -> serde_json::Result<CertificationRunnerComponentDescriptorDigest> {
        Ok(CertificationRunnerComponentDescriptorDigest::new(
            hash_canonical(self)?,
        ))
    }

    /// Returns the serialized format version.
    #[must_use]
    pub const fn format_version(&self) -> &'static str {
        CERTIFICATION_RUNNER_COMPONENT_DESCRIPTOR_FORMAT_VERSION
    }

    /// Returns the exact component role.
    #[must_use]
    pub const fn role(&self) -> CertificationRunnerComponentRole {
        self.role
    }

    /// Returns the stable component identifier.
    #[must_use]
    pub const fn component_id(&self) -> &CertificationRunnerComponentId {
        &self.component_id
    }

    /// Returns the exact component version.
    #[must_use]
    pub const fn version(&self) -> &CertificationRunnerComponentVersion {
        &self.version
    }

    /// Returns the component provenance identity.
    #[must_use]
    pub const fn provenance_digest(&self) -> CertificationRunnerComponentProvenanceDigest {
        self.provenance_digest
    }

    /// Returns exact component artifacts in canonical order.
    #[must_use]
    pub const fn artifacts(&self) -> &BTreeSet<CertificationRunnerComponentArtifact> {
        &self.artifacts
    }
}

fn validate_component_artifacts(
    artifacts: &BTreeSet<CertificationRunnerComponentArtifact>,
) -> Result<(), CertificationRunnerComponentDescriptorError> {
    if artifacts.is_empty() {
        return Err(CertificationRunnerComponentDescriptorError::MissingArtifacts);
    }
    if artifacts.len() > MAX_CERTIFICATION_RUNNER_COMPONENT_ARTIFACTS {
        return Err(CertificationRunnerComponentDescriptorError::TooManyArtifacts);
    }
    let mut aggregate_name_bytes = 0_usize;
    let mut previous_name: Option<&CertificationRunnerArtifactName> = None;
    for artifact in artifacts {
        validate_component_text(artifact.name.as_str(), "artifact name")
            .map_err(CertificationRunnerComponentDescriptorError::InvalidText)?;
        if artifact.size_bytes == 0
            || artifact.size_bytes > MAX_CERTIFICATION_RUNNER_COMPONENT_ARTIFACT_BYTES
        {
            return Err(CertificationRunnerComponentDescriptorError::InvalidArtifactSize);
        }
        if previous_name == Some(&artifact.name) {
            return Err(CertificationRunnerComponentDescriptorError::DuplicateArtifactName);
        }
        previous_name = Some(&artifact.name);
        aggregate_name_bytes = aggregate_name_bytes
            .checked_add(artifact.name.as_str().len())
            .ok_or(CertificationRunnerComponentDescriptorError::ArtifactNameBytesExceeded)?;
        if aggregate_name_bytes > MAX_CERTIFICATION_RUNNER_COMPONENT_ARTIFACT_NAME_BYTES {
            return Err(CertificationRunnerComponentDescriptorError::ArtifactNameBytesExceeded);
        }
    }
    Ok(())
}

/// Invalid runner-component descriptor construction.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CertificationRunnerComponentDescriptorError {
    /// One bounded text field was invalid.
    #[error("runner-component descriptor text is invalid")]
    InvalidText(#[source] CertificationRunnerComponentTextError),
    /// At least one exact artifact is required.
    #[error("runner-component descriptor has no artifacts")]
    MissingArtifacts,
    /// The fixed artifact-count ceiling was exceeded.
    #[error("runner-component descriptor has too many artifacts")]
    TooManyArtifacts,
    /// Two artifacts used the same logical name.
    #[error("runner-component descriptor contains a duplicate artifact name")]
    DuplicateArtifactName,
    /// One artifact byte length was zero or exceeded its implementation ceiling.
    #[error("runner-component artifact byte length is invalid")]
    InvalidArtifactSize,
    /// Aggregate artifact-name bytes exceeded their fixed ceiling.
    #[error("runner-component artifact names exceed their aggregate byte ceiling")]
    ArtifactNameBytesExceeded,
}

/// Failure to read or parse one bounded runner-component descriptor.
#[derive(Debug, Error)]
pub enum CertificationRunnerComponentDocumentError {
    /// Serialized input exceeded the fixed ceiling.
    #[error("runner-component descriptor exceeds its byte ceiling")]
    DocumentTooLarge,
    /// Bounded input could not be read.
    #[error("runner-component descriptor bounded read failed")]
    BoundedRead(#[source] BoundedDocumentReadError),
    /// JSON syntax or the closed transport shape was invalid.
    #[error("runner-component descriptor is invalid")]
    InvalidDocument(#[source] serde_json::Error),
    /// A known but unsupported version was supplied.
    #[error("runner-component descriptor version is unsupported")]
    UnsupportedVersion,
    /// Domain validation rejected the parsed descriptor.
    #[error("runner-component descriptor contract is invalid")]
    InvalidContract(#[source] CertificationRunnerComponentDescriptorError),
}

/// Monotonic freshness evidence retained by one local run attestation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationRunFreshness {
    challenge: Uuid,
    maximum_elapsed_millis: u64,
    elapsed_millis: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedCertificationRunFreshness {
    challenge: Uuid,
    maximum_elapsed_millis: u64,
    elapsed_millis: u64,
}

impl<'de> Deserialize<'de> for CertificationRunFreshness {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedCertificationRunFreshness::deserialize(deserializer)?;
        Self::new(
            unchecked.challenge,
            unchecked.maximum_elapsed_millis,
            unchecked.elapsed_millis,
        )
        .map_err(D::Error::custom)
    }
}

impl CertificationRunFreshness {
    /// Constructs one bounded monotonic freshness observation.
    ///
    /// # Errors
    ///
    /// Returns [`CertificationRunAttestationError`] for a zero or excessive window or an elapsed
    /// duration beyond that window.
    pub const fn new(
        challenge: Uuid,
        maximum_elapsed_millis: u64,
        elapsed_millis: u64,
    ) -> Result<Self, CertificationRunAttestationError> {
        if maximum_elapsed_millis == 0
            || maximum_elapsed_millis > MAX_LOCAL_CERTIFICATION_RUN_FRESHNESS_MILLIS
        {
            return Err(CertificationRunAttestationError::InvalidFreshnessLimit);
        }
        if elapsed_millis > maximum_elapsed_millis {
            return Err(CertificationRunAttestationError::FreshnessExpired);
        }
        Ok(Self {
            challenge,
            maximum_elapsed_millis,
            elapsed_millis,
        })
    }

    /// Returns the cryptographically random single-use challenge.
    #[must_use]
    pub const fn challenge(&self) -> Uuid {
        self.challenge
    }

    /// Returns the maximum accepted monotonic elapsed duration.
    #[must_use]
    pub const fn maximum_elapsed_millis(&self) -> u64 {
        self.maximum_elapsed_millis
    }

    /// Returns the observed monotonic elapsed duration.
    #[must_use]
    pub const fn elapsed_millis(&self) -> u64 {
        self.elapsed_millis
    }

    fn validate(&self) -> Result<(), CertificationRunAttestationError> {
        Self::new(
            self.challenge,
            self.maximum_elapsed_millis,
            self.elapsed_millis,
        )
        .map(|_| ())
    }
}

/// Exact runner and runner-policy identities retained by one local run attestation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationRunRunnerIdentity {
    runner_identity_digest: CertificationRunnerIdentityDigest,
    descriptor_set_digest: CertificationRunnerDescriptorSetDigest,
    policy_revision_digest: CertificationRunnerPolicyRevisionDigest,
    policy_generation: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedCertificationRunRunnerIdentity {
    runner_identity_digest: CertificationRunnerIdentityDigest,
    descriptor_set_digest: CertificationRunnerDescriptorSetDigest,
    policy_revision_digest: CertificationRunnerPolicyRevisionDigest,
    policy_generation: u64,
}

impl<'de> Deserialize<'de> for CertificationRunRunnerIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedCertificationRunRunnerIdentity::deserialize(deserializer)?;
        Self::new(
            unchecked.runner_identity_digest,
            unchecked.descriptor_set_digest,
            unchecked.policy_revision_digest,
            unchecked.policy_generation,
        )
        .map_err(D::Error::custom)
    }
}

impl CertificationRunRunnerIdentity {
    /// Constructs exact runner identities under one nonzero local policy generation.
    ///
    /// # Errors
    ///
    /// Returns [`CertificationRunAttestationError::InvalidPolicyGeneration`] for generation zero.
    pub const fn new(
        runner_identity_digest: CertificationRunnerIdentityDigest,
        descriptor_set_digest: CertificationRunnerDescriptorSetDigest,
        policy_revision_digest: CertificationRunnerPolicyRevisionDigest,
        policy_generation: u64,
    ) -> Result<Self, CertificationRunAttestationError> {
        if policy_generation == 0 {
            return Err(CertificationRunAttestationError::InvalidPolicyGeneration);
        }
        Ok(Self {
            runner_identity_digest,
            descriptor_set_digest,
            policy_revision_digest,
            policy_generation,
        })
    }

    /// Returns the exact runner-identity manifest identity.
    #[must_use]
    pub const fn runner_identity_digest(&self) -> CertificationRunnerIdentityDigest {
        self.runner_identity_digest
    }

    /// Returns the verified runner descriptor-set identity.
    #[must_use]
    pub const fn descriptor_set_digest(&self) -> CertificationRunnerDescriptorSetDigest {
        self.descriptor_set_digest
    }

    /// Returns the runner-policy revision identity.
    #[must_use]
    pub const fn policy_revision_digest(&self) -> CertificationRunnerPolicyRevisionDigest {
        self.policy_revision_digest
    }

    /// Returns the runner-policy generation.
    #[must_use]
    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    fn validate(&self) -> Result<(), CertificationRunAttestationError> {
        Self::new(
            self.runner_identity_digest,
            self.descriptor_set_digest,
            self.policy_revision_digest,
            self.policy_generation,
        )
        .map(|_| ())
    }
}

/// Exact report, certification, policy, and artifact identities of one locally attested run.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationRunResultIdentity {
    semantic_report: CertificationArtifactRef,
    target: CertificationTarget,
    profile_digest: CertificationProfileDigest,
    evidence_digest: CertificationEvidenceDigest,
    artifact_set_digest: CertificationArtifactSetDigest,
    class: CertificationClass,
    policy_revision_digest: CertificationPolicyRevisionDigest,
    policy_generation: u64,
    artifact_count: u32,
    total_artifact_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedCertificationRunResultIdentity {
    semantic_report: CertificationArtifactRef,
    target: CertificationTarget,
    profile_digest: CertificationProfileDigest,
    evidence_digest: CertificationEvidenceDigest,
    artifact_set_digest: CertificationArtifactSetDigest,
    class: CertificationClass,
    policy_revision_digest: CertificationPolicyRevisionDigest,
    policy_generation: u64,
    artifact_count: u32,
    total_artifact_bytes: u64,
}

impl<'de> Deserialize<'de> for CertificationRunResultIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedCertificationRunResultIdentity::deserialize(deserializer)?;
        Self::new(
            unchecked.semantic_report,
            unchecked.target,
            unchecked.profile_digest,
            unchecked.evidence_digest,
            unchecked.artifact_set_digest,
            unchecked.class,
            unchecked.policy_revision_digest,
            unchecked.policy_generation,
            unchecked.artifact_count,
            unchecked.total_artifact_bytes,
        )
        .map_err(D::Error::custom)
    }
}

impl CertificationRunResultIdentity {
    /// Constructs one exact trusted local certification result identity.
    ///
    /// # Errors
    ///
    /// Rejects unassignable classes, zero policy generations, empty artifact sets, or zero bytes.
    #[expect(
        clippy::too_many_arguments,
        reason = "every identity is an independent security pin in the serialized contract"
    )]
    pub const fn new(
        semantic_report: CertificationArtifactRef,
        target: CertificationTarget,
        profile_digest: CertificationProfileDigest,
        evidence_digest: CertificationEvidenceDigest,
        artifact_set_digest: CertificationArtifactSetDigest,
        class: CertificationClass,
        policy_revision_digest: CertificationPolicyRevisionDigest,
        policy_generation: u64,
        artifact_count: u32,
        total_artifact_bytes: u64,
    ) -> Result<Self, CertificationRunAttestationError> {
        if matches!(
            class,
            CertificationClass::Blocked | CertificationClass::Provisional
        ) {
            return Err(CertificationRunAttestationError::UnassignableClass);
        }
        if policy_generation == 0 {
            return Err(CertificationRunAttestationError::InvalidPolicyGeneration);
        }
        if artifact_count == 0 {
            return Err(CertificationRunAttestationError::MissingArtifacts);
        }
        if total_artifact_bytes == 0 {
            return Err(CertificationRunAttestationError::MissingArtifactBytes);
        }
        Ok(Self {
            semantic_report,
            target,
            profile_digest,
            evidence_digest,
            artifact_set_digest,
            class,
            policy_revision_digest,
            policy_generation,
            artifact_count,
            total_artifact_bytes,
        })
    }

    /// Returns the exact semantic-report artifact reference.
    #[must_use]
    pub const fn semantic_report(&self) -> &CertificationArtifactRef {
        &self.semantic_report
    }

    /// Returns the exact certification target.
    #[must_use]
    pub const fn target(&self) -> &CertificationTarget {
        &self.target
    }

    /// Returns the exact certification-profile identity.
    #[must_use]
    pub const fn profile_digest(&self) -> CertificationProfileDigest {
        self.profile_digest
    }

    /// Returns the exact certification-evidence identity.
    #[must_use]
    pub const fn evidence_digest(&self) -> CertificationEvidenceDigest {
        self.evidence_digest
    }

    /// Returns the exact verified artifact-set identity.
    #[must_use]
    pub const fn artifact_set_digest(&self) -> CertificationArtifactSetDigest {
        self.artifact_set_digest
    }

    /// Returns the trusted local class.
    #[must_use]
    pub const fn class(&self) -> CertificationClass {
        self.class
    }

    /// Returns the certification-policy revision identity.
    #[must_use]
    pub const fn policy_revision_digest(&self) -> CertificationPolicyRevisionDigest {
        self.policy_revision_digest
    }

    /// Returns the certification-policy generation.
    #[must_use]
    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    /// Returns the verified unique artifact count.
    #[must_use]
    pub const fn artifact_count(&self) -> u32 {
        self.artifact_count
    }

    /// Returns the verified aggregate artifact bytes.
    #[must_use]
    pub const fn total_artifact_bytes(&self) -> u64 {
        self.total_artifact_bytes
    }

    fn validate(&self) -> Result<(), CertificationRunAttestationError> {
        Self::new(
            self.semantic_report.clone(),
            self.target.clone(),
            self.profile_digest,
            self.evidence_digest,
            self.artifact_set_digest,
            self.class,
            self.policy_revision_digest,
            self.policy_generation,
            self.artifact_count,
            self.total_artifact_bytes,
        )
        .map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
enum LocalCertificationRunAttestationFormatVersion {
    #[serde(rename = "1")]
    V1,
}

/// Canonical historical evidence for one freshness-bound local certification run.
///
/// This document does not authorize transformation, execution, or external publication. Generic
/// deserialization is unavailable; use the bounded parser.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalCertificationRunAttestation {
    format_version: LocalCertificationRunAttestationFormatVersion,
    freshness: CertificationRunFreshness,
    runner: CertificationRunRunnerIdentity,
    result: CertificationRunResultIdentity,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedLocalCertificationRunAttestation {
    #[serde(rename = "format_version")]
    _format_version: LocalCertificationRunAttestationFormatVersion,
    freshness: CertificationRunFreshness,
    runner: CertificationRunRunnerIdentity,
    result: CertificationRunResultIdentity,
}

impl LocalCertificationRunAttestation {
    /// Constructs one already validated local run attestation.
    #[must_use]
    pub const fn new(
        freshness: CertificationRunFreshness,
        runner: CertificationRunRunnerIdentity,
        result: CertificationRunResultIdentity,
    ) -> Self {
        Self {
            format_version: LocalCertificationRunAttestationFormatVersion::V1,
            freshness,
            runner,
            result,
        }
    }

    /// Parses one attestation after enforcing its serialized-byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`CertificationRunAttestationDocumentError`] for oversized, malformed, or invalid
    /// input.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, CertificationRunAttestationDocumentError> {
        if bytes.len() > MAX_LOCAL_CERTIFICATION_RUN_ATTESTATION_BYTES {
            return Err(CertificationRunAttestationDocumentError::DocumentTooLarge);
        }
        let unchecked: UncheckedLocalCertificationRunAttestation = serde_json::from_slice(bytes)
            .map_err(CertificationRunAttestationDocumentError::InvalidDocument)?;
        unchecked
            .freshness
            .validate()
            .and_then(|()| unchecked.runner.validate())
            .and_then(|()| unchecked.result.validate())
            .map_err(CertificationRunAttestationDocumentError::InvalidContract)?;
        Ok(Self::new(
            unchecked.freshness,
            unchecked.runner,
            unchecked.result,
        ))
    }

    /// Reads one attestation through its fixed input ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`CertificationRunAttestationDocumentError`] for bounded read or parse failures.
    pub fn from_json_reader(
        reader: impl Read,
    ) -> Result<Self, CertificationRunAttestationDocumentError> {
        let bytes = read_bounded(reader, MAX_LOCAL_CERTIFICATION_RUN_ATTESTATION_BYTES)
            .map_err(CertificationRunAttestationDocumentError::BoundedRead)?;
        Self::from_json_slice(&bytes)
    }

    /// Returns canonical compact JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns a serializer error if canonical bytes cannot be produced.
    pub fn canonical_json_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

    /// Returns the role-specific identity of canonical attestation bytes.
    ///
    /// # Errors
    ///
    /// Returns a serializer error if canonical bytes cannot be produced.
    pub fn canonical_document_digest(
        &self,
    ) -> serde_json::Result<LocalCertificationRunAttestationDigest> {
        Ok(LocalCertificationRunAttestationDigest::new(hash_canonical(
            self,
        )?))
    }

    /// Returns the exact format version.
    #[must_use]
    pub const fn format_version(&self) -> &'static str {
        LOCAL_CERTIFICATION_RUN_ATTESTATION_FORMAT_VERSION
    }

    /// Returns monotonic freshness evidence.
    #[must_use]
    pub const fn freshness(&self) -> &CertificationRunFreshness {
        &self.freshness
    }

    /// Returns exact runner identities.
    #[must_use]
    pub const fn runner(&self) -> &CertificationRunRunnerIdentity {
        &self.runner
    }

    /// Returns exact certification result identities.
    #[must_use]
    pub const fn result(&self) -> &CertificationRunResultIdentity {
        &self.result
    }
}

/// Invalid local run-attestation construction.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CertificationRunAttestationError {
    /// Freshness maximum was zero or exceeded the implementation ceiling.
    #[error("local certification-run freshness limit is invalid")]
    InvalidFreshnessLimit,
    /// Monotonic elapsed time exceeded the selected freshness maximum.
    #[error("local certification-run freshness window expired")]
    FreshnessExpired,
    /// A policy generation was zero.
    #[error("local certification policy generation must be nonzero")]
    InvalidPolicyGeneration,
    /// Blocked or provisional cannot be attested as exact verified local classes.
    #[error("local certification-run class is not assignable")]
    UnassignableClass,
    /// No verified artifacts were present.
    #[error("local certification-run result has no artifacts")]
    MissingArtifacts,
    /// Verified artifact byte count was zero.
    #[error("local certification-run result has no artifact bytes")]
    MissingArtifactBytes,
}

/// Failure to read or parse one bounded local run attestation.
#[derive(Debug, Error)]
pub enum CertificationRunAttestationDocumentError {
    /// Serialized bytes exceeded the fixed ceiling.
    #[error("local certification-run attestation exceeds its byte ceiling")]
    DocumentTooLarge,
    /// Bounded input could not be read.
    #[error("local certification-run attestation bounded read failed")]
    BoundedRead(#[source] BoundedDocumentReadError),
    /// JSON syntax or the closed transport shape was invalid.
    #[error("local certification-run attestation document is invalid")]
    InvalidDocument(#[source] serde_json::Error),
    /// Parsed fields violated the attestation contract.
    #[error("local certification-run attestation contract is invalid")]
    InvalidContract(#[source] CertificationRunAttestationError),
}

/// Exact current local policies accepted by one certification-control ledger generation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationControlPolicy {
    runner: CertificationRunRunnerIdentity,
    semantic_report: CertificationArtifactRef,
    target: CertificationTarget,
    profile_digest: CertificationProfileDigest,
    evidence_digest: CertificationEvidenceDigest,
    artifact_set_digest: CertificationArtifactSetDigest,
    class: CertificationClass,
    policy_revision_digest: CertificationPolicyRevisionDigest,
    policy_generation: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedCertificationControlPolicy {
    runner: CertificationRunRunnerIdentity,
    semantic_report: CertificationArtifactRef,
    target: CertificationTarget,
    profile_digest: CertificationProfileDigest,
    evidence_digest: CertificationEvidenceDigest,
    artifact_set_digest: CertificationArtifactSetDigest,
    class: CertificationClass,
    policy_revision_digest: CertificationPolicyRevisionDigest,
    policy_generation: u64,
}

impl<'de> Deserialize<'de> for CertificationControlPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedCertificationControlPolicy::deserialize(deserializer)?;
        Self::new(
            unchecked.runner,
            unchecked.semantic_report,
            unchecked.target,
            unchecked.profile_digest,
            unchecked.evidence_digest,
            unchecked.artifact_set_digest,
            unchecked.class,
            unchecked.policy_revision_digest,
            unchecked.policy_generation,
        )
        .map_err(D::Error::custom)
    }
}

impl CertificationControlPolicy {
    /// Constructs one exact combined runner and certification policy snapshot.
    ///
    /// # Errors
    ///
    /// Rejects invalid runner generations, unassignable classes, or a zero certification-policy
    /// generation.
    #[expect(
        clippy::too_many_arguments,
        reason = "every identity is an independent durable policy pin"
    )]
    pub fn new(
        runner: CertificationRunRunnerIdentity,
        semantic_report: CertificationArtifactRef,
        target: CertificationTarget,
        profile_digest: CertificationProfileDigest,
        evidence_digest: CertificationEvidenceDigest,
        artifact_set_digest: CertificationArtifactSetDigest,
        class: CertificationClass,
        policy_revision_digest: CertificationPolicyRevisionDigest,
        policy_generation: u64,
    ) -> Result<Self, CertificationRunAttestationError> {
        let policy = Self {
            runner,
            semantic_report,
            target,
            profile_digest,
            evidence_digest,
            artifact_set_digest,
            class,
            policy_revision_digest,
            policy_generation,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Returns the exact runner policy snapshot.
    #[must_use]
    pub const fn runner(&self) -> &CertificationRunRunnerIdentity {
        &self.runner
    }

    /// Returns the exact semantic report reference.
    #[must_use]
    pub const fn semantic_report(&self) -> &CertificationArtifactRef {
        &self.semantic_report
    }

    /// Returns the exact certification target.
    #[must_use]
    pub const fn target(&self) -> &CertificationTarget {
        &self.target
    }

    /// Returns the exact profile identity.
    #[must_use]
    pub const fn profile_digest(&self) -> CertificationProfileDigest {
        self.profile_digest
    }

    /// Returns the exact evidence identity.
    #[must_use]
    pub const fn evidence_digest(&self) -> CertificationEvidenceDigest {
        self.evidence_digest
    }

    /// Returns the exact verified artifact-set identity.
    #[must_use]
    pub const fn artifact_set_digest(&self) -> CertificationArtifactSetDigest {
        self.artifact_set_digest
    }

    /// Returns the trusted local certification class.
    #[must_use]
    pub const fn class(&self) -> CertificationClass {
        self.class
    }

    /// Returns the certification-policy revision identity.
    #[must_use]
    pub const fn policy_revision_digest(&self) -> CertificationPolicyRevisionDigest {
        self.policy_revision_digest
    }

    /// Returns the certification-policy generation.
    #[must_use]
    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    /// Reports whether one attestation exactly matches every current control-policy pin.
    ///
    /// This relationship check does not establish policy currentness or authorize any effect.
    #[must_use]
    pub fn accepts_attestation(&self, attestation: &LocalCertificationRunAttestation) -> bool {
        let result = attestation.result();
        self.runner == *attestation.runner()
            && self.semantic_report == *result.semantic_report()
            && self.target == *result.target()
            && self.profile_digest == result.profile_digest()
            && self.evidence_digest == result.evidence_digest()
            && self.artifact_set_digest == result.artifact_set_digest()
            && self.class == result.class()
            && self.policy_revision_digest == result.policy_revision_digest()
            && self.policy_generation == result.policy_generation()
    }

    fn validate(&self) -> Result<(), CertificationRunAttestationError> {
        self.runner.validate()?;
        CertificationRunResultIdentity::new(
            self.semantic_report.clone(),
            self.target.clone(),
            self.profile_digest,
            self.evidence_digest,
            self.artifact_set_digest,
            self.class,
            self.policy_revision_digest,
            self.policy_generation,
            1,
            1,
        )
        .map(|_| ())
    }
}

/// Durable local-only receipt paired with one exact run attestation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalCertificationLedgerReceipt {
    attestation_digest: LocalCertificationRunAttestationDigest,
    publication_status: PublicationStatus,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedLocalCertificationLedgerReceipt {
    attestation_digest: LocalCertificationRunAttestationDigest,
    publication_status: PublicationStatus,
}

impl<'de> Deserialize<'de> for LocalCertificationLedgerReceipt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedLocalCertificationLedgerReceipt::deserialize(deserializer)?;
        if unchecked.publication_status != PublicationStatus::LocalOnly {
            return Err(D::Error::custom(
                "local certification ledger receipt must be local_only",
            ));
        }
        Ok(Self {
            attestation_digest: unchecked.attestation_digest,
            publication_status: unchecked.publication_status,
        })
    }
}

impl LocalCertificationLedgerReceipt {
    fn from_attestation(
        attestation: &LocalCertificationRunAttestation,
    ) -> Result<Self, LocalCertificationLedgerContractError> {
        Ok(Self {
            attestation_digest: attestation
                .canonical_document_digest()
                .map_err(LocalCertificationLedgerContractError::CanonicalDocumentUnavailable)?,
            publication_status: PublicationStatus::LocalOnly,
        })
    }

    /// Returns the exact attestation identity.
    #[must_use]
    pub const fn attestation_digest(&self) -> LocalCertificationRunAttestationDigest {
        self.attestation_digest
    }

    /// Returns `local_only`.
    #[must_use]
    pub const fn publication_status(&self) -> PublicationStatus {
        self.publication_status
    }
}

/// Genesis ledger event containing exact policy plus the first attested publication.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalCertificationLedgerGenesis {
    policy: CertificationControlPolicy,
    attestation: LocalCertificationRunAttestation,
    receipt: LocalCertificationLedgerReceipt,
}

impl LocalCertificationLedgerGenesis {
    /// Constructs a relationship-checked genesis event.
    ///
    /// # Errors
    ///
    /// Returns [`LocalCertificationLedgerContractError`] when policy and attestation differ or a
    /// canonical attestation identity cannot be produced.
    pub fn new(
        policy: CertificationControlPolicy,
        attestation: LocalCertificationRunAttestation,
    ) -> Result<Self, LocalCertificationLedgerContractError> {
        if !policy.accepts_attestation(&attestation) {
            return Err(LocalCertificationLedgerContractError::PolicyMismatch);
        }
        let receipt = LocalCertificationLedgerReceipt::from_attestation(&attestation)?;
        Ok(Self {
            policy,
            attestation,
            receipt,
        })
    }

    /// Returns the exact control policy.
    #[must_use]
    pub const fn policy(&self) -> &CertificationControlPolicy {
        &self.policy
    }

    /// Returns the first exact run attestation.
    #[must_use]
    pub const fn attestation(&self) -> &LocalCertificationRunAttestation {
        &self.attestation
    }

    /// Returns the first durable local receipt.
    #[must_use]
    pub const fn receipt(&self) -> &LocalCertificationLedgerReceipt {
        &self.receipt
    }

    fn validate(&self) -> Result<(), LocalCertificationLedgerContractError> {
        if !self.policy.accepts_attestation(&self.attestation) {
            return Err(LocalCertificationLedgerContractError::PolicyMismatch);
        }
        validate_receipt(&self.attestation, &self.receipt)
    }
}

/// One later attested local publication event.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalCertificationLedgerPublication {
    attestation: LocalCertificationRunAttestation,
    receipt: LocalCertificationLedgerReceipt,
}

impl LocalCertificationLedgerPublication {
    fn new(
        attestation: LocalCertificationRunAttestation,
    ) -> Result<Self, LocalCertificationLedgerContractError> {
        let receipt = LocalCertificationLedgerReceipt::from_attestation(&attestation)?;
        Ok(Self {
            attestation,
            receipt,
        })
    }

    /// Returns the exact run attestation.
    #[must_use]
    pub const fn attestation(&self) -> &LocalCertificationRunAttestation {
        &self.attestation
    }

    /// Returns its durable local receipt.
    #[must_use]
    pub const fn receipt(&self) -> &LocalCertificationLedgerReceipt {
        &self.receipt
    }

    fn validate(&self) -> Result<(), LocalCertificationLedgerContractError> {
        validate_receipt(&self.attestation, &self.receipt)
    }
}

fn validate_receipt(
    attestation: &LocalCertificationRunAttestation,
    receipt: &LocalCertificationLedgerReceipt,
) -> Result<(), LocalCertificationLedgerContractError> {
    if receipt.publication_status != PublicationStatus::LocalOnly {
        return Err(LocalCertificationLedgerContractError::InvalidPublicationStatus);
    }
    let expected = attestation
        .canonical_document_digest()
        .map_err(LocalCertificationLedgerContractError::CanonicalDocumentUnavailable)?;
    if receipt.attestation_digest != expected {
        return Err(LocalCertificationLedgerContractError::ReceiptMismatch);
    }
    Ok(())
}

/// Policy replacement retained by a durable local ledger.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalCertificationLedgerPolicyReplacement {
    policy: CertificationControlPolicy,
}

impl LocalCertificationLedgerPolicyReplacement {
    /// Constructs one exact replacement policy event.
    #[must_use]
    pub const fn new(policy: CertificationControlPolicy) -> Self {
        Self { policy }
    }

    /// Returns the exact replacement policy.
    #[must_use]
    pub const fn policy(&self) -> &CertificationControlPolicy {
        &self.policy
    }
}

/// Local certification-policy revocation event.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalCertificationLedgerCertificationRevocation {
    evidence_digest: CertificationPolicyRevocationDigest,
}

impl LocalCertificationLedgerCertificationRevocation {
    /// Constructs one certification-policy revocation event.
    #[must_use]
    pub const fn new(evidence_digest: CertificationPolicyRevocationDigest) -> Self {
        Self { evidence_digest }
    }

    /// Returns exact revocation-evidence identity.
    #[must_use]
    pub const fn evidence_digest(&self) -> CertificationPolicyRevocationDigest {
        self.evidence_digest
    }
}

/// Local runner-policy revocation event.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalCertificationLedgerRunnerRevocation {
    evidence_digest: CertificationRunnerPolicyRevocationDigest,
}

impl LocalCertificationLedgerRunnerRevocation {
    /// Constructs one runner-policy revocation event.
    #[must_use]
    pub const fn new(evidence_digest: CertificationRunnerPolicyRevocationDigest) -> Self {
        Self { evidence_digest }
    }

    /// Returns exact revocation-evidence identity.
    #[must_use]
    pub const fn evidence_digest(&self) -> CertificationRunnerPolicyRevocationDigest {
        self.evidence_digest
    }
}

/// Closed event vocabulary for the durable local certification ledger.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum LocalCertificationLedgerEvent {
    /// Ledger creation, policies, and first attested publication.
    Genesis(Box<LocalCertificationLedgerGenesis>),
    /// Later attested local publication.
    Publication(Box<LocalCertificationLedgerPublication>),
    /// Exact replacement of both local policies.
    PolicyReplacement(Box<LocalCertificationLedgerPolicyReplacement>),
    /// Certification-policy revocation.
    CertificationRevocation(LocalCertificationLedgerCertificationRevocation),
    /// Runner-policy revocation.
    RunnerRevocation(LocalCertificationLedgerRunnerRevocation),
}

impl LocalCertificationLedgerEvent {
    /// Constructs one relationship-checked publication event.
    ///
    /// # Errors
    ///
    /// Returns [`LocalCertificationLedgerContractError`] if its receipt identity cannot be
    /// constructed.
    pub fn publication(
        attestation: LocalCertificationRunAttestation,
    ) -> Result<Self, LocalCertificationLedgerContractError> {
        Ok(Self::Publication(Box::new(
            LocalCertificationLedgerPublication::new(attestation)?,
        )))
    }

    /// Constructs one policy-replacement event.
    #[must_use]
    pub fn policy_replacement(policy: CertificationControlPolicy) -> Self {
        Self::PolicyReplacement(Box::new(LocalCertificationLedgerPolicyReplacement::new(
            policy,
        )))
    }

    /// Constructs one certification-policy revocation event.
    #[must_use]
    pub const fn certification_revocation(
        evidence_digest: CertificationPolicyRevocationDigest,
    ) -> Self {
        Self::CertificationRevocation(LocalCertificationLedgerCertificationRevocation::new(
            evidence_digest,
        ))
    }

    /// Constructs one runner-policy revocation event.
    #[must_use]
    pub const fn runner_revocation(
        evidence_digest: CertificationRunnerPolicyRevocationDigest,
    ) -> Self {
        Self::RunnerRevocation(LocalCertificationLedgerRunnerRevocation::new(
            evidence_digest,
        ))
    }

    fn validate(&self) -> Result<(), LocalCertificationLedgerContractError> {
        match self {
            Self::Genesis(genesis) => genesis.validate(),
            Self::Publication(publication) => publication.validate(),
            Self::PolicyReplacement(replacement) => replacement
                .policy
                .validate()
                .map_err(LocalCertificationLedgerContractError::InvalidAttestation),
            Self::CertificationRevocation(_) | Self::RunnerRevocation(_) => Ok(()),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedLocalCertificationLedgerGenesis {
    policy: CertificationControlPolicy,
    attestation: UncheckedLocalCertificationRunAttestation,
    receipt: LocalCertificationLedgerReceipt,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedLocalCertificationLedgerPublication {
    attestation: UncheckedLocalCertificationRunAttestation,
    receipt: LocalCertificationLedgerReceipt,
}

#[derive(Deserialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum UncheckedLocalCertificationLedgerEvent {
    Genesis(Box<UncheckedLocalCertificationLedgerGenesis>),
    Publication(Box<UncheckedLocalCertificationLedgerPublication>),
    PolicyReplacement(Box<LocalCertificationLedgerPolicyReplacement>),
    CertificationRevocation(LocalCertificationLedgerCertificationRevocation),
    RunnerRevocation(LocalCertificationLedgerRunnerRevocation),
}

impl UncheckedLocalCertificationRunAttestation {
    fn into_checked(
        self,
    ) -> Result<LocalCertificationRunAttestation, CertificationRunAttestationError> {
        self.freshness.validate()?;
        self.runner.validate()?;
        self.result.validate()?;
        Ok(LocalCertificationRunAttestation::new(
            self.freshness,
            self.runner,
            self.result,
        ))
    }
}

impl UncheckedLocalCertificationLedgerEvent {
    fn into_checked(
        self,
    ) -> Result<LocalCertificationLedgerEvent, LocalCertificationLedgerContractError> {
        match self {
            Self::Genesis(unchecked) => {
                let attestation = unchecked
                    .attestation
                    .into_checked()
                    .map_err(LocalCertificationLedgerContractError::InvalidAttestation)?;
                let genesis = LocalCertificationLedgerGenesis {
                    policy: unchecked.policy,
                    attestation,
                    receipt: unchecked.receipt,
                };
                genesis.validate()?;
                Ok(LocalCertificationLedgerEvent::Genesis(Box::new(genesis)))
            }
            Self::Publication(unchecked) => {
                let attestation = unchecked
                    .attestation
                    .into_checked()
                    .map_err(LocalCertificationLedgerContractError::InvalidAttestation)?;
                let publication = LocalCertificationLedgerPublication {
                    attestation,
                    receipt: unchecked.receipt,
                };
                publication.validate()?;
                Ok(LocalCertificationLedgerEvent::Publication(Box::new(
                    publication,
                )))
            }
            Self::PolicyReplacement(replacement) => Ok(
                LocalCertificationLedgerEvent::PolicyReplacement(replacement),
            ),
            Self::CertificationRevocation(revocation) => Ok(
                LocalCertificationLedgerEvent::CertificationRevocation(revocation),
            ),
            Self::RunnerRevocation(revocation) => {
                Ok(LocalCertificationLedgerEvent::RunnerRevocation(revocation))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
enum LocalCertificationLedgerRecordFormatVersion {
    #[serde(rename = "1")]
    V1,
}

/// Canonical hash-chained record in one local certification ledger.
///
/// Generic deserialization is unavailable so the fixed parser ceiling cannot be bypassed.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalCertificationLedgerRecord {
    format_version: LocalCertificationLedgerRecordFormatVersion,
    sequence: u64,
    previous_record_digest: Option<LocalCertificationLedgerRecordDigest>,
    event: LocalCertificationLedgerEvent,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedLocalCertificationLedgerRecord {
    format_version: LocalCertificationLedgerRecordFormatVersion,
    sequence: u64,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    previous_record_digest: Option<LocalCertificationLedgerRecordDigest>,
    event: UncheckedLocalCertificationLedgerEvent,
}

fn deserialize_required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

impl LocalCertificationLedgerRecord {
    /// Constructs sequence one from one genesis event.
    ///
    /// # Errors
    ///
    /// Returns [`LocalCertificationLedgerContractError`] when the genesis relationships are invalid.
    pub fn genesis(
        genesis: LocalCertificationLedgerGenesis,
    ) -> Result<Self, LocalCertificationLedgerContractError> {
        genesis.validate()?;
        Ok(Self {
            format_version: LocalCertificationLedgerRecordFormatVersion::V1,
            sequence: 1,
            previous_record_digest: None,
            event: LocalCertificationLedgerEvent::Genesis(Box::new(genesis)),
        })
    }

    /// Constructs the exact next record linked to an existing record.
    ///
    /// # Errors
    ///
    /// Rejects a second genesis, sequence exhaustion, invalid event relationships, or unavailable
    /// canonical predecessor identity.
    pub fn next(
        previous: &Self,
        event: LocalCertificationLedgerEvent,
    ) -> Result<Self, LocalCertificationLedgerContractError> {
        if matches!(event, LocalCertificationLedgerEvent::Genesis(_)) {
            return Err(LocalCertificationLedgerContractError::UnexpectedGenesis);
        }
        event.validate()?;
        let sequence = previous
            .sequence
            .checked_add(1)
            .ok_or(LocalCertificationLedgerContractError::SequenceExhausted)?;
        Ok(Self {
            format_version: LocalCertificationLedgerRecordFormatVersion::V1,
            sequence,
            previous_record_digest: Some(
                previous
                    .canonical_document_digest()
                    .map_err(LocalCertificationLedgerContractError::CanonicalDocumentUnavailable)?,
            ),
            event,
        })
    }

    /// Parses one ledger record after enforcing its serialized-byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`LocalCertificationLedgerDocumentError`] for oversized, malformed, or invalid
    /// record bytes.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, LocalCertificationLedgerDocumentError> {
        if bytes.len() > MAX_LOCAL_CERTIFICATION_LEDGER_RECORD_BYTES {
            return Err(LocalCertificationLedgerDocumentError::DocumentTooLarge);
        }
        let unchecked: UncheckedLocalCertificationLedgerRecord = serde_json::from_slice(bytes)
            .map_err(LocalCertificationLedgerDocumentError::InvalidDocument)?;
        let event = unchecked
            .event
            .into_checked()
            .map_err(LocalCertificationLedgerDocumentError::InvalidContract)?;
        let record = Self {
            format_version: unchecked.format_version,
            sequence: unchecked.sequence,
            previous_record_digest: unchecked.previous_record_digest,
            event,
        };
        record
            .validate_shape()
            .map_err(LocalCertificationLedgerDocumentError::InvalidContract)?;
        Ok(record)
    }

    /// Reads one ledger record through its fixed input ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`LocalCertificationLedgerDocumentError`] for bounded read or parse failures.
    pub fn from_json_reader(
        reader: impl Read,
    ) -> Result<Self, LocalCertificationLedgerDocumentError> {
        let bytes = read_bounded(reader, MAX_LOCAL_CERTIFICATION_LEDGER_RECORD_BYTES)
            .map_err(LocalCertificationLedgerDocumentError::BoundedRead)?;
        Self::from_json_slice(&bytes)
    }

    /// Returns canonical compact JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns a serializer error if canonical bytes cannot be produced.
    pub fn canonical_json_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

    /// Returns the exact canonical record identity.
    ///
    /// # Errors
    ///
    /// Returns a serializer error if canonical bytes cannot be produced.
    pub fn canonical_document_digest(
        &self,
    ) -> serde_json::Result<LocalCertificationLedgerRecordDigest> {
        Ok(LocalCertificationLedgerRecordDigest::new(hash_canonical(
            self,
        )?))
    }

    /// Returns the one-based ledger sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the exact previous-record identity, absent only for genesis.
    #[must_use]
    pub const fn previous_record_digest(&self) -> Option<LocalCertificationLedgerRecordDigest> {
        self.previous_record_digest
    }

    /// Returns the closed ledger event.
    #[must_use]
    pub const fn event(&self) -> &LocalCertificationLedgerEvent {
        &self.event
    }

    fn validate_shape(&self) -> Result<(), LocalCertificationLedgerContractError> {
        if self.sequence == 0 {
            return Err(LocalCertificationLedgerContractError::InvalidSequence);
        }
        match (self.sequence, self.previous_record_digest, &self.event) {
            (1, None, LocalCertificationLedgerEvent::Genesis(_)) => {}
            (1, _, _) => return Err(LocalCertificationLedgerContractError::InvalidGenesis),
            (_, Some(_), LocalCertificationLedgerEvent::Genesis(_)) => {
                return Err(LocalCertificationLedgerContractError::UnexpectedGenesis);
            }
            (_, Some(_), _) => {}
            (_, None, _) => return Err(LocalCertificationLedgerContractError::MissingPreviousLink),
        }
        self.event.validate()
    }
}

/// Invalid canonical ledger relationship.
#[derive(Debug, Error)]
pub enum LocalCertificationLedgerContractError {
    /// A nested run attestation violated its contract.
    #[error("local certification ledger contains an invalid run attestation")]
    InvalidAttestation(#[source] CertificationRunAttestationError),
    /// Genesis policy did not exactly match its attestation.
    #[error("local certification ledger policy does not match the attestation")]
    PolicyMismatch,
    /// Receipt attestation identity did not match its attestation.
    #[error("local certification ledger receipt does not match the attestation")]
    ReceiptMismatch,
    /// Receipt publication status was not local-only.
    #[error("local certification ledger receipt publication status is invalid")]
    InvalidPublicationStatus,
    /// A canonical nested document could not be produced.
    #[error("canonical local certification ledger document is unavailable")]
    CanonicalDocumentUnavailable(#[source] serde_json::Error),
    /// Ledger sequence was zero.
    #[error("local certification ledger sequence must be nonzero")]
    InvalidSequence,
    /// Genesis shape was invalid.
    #[error("local certification ledger genesis shape is invalid")]
    InvalidGenesis,
    /// A later record attempted to contain a genesis event.
    #[error("local certification ledger contains an unexpected genesis event")]
    UnexpectedGenesis,
    /// A non-genesis record omitted its previous-record identity.
    #[error("local certification ledger record is missing its previous-record identity")]
    MissingPreviousLink,
    /// The sequence could not advance.
    #[error("local certification ledger sequence is exhausted")]
    SequenceExhausted,
}

/// Failure to read or parse one bounded ledger record.
#[derive(Debug, Error)]
pub enum LocalCertificationLedgerDocumentError {
    /// Serialized bytes exceeded the fixed ceiling.
    #[error("local certification ledger record exceeds its byte ceiling")]
    DocumentTooLarge,
    /// Bounded input could not be read.
    #[error("local certification ledger record bounded read failed")]
    BoundedRead(#[source] BoundedDocumentReadError),
    /// JSON syntax or closed transport shape was invalid.
    #[error("local certification ledger record is invalid")]
    InvalidDocument(#[source] serde_json::Error),
    /// Parsed fields violated ledger-record relationships.
    #[error("local certification ledger record contract is invalid")]
    InvalidContract(#[source] LocalCertificationLedgerContractError),
}

fn hash_canonical(value: &impl Serialize) -> serde_json::Result<Sha256Digest> {
    let bytes = serde_json::to_vec(value)?;
    Ok(Sha256Digest::from_bytes(Sha256::digest(bytes).into()))
}

fn read_bounded(
    reader: impl Read,
    maximum_bytes: usize,
) -> Result<Vec<u8>, BoundedDocumentReadError> {
    let read_limit = u64::try_from(maximum_bytes)
        .ok()
        .and_then(|limit| limit.checked_add(1))
        .ok_or(BoundedDocumentReadError::DocumentTooLarge)?;
    let mut bounded = reader.take(read_limit);
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(maximum_bytes.min(8 * 1024))
        .map_err(|_| BoundedDocumentReadError::BufferAllocationFailed)?;
    bounded
        .read_to_end(&mut bytes)
        .map_err(BoundedDocumentReadError::Read)?;
    if bytes.len() > maximum_bytes {
        return Err(BoundedDocumentReadError::DocumentTooLarge);
    }
    Ok(bytes)
}

/// Shared bounded-document reader failure.
#[derive(Debug, Error)]
pub enum BoundedDocumentReadError {
    /// Input exceeded its selected fixed ceiling.
    #[error("bounded document exceeds its byte ceiling")]
    DocumentTooLarge,
    /// The bounded buffer could not be reserved.
    #[error("bounded document buffer allocation failed")]
    BufferAllocationFailed,
    /// Input read failed.
    #[error("bounded document read failed")]
    Read(#[source] io::Error),
}
