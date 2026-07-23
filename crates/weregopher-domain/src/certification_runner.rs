//! Bounded canonical identity of the immutable certification-runner environment.

use std::{
    fmt,
    io::{self, Read},
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::Sha256Digest;

/// Current serialized certification-runner identity format version.
pub const CERTIFICATION_RUNNER_IDENTITY_FORMAT_VERSION: &str = "1";
/// Maximum serialized bytes accepted by the certification-runner identity parser.
pub const MAX_CERTIFICATION_RUNNER_IDENTITY_DOCUMENT_BYTES: usize = 32 * 1024;

macro_rules! certification_runner_digest_role {
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
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

certification_runner_digest_role!(
    /// Identity of the immutable runner image or executable closure.
    CertificationRunnerImageDigest
);
certification_runner_digest_role!(
    /// Identity of the immutable host operating-system image and build descriptor.
    CertificationHostImageDigest
);
certification_runner_digest_role!(
    /// Identity of the exact host patch-set descriptor.
    CertificationHostPatchSetDigest
);
certification_runner_digest_role!(
    /// Identity of the exact Electron runtime descriptor and bytes.
    CertificationElectronRuntimeDigest
);
certification_runner_digest_role!(
    /// Identity of the complete exact language-runtime version and artifact set.
    CertificationLanguageRuntimeSetDigest
);
certification_runner_digest_role!(
    /// Identity of the complete exact compiler/toolchain version and artifact set.
    CertificationToolchainSetDigest
);
certification_runner_digest_role!(
    /// Identity of the exact host-agent implementation.
    CertificationHostAgentDigest
);
certification_runner_digest_role!(
    /// Identity of the exact evidence verifier implementation.
    CertificationVerifierDigest
);
certification_runner_digest_role!(
    /// Identity of the complete exact probe-asset set.
    CertificationProbeAssetSetDigest
);
certification_runner_digest_role!(
    /// Identity of the exact certification source revision.
    CertificationSourceRevisionDigest
);
certification_runner_digest_role!(
    /// Identity of the complete approved exception-provenance set, including the canonical empty set.
    CertificationExceptionProvenanceDigest
);
certification_runner_digest_role!(
    /// Identity of canonical certification-runner identity document bytes.
    ///
    /// Runner identities cannot be substituted for runner-image identities:
    ///
    /// ```compile_fail
    /// use weregopher_domain::{
    ///     CertificationRunnerIdentityDigest, CertificationRunnerImageDigest, Sha256Digest,
    /// };
    ///
    /// let identity = CertificationRunnerIdentityDigest::new(Sha256Digest::from_bytes([0; 32]));
    /// let image: CertificationRunnerImageDigest = identity;
    /// # let _ = image;
    /// ```
    CertificationRunnerIdentityDigest
);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CertificationRunnerIdentityFormatVersion {
    #[serde(rename = "1")]
    V1,
}

/// Platform fixed by certification-runner identity format version 1.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificationRunnerPlatform {
    /// Microsoft Windows.
    Windows,
}

/// Architecture fixed by certification-runner identity format version 1.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificationRunnerArchitecture {
    /// AMD64/x86-64.
    X86_64,
}

/// Exact platform and executable environment of a certification runner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationRunnerEnvironmentIdentity {
    platform: CertificationRunnerPlatform,
    architecture: CertificationRunnerArchitecture,
    runner_image_digest: CertificationRunnerImageDigest,
    host_image_digest: CertificationHostImageDigest,
    host_patch_set_digest: CertificationHostPatchSetDigest,
    electron_runtime_digest: CertificationElectronRuntimeDigest,
    language_runtime_set_digest: CertificationLanguageRuntimeSetDigest,
}

impl CertificationRunnerEnvironmentIdentity {
    /// Constructs the initial Windows x64 runner environment identity.
    #[must_use]
    pub const fn windows_x86_64(
        runner_image_digest: CertificationRunnerImageDigest,
        host_image_digest: CertificationHostImageDigest,
        host_patch_set_digest: CertificationHostPatchSetDigest,
        electron_runtime_digest: CertificationElectronRuntimeDigest,
        language_runtime_set_digest: CertificationLanguageRuntimeSetDigest,
    ) -> Self {
        Self {
            platform: CertificationRunnerPlatform::Windows,
            architecture: CertificationRunnerArchitecture::X86_64,
            runner_image_digest,
            host_image_digest,
            host_patch_set_digest,
            electron_runtime_digest,
            language_runtime_set_digest,
        }
    }

    const fn from_unchecked(unchecked: UncheckedCertificationRunnerEnvironmentIdentity) -> Self {
        Self {
            platform: unchecked.platform,
            architecture: unchecked.architecture,
            runner_image_digest: unchecked.runner_image_digest,
            host_image_digest: unchecked.host_image_digest,
            host_patch_set_digest: unchecked.host_patch_set_digest,
            electron_runtime_digest: unchecked.electron_runtime_digest,
            language_runtime_set_digest: unchecked.language_runtime_set_digest,
        }
    }
}

/// Exact tool and probe environment of a certification runner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationRunnerToolingIdentity {
    #[serde(rename = "toolchain_set_digest")]
    toolchain_set: CertificationToolchainSetDigest,
    #[serde(rename = "host_agent_digest")]
    host_agent: CertificationHostAgentDigest,
    #[serde(rename = "verifier_digest")]
    verifier: CertificationVerifierDigest,
    #[serde(rename = "probe_asset_set_digest")]
    probe_asset_set: CertificationProbeAssetSetDigest,
}

impl CertificationRunnerToolingIdentity {
    /// Constructs the exact runner tooling identity.
    #[must_use]
    pub const fn new(
        toolchain_set_digest: CertificationToolchainSetDigest,
        host_agent_digest: CertificationHostAgentDigest,
        verifier_digest: CertificationVerifierDigest,
        probe_asset_set_digest: CertificationProbeAssetSetDigest,
    ) -> Self {
        Self {
            toolchain_set: toolchain_set_digest,
            host_agent: host_agent_digest,
            verifier: verifier_digest,
            probe_asset_set: probe_asset_set_digest,
        }
    }

    const fn from_unchecked(unchecked: UncheckedCertificationRunnerToolingIdentity) -> Self {
        Self {
            toolchain_set: unchecked.toolchain_set,
            host_agent: unchecked.host_agent,
            verifier: unchecked.verifier,
            probe_asset_set: unchecked.probe_asset_set,
        }
    }
}

/// Exact source and exception provenance of a certification runner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationRunnerProvenanceIdentity {
    source_revision_digest: CertificationSourceRevisionDigest,
    exception_provenance_digest: CertificationExceptionProvenanceDigest,
}

impl CertificationRunnerProvenanceIdentity {
    /// Constructs the exact runner provenance identity.
    #[must_use]
    pub const fn new(
        source_revision_digest: CertificationSourceRevisionDigest,
        exception_provenance_digest: CertificationExceptionProvenanceDigest,
    ) -> Self {
        Self {
            source_revision_digest,
            exception_provenance_digest,
        }
    }

    const fn from_unchecked(unchecked: UncheckedCertificationRunnerProvenanceIdentity) -> Self {
        Self {
            source_revision_digest: unchecked.source_revision,
            exception_provenance_digest: unchecked.exception_provenance,
        }
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedCertificationRunnerEnvironmentIdentity {
    platform: CertificationRunnerPlatform,
    architecture: CertificationRunnerArchitecture,
    runner_image_digest: CertificationRunnerImageDigest,
    host_image_digest: CertificationHostImageDigest,
    host_patch_set_digest: CertificationHostPatchSetDigest,
    electron_runtime_digest: CertificationElectronRuntimeDigest,
    language_runtime_set_digest: CertificationLanguageRuntimeSetDigest,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedCertificationRunnerToolingIdentity {
    #[serde(rename = "toolchain_set_digest")]
    toolchain_set: CertificationToolchainSetDigest,
    #[serde(rename = "host_agent_digest")]
    host_agent: CertificationHostAgentDigest,
    #[serde(rename = "verifier_digest")]
    verifier: CertificationVerifierDigest,
    #[serde(rename = "probe_asset_set_digest")]
    probe_asset_set: CertificationProbeAssetSetDigest,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedCertificationRunnerProvenanceIdentity {
    #[serde(rename = "source_revision_digest")]
    source_revision: CertificationSourceRevisionDigest,
    #[serde(rename = "exception_provenance_digest")]
    exception_provenance: CertificationExceptionProvenanceDigest,
}

/// Canonical non-authorizing identity of every immutable certification-runner input.
///
/// Every aggregate digest names a separately canonical descriptor that includes exact versions and
/// artifact identities for that role. This document alone does not authenticate a producer, prove
/// that a run occurred, bind evidence to a run, establish freshness, or assign certification trust.
///
/// Generic deserialization is deliberately unavailable so hostile bytes cannot bypass the document
/// ceiling:
///
/// ```compile_fail
/// fn require_deserialize<T: for<'de> serde::Deserialize<'de>>() {}
/// require_deserialize::<weregopher_domain::CertificationRunnerIdentity>();
/// ```
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationRunnerIdentity {
    format_version: CertificationRunnerIdentityFormatVersion,
    environment: CertificationRunnerEnvironmentIdentity,
    tooling: CertificationRunnerToolingIdentity,
    provenance: CertificationRunnerProvenanceIdentity,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedCertificationRunnerIdentity {
    format_version: CertificationRunnerIdentityFormatVersion,
    environment: UncheckedCertificationRunnerEnvironmentIdentity,
    tooling: UncheckedCertificationRunnerToolingIdentity,
    provenance: UncheckedCertificationRunnerProvenanceIdentity,
}

impl CertificationRunnerIdentity {
    /// Constructs the exact certification-runner identity.
    #[must_use]
    pub const fn new(
        environment: CertificationRunnerEnvironmentIdentity,
        tooling: CertificationRunnerToolingIdentity,
        provenance: CertificationRunnerProvenanceIdentity,
    ) -> Self {
        Self {
            format_version: CertificationRunnerIdentityFormatVersion::V1,
            environment,
            tooling,
            provenance,
        }
    }

    /// Parses a runner identity after enforcing the serialized-byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`CertificationRunnerDocumentError`] for oversized or invalid document bytes.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, CertificationRunnerDocumentError> {
        if bytes.len() > MAX_CERTIFICATION_RUNNER_IDENTITY_DOCUMENT_BYTES {
            return Err(CertificationRunnerDocumentError::DocumentTooLarge);
        }
        let unchecked: UncheckedCertificationRunnerIdentity = serde_json::from_slice(bytes)
            .map_err(CertificationRunnerDocumentError::InvalidDocument)?;
        Ok(Self::from_unchecked(&unchecked))
    }

    /// Reads and parses a runner identity without buffering beyond the serialized-byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`CertificationRunnerDocumentError`] for read failures, oversized input, or invalid
    /// document bytes.
    pub fn from_json_reader(reader: impl Read) -> Result<Self, CertificationRunnerDocumentError> {
        let read_limit = u64::try_from(MAX_CERTIFICATION_RUNNER_IDENTITY_DOCUMENT_BYTES)
            .ok()
            .and_then(|limit| limit.checked_add(1))
            .ok_or(CertificationRunnerDocumentError::DocumentTooLarge)?;
        let mut bounded = reader.take(read_limit);
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(MAX_CERTIFICATION_RUNNER_IDENTITY_DOCUMENT_BYTES.min(8 * 1024))
            .map_err(|_| CertificationRunnerDocumentError::BufferAllocationFailed)?;
        bounded
            .read_to_end(&mut bytes)
            .map_err(CertificationRunnerDocumentError::Read)?;
        Self::from_json_slice(&bytes)
    }

    /// Returns canonical compact JSON bytes.
    ///
    /// Field order, fixed string spellings, and SHA-256 spellings are normative for format version 1.
    ///
    /// # Errors
    ///
    /// Returns the serializer error if the in-memory identity cannot be encoded.
    pub fn canonical_json_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

    /// Returns the SHA-256 identity of canonical runner-identity bytes.
    ///
    /// # Errors
    ///
    /// Returns the serializer error if canonical bytes cannot be produced.
    pub fn canonical_document_digest(
        &self,
    ) -> serde_json::Result<CertificationRunnerIdentityDigest> {
        let bytes = self.canonical_json_bytes()?;
        Ok(CertificationRunnerIdentityDigest::new(
            Sha256Digest::from_bytes(Sha256::digest(bytes).into()),
        ))
    }

    /// Returns the exact format version.
    #[must_use]
    pub const fn format_version(&self) -> &'static str {
        CERTIFICATION_RUNNER_IDENTITY_FORMAT_VERSION
    }

    /// Returns the fixed runner platform.
    #[must_use]
    pub const fn platform(&self) -> CertificationRunnerPlatform {
        self.environment.platform
    }

    /// Returns the fixed runner architecture.
    #[must_use]
    pub const fn architecture(&self) -> CertificationRunnerArchitecture {
        self.environment.architecture
    }

    /// Returns the exact runner-image identity.
    #[must_use]
    pub const fn runner_image_digest(&self) -> CertificationRunnerImageDigest {
        self.environment.runner_image_digest
    }

    /// Returns the exact host-image identity.
    #[must_use]
    pub const fn host_image_digest(&self) -> CertificationHostImageDigest {
        self.environment.host_image_digest
    }

    /// Returns the exact host patch-set identity.
    #[must_use]
    pub const fn host_patch_set_digest(&self) -> CertificationHostPatchSetDigest {
        self.environment.host_patch_set_digest
    }

    /// Returns the exact Electron-runtime identity.
    #[must_use]
    pub const fn electron_runtime_digest(&self) -> CertificationElectronRuntimeDigest {
        self.environment.electron_runtime_digest
    }

    /// Returns the exact language-runtime-set identity.
    #[must_use]
    pub const fn language_runtime_set_digest(&self) -> CertificationLanguageRuntimeSetDigest {
        self.environment.language_runtime_set_digest
    }

    /// Returns the exact toolchain-set identity.
    #[must_use]
    pub const fn toolchain_set_digest(&self) -> CertificationToolchainSetDigest {
        self.tooling.toolchain_set
    }

    /// Returns the exact host-agent identity.
    #[must_use]
    pub const fn host_agent_digest(&self) -> CertificationHostAgentDigest {
        self.tooling.host_agent
    }

    /// Returns the exact verifier identity.
    #[must_use]
    pub const fn verifier_digest(&self) -> CertificationVerifierDigest {
        self.tooling.verifier
    }

    /// Returns the exact probe-asset-set identity.
    #[must_use]
    pub const fn probe_asset_set_digest(&self) -> CertificationProbeAssetSetDigest {
        self.tooling.probe_asset_set
    }

    /// Returns the exact source-revision identity.
    #[must_use]
    pub const fn source_revision_digest(&self) -> CertificationSourceRevisionDigest {
        self.provenance.source_revision_digest
    }

    /// Returns the exact exception-provenance-set identity.
    #[must_use]
    pub const fn exception_provenance_digest(&self) -> CertificationExceptionProvenanceDigest {
        self.provenance.exception_provenance_digest
    }

    const fn from_unchecked(unchecked: &UncheckedCertificationRunnerIdentity) -> Self {
        Self {
            format_version: unchecked.format_version,
            environment: CertificationRunnerEnvironmentIdentity::from_unchecked(
                unchecked.environment,
            ),
            tooling: CertificationRunnerToolingIdentity::from_unchecked(unchecked.tooling),
            provenance: CertificationRunnerProvenanceIdentity::from_unchecked(unchecked.provenance),
        }
    }
}

/// Failure to read or parse a bounded certification-runner identity document.
#[derive(Debug, Error)]
pub enum CertificationRunnerDocumentError {
    /// Serialized bytes exceeded the implementation ceiling.
    #[error("certification-runner identity document exceeds the byte ceiling")]
    DocumentTooLarge,
    /// The bounded input buffer could not be reserved.
    #[error("certification-runner identity input buffer allocation failed")]
    BufferAllocationFailed,
    /// The bounded reader failed.
    #[error("certification-runner identity document read failed")]
    Read(#[source] io::Error),
    /// JSON syntax or the closed transport shape was invalid.
    #[error("certification-runner identity document is invalid")]
    InvalidDocument(#[source] serde_json::Error),
}
