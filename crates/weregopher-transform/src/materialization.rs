//! Deterministic content-addressed materialization manifests for verified artifacts.

use std::{collections::BTreeMap, fmt, io};

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use weregopher_domain::{Sha256Digest, TransformRuleId};

use crate::VerifiedTransformArtifacts;

const ARTIFACTS_PER_RULE: usize = 5;
const CONTENT_PATH_LENGTH: usize = 72;
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

/// Caller-selected bounds for one deterministic materialization manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaterializationManifestLimits {
    rules: usize,
    references: usize,
    blobs: usize,
    manifest: usize,
}

impl MaterializationManifestLimits {
    /// Constructs nonzero rule, artifact-reference, unique-blob, and manifest-byte limits.
    ///
    /// # Errors
    ///
    /// Returns [`MaterializationManifestError::InvalidLimits`] when any limit is zero.
    pub const fn new(
        max_rules: usize,
        max_references: usize,
        max_unique_blobs: usize,
        max_manifest_bytes: usize,
    ) -> Result<Self, MaterializationManifestError> {
        if max_rules == 0 || max_references == 0 || max_unique_blobs == 0 || max_manifest_bytes == 0
        {
            return Err(MaterializationManifestError::InvalidLimits);
        }
        Ok(Self {
            rules: max_rules,
            references: max_references,
            blobs: max_unique_blobs,
            manifest: max_manifest_bytes,
        })
    }
}

/// Canonical materialization intent for one verified transform artifact set.
///
/// This type retains the exact structural and byte-verification proof that produced it. It plans
/// safe relative content-addressed names but performs no filesystem access or authorization.
pub struct MaterializationManifest<'verified, 'overlay, 'authority, 'artifacts, 'bytes> {
    verified: &'verified VerifiedTransformArtifacts<'overlay, 'authority, 'artifacts, 'bytes>,
    bytes: Vec<u8>,
    digest: Sha256Digest,
    blobs: BTreeMap<Sha256Digest, &'bytes [u8]>,
    rule_count: usize,
    reference_count: usize,
}

impl fmt::Debug for MaterializationManifest<'_, '_, '_, '_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaterializationManifest")
            .field("binding", self.verified.overlay().binding())
            .field("rule_count", &self.rule_count)
            .field("reference_count", &self.reference_count)
            .field("blob_count", &self.blobs.len())
            .field("manifest_length", &self.bytes.len())
            .field("manifest_digest", &self.digest)
            .finish()
    }
}

impl<'verified, 'overlay, 'authority, 'artifacts, 'bytes>
    MaterializationManifest<'verified, 'overlay, 'authority, 'artifacts, 'bytes>
{
    /// Returns the exact verified artifact proof represented by this manifest.
    #[must_use]
    pub const fn verified_artifacts(
        &self,
    ) -> &'verified VerifiedTransformArtifacts<'overlay, 'authority, 'artifacts, 'bytes> {
        self.verified
    }

    /// Returns canonical compact UTF-8 manifest JSON bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the SHA-256 identity of the canonical manifest bytes.
    #[must_use]
    pub const fn digest(&self) -> &Sha256Digest {
        &self.digest
    }

    /// Returns unique digest-to-byte bindings in deterministic digest order.
    #[must_use]
    pub const fn blobs(&self) -> &BTreeMap<Sha256Digest, &'bytes [u8]> {
        &self.blobs
    }

    /// Returns the number of represented transform rules.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Returns the number of rule-to-artifact references.
    #[must_use]
    pub const fn reference_count(&self) -> usize {
        self.reference_count
    }

    /// Returns the number of unique content-addressed blobs after deduplication.
    #[must_use]
    pub fn blob_count(&self) -> usize {
        self.blobs.len()
    }
}

#[derive(Serialize)]
struct ManifestDocument<'a> {
    format_version: &'static str,
    layout: &'static str,
    target: &'static str,
    binding: ManifestBinding<'a>,
    rules: &'a [ManifestRule<'a>],
}

#[derive(Serialize)]
struct ManifestBinding<'a> {
    source_build_fingerprint_digest: &'a Sha256Digest,
    family: &'a weregopher_domain::ApplicationFamilyId,
    adapter_id: &'a weregopher_domain::AdapterId,
    adapter_content_digest: &'a Sha256Digest,
    adapter_transform_authority_digest: &'a Sha256Digest,
    build_descriptor_digest: &'a Sha256Digest,
}

#[derive(Serialize)]
struct ManifestRule<'a> {
    rule_id: &'a TransformRuleId,
    source_unit_id: &'a weregopher_domain::SourceUnitId,
    artifacts: [ManifestArtifact<'a>; ARTIFACTS_PER_RULE],
}

#[derive(Serialize)]
struct ManifestArtifact<'a> {
    kind: &'static str,
    digest: &'a Sha256Digest,
    bytes: usize,
    path: String,
}

type BlobMap<'bytes> = BTreeMap<Sha256Digest, &'bytes [u8]>;

struct ManifestRecords<'overlay, 'bytes> {
    rules: Vec<ManifestRule<'overlay>>,
    blobs: BlobMap<'bytes>,
}

/// Plans deterministic content-addressed relative paths for one verified artifact set.
///
/// Blob paths use `sha256/<first-byte-hex>/<remaining-hex>` and contain only fixed ASCII
/// components. The returned manifest retains verified bytes by reference and performs no I/O.
///
/// # Errors
///
/// Returns [`MaterializationManifestError`] when limits, verified coverage invariants, digest-to-
/// byte uniqueness, path construction, canonical serialization, or bounded allocation fail.
pub fn plan_content_addressed_materialization<
    'verified,
    'overlay,
    'authority,
    'artifacts,
    'bytes,
>(
    verified: &'verified VerifiedTransformArtifacts<'overlay, 'authority, 'artifacts, 'bytes>,
    limits: MaterializationManifestLimits,
) -> Result<
    MaterializationManifest<'verified, 'overlay, 'authority, 'artifacts, 'bytes>,
    MaterializationManifestError,
> {
    let rule_count = verified.rule_count();
    if rule_count > limits.rules {
        return Err(MaterializationManifestError::RuleLimitExceeded {
            actual: rule_count,
            max: limits.rules,
        });
    }
    let reference_count = rule_count
        .checked_mul(ARTIFACTS_PER_RULE)
        .ok_or(MaterializationManifestError::ReferenceCountOverflow)?;
    if reference_count > limits.references {
        return Err(MaterializationManifestError::ReferenceLimitExceeded {
            actual: reference_count,
            max: limits.references,
        });
    }

    let overlay = verified.overlay();
    let binding = overlay.binding();
    let ManifestRecords { rules, blobs } =
        collect_manifest_records(verified, rule_count, limits.blobs)?;

    let document = ManifestDocument {
        format_version: "1",
        layout: "sha256-fanout-v1",
        target: "windows-x86_64",
        binding: ManifestBinding {
            source_build_fingerprint_digest: binding.source_build_fingerprint_digest(),
            family: binding.family(),
            adapter_id: binding.adapter_id(),
            adapter_content_digest: binding.adapter_content_digest(),
            adapter_transform_authority_digest: binding.adapter_transform_authority_digest(),
            build_descriptor_digest: binding.build_descriptor_digest(),
        },
        rules: &rules,
    };
    let manifest_length = serialized_length(&document)?;
    if manifest_length > limits.manifest {
        return Err(MaterializationManifestError::ManifestTooLarge {
            actual_bytes: manifest_length,
            max_bytes: limits.manifest,
        });
    }
    let mut manifest_bytes = Vec::new();
    manifest_bytes
        .try_reserve_exact(manifest_length)
        .map_err(|_| MaterializationManifestError::ManifestAllocationFailed {
            requested_bytes: manifest_length,
        })?;
    serde_json::to_writer(&mut manifest_bytes, &document)
        .map_err(|_| MaterializationManifestError::SerializationFailed)?;
    if manifest_bytes.len() != manifest_length {
        return Err(MaterializationManifestError::ManifestLengthMismatch {
            expected_bytes: manifest_length,
            actual_bytes: manifest_bytes.len(),
        });
    }
    let manifest_digest = digest(&manifest_bytes);

    Ok(MaterializationManifest {
        verified,
        bytes: manifest_bytes,
        digest: manifest_digest,
        blobs,
        rule_count,
        reference_count,
    })
}

fn collect_manifest_records<'overlay, 'bytes>(
    verified: &VerifiedTransformArtifacts<'overlay, '_, '_, 'bytes>,
    rule_count: usize,
    max_blobs: usize,
) -> Result<ManifestRecords<'overlay, 'bytes>, MaterializationManifestError> {
    let mut rules = Vec::new();
    rules
        .try_reserve_exact(rule_count)
        .map_err(|_| MaterializationManifestError::RuleAllocationFailed { rules: rule_count })?;
    let mut blobs = BTreeMap::new();

    for (rule_id, rebinding) in verified.overlay().rebindings() {
        let artifact_bytes = verified
            .artifacts()
            .get(rule_id)
            .ok_or_else(|| MaterializationManifestError::MissingVerifiedRule(rule_id.clone()))?;
        let artifacts = [
            manifest_artifact(
                "source",
                rebinding.source().source_digest(),
                artifact_bytes.source(),
                &mut blobs,
                max_blobs,
            )?,
            manifest_artifact(
                "match_evidence",
                rebinding.match_evidence_digest(),
                artifact_bytes.match_evidence(),
                &mut blobs,
                max_blobs,
            )?,
            manifest_artifact(
                "transformed_source",
                rebinding.transformed_source_digest(),
                artifact_bytes.transformed_source(),
                &mut blobs,
                max_blobs,
            )?,
            manifest_artifact(
                "source_map",
                rebinding.source_map_digest(),
                artifact_bytes.source_map(),
                &mut blobs,
                max_blobs,
            )?,
            manifest_artifact(
                "audit_log",
                rebinding.audit_log_digest(),
                artifact_bytes.audit_log(),
                &mut blobs,
                max_blobs,
            )?,
        ];
        rules.push(ManifestRule {
            rule_id,
            source_unit_id: rebinding.source().unit_id(),
            artifacts,
        });
    }
    Ok(ManifestRecords { rules, blobs })
}

fn manifest_artifact<'digest, 'bytes>(
    kind: &'static str,
    digest: &'digest Sha256Digest,
    bytes: &'bytes [u8],
    blobs: &mut BTreeMap<Sha256Digest, &'bytes [u8]>,
    max_blobs: usize,
) -> Result<ManifestArtifact<'digest>, MaterializationManifestError> {
    if let Some(existing) = blobs.get(digest) {
        if *existing != bytes {
            return Err(MaterializationManifestError::DigestCollision { digest: *digest });
        }
    } else {
        if blobs.len() >= max_blobs {
            return Err(MaterializationManifestError::BlobLimitExceeded { max: max_blobs });
        }
        blobs.insert(*digest, bytes);
    }
    Ok(ManifestArtifact {
        kind,
        digest,
        bytes: bytes.len(),
        path: content_path(digest)?,
    })
}

fn content_path(digest: &Sha256Digest) -> Result<String, MaterializationManifestError> {
    let mut path = String::new();
    path.try_reserve_exact(CONTENT_PATH_LENGTH)
        .map_err(|_| MaterializationManifestError::PathAllocationFailed)?;
    path.push_str("sha256/");
    for (index, byte) in digest.as_bytes().iter().copied().enumerate() {
        if index == 1 {
            path.push('/');
        }
        let high = LOWER_HEX
            .get(usize::from(byte >> 4))
            .ok_or(MaterializationManifestError::PathEncodingFailed)?;
        let low = LOWER_HEX
            .get(usize::from(byte & 0x0f))
            .ok_or(MaterializationManifestError::PathEncodingFailed)?;
        path.push(char::from(*high));
        path.push(char::from(*low));
    }
    if path.len() != CONTENT_PATH_LENGTH {
        return Err(MaterializationManifestError::PathEncodingFailed);
    }
    Ok(path)
}

#[derive(Default)]
struct CountingWriter {
    bytes: usize,
    overflowed: bool,
}

impl io::Write for CountingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let Some(total) = self.bytes.checked_add(buffer.len()) else {
            self.overflowed = true;
            return Err(io::Error::other("serialized manifest length overflow"));
        };
        self.bytes = total;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialized_length(
    document: &ManifestDocument<'_>,
) -> Result<usize, MaterializationManifestError> {
    let mut writer = CountingWriter::default();
    let result = serde_json::to_writer(&mut writer, document);
    if writer.overflowed {
        return Err(MaterializationManifestError::ManifestLengthOverflow);
    }
    result.map_err(|_| MaterializationManifestError::SerializationFailed)?;
    Ok(writer.bytes)
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

/// Failure planning a deterministic content-addressed materialization manifest.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MaterializationManifestError {
    /// One or more caller-selected limits were zero.
    #[error("materialization manifest limits must be nonzero")]
    InvalidLimits,
    /// Verified rule coverage exceeded the caller-selected limit.
    #[error("verified artifacts contain {actual} rules; manifest limit is {max}")]
    RuleLimitExceeded {
        /// Exact verified rule count.
        actual: usize,
        /// Caller-selected rule limit.
        max: usize,
    },
    /// Rule-to-artifact reference-count arithmetic overflowed.
    #[error("materialization artifact reference count overflowed")]
    ReferenceCountOverflow,
    /// Artifact references exceeded the caller-selected limit.
    #[error("verified artifacts contain {actual} references; manifest limit is {max}")]
    ReferenceLimitExceeded {
        /// Exact rule-to-artifact reference count.
        actual: usize,
        /// Caller-selected reference limit.
        max: usize,
    },
    /// Retained rule-record allocation failed.
    #[error("could not allocate {rules} materialization rule records")]
    RuleAllocationFailed {
        /// Exact requested rule capacity.
        rules: usize,
    },
    /// A verified artifact rule unexpectedly lacked its byte bundle.
    #[error("verified artifact bytes are missing rule {0}")]
    MissingVerifiedRule(TransformRuleId),
    /// Two different byte sequences claimed the same SHA-256 identity.
    #[error("distinct verified bytes claim digest {digest}")]
    DigestCollision {
        /// Conflicting digest identity.
        digest: Sha256Digest,
    },
    /// Unique content blobs exceeded the caller-selected limit.
    #[error("materialization unique-blob limit is {max}")]
    BlobLimitExceeded {
        /// Caller-selected unique-blob limit.
        max: usize,
    },
    /// Fixed relative content-addressed path allocation failed.
    #[error("could not allocate a content-addressed relative path")]
    PathAllocationFailed,
    /// Fixed relative content-addressed path encoding violated its invariant.
    #[error("could not encode a content-addressed relative path")]
    PathEncodingFailed,
    /// Canonical JSON serialization failed.
    #[error("could not serialize the materialization manifest")]
    SerializationFailed,
    /// Checked canonical manifest length arithmetic overflowed.
    #[error("materialization manifest length overflowed the platform byte index")]
    ManifestLengthOverflow,
    /// Canonical manifest bytes exceeded the caller-selected pre-allocation limit.
    #[error("materialization manifest is {actual_bytes} bytes; limit is {max_bytes}")]
    ManifestTooLarge {
        /// Exact computed manifest length.
        actual_bytes: usize,
        /// Caller-selected manifest-byte limit.
        max_bytes: usize,
    },
    /// Exact-capacity canonical manifest allocation failed.
    #[error("could not allocate {requested_bytes} materialization manifest bytes")]
    ManifestAllocationFailed {
        /// Exact requested manifest capacity.
        requested_bytes: usize,
    },
    /// Emitted manifest length differed from its exact counted length.
    #[error("emitted {actual_bytes} manifest bytes; expected {expected_bytes}")]
    ManifestLengthMismatch {
        /// Exact counted manifest length.
        expected_bytes: usize,
        /// Actual emitted manifest length.
        actual_bytes: usize,
    },
}
