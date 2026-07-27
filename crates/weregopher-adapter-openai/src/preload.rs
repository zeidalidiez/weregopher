//! Exact package-derived preload source preparation.

use std::fmt;

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use weregopher_asar::{AsarError, AsarLimits, AsarReadOnlyIndex};
use weregopher_domain::{G2ComponentSource, G2PackagePath, OpenAiPackageInventory, Sha256Digest};

use crate::{MAX_OPENAI_PRELOAD_SOURCE_BYTES, OPENAI_APPLICATION_ARCHIVE_PATH};

/// Immutable, content-addressed exact preload source ready for a native probe.
#[derive(Clone, Eq, PartialEq)]
pub struct ExactPreloadSource {
    source_build_fingerprint_digest: Sha256Digest,
    preload_digest: Sha256Digest,
    path: G2PackagePath,
    source: String,
}

impl fmt::Debug for ExactPreloadSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactPreloadSource")
            .field(
                "source_build_fingerprint_digest",
                &self.source_build_fingerprint_digest,
            )
            .field("preload_digest", &self.preload_digest)
            .field("path", &self.path)
            .field("source_bytes", &self.source.len())
            .finish()
    }
}

impl ExactPreloadSource {
    /// Returns the exact source build-fingerprint identity.
    #[must_use]
    pub const fn source_build_fingerprint_digest(&self) -> &Sha256Digest {
        &self.source_build_fingerprint_digest
    }

    /// Returns the exact package-derived preload identity.
    #[must_use]
    pub const fn preload_digest(&self) -> &Sha256Digest {
        &self.preload_digest
    }

    /// Returns the canonical application-archive member path.
    #[must_use]
    pub const fn path(&self) -> &G2PackagePath {
        &self.path
    }

    /// Returns the validated UTF-8 JavaScript source.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }
}

/// Fail-closed exact preload source preparation error.
#[derive(Debug, Error)]
pub enum ExactPreloadPreparationError {
    /// The application-archive evidence is outside the maintained package-file boundary.
    #[error("exact preload preparation received unexpected application archive evidence")]
    UnexpectedApplicationArchiveEvidence,
    /// Supplied archive length did not match exact package evidence.
    #[error("exact preload application archive length does not match package evidence")]
    ApplicationArchiveLengthMismatch,
    /// Supplied archive digest did not match exact package evidence.
    #[error("exact preload application archive digest does not match package evidence")]
    ApplicationArchiveDigestMismatch,
    /// Static discovery retained more than one candidate and did not establish an entry.
    #[error("exact preload selection is ambiguous across {observed} package candidates")]
    AmbiguousPreloadCandidates {
        /// Number of candidates that require a stronger entry-resolution rule.
        observed: usize,
    },
    /// Candidate evidence was outside the maintained archive-member boundary.
    #[error("exact preload candidate has an unexpected evidence source")]
    UnexpectedPreloadSource,
    /// Candidate evidence exceeded the runner's source ceiling.
    #[error("exact preload candidate exceeds its byte limit")]
    PreloadSourceTooLarge,
    /// The candidate was absent from the integrity-checked packed archive.
    #[error("exact preload candidate is absent from the application archive")]
    MissingPreloadMember,
    /// Candidate length did not match exact package evidence.
    #[error("exact preload candidate length does not match package evidence")]
    PreloadLengthMismatch,
    /// Candidate digest did not match exact package evidence.
    #[error("exact preload candidate digest does not match package evidence")]
    PreloadDigestMismatch,
    /// Candidate source cannot be injected as JavaScript source text.
    #[error("exact preload candidate is not valid UTF-8 JavaScript source")]
    PreloadSourceNotUtf8,
    /// The exact application archive failed bounded integrity validation.
    #[error("exact preload application archive is invalid: {0}")]
    Archive(#[from] AsarError),
}

/// Revalidates and extracts the sole exact package-derived preload candidate.
///
/// The preparation stage accepts immutable archive bytes already bound to the
/// package inventory. It rechecks the archive component length and digest,
/// reparses the complete packed ASAR body, and rechecks the selected member
/// before retaining source text. Static candidate discovery does not establish
/// an actual Electron preload entry, so an inventory with multiple candidates
/// fails closed until a stronger entry-resolution rule exists.
///
/// This function does not access the filesystem, execute source, or grant the
/// candidate any authority.
///
/// # Errors
///
/// Returns [`ExactPreloadPreparationError`] when archive or candidate evidence
/// is ambiguous, malformed, oversized, unbound, absent, or non-UTF-8.
pub fn prepare_exact_preload(
    inventory: &OpenAiPackageInventory,
    application_archive_bytes: &[u8],
) -> Result<ExactPreloadSource, ExactPreloadPreparationError> {
    let archive_evidence = inventory.application_archive();
    if archive_evidence.source() != G2ComponentSource::PackageFile
        || archive_evidence.path().as_str() != OPENAI_APPLICATION_ARCHIVE_PATH
    {
        return Err(ExactPreloadPreparationError::UnexpectedApplicationArchiveEvidence);
    }
    if u64::try_from(application_archive_bytes.len()).ok() != Some(archive_evidence.byte_length()) {
        return Err(ExactPreloadPreparationError::ApplicationArchiveLengthMismatch);
    }
    if digest(application_archive_bytes) != *archive_evidence.sha256() {
        return Err(ExactPreloadPreparationError::ApplicationArchiveDigestMismatch);
    }

    let mut candidates = inventory.preload_candidates().iter();
    let candidate = candidates
        .next()
        .ok_or(ExactPreloadPreparationError::AmbiguousPreloadCandidates { observed: 0 })?;
    if candidates.next().is_some() {
        return Err(ExactPreloadPreparationError::AmbiguousPreloadCandidates {
            observed: inventory.preload_candidates().len(),
        });
    }
    if candidate.source() != G2ComponentSource::ApplicationArchiveMember {
        return Err(ExactPreloadPreparationError::UnexpectedPreloadSource);
    }
    if candidate.byte_length() > u64::try_from(MAX_OPENAI_PRELOAD_SOURCE_BYTES).unwrap_or(u64::MAX)
    {
        return Err(ExactPreloadPreparationError::PreloadSourceTooLarge);
    }

    let archive = AsarReadOnlyIndex::parse(application_archive_bytes, AsarLimits::initial())?;
    let source_bytes = archive
        .packed_file(candidate.path().as_str())
        .ok_or(ExactPreloadPreparationError::MissingPreloadMember)?;
    if u64::try_from(source_bytes.len()).ok() != Some(candidate.byte_length()) {
        return Err(ExactPreloadPreparationError::PreloadLengthMismatch);
    }
    if digest(source_bytes) != *candidate.sha256() {
        return Err(ExactPreloadPreparationError::PreloadDigestMismatch);
    }
    let source = std::str::from_utf8(source_bytes)
        .map_err(|_| ExactPreloadPreparationError::PreloadSourceNotUtf8)?
        .to_owned();
    Ok(ExactPreloadSource {
        source_build_fingerprint_digest: *inventory.source_build_fingerprint_digest(),
        preload_digest: *candidate.sha256(),
        path: candidate.path().clone(),
        source,
    })
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}
