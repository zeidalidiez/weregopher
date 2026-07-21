//! Conservative grouping of candidate evidence from independent sources.

use weregopher_domain::{CandidateInstallationEvidence, CandidateTarget};

use crate::DiscoveryError;

const MAX_CORRELATION_INPUTS: usize = 64;

/// Runs every bounded current-user Windows discovery source and groups exact
/// target/root matches without merging their provenance-bound records.
///
/// # Errors
///
/// Returns the first source or correlation error encountered. Off Windows,
/// returns [`DiscoveryError::UnsupportedPlatform`].
#[cfg(windows)]
pub fn discover_current_user_candidate_evidence()
-> Result<Vec<CandidateEvidenceGroup>, DiscoveryError> {
    let mut evidence = crate::discover_current_user_known_locations()?;
    evidence.extend(crate::discover_windows_uninstall_registry()?);
    evidence.extend(crate::discover_windows_package_catalog()?);
    correlate_candidate_evidence(evidence)
}

/// Reports that aggregate Windows candidate discovery is unavailable on this
/// platform.
///
/// # Errors
///
/// Always returns [`DiscoveryError::UnsupportedPlatform`].
#[cfg(not(windows))]
pub fn discover_current_user_candidate_evidence()
-> Result<Vec<CandidateEvidenceGroup>, DiscoveryError> {
    Err(DiscoveryError::UnsupportedPlatform)
}

/// Evidence records that identify the same target at the same lexical Windows
/// root while retaining every distinct source observation.
///
/// The grouping key is an internal comparison aid, not a canonical path,
/// filesystem identity, authorization claim, or compatibility verdict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateEvidenceGroup {
    target: CandidateTarget,
    comparison_root: String,
    observations: Vec<CandidateInstallationEvidence>,
}

impl CandidateEvidenceGroup {
    /// Candidate target shared by every retained observation.
    #[must_use]
    pub const fn target(&self) -> CandidateTarget {
        self.target
    }

    /// Distinct source records retained in deterministic order.
    #[must_use]
    pub fn observations(&self) -> &[CandidateInstallationEvidence] {
        &self.observations
    }
}

/// Groups at most 64 candidate-evidence records by target and conservative
/// lexical Windows-root equivalence.
///
/// Exact duplicate records are removed. Distinct records are never merged:
/// each field remains attached to its original confidence and source.
/// Comparison folds ASCII case, treats slash styles equally, and ignores only
/// trailing separators. It deliberately does not resolve `.` or `..`, follow
/// links, access the filesystem, or claim that different roots are equivalent.
///
/// # Errors
///
/// Returns [`DiscoveryError::CorrelationInputLimit`] when more than 64 records
/// are supplied.
pub fn correlate_candidate_evidence(
    evidence: impl IntoIterator<Item = CandidateInstallationEvidence>,
) -> Result<Vec<CandidateEvidenceGroup>, DiscoveryError> {
    let mut evidence_records = Vec::new();
    for record in evidence {
        if evidence_records.len() >= MAX_CORRELATION_INPUTS {
            return Err(DiscoveryError::CorrelationInputLimit {
                limit: MAX_CORRELATION_INPUTS,
            });
        }
        evidence_records.push(record);
    }

    evidence_records.sort_by_cached_key(evidence_sort_key);
    evidence_records.dedup();

    let mut groups: Vec<CandidateEvidenceGroup> = Vec::new();
    for record in evidence_records {
        let comparison_root = windows_root_comparison_key(&record.root_path.value);
        let target = record.target;
        if let Some(group) = groups.last_mut()
            && group.target == target
            && group.comparison_root == comparison_root
        {
            group.observations.push(record);
            continue;
        }
        groups.push(CandidateEvidenceGroup {
            target,
            comparison_root,
            observations: vec![record],
        });
    }
    Ok(groups)
}

fn evidence_sort_key(evidence: &CandidateInstallationEvidence) -> (u8, String, String) {
    (
        target_rank(evidence.target),
        windows_root_comparison_key(&evidence.root_path.value),
        format!("{evidence:?}"),
    )
}

const fn target_rank(target: CandidateTarget) -> u8 {
    match target {
        CandidateTarget::Codex => 0,
        CandidateTarget::HermesAgent => 1,
        CandidateTarget::Discord => 2,
        CandidateTarget::VisualStudioCode => 3,
    }
}

fn windows_root_comparison_key(value: &str) -> String {
    let normalized_separators = value.replace('/', "\\");
    let bytes = normalized_separators.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2..].iter().all(|byte| *byte == b'\\')
    {
        return format!("{}:\\", char::from(bytes[0]).to_ascii_lowercase());
    }
    normalized_separators
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}
