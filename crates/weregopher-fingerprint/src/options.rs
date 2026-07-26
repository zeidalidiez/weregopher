//! Explicit package-tree scan policy.

use thiserror::Error;

/// Conservative upper bound used unless the caller supplies a lower value.
pub const DEFAULT_MAX_ENTRIES: usize = 1_000_000;

/// Bounded policy for a complete package fingerprint scan.
///
/// Selective exclusions are deliberately unavailable until a signed mutable-path
/// policy can prove that omitted paths cannot contain executable or identity-bearing
/// package content. The caller-selected aggregate entry limit is additional to the
/// fixed format-v1 record, normalized-path, and aggregate path-byte ceilings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FingerprintOptions {
    pub(crate) max_entries: usize,
}

impl FingerprintOptions {
    /// Replaces the complete-tree aggregate entry budget. Zero is rejected.
    ///
    /// A larger value does not relax the canonical manifest ceilings. Scanning
    /// still rejects more than 65,536 file/link records, paths deeper than 256
    /// components or longer than 32,767 scalars, and aggregate normalized entry
    /// paths larger than 16 MiB.
    ///
    /// # Errors
    ///
    /// Returns [`FingerprintOptionsError::ZeroEntryLimit`] for a zero budget.
    pub fn with_max_entries(mut self, max_entries: usize) -> Result<Self, FingerprintOptionsError> {
        if max_entries == 0 {
            return Err(FingerprintOptionsError::ZeroEntryLimit);
        }
        self.max_entries = max_entries;
        Ok(self)
    }
}

impl Default for FingerprintOptions {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }
}

/// Invalid caller-supplied fingerprint policy.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FingerprintOptionsError {
    /// A zero budget cannot scan a package.
    #[error("fingerprint entry limit must be greater than zero")]
    ZeroEntryLimit,
}
