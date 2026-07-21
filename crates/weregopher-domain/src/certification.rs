//! Certification evidence, publication, and trust classifications.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Strength of compatibility evidence for one environment-bound build contract.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificationClass {
    /// Launch is forbidden by policy or known incompatibility.
    Blocked,
    /// Exploratory evidence only.
    Provisional,
    /// Structural invariants passed without behavioral smoke coverage.
    StructuralVerified,
    /// A fixed disposable-state smoke profile passed.
    SmokeVerified,
    /// The declared family contract profile passed without authority expansion.
    ContractVerified,
    /// The exact build and complete configured feature profile passed certification.
    ExactCertified,
}

/// Where certification or adapter metadata has been published.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationStatus {
    /// Evidence exists only on the local machine.
    LocalOnly,
    /// An unpublished artifact is under review.
    Draft,
    /// The artifact is present in an authenticated registry.
    Published,
    /// A previously published artifact was withdrawn without a security revocation.
    Withdrawn,
}

/// How the current installation chose to trust an adapter artifact.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustMode {
    /// Accepted through the configured registry trust roots.
    RegistryTrusted,
    /// Explicitly trusted by the local user or administrator.
    LocallyTrusted,
    /// Unsigned development artifact under disposable-state restrictions.
    Developer,
    /// Explicit isolated forensic execution of an otherwise blocked artifact.
    ForensicOverride,
}
