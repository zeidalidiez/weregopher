//! Discord smoke-report analysis and local certification resolution.

#![cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "the concrete certification flow is wired to the Windows-only live smoke boundary"
    )
)]

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use weregopher_adapter_discord::{
    DISCORD_SMOKE_WORKFLOW_ID, DiscordSmokeCertificationReport,
    DiscordSmokeCertificationReportDigest, MAX_DISCORD_SMOKE_CERTIFICATION_REPORT_BYTES,
};
use weregopher_domain::{
    CertificationArtifactDigest, CertificationArtifactKind, CertificationArtifactRef,
    CertificationCheckAssessment, CertificationCheckStatus, CertificationChecks,
    CertificationClass, CertificationContractError, CertificationEvidence,
    CertificationEvidenceDigest, CertificationExpectedStatus, CertificationProfile,
    CertificationProfileChecks, CertificationProfileClass, CertificationProfileDigest,
    CertificationProfileValidationError, CertificationTarget, CompatibilityAnalysis,
    CompatibilityAnalysisDigest, CompatibilityContractError, CompatibilityDimensions,
    CompatibilityEvidenceKind, CompatibilityEvidenceRef, CompatibilityTarget, DimensionAssessment,
    DimensionStatus, ExecutableDigest, ExecutionArtifactSourceDigest, ExecutionContractDigest,
    ExecutionResolutionEvidenceDigest, FeatureId, IdentifierError, PublicationStatus, Sha256Digest,
};
use weregopher_transform::{
    CertificationArtifactSetDigest, CertificationArtifactVerificationError,
    CertificationArtifactVerificationLimits, CertificationPolicyError,
    CertificationPolicyRevisionDigest, CertificationPublicationError, LocalCertificationPolicy,
    LocalCertificationPolicyStore, LocalCertificationPublicationStore, assign_local_certification,
    prepare_local_certification_publication, publish_local_certification,
    verify_certification_artifacts,
};

const ARTIFACT_LIMIT_MULTIPLIER: usize = 16;

/// Deterministically derived generic certification documents for one semantic smoke report.
pub(crate) struct DiscordSmokeCertificationBundle {
    report_digest: DiscordSmokeCertificationReportDigest,
    report_bytes: Vec<u8>,
    compatibility_analysis: CompatibilityAnalysis,
    certification_profile: CertificationProfile,
    certification_evidence: CertificationEvidence,
}

impl DiscordSmokeCertificationBundle {
    /// Returns the exact candidate-report identity.
    pub(crate) const fn report_digest(&self) -> DiscordSmokeCertificationReportDigest {
        self.report_digest
    }

    /// Returns the exact-target compatibility analysis.
    #[cfg(test)]
    pub(crate) const fn compatibility_analysis(&self) -> &CompatibilityAnalysis {
        &self.compatibility_analysis
    }

    /// Returns the immutable smoke certification profile.
    #[cfg(test)]
    pub(crate) const fn certification_profile(&self) -> &CertificationProfile {
        &self.certification_profile
    }

    /// Returns the non-authorizing exact-target certification evidence.
    #[cfg(test)]
    pub(crate) const fn certification_evidence(&self) -> &CertificationEvidence {
        &self.certification_evidence
    }

    pub(crate) fn compatibility_analysis_digest(
        &self,
    ) -> serde_json::Result<CompatibilityAnalysisDigest> {
        canonical_digest(&self.compatibility_analysis).map(CompatibilityAnalysisDigest::new)
    }

    pub(crate) fn certification_profile_digest(
        &self,
    ) -> serde_json::Result<CertificationProfileDigest> {
        self.certification_profile.canonical_document_digest()
    }

    pub(crate) fn certification_evidence_digest(
        &self,
    ) -> serde_json::Result<CertificationEvidenceDigest> {
        self.certification_evidence.canonical_document_digest()
    }
}

/// Copyable summary of one locally trusted, locally published smoke decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DiscordSmokeLocalCertificationDecision {
    report_digest: DiscordSmokeCertificationReportDigest,
    compatibility_analysis_digest: CompatibilityAnalysisDigest,
    profile_digest: CertificationProfileDigest,
    evidence_digest: CertificationEvidenceDigest,
    artifact_set_digest: CertificationArtifactSetDigest,
    policy_revision_digest: CertificationPolicyRevisionDigest,
    class: CertificationClass,
    publication_status: PublicationStatus,
    policy_generation: u64,
    artifact_count: usize,
    total_artifact_bytes: usize,
}

impl DiscordSmokeLocalCertificationDecision {
    pub(crate) const fn report_digest(&self) -> DiscordSmokeCertificationReportDigest {
        self.report_digest
    }

    pub(crate) const fn compatibility_analysis_digest(&self) -> CompatibilityAnalysisDigest {
        self.compatibility_analysis_digest
    }

    pub(crate) const fn profile_digest(&self) -> CertificationProfileDigest {
        self.profile_digest
    }

    pub(crate) const fn evidence_digest(&self) -> CertificationEvidenceDigest {
        self.evidence_digest
    }

    pub(crate) const fn artifact_set_digest(&self) -> CertificationArtifactSetDigest {
        self.artifact_set_digest
    }

    pub(crate) const fn policy_revision_digest(&self) -> CertificationPolicyRevisionDigest {
        self.policy_revision_digest
    }

    pub(crate) const fn class(&self) -> CertificationClass {
        self.class
    }

    pub(crate) const fn publication_status(&self) -> PublicationStatus {
        self.publication_status
    }

    pub(crate) const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    pub(crate) const fn artifact_count(&self) -> usize {
        self.artifact_count
    }

    pub(crate) const fn total_artifact_bytes(&self) -> usize {
        self.total_artifact_bytes
    }
}

/// Builds exact-target compatibility and certification documents from one validated report.
pub(crate) fn build_discord_smoke_certification(
    report: &DiscordSmokeCertificationReport,
) -> Result<DiscordSmokeCertificationBundle, DiscordSmokeCertificationError> {
    let report_bytes = report.canonical_json_bytes()?;
    let report_digest = report.canonical_document_digest()?;
    let artifact_digest = digest(&report_bytes);
    let workflow = FeatureId::new(DISCORD_SMOKE_WORKFLOW_ID)?;
    let compatibility_analysis =
        build_compatibility_analysis(report, artifact_digest, workflow.clone())?;
    let certification_profile = build_certification_profile(workflow.clone())?;
    let profile_digest = certification_profile.canonical_document_digest()?;
    let certification_evidence = build_certification_evidence(
        report,
        &compatibility_analysis,
        profile_digest,
        artifact_digest,
        workflow,
    )?;
    Ok(DiscordSmokeCertificationBundle {
        report_digest,
        report_bytes,
        compatibility_analysis,
        certification_profile,
        certification_evidence,
    })
}

/// Assigns and atomically publishes local smoke trust only for an operator-pinned exact report.
pub(crate) fn approve_discord_smoke_certification(
    report: &DiscordSmokeCertificationReport,
    expected_report_digest: Sha256Digest,
    policy_revision_digest: Sha256Digest,
) -> Result<DiscordSmokeLocalCertificationDecision, DiscordSmokeCertificationError> {
    let bundle = build_discord_smoke_certification(report)?;
    let actual_report_digest = *bundle.report_digest.as_sha256();
    if actual_report_digest != expected_report_digest {
        return Err(DiscordSmokeCertificationError::ReportDigestMismatch {
            expected: expected_report_digest,
            actual: actual_report_digest,
        });
    }
    resolve_local_decision(bundle, policy_revision_digest)
}

fn build_compatibility_analysis(
    report: &DiscordSmokeCertificationReport,
    artifact_digest: Sha256Digest,
    workflow: FeatureId,
) -> Result<CompatibilityAnalysis, DiscordSmokeCertificationError> {
    let scoped_not_applicable = compatibility_assessment(
        DimensionStatus::NotApplicable,
        CompatibilityEvidenceKind::StaticAnalysis,
        artifact_digest,
    )?;
    let runtime = compatibility_assessment(
        DimensionStatus::Satisfied,
        CompatibilityEvidenceKind::RuntimeProbe,
        artifact_digest,
    )?;
    let dimensions = CompatibilityDimensions {
        package: compatibility_assessment(
            DimensionStatus::Satisfied,
            CompatibilityEvidenceKind::PackageManifest,
            artifact_digest,
        )?,
        main_runtime: runtime.clone(),
        renderer: scoped_not_applicable.clone(),
        preload: scoped_not_applicable.clone(),
        electron_api: scoped_not_applicable.clone(),
        node_api: runtime,
        native_modules: scoped_not_applicable.clone(),
        helpers: scoped_not_applicable,
        state: compatibility_assessment(
            DimensionStatus::Satisfied,
            CompatibilityEvidenceKind::StateProbe,
            artifact_digest,
        )?,
        security: compatibility_assessment(
            DimensionStatus::Satisfied,
            CompatibilityEvidenceKind::SecurityProbe,
            artifact_digest,
        )?,
    };
    let workflows = BTreeMap::from([(
        workflow,
        compatibility_assessment(
            DimensionStatus::Satisfied,
            CompatibilityEvidenceKind::WorkflowProbe,
            artifact_digest,
        )?,
    )]);
    Ok(CompatibilityAnalysis::new(
        report.source_build_fingerprint_digest(),
        CompatibilityTarget::windows_x64(
            *report.static_observation().adapter_contract_digest(),
            report.main_runtime_contract_digest(),
            report.renderer_scope_contract_digest(),
            report.execution_environment_digest(),
        ),
        dimensions,
        workflows,
    )?)
}

fn build_certification_profile(
    workflow: FeatureId,
) -> Result<CertificationProfile, DiscordSmokeCertificationError> {
    Ok(CertificationProfile::new(
        CertificationProfileClass::SmokeVerified,
        CertificationProfileChecks {
            package_identity: CertificationExpectedStatus::Passed,
            entry_point_resolution: CertificationExpectedStatus::Passed,
            transform_matches: CertificationExpectedStatus::Passed,
            module_graph: CertificationExpectedStatus::NotApplicable,
            native_dependencies: CertificationExpectedStatus::NotApplicable,
            runtime_bootstrap: CertificationExpectedStatus::Passed,
            renderer_bootstrap: CertificationExpectedStatus::NotApplicable,
            preload_handshake: CertificationExpectedStatus::NotApplicable,
            state_safety: CertificationExpectedStatus::Passed,
            helper_lifecycle: CertificationExpectedStatus::NotApplicable,
            security_contract: CertificationExpectedStatus::Passed,
            resource_scenario: CertificationExpectedStatus::Passed,
            declared_exceptions: CertificationExpectedStatus::NotApplicable,
        },
        BTreeSet::from([workflow]),
    )?)
}

fn build_certification_evidence(
    report: &DiscordSmokeCertificationReport,
    compatibility: &CompatibilityAnalysis,
    profile_digest: CertificationProfileDigest,
    artifact_digest: Sha256Digest,
    workflow: FeatureId,
) -> Result<CertificationEvidence, DiscordSmokeCertificationError> {
    let compatibility_digest = CompatibilityAnalysisDigest::new(canonical_digest(compatibility)?);
    let static_analysis = certification_assessment(
        CertificationCheckStatus::NotApplicable,
        CertificationArtifactKind::StaticAnalysis,
        artifact_digest,
    )?;
    let checks = CertificationChecks {
        package_identity: certification_assessment(
            CertificationCheckStatus::Passed,
            CertificationArtifactKind::PackageIdentity,
            artifact_digest,
        )?,
        entry_point_resolution: certification_assessment(
            CertificationCheckStatus::Passed,
            CertificationArtifactKind::StaticAnalysis,
            artifact_digest,
        )?,
        transform_matches: certification_assessment(
            CertificationCheckStatus::Passed,
            CertificationArtifactKind::StaticAnalysis,
            artifact_digest,
        )?,
        module_graph: static_analysis.clone(),
        native_dependencies: static_analysis.clone(),
        runtime_bootstrap: certification_assessment(
            CertificationCheckStatus::Passed,
            CertificationArtifactKind::RuntimeProbe,
            artifact_digest,
        )?,
        renderer_bootstrap: static_analysis.clone(),
        preload_handshake: static_analysis.clone(),
        state_safety: certification_assessment(
            CertificationCheckStatus::Passed,
            CertificationArtifactKind::StateProbe,
            artifact_digest,
        )?,
        helper_lifecycle: static_analysis,
        security_contract: certification_assessment(
            CertificationCheckStatus::Passed,
            CertificationArtifactKind::SecurityProbe,
            artifact_digest,
        )?,
        resource_scenario: certification_assessment(
            CertificationCheckStatus::Passed,
            CertificationArtifactKind::ResourceProbe,
            artifact_digest,
        )?,
        declared_exceptions: certification_assessment(
            CertificationCheckStatus::NotApplicable,
            CertificationArtifactKind::ExceptionVerification,
            artifact_digest,
        )?,
    };
    let workflows = BTreeMap::from([(
        workflow,
        certification_assessment(
            CertificationCheckStatus::Passed,
            CertificationArtifactKind::WorkflowProbe,
            artifact_digest,
        )?,
    )]);
    Ok(CertificationEvidence::new(
        CertificationTarget::new(
            compatibility_digest,
            ExecutionContractDigest::new(report.execution_contract_digest()),
            ExecutionResolutionEvidenceDigest::new(report.execution_resolution_evidence_digest()),
            ExecutionArtifactSourceDigest::new(report.execution_artifact_source_digest()),
            ExecutableDigest::new(*report.runtime_observation().managed_executable_sha256()),
        ),
        profile_digest,
        checks,
        workflows,
    )?)
}

fn resolve_local_decision(
    bundle: DiscordSmokeCertificationBundle,
    policy_revision_digest: Sha256Digest,
) -> Result<DiscordSmokeLocalCertificationDecision, DiscordSmokeCertificationError> {
    let report_digest = bundle.report_digest;
    let compatibility_analysis_digest =
        CompatibilityAnalysisDigest::new(canonical_digest(&bundle.compatibility_analysis)?);
    let profile_digest = bundle.certification_profile.canonical_document_digest()?;
    let evidence_digest = bundle.certification_evidence.canonical_document_digest()?;
    let target = bundle.certification_evidence.target().clone();
    let structural = bundle
        .certification_evidence
        .validate_against_profile(bundle.certification_profile)?;
    let mut artifacts = BTreeMap::new();
    for reference in structural.evidence().artifact_references() {
        artifacts.insert(reference.clone(), bundle.report_bytes.as_slice());
    }
    let aggregate_limit = MAX_DISCORD_SMOKE_CERTIFICATION_REPORT_BYTES
        .checked_mul(ARTIFACT_LIMIT_MULTIPLIER)
        .ok_or(DiscordSmokeCertificationError::ArtifactLimitOverflow)?;
    let verified = verify_certification_artifacts(
        structural,
        &artifacts,
        CertificationArtifactVerificationLimits::new(
            MAX_DISCORD_SMOKE_CERTIFICATION_REPORT_BYTES,
            aggregate_limit,
        )?,
    )?;
    let policy = LocalCertificationPolicy::new(
        target,
        profile_digest,
        evidence_digest,
        CertificationClass::SmokeVerified,
        CertificationPolicyRevisionDigest::new(policy_revision_digest),
    )?;
    let policy_store = LocalCertificationPolicyStore::new(policy);
    let publication_store = LocalCertificationPublicationStore::new(1)?;
    let certified = assign_local_certification(verified, &policy_store)?;
    let class = certified.current_class()?;
    let receipt = publish_local_certification(
        prepare_local_certification_publication(certified)?,
        &publication_store,
    )?;
    Ok(DiscordSmokeLocalCertificationDecision {
        report_digest,
        compatibility_analysis_digest,
        profile_digest,
        evidence_digest,
        artifact_set_digest: receipt.artifact_set_digest(),
        policy_revision_digest: receipt.policy_revision_digest(),
        class,
        publication_status: receipt.publication_status(),
        policy_generation: receipt.policy_generation(),
        artifact_count: receipt.artifact_count(),
        total_artifact_bytes: receipt.total_artifact_bytes(),
    })
}

fn compatibility_assessment(
    status: DimensionStatus,
    kind: CompatibilityEvidenceKind,
    digest: Sha256Digest,
) -> Result<DimensionAssessment, CompatibilityContractError> {
    DimensionAssessment::new(status, [CompatibilityEvidenceRef::new(kind, digest)])
}

fn certification_assessment(
    status: CertificationCheckStatus,
    kind: CertificationArtifactKind,
    digest: Sha256Digest,
) -> Result<CertificationCheckAssessment, CertificationContractError> {
    CertificationCheckAssessment::new(
        status,
        [CertificationArtifactRef::new(
            kind,
            CertificationArtifactDigest::new(digest),
        )],
    )
}

fn canonical_digest(value: &impl serde::Serialize) -> serde_json::Result<Sha256Digest> {
    serde_json::to_vec(value).map(|bytes| digest(&bytes))
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

/// Failure to derive or locally trust the exact Discord smoke certification slice.
#[derive(Debug, Error)]
pub(crate) enum DiscordSmokeCertificationError {
    #[error("Discord smoke report digest mismatch: expected {expected}, got {actual}")]
    ReportDigestMismatch {
        expected: Sha256Digest,
        actual: Sha256Digest,
    },
    #[error("Discord smoke certification artifact limit overflowed")]
    ArtifactLimitOverflow,
    #[error(transparent)]
    Identifier(#[from] IdentifierError),
    #[error(transparent)]
    Compatibility(#[from] CompatibilityContractError),
    #[error(transparent)]
    Certification(#[from] CertificationContractError),
    #[error(transparent)]
    Profile(#[from] CertificationProfileValidationError),
    #[error(transparent)]
    ArtifactVerification(#[from] CertificationArtifactVerificationError),
    #[error(transparent)]
    Policy(#[from] CertificationPolicyError),
    #[error(transparent)]
    Publication(#[from] CertificationPublicationError),
    #[error("failed to serialize canonical Discord smoke certification evidence")]
    Serialization(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};
    use weregopher_adapter_discord::{
        DiscordSmokeCertificationReport, DiscordSmokeRuntimeObservation,
        DiscordSmokeStaticObservation, SMOKE_MARKER_CONTENT, transform_smoke_source,
    };
    use weregopher_domain::{
        AnalysisDisposition, CertificationClass, CertificationEvidenceDisposition,
        CertificationProfileClass, PublicationStatus, Sha256Digest,
    };

    use super::{
        DiscordSmokeCertificationError, approve_discord_smoke_certification,
        build_discord_smoke_certification,
    };

    #[test]
    fn exact_smoke_report_builds_a_complete_locally_trusted_vertical_slice()
    -> Result<(), Box<dyn std::error::Error>> {
        let report = fixture_report()?;
        let report_digest = report.canonical_document_digest()?;
        let bundle = build_discord_smoke_certification(&report)?;

        assert_eq!(
            bundle.compatibility_analysis().disposition(),
            AnalysisDisposition::Complete
        );
        assert_eq!(
            bundle.certification_profile().class(),
            CertificationProfileClass::SmokeVerified
        );
        assert_eq!(
            bundle.certification_evidence().disposition(),
            CertificationEvidenceDisposition::Complete
        );
        let decision = approve_discord_smoke_certification(
            &report,
            *report_digest.as_sha256(),
            digest(b"local policy revision"),
        )?;
        assert_eq!(decision.class(), CertificationClass::SmokeVerified);
        assert_eq!(decision.publication_status(), PublicationStatus::LocalOnly);
        assert_eq!(decision.policy_generation(), 1);
        assert!(decision.artifact_count() >= 1);
        Ok(())
    }

    #[test]
    fn local_trust_requires_the_exact_operator_pinned_report()
    -> Result<(), Box<dyn std::error::Error>> {
        let report = fixture_report()?;

        let Err(error) = approve_discord_smoke_certification(
            &report,
            digest(b"different report"),
            digest(b"local policy revision"),
        ) else {
            return Err("a report outside the operator pin received local trust".into());
        };
        assert!(matches!(
            error,
            DiscordSmokeCertificationError::ReportDigestMismatch { .. }
        ));
        Ok(())
    }

    fn fixture_report() -> Result<DiscordSmokeCertificationReport, Box<dyn std::error::Error>> {
        let package = br#"{"name":"discord","main":"bundle.js"}"#;
        let source = b"(()=>{console.log('discord')})();";
        let transformed = transform_smoke_source(package, source)?;
        let source_app_asar_sha256 = digest(b"source archive");
        let static_observation = DiscordSmokeStaticObservation::from_transform(
            source_app_asar_sha256,
            digest(b"transformed archive"),
            package,
            source,
            &transformed,
        )?;
        let runtime_observation = DiscordSmokeRuntimeObservation::successful(
            digest(b"managed package"),
            digest(b"managed executable"),
            42,
            1_024,
            source_app_asar_sha256,
            SMOKE_MARKER_CONTENT.as_bytes(),
            20,
        )?;
        Ok(DiscordSmokeCertificationReport::new(
            static_observation,
            runtime_observation,
        )?)
    }

    fn digest(bytes: &[u8]) -> Sha256Digest {
        Sha256Digest::from_bytes(Sha256::digest(bytes).into())
    }
}
