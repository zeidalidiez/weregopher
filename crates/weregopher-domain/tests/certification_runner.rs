//! Certification-runner identity contract tests.

use std::io::Cursor;

use serde_json::json;
use weregopher_domain::{
    CERTIFICATION_RUNNER_IDENTITY_FORMAT_VERSION, CertificationElectronRuntimeDigest,
    CertificationExceptionProvenanceDigest, CertificationHostAgentDigest,
    CertificationHostImageDigest, CertificationHostPatchSetDigest,
    CertificationLanguageRuntimeSetDigest, CertificationProbeAssetSetDigest,
    CertificationRunnerArchitecture, CertificationRunnerEnvironmentIdentity,
    CertificationRunnerIdentity, CertificationRunnerIdentityDigest, CertificationRunnerImageDigest,
    CertificationRunnerPlatform, CertificationRunnerProvenanceIdentity,
    CertificationRunnerToolingIdentity, CertificationSourceRevisionDigest,
    CertificationToolchainSetDigest, CertificationVerifierDigest,
    MAX_CERTIFICATION_RUNNER_IDENTITY_DOCUMENT_BYTES, Sha256Digest,
};

#[test]
fn runner_identity_is_exact_canonical_and_content_addressed()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = runner_identity(0x10);

    assert_eq!(
        identity.format_version(),
        CERTIFICATION_RUNNER_IDENTITY_FORMAT_VERSION
    );
    assert_eq!(identity.platform(), CertificationRunnerPlatform::Windows);
    assert_eq!(
        identity.architecture(),
        CertificationRunnerArchitecture::X86_64
    );
    assert_eq!(
        identity.runner_image_digest(),
        CertificationRunnerImageDigest::new(digest(0x10))
    );
    assert_eq!(
        identity.host_image_digest(),
        CertificationHostImageDigest::new(digest(0x11))
    );
    assert_eq!(
        identity.host_patch_set_digest(),
        CertificationHostPatchSetDigest::new(digest(0x12))
    );
    assert_eq!(
        identity.electron_runtime_digest(),
        CertificationElectronRuntimeDigest::new(digest(0x13))
    );
    assert_eq!(
        identity.language_runtime_set_digest(),
        CertificationLanguageRuntimeSetDigest::new(digest(0x14))
    );
    assert_eq!(
        identity.toolchain_set_digest(),
        CertificationToolchainSetDigest::new(digest(0x15))
    );
    assert_eq!(
        identity.host_agent_digest(),
        CertificationHostAgentDigest::new(digest(0x16))
    );
    assert_eq!(
        identity.verifier_digest(),
        CertificationVerifierDigest::new(digest(0x17))
    );
    assert_eq!(
        identity.probe_asset_set_digest(),
        CertificationProbeAssetSetDigest::new(digest(0x18))
    );
    assert_eq!(
        identity.source_revision_digest(),
        CertificationSourceRevisionDigest::new(digest(0x19))
    );
    assert_eq!(
        identity.exception_provenance_digest(),
        CertificationExceptionProvenanceDigest::new(digest(0x1a))
    );

    let canonical = identity.canonical_json_bytes()?;
    assert_eq!(
        canonical,
        include_bytes!("fixtures/certification-runner-identity-v1.golden.json")
    );
    let content_digest: CertificationRunnerIdentityDigest = identity.canonical_document_digest()?;
    assert_eq!(
        content_digest.to_string(),
        "sha256:b68268114751079bf85d12b5fe38b23c870c56927d41ef1b584872cc946672a1"
    );
    assert_eq!(
        CertificationRunnerIdentity::from_json_slice(&canonical)?,
        identity
    );
    assert_eq!(
        CertificationRunnerIdentity::from_json_reader(Cursor::new(&canonical))?,
        identity
    );

    let changed = runner_identity(0x20);
    assert_ne!(
        identity.canonical_document_digest()?,
        changed.canonical_document_digest()?
    );
    Ok(())
}

#[test]
fn runner_identity_parser_is_closed_and_bounded_before_deserialization()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = runner_identity(0x10);
    let canonical = identity.canonical_json_bytes()?;

    let mut exact_limit = canonical.clone();
    exact_limit.resize(MAX_CERTIFICATION_RUNNER_IDENTITY_DOCUMENT_BYTES, b' ');
    assert_eq!(
        CertificationRunnerIdentity::from_json_slice(&exact_limit)?,
        identity
    );
    assert_eq!(
        CertificationRunnerIdentity::from_json_reader(Cursor::new(&exact_limit))?,
        identity
    );

    exact_limit.push(b' ');
    assert!(CertificationRunnerIdentity::from_json_slice(&exact_limit).is_err());
    assert!(CertificationRunnerIdentity::from_json_reader(Cursor::new(&exact_limit)).is_err());

    let mut unknown: serde_json::Value = serde_json::from_slice(&canonical)?;
    unknown["authority"] = json!(true);
    assert!(CertificationRunnerIdentity::from_json_slice(&serde_json::to_vec(&unknown)?).is_err());

    let mut unsupported: serde_json::Value = serde_json::from_slice(&canonical)?;
    unsupported["format_version"] = json!("2");
    assert!(
        CertificationRunnerIdentity::from_json_slice(&serde_json::to_vec(&unsupported)?).is_err()
    );

    let mut missing: serde_json::Value = serde_json::from_slice(&canonical)?;
    missing["tooling"]
        .as_object_mut()
        .ok_or("runner tooling fixture must be an object")?
        .remove("verifier_digest");
    assert!(CertificationRunnerIdentity::from_json_slice(&serde_json::to_vec(&missing)?).is_err());
    Ok(())
}

fn runner_identity(base: u8) -> CertificationRunnerIdentity {
    CertificationRunnerIdentity::new(
        CertificationRunnerEnvironmentIdentity::windows_x86_64(
            CertificationRunnerImageDigest::new(digest(base)),
            CertificationHostImageDigest::new(digest(base.wrapping_add(1))),
            CertificationHostPatchSetDigest::new(digest(base.wrapping_add(2))),
            CertificationElectronRuntimeDigest::new(digest(base.wrapping_add(3))),
            CertificationLanguageRuntimeSetDigest::new(digest(base.wrapping_add(4))),
        ),
        CertificationRunnerToolingIdentity::new(
            CertificationToolchainSetDigest::new(digest(base.wrapping_add(5))),
            CertificationHostAgentDigest::new(digest(base.wrapping_add(6))),
            CertificationVerifierDigest::new(digest(base.wrapping_add(7))),
            CertificationProbeAssetSetDigest::new(digest(base.wrapping_add(8))),
        ),
        CertificationRunnerProvenanceIdentity::new(
            CertificationSourceRevisionDigest::new(digest(base.wrapping_add(9))),
            CertificationExceptionProvenanceDigest::new(digest(base.wrapping_add(10))),
        ),
    )
}

const fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}
