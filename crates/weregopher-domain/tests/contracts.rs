//! Canonical identity, digest, build, security, and certification contract tests.

use std::str::FromStr;

use serde_json::json;
use weregopher_domain::{
    ApplicationFamilyId, Architecture, BuildFingerprint, CertificationClass,
    EffectiveSecurityPosture, InstallationKind, Sha256Digest,
};

#[test]
fn application_family_ids_are_nonempty_canonical_names() {
    assert!(ApplicationFamilyId::new("openai.chatgpt").is_ok());
    assert!(ApplicationFamilyId::new("").is_err());
    assert!(ApplicationFamilyId::new(" openai.chatgpt").is_err());
    assert!(ApplicationFamilyId::new("OpenAI.ChatGPT").is_err());
    assert!(ApplicationFamilyId::new("openai/chatgpt").is_err());
}

#[test]
fn sha256_digest_uses_prefixed_lowercase_hex() -> Result<(), Box<dyn std::error::Error>> {
    let digest = Sha256Digest::from_bytes([0xab; 32]);
    let text = format!("sha256:{}", "ab".repeat(32));

    assert_eq!(digest.to_string(), text);
    assert_eq!(Sha256Digest::from_str(&text)?, digest);
    assert_eq!(serde_json::to_string(&digest)?, format!("\"{text}\""));
    assert_eq!(
        serde_json::from_str::<Sha256Digest>(&format!("\"{text}\""))?,
        digest
    );

    assert!(Sha256Digest::from_str(&"ab".repeat(32)).is_err());
    assert!(Sha256Digest::from_str("sha256:abcd").is_err());
    assert!(Sha256Digest::from_str(&format!("sha256:{}", "AB".repeat(32))).is_err());
    Ok(())
}

#[test]
fn build_fingerprint_serializes_the_canonical_field_names() -> Result<(), Box<dyn std::error::Error>>
{
    let family = ApplicationFamilyId::new("openai.chatgpt")?;
    let fingerprint = BuildFingerprint::minimal(
        family,
        InstallationKind::Msix,
        Architecture::X86_64,
        Sha256Digest::from_bytes([0x11; 32]),
    );
    let value = serde_json::to_value(fingerprint)?;

    assert_eq!(value["family"], json!("openai.chatgpt"));
    assert_eq!(value["installation_kind"], json!("msix"));
    assert_eq!(value["architecture"], json!("x86_64"));
    assert_eq!(
        value["package_tree_merkle"],
        json!(format!("sha256:{}", "11".repeat(32)))
    );
    assert!(value.get("package_merkle_root").is_none());
    assert!(value.get("package_family").is_none());
    assert!(value.get("renderer_merkle").is_some());
    Ok(())
}

#[test]
fn security_certification_and_publication_concepts_do_not_collapse()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        serde_json::to_value(EffectiveSecurityPosture::VendorEquivalentFullTrust)?,
        json!("vendor_equivalent_full_trust")
    );
    assert_eq!(
        serde_json::to_value(CertificationClass::SmokeVerified)?,
        json!("smoke_verified")
    );
    assert_ne!(
        CertificationClass::SmokeVerified,
        CertificationClass::ContractVerified
    );
    Ok(())
}
