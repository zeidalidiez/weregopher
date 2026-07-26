//! Discord disposable-smoke certification artifact behavior tests.

use serde_json::json;
use sha2::{Digest as _, Sha256};
use weregopher_adapter_discord::{
    DISCORD_SMOKE_CERTIFICATION_REPORT_FORMAT_VERSION, DiscordSmokeCertificationReport,
    DiscordSmokeCertificationReportError, DiscordSmokeRuntimeObservation,
    DiscordSmokeStaticObservation, MAX_DISCORD_SMOKE_CERTIFICATION_REPORT_BYTES,
    SMOKE_MARKER_CONTENT, transform_smoke_source,
};
use weregopher_domain::Sha256Digest;

#[test]
fn certification_report_round_trips_and_binds_exact_smoke_semantics()
-> Result<(), Box<dyn std::error::Error>> {
    let report = fixture_report()?;
    let canonical = report.canonical_json_bytes()?;
    let parsed = DiscordSmokeCertificationReport::from_json_slice(&canonical)?;

    assert_eq!(parsed, report);
    assert_eq!(
        parsed.format_version(),
        DISCORD_SMOKE_CERTIFICATION_REPORT_FORMAT_VERSION
    );
    assert_eq!(
        parsed.canonical_document_digest()?,
        report.canonical_document_digest()?
    );
    assert_eq!(
        parsed.canonical_document_digest()?.as_sha256(),
        &digest(&canonical)
    );
    let golden =
        include_bytes!("fixtures/discord-smoke-certification-report-v1.golden.json").as_slice();
    let golden = golden
        .strip_suffix(b"\n")
        .ok_or("golden fixture must end with exactly one repository newline")?;
    assert_eq!(canonical, golden);
    assert_eq!(
        report.canonical_document_digest()?.to_string(),
        "sha256:c5a244ab795fa2b5e4a1787658cf864a32e828c2693c48a81a1ea7eafd0fdfe2"
    );
    assert_eq!(
        parsed.runtime_observation().marker_sha256(),
        &digest(SMOKE_MARKER_CONTENT.as_bytes())
    );
    assert!(canonical.len() <= MAX_DISCORD_SMOKE_CERTIFICATION_REPORT_BYTES);
    Ok(())
}

#[test]
fn certification_report_rejects_tampered_probe_semantics_and_unbounded_input()
-> Result<(), Box<dyn std::error::Error>> {
    let report = fixture_report()?;
    let mut wrong_marker = serde_json::to_value(&report)?;
    wrong_marker["runtime_observation"]["marker_sha256"] = json!(digest(b"wrong marker"));
    let Err(error) =
        DiscordSmokeCertificationReport::from_json_slice(&serde_json::to_vec(&wrong_marker)?)
    else {
        return Err("tampered marker evidence was accepted".into());
    };
    assert!(matches!(
        error,
        DiscordSmokeCertificationReportError::MarkerMismatch
    ));

    let mut vendor_changed = serde_json::to_value(&report)?;
    vendor_changed["runtime_observation"]["source_app_asar_after_sha256"] =
        json!(digest(b"changed vendor archive"));
    let Err(error) =
        DiscordSmokeCertificationReport::from_json_slice(&serde_json::to_vec(&vendor_changed)?)
    else {
        return Err("changed vendor evidence was accepted".into());
    };
    assert!(matches!(
        error,
        DiscordSmokeCertificationReportError::VendorSourceChanged
    ));

    let mut unknown_field = serde_json::to_value(&report)?;
    unknown_field["runtime_observation"]["unreviewed"] = json!(true);
    assert!(matches!(
        DiscordSmokeCertificationReport::from_json_slice(&serde_json::to_vec(&unknown_field)?),
        Err(DiscordSmokeCertificationReportError::InvalidDocument(_))
    ));

    let oversized = vec![b' '; MAX_DISCORD_SMOKE_CERTIFICATION_REPORT_BYTES + 1];
    assert!(matches!(
        DiscordSmokeCertificationReport::from_json_slice(&oversized),
        Err(DiscordSmokeCertificationReportError::DocumentTooLarge)
    ));
    Ok(())
}

#[test]
fn static_observation_requires_the_exact_adapter_transform()
-> Result<(), Box<dyn std::error::Error>> {
    let package = br#"{"name":"discord","main":"bundle.js"}"#;
    let source = b"(()=>{console.log('discord')})();";
    let transformed = transform_smoke_source(package, source)?;
    let Err(error) = DiscordSmokeStaticObservation::from_transform(
        digest(b"source archive"),
        digest(b"transformed archive"),
        package,
        source,
        b"not the adapter output",
    ) else {
        return Err("mismatched transformed source was accepted".into());
    };
    assert!(matches!(
        error,
        DiscordSmokeCertificationReportError::TransformOutputMismatch
    ));

    DiscordSmokeStaticObservation::from_transform(
        digest(b"source archive"),
        digest(b"transformed archive"),
        package,
        source,
        &transformed,
    )?;
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
