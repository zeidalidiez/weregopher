//! Native Windows G2 isolated-world and page projection fixture.

#![cfg(windows)]

use std::{sync::Arc, time::Duration};

use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use weregopher_domain::{
    AppInstanceId, G2ProbeScope, PreloadBridgeChecks, PreloadBridgeProbeReport, RendererId,
    Sha256Digest,
};
use weregopher_renderer::{
    ImmutablePackage, PackageAsset, PackageOrigin, PackageOriginLimits, PrivateOrigin,
    RendererLifecycleState,
};
use weregopher_renderer_webview2::WebView2Fixture;

const FIXTURE_TIMEOUT: Duration = Duration::from_secs(20);
const ISOLATED_WORLD_NAME: &str = "weregopher.g2.preload";
const PRELOAD_SOURCE: &str = include_str!("fixtures/g2/preload.js");
const MAIN_BOOTSTRAP_SOURCE: &str = include_str!("fixtures/g2/main-bootstrap.js");

fn app_id() -> AppInstanceId {
    AppInstanceId::from_uuid(Uuid::from_u128(22))
}

fn package_origin() -> Result<PackageOrigin, Box<dyn std::error::Error>> {
    let limits = PackageOriginLimits::g1_fixture();
    let package = ImmutablePackage::new(
        vec![
            PackageAsset::new(
                "index.html",
                Arc::<[u8]>::from(include_bytes!("fixtures/g2/index.html").as_slice()),
                &limits,
            )?,
            PackageAsset::new(
                "main.js",
                Arc::<[u8]>::from(include_bytes!("fixtures/g2/main.js").as_slice()),
                &limits,
            )?,
        ],
        limits,
    )?;
    Ok(PackageOrigin::new(
        PrivateOrigin::for_app(app_id()),
        package,
    ))
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum FixtureObservation {
    G2PreloadObservation {
        generation: u32,
        round_trip_value: String,
        checks: PreloadBridgeChecks,
    },
    G2PreloadFailure {
        message: String,
    },
}

fn observation(
    fixture: &WebView2Fixture,
) -> Result<(u32, String, PreloadBridgeChecks), Box<dyn std::error::Error>> {
    let message = fixture.wait_for_message(FIXTURE_TIMEOUT)?;
    match serde_json::from_str::<FixtureObservation>(message.json())? {
        FixtureObservation::G2PreloadObservation {
            generation,
            round_trip_value,
            checks,
        } => Ok((generation, round_trip_value, checks)),
        FixtureObservation::G2PreloadFailure { message } => {
            Err(format!("G2 preload fixture failed: {message}").into())
        }
    }
}

#[test]
fn isolated_preload_projects_frozen_api_and_invalidates_navigation()
-> Result<(), Box<dyn std::error::Error>> {
    let package = package_origin()?;
    let entry_url = package.origin().entry_url("index.html")?;
    let mut fixture = WebView2Fixture::create(package, RendererId::new(22))?;
    fixture.install_isolated_world_document_start_script(ISOLATED_WORLD_NAME, PRELOAD_SOURCE)?;
    fixture.install_main_world_document_start_script(MAIN_BOOTSTRAP_SOURCE)?;

    let first_generation = fixture.navigate(&entry_url, FIXTURE_TIMEOUT)?;
    let (first_observed_generation, first_value, first_checks) = observation(&fixture)?;
    assert_eq!(first_generation.get(), 1);
    assert_eq!(first_observed_generation, 1);
    assert_eq!(first_value, "isolated:from-page");
    assert!(first_checks.document_start);
    assert!(first_checks.isolated_globals);
    assert!(first_checks.prototype_isolation);
    assert!(first_checks.frozen_projection);
    assert!(first_checks.function_round_trip);
    assert!(!first_checks.navigation_invalidation);

    let second_generation = fixture.navigate(&entry_url, FIXTURE_TIMEOUT)?;
    let (second_observed_generation, second_value, second_checks) = observation(&fixture)?;
    assert_eq!(second_generation.get(), 2);
    assert_eq!(second_observed_generation, 2);
    assert_eq!(second_value, "isolated:from-page");

    let report = PreloadBridgeProbeReport::new(
        digest(b"synthetic-g2-build"),
        digest(PRELOAD_SOURCE.as_bytes()),
        digest(b"weregopher-renderer-webview2"),
        fixture.browser_version(),
        G2ProbeScope::SyntheticFixture,
        second_checks,
    )?;
    assert!(report.checks_pass());
    assert!(!report.is_exact_package_evidence());
    assert_eq!(fixture.lifecycle_state(), RendererLifecycleState::Loaded);

    let shutdown = fixture.close(FIXTURE_TIMEOUT)?;
    assert!(shutdown.browser_process_exited());
    assert!(shutdown.user_data_removed());
    assert_eq!(shutdown.final_state(), RendererLifecycleState::Closed);
    Ok(())
}
