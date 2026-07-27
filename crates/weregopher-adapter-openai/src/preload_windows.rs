//! Native Windows execution of one prepared exact package-derived preload.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use serde::Deserialize;
use thiserror::Error;
use uuid::Uuid;
use weregopher_domain::{
    AppInstanceId, G2ContractError, G2ProbeScope, PreloadBridgeChecks, PreloadBridgeProbeReport,
    RendererId, Sha256Digest,
};
use weregopher_renderer::{
    ImmutablePackage, PackageAsset, PackageOrigin, PackageOriginError, PackageOriginLimits,
    PrivateOrigin,
};
use weregopher_renderer_webview2::{WebView2Fixture, WebView2FixtureError};

use crate::{
    ExactPreloadSource,
    preload_probe::{
        PRELOAD_PROBE_INDEX_HTML, PRELOAD_PROBE_MAIN_BOOTSTRAP, PRELOAD_PROBE_MAIN_SOURCE,
        PRELOAD_PROBE_WORLD_NAME, PreloadProbeProgramError, assemble_isolated_world_program,
        renderer_backend_digest,
    },
};

const PROBE_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_OBSERVED_MESSAGES_PER_NAVIGATION: usize = 64;
const PROBE_RENDERER_ID: u64 = 0x4732;
const PROBE_APP_INSTANCE: u128 = 0x813e_5ec7_8c4b_47fb_973f_51a9_4de6_4311;

/// Native exact-preload runner failure that contains no source bytes or raw trace.
#[derive(Debug, Error)]
pub enum ExactPreloadProbeError {
    /// The bounded source could not fit the registered probe program.
    #[error("exact preload source cannot be represented by the bounded probe program")]
    Program,
    /// The immutable synthetic probe origin could not be constructed.
    #[error("failed to construct the exact preload probe origin: {0}")]
    Origin(#[from] PackageOriginError),
    /// The native `WebView2` fixture failed or did not clean up.
    #[error("exact preload WebView2 probe failed: {0}")]
    Renderer(#[from] WebView2FixtureError),
    /// Host-observed JSON did not satisfy the closed probe shape.
    #[error("exact preload probe returned an invalid observation")]
    InvalidObservation,
    /// Too many unrelated `WebView` messages arrived before canonical evidence.
    #[error("exact preload probe exceeded its observed-message limit")]
    TooManyObservedMessages,
    /// The page reported evidence for another navigation generation.
    #[error("exact preload probe returned the wrong navigation generation")]
    NavigationGenerationMismatch,
    /// Canonical report construction rejected backend evidence.
    #[error("exact preload probe report contract failed: {0}")]
    Contract(#[from] G2ContractError),
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ProbeObservation {
    G2ExactPreloadObservation {
        generation: u32,
        checks: PreloadBridgeChecks,
    },
}

/// Executes one revalidated package-derived preload in the bounded `WebView2` bridge probe.
///
/// The exact source runs in a named isolated world against a closed synthetic
/// page and an inert, bounded Electron preload shim. The probe does not run the
/// vendor renderer or main process, does not forward IPC, and does not establish
/// complete Electron or Node compatibility. The returned report is exact only
/// with respect to the package-derived preload bytes bound by
/// [`ExactPreloadSource`].
///
/// # Errors
///
/// Returns [`ExactPreloadProbeError`] for program bounds, immutable-origin,
/// `WebView2`, observation, cleanup, or report-contract failures. JavaScript
/// compatibility failures that remain observable produce a canonical report
/// with failed checks instead of exposing source errors.
pub fn probe_exact_preload(
    preload: &ExactPreloadSource,
) -> Result<PreloadBridgeProbeReport, ExactPreloadProbeError> {
    run_preload_probe(
        preload.source(),
        preload.path().as_str(),
        *preload.source_build_fingerprint_digest(),
        *preload.preload_digest(),
        G2ProbeScope::ExactPackage,
    )
}

fn run_preload_probe(
    source: &str,
    archive_path: &str,
    source_build_fingerprint_digest: Sha256Digest,
    preload_digest: Sha256Digest,
    scope: G2ProbeScope,
) -> Result<PreloadBridgeProbeReport, ExactPreloadProbeError> {
    let isolated_program =
        assemble_isolated_world_program(source, archive_path).map_err(map_program_error)?;
    let (package, entry_url) = probe_origin()?;
    let mut fixture = WebView2Fixture::create(package, RendererId::new(PROBE_RENDERER_ID))?;
    let browser_version = fixture.browser_version().to_owned();
    let probe_result = run_navigations(&mut fixture, &entry_url, &isolated_program);
    let close_result = fixture.close(PROBE_TIMEOUT);
    let checks = probe_result?;
    close_result?;

    Ok(PreloadBridgeProbeReport::new(
        source_build_fingerprint_digest,
        preload_digest,
        renderer_backend_digest(),
        browser_version,
        scope,
        checks,
    )?)
}

fn run_navigations(
    fixture: &mut WebView2Fixture,
    entry_url: &str,
    isolated_program: &str,
) -> Result<PreloadBridgeChecks, ExactPreloadProbeError> {
    fixture.install_main_world_document_start_script(PRELOAD_PROBE_MAIN_BOOTSTRAP)?;
    fixture
        .install_isolated_world_document_start_script(PRELOAD_PROBE_WORLD_NAME, isolated_program)?;

    let first_generation = fixture.navigate(entry_url, PROBE_TIMEOUT)?;
    let first = wait_for_observation(fixture, entry_url, first_generation.get(), PROBE_TIMEOUT)?;
    let second_generation = fixture.navigate(entry_url, PROBE_TIMEOUT)?;
    let second = wait_for_observation(fixture, entry_url, second_generation.get(), PROBE_TIMEOUT)?;
    Ok(combine_checks(first, second))
}

fn probe_origin() -> Result<(PackageOrigin, String), PackageOriginError> {
    let limits = PackageOriginLimits::new(2, 128, 1024 * 1024, 2 * 1024 * 1024, 4096)?;
    let package = ImmutablePackage::new(
        vec![
            PackageAsset::new(
                "index.html",
                Arc::<[u8]>::from(PRELOAD_PROBE_INDEX_HTML),
                &limits,
            )?,
            PackageAsset::new(
                "main.js",
                Arc::<[u8]>::from(PRELOAD_PROBE_MAIN_SOURCE),
                &limits,
            )?,
        ],
        limits,
    )?;
    let origin = PrivateOrigin::for_app(AppInstanceId::from_uuid(Uuid::from_u128(
        PROBE_APP_INSTANCE,
    )));
    let entry_url = origin.entry_url("index.html")?;
    Ok((PackageOrigin::new(origin, package), entry_url))
}

fn wait_for_observation(
    fixture: &WebView2Fixture,
    expected_source: &str,
    expected_generation: u32,
    timeout: Duration,
) -> Result<PreloadBridgeChecks, ExactPreloadProbeError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(ExactPreloadProbeError::InvalidObservation)?;
    for _ in 0..MAX_OBSERVED_MESSAGES_PER_NAVIGATION {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(WebView2FixtureError::Timeout {
                operation: "exact preload observation",
            }
            .into());
        }
        let message = fixture.wait_for_message(remaining)?;
        if message.source() != expected_source {
            continue;
        }
        let Ok(observation) = serde_json::from_str::<ProbeObservation>(message.json()) else {
            continue;
        };
        let ProbeObservation::G2ExactPreloadObservation { generation, checks } = observation;
        if generation != expected_generation {
            return Err(ExactPreloadProbeError::NavigationGenerationMismatch);
        }
        return Ok(checks);
    }
    Err(ExactPreloadProbeError::TooManyObservedMessages)
}

const fn combine_checks(
    first: PreloadBridgeChecks,
    second: PreloadBridgeChecks,
) -> PreloadBridgeChecks {
    PreloadBridgeChecks {
        document_start: first.document_start && second.document_start,
        isolated_globals: first.isolated_globals && second.isolated_globals,
        prototype_isolation: first.prototype_isolation && second.prototype_isolation,
        frozen_projection: first.frozen_projection && second.frozen_projection,
        function_round_trip: first.function_round_trip && second.function_round_trip,
        navigation_invalidation: !first.navigation_invalidation && second.navigation_invalidation,
    }
}

const fn map_program_error(_error: PreloadProbeProgramError) -> ExactPreloadProbeError {
    ExactPreloadProbeError::Program
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    #[test]
    fn package_derived_source_runs_without_promoting_fixture_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = r#"
const { contextBridge } = require("electron");
contextBridge.exposeInMainWorld("desktop", {
  version: { major: 1, profile: "package-derived-fixture" },
  echo: value => value,
});
"#;
        let report = run_preload_probe(
            source,
            "preload.js",
            digest(1),
            digest(2),
            G2ProbeScope::SyntheticFixture,
        )?;
        assert!(report.checks_pass());
        assert!(!report.is_exact_package_evidence());
        Ok(())
    }
}
