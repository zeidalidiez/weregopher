//! Explicit, evidence-only `OpenAI` G2 feasibility command.

#[cfg(windows)]
use std::io::{self, Write as _};

#[cfg(any(windows, test))]
use anyhow::Context as _;
use anyhow::{Result, bail};
#[cfg(any(windows, test))]
use serde::Serialize;
#[cfg(any(windows, test))]
use sha2::{Digest as _, Sha256};
#[cfg(windows)]
use weregopher_domain::{AppServerProbeReport, G2FeasibilityReport};
#[cfg(any(windows, test))]
use weregopher_domain::{
    G2GateEvidence, OpenAiPackageInventory, PreloadBridgeProbeReport, Sha256Digest,
};

use crate::OpenAiFeasibilityArguments;

#[cfg(windows)]
const MAX_PRELOAD_REPORT_BYTES: u64 = 1024 * 1024;

#[cfg(windows)]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct OpenAiFeasibilityOutput {
    package_inventory: OpenAiPackageInventory,
    preload_bridge: Option<PreloadBridgeProbeReport>,
    app_server: Option<AppServerProbeReport>,
    feasibility: G2FeasibilityReport,
}

pub(crate) fn run(arguments: &OpenAiFeasibilityArguments) -> Result<()> {
    run_platform(arguments)
}

#[cfg(not(windows))]
fn run_platform(_arguments: &OpenAiFeasibilityArguments) -> Result<()> {
    bail!("OpenAI installed-package feasibility is supported only on native Windows")
}

#[cfg(windows)]
fn run_platform(arguments: &OpenAiFeasibilityArguments) -> Result<()> {
    use std::{
        fs::{self, File},
        io::Read as _,
        path::{Path, PathBuf},
    };

    use weregopher_adapter_openai::{
        OPENAI_APPLICATION_ARCHIVE_PATH, OPENAI_WINDOWS_FAMILY, analyze_openai_package,
        probe_exact_app_server,
    };
    use weregopher_asar::AsarLimits;
    use weregopher_discovery::discover_windows_package_catalog;
    use weregopher_domain::{
        ApplicationFamilyId, Architecture, BuildFingerprint, CandidateInstallationEvidence,
        CandidateTarget, InstallationKind,
    };
    use weregopher_fingerprint::{FingerprintOptions, PackageFileKind, fingerprint_package};

    if arguments.probe_app_server && !arguments.allow_unrestricted_same_user_probe {
        bail!("--probe-app-server requires --allow-unrestricted-same-user-probe");
    }
    let candidate = select_candidate(
        discover_windows_package_catalog()
            .context("failed to query the bounded current-user package catalog")?,
        arguments.package_full_name.as_deref(),
    )?;
    let package_root = PathBuf::from(&candidate.root_path.value);
    let architecture = candidate
        .architecture
        .as_ref()
        .map(|value| value.value)
        .context("selected OpenAI package has no supported architecture")?;
    if architecture != Architecture::X86_64
        || candidate.installation_kind.value != InstallationKind::Msix
    {
        bail!("selected OpenAI package is not the maintained Windows x64 MSIX target");
    }
    let options = FingerprintOptions::default()
        .with_max_entries(arguments.max_entries)
        .context("invalid --max-entries value")?;
    let package_tree = fingerprint_package(&package_root, &options)
        .context("failed to fingerprint the selected package")?;
    let mut build = BuildFingerprint::minimal(
        ApplicationFamilyId::new(OPENAI_WINDOWS_FAMILY)?,
        candidate.installation_kind.value,
        architecture,
        *package_tree.package_tree_merkle(),
    );
    build.package_identity = Some(
        candidate
            .package_identity
            .as_ref()
            .context("selected OpenAI package has no package identity")?
            .value
            .clone(),
    );
    build.package_version = Some(
        candidate
            .observed_version
            .as_ref()
            .context("selected OpenAI package has no package version")?
            .value
            .clone(),
    );
    build.channel = candidate
        .channel
        .as_ref()
        .map(|channel| channel.value.clone());
    build.app_asar_sha256 = package_tree
        .files()
        .iter()
        .find(|record| {
            record.kind == PackageFileKind::Asar
                && record.normalized_path == OPENAI_APPLICATION_ARCHIVE_PATH
        })
        .map(|record| record.sha256);

    let archive_path = package_root.join(OPENAI_APPLICATION_ARCHIVE_PATH);
    let archive = read_bounded_file(
        &archive_path,
        u64::try_from(AsarLimits::initial().max_archive_bytes())
            .context("ASAR byte limit is not representable")?,
        "application archive",
    )?;
    let inventory = analyze_openai_package(&build, &package_tree, &archive)
        .context("selected OpenAI package did not satisfy the G2 package contract")?;
    let package_gate = G2GateEvidence::passed(canonical_digest(&inventory)?);

    let preload_bridge = arguments
        .preload_report
        .as_deref()
        .map(read_preload_report)
        .transpose()?;
    let preload_gate = preload_gate(&inventory, preload_bridge.as_ref())?;

    let app_server = if arguments.probe_app_server {
        let executable_path = package_root.join(
            inventory
                .app_server()
                .path()
                .as_str()
                .replace('/', std::path::MAIN_SEPARATOR_STR),
        );
        Some(
            probe_exact_app_server(&executable_path, &inventory)
                .context("exact bundled app-server probe failed")?,
        )
    } else {
        None
    };
    let app_server_gate = app_server
        .as_ref()
        .map_or_else(G2GateEvidence::not_run, |report| {
            if report.checks_pass() && report.is_exact_package_evidence() {
                canonical_digest(report).map(G2GateEvidence::passed)
            } else {
                canonical_digest(report).map(G2GateEvidence::failed)
            }
        })?;
    let feasibility = G2FeasibilityReport::new(
        *inventory.source_build_fingerprint_digest(),
        package_gate,
        preload_gate,
        app_server_gate,
    );
    write_output(&OpenAiFeasibilityOutput {
        package_inventory: inventory,
        preload_bridge,
        app_server,
        feasibility,
    })?;

    fn select_candidate(
        candidates: Vec<CandidateInstallationEvidence>,
        selected_full_name: Option<&str>,
    ) -> Result<CandidateInstallationEvidence> {
        if selected_full_name.is_some_and(|value| {
            value.is_empty() || value.len() > 32_768 || value.chars().any(char::is_control)
        }) {
            bail!("--package-full-name is empty, oversized, or contains controls");
        }
        let mut candidates = candidates
            .into_iter()
            .filter(|candidate| candidate.target == CandidateTarget::Codex)
            .filter(|candidate| {
                selected_full_name.is_none_or(|selected| {
                    candidate
                        .package_identity
                        .as_ref()
                        .is_some_and(|identity| identity.value.package_full_name == selected)
                })
            })
            .collect::<Vec<_>>();
        match candidates.len() {
            0 => bail!("no matching registered OpenAI package was found"),
            1 => Ok(candidates.remove(0)),
            _ => bail!("multiple registered OpenAI packages matched; supply --package-full-name"),
        }
    }

    fn read_bounded_file(path: &Path, maximum: u64, label: &'static str) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        File::open(path)
            .with_context(|| format!("failed to open {label}"))?
            .take(maximum.saturating_add(1))
            .read_to_end(&mut bytes)
            .with_context(|| format!("failed to read {label}"))?;
        if u64::try_from(bytes.len()).context("file length is not representable")? > maximum {
            bail!("{label} exceeds its byte limit");
        }
        Ok(bytes)
    }

    fn read_preload_report(path: &Path) -> Result<PreloadBridgeProbeReport> {
        let bytes = read_bounded_file(path, MAX_PRELOAD_REPORT_BYTES, "preload probe report")?;
        serde_json::from_slice(&bytes)
            .context("preload probe report does not satisfy its canonical contract")
    }

    Ok(())
}

#[cfg(any(windows, test))]
fn preload_gate(
    inventory: &OpenAiPackageInventory,
    report: Option<&PreloadBridgeProbeReport>,
) -> Result<G2GateEvidence> {
    let Some(report) = report else {
        return Ok(G2GateEvidence::not_run());
    };
    if report.source_build_fingerprint_digest() != inventory.source_build_fingerprint_digest()
        || !inventory
            .preload_candidates()
            .iter()
            .any(|candidate| candidate.sha256() == report.preload_digest())
        || !report.is_exact_package_evidence()
    {
        bail!("preload probe report is not bound to this exact package candidate");
    }
    let digest = canonical_digest(report)?;
    Ok(if report.checks_pass() {
        G2GateEvidence::passed(digest)
    } else {
        G2GateEvidence::failed(digest)
    })
}

#[cfg(any(windows, test))]
fn canonical_digest<T: Serialize>(value: &T) -> Result<Sha256Digest> {
    let bytes = serde_json::to_vec(value).context("failed to serialize canonical G2 evidence")?;
    Ok(Sha256Digest::from_bytes(Sha256::digest(bytes).into()))
}

#[cfg(windows)]
fn write_output(output: &OpenAiFeasibilityOutput) -> Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(&mut stdout, output)
        .context("failed to serialize OpenAI feasibility output")?;
    writeln!(&mut stdout).context("failed to terminate OpenAI feasibility output")
}

#[cfg(test)]
mod tests {
    use weregopher_domain::{
        G2ComponentEvidence, G2ComponentSource, G2ContractError, G2PackagePath, G2ProbeScope,
        PreloadBridgeChecks,
    };

    use super::*;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn component(
        source: G2ComponentSource,
        path: &str,
        byte: u8,
    ) -> Result<G2ComponentEvidence, G2ContractError> {
        G2ComponentEvidence::new(
            source,
            G2PackagePath::new(path)?,
            digest(byte),
            u64::from(byte),
        )
    }

    fn inventory() -> Result<OpenAiPackageInventory, G2ContractError> {
        OpenAiPackageInventory::new(
            digest(1),
            digest(2),
            component(G2ComponentSource::PackageFile, "app/ChatGPT.exe", 3)?,
            component(G2ComponentSource::PackageFile, "app/resources/app.asar", 4)?,
            component(G2ComponentSource::ApplicationArchiveMember, "main.js", 5)?,
            [component(
                G2ComponentSource::ApplicationArchiveMember,
                "preload.js",
                6,
            )?],
            [component(
                G2ComponentSource::ApplicationArchiveMember,
                "index.html",
                7,
            )?],
            component(G2ComponentSource::PackageFile, "app/resources/codex.exe", 8)?,
        )
    }

    fn preload(
        scope: G2ProbeScope,
        source_build: Sha256Digest,
        preload_digest: Sha256Digest,
    ) -> Result<PreloadBridgeProbeReport, G2ContractError> {
        PreloadBridgeProbeReport::new(
            source_build,
            preload_digest,
            digest(9),
            "fixture",
            scope,
            PreloadBridgeChecks {
                document_start: true,
                isolated_globals: true,
                prototype_isolation: true,
                frozen_projection: true,
                function_round_trip: true,
                navigation_invalidation: true,
            },
        )
    }

    #[test]
    fn preload_gate_requires_exact_package_and_component_binding()
    -> Result<(), Box<dyn std::error::Error>> {
        let inventory = inventory()?;
        assert_eq!(
            preload_gate(&inventory, None)?.status(),
            weregopher_domain::G2GateStatus::NotRun
        );
        let exact = preload(G2ProbeScope::ExactPackage, digest(1), digest(6))?;
        assert_eq!(
            preload_gate(&inventory, Some(&exact))?.status(),
            weregopher_domain::G2GateStatus::Passed
        );
        let synthetic = preload(G2ProbeScope::SyntheticFixture, digest(1), digest(6))?;
        assert!(preload_gate(&inventory, Some(&synthetic)).is_err());
        let wrong_component = preload(G2ProbeScope::ExactPackage, digest(1), digest(99))?;
        assert!(preload_gate(&inventory, Some(&wrong_component)).is_err());
        Ok(())
    }
}
