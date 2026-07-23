//! Weregopher command-line entry point.

#![forbid(unsafe_code)]

use std::{
    fs::{self, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use weregopher_adapter_discord::{
    DISCORD_MAIN_ENTRY, DISCORD_PACKAGE_MANIFEST, SMOKE_ADAPTER_ID, transform_smoke_source,
};
use weregopher_asar::{AsarArchive, AsarLimits};
use weregopher_domain::{
    ApplicationFamilyId, Architecture, BuildFingerprint, InstallationKind, Sha256Digest,
};
use weregopher_fingerprint::{
    DEFAULT_MAX_ENTRIES, FingerprintOptions, PackageFileKind, PackageTreeManifest,
    fingerprint_package,
};

#[derive(Debug, Parser)]
#[command(
    name = "weregopher",
    version,
    about = "Transform and inspect installed Electron application packages"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Produce deterministic package-tree and build-fingerprint evidence.
    Fingerprint(FingerprintArguments),
    /// Apply an application-family transform to a distinct managed artifact.
    Transform(TransformArguments),
}

#[derive(Debug, Args)]
struct TransformArguments {
    #[command(subcommand)]
    adapter: TransformCommand,
}

#[derive(Debug, Subcommand)]
enum TransformCommand {
    /// Inject an opt-in launch marker into a supported Discord ASAR main entry.
    DiscordSmoke(DiscordSmokeArguments),
}

#[derive(Debug, Args)]
struct DiscordSmokeArguments {
    /// Vendor `app.asar` to read without modification.
    input_asar: PathBuf,
    /// New transformed ASAR path; it must not already exist.
    output_asar: PathBuf,
}

#[derive(Debug, Args)]
struct FingerprintArguments {
    /// Package directory to read without modification.
    package_root: PathBuf,
    /// Canonical durable application family, for example `openai.chatgpt`.
    #[arg(long)]
    family: String,
    /// Installation technology that owns the package.
    #[arg(long, value_enum)]
    installation_kind: CliInstallationKind,
    /// Package machine architecture.
    #[arg(long, value_enum)]
    architecture: CliArchitecture,
    /// Maximum files and directories before failing closed.
    #[arg(long, default_value_t = DEFAULT_MAX_ENTRIES)]
    max_entries: usize,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
#[value(rename_all = "snake_case")]
enum CliArchitecture {
    X86_64,
    Aarch64,
}

impl From<CliArchitecture> for Architecture {
    fn from(value: CliArchitecture) -> Self {
        match value {
            CliArchitecture::X86_64 => Self::X86_64,
            CliArchitecture::Aarch64 => Self::Aarch64,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
#[value(rename_all = "snake_case")]
enum CliInstallationKind {
    Msix,
    Squirrel,
    Msi,
    Exe,
    Portable,
    Unknown,
}

impl From<CliInstallationKind> for InstallationKind {
    fn from(value: CliInstallationKind) -> Self {
        match value {
            CliInstallationKind::Msix => Self::Msix,
            CliInstallationKind::Squirrel => Self::Squirrel,
            CliInstallationKind::Msi => Self::Msi,
            CliInstallationKind::Exe => Self::Exe,
            CliInstallationKind::Portable => Self::Portable,
            CliInstallationKind::Unknown => Self::Unknown,
        }
    }
}

#[derive(Debug, Serialize)]
struct FingerprintReport {
    fingerprint: BuildFingerprint,
    package_tree: PackageTreeManifest,
}

#[derive(Debug, Serialize)]
struct TransformReport {
    adapter_id: &'static str,
    source_unit: &'static str,
    source_archive_sha256: Sha256Digest,
    source_sha256: Sha256Digest,
    transformed_source_sha256: Sha256Digest,
    output_archive_sha256: Sha256Digest,
    output_bytes: usize,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Fingerprint(arguments) => run_fingerprint(arguments),
        Command::Transform(arguments) => match arguments.adapter {
            TransformCommand::DiscordSmoke(arguments) => run_discord_smoke_transform(&arguments),
        },
    }
}

fn run_fingerprint(arguments: FingerprintArguments) -> Result<()> {
    let family = ApplicationFamilyId::new(arguments.family)
        .context("invalid application family supplied to --family")?;
    let options = FingerprintOptions::default()
        .with_max_entries(arguments.max_entries)
        .context("invalid --max-entries value")?;

    let package_tree =
        fingerprint_package(&arguments.package_root, &options).with_context(|| {
            format!(
                "failed to fingerprint package root {}",
                arguments.package_root.display()
            )
        })?;
    let mut fingerprint = BuildFingerprint::minimal(
        family,
        arguments.installation_kind.into(),
        arguments.architecture.into(),
        *package_tree.package_tree_merkle(),
    );
    fingerprint.app_asar_sha256 = package_tree
        .files()
        .iter()
        .find(|record| {
            record.kind == PackageFileKind::Asar
                && record
                    .normalized_path
                    .eq_ignore_ascii_case("resources/app.asar")
        })
        .map(|record| record.sha256);

    let report = FingerprintReport {
        fingerprint,
        package_tree,
    };
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &report)
        .context("failed to serialize fingerprint report")?;
    writeln!(&mut output).context("failed to finish fingerprint report")?;
    Ok(())
}

fn run_discord_smoke_transform(arguments: &DiscordSmokeArguments) -> Result<()> {
    reject_in_place_output(&arguments.input_asar, &arguments.output_asar)?;
    let limits = AsarLimits::initial();
    let metadata = fs::metadata(&arguments.input_asar).with_context(|| {
        format!(
            "failed to inspect input ASAR {}",
            arguments.input_asar.display()
        )
    })?;
    let input_size =
        usize::try_from(metadata.len()).context("input ASAR size is not representable")?;
    if input_size > limits.max_archive_bytes() {
        anyhow::bail!("input ASAR exceeds the configured byte limit");
    }
    let input = fs::read(&arguments.input_asar).with_context(|| {
        format!(
            "failed to read input ASAR {}",
            arguments.input_asar.display()
        )
    })?;
    let mut archive =
        AsarArchive::parse(&input, limits).context("failed to validate input ASAR")?;
    let package_manifest = archive
        .file(DISCORD_PACKAGE_MANIFEST)
        .context("input ASAR does not contain Discord package.json")?
        .to_vec();
    let source = archive
        .file(DISCORD_MAIN_ENTRY)
        .context("input ASAR does not contain Discord bundle.js")?
        .to_vec();
    let transformed = transform_smoke_source(&package_manifest, &source)
        .context("Discord smoke adapter rejected the input package")?;
    archive
        .replace_file(DISCORD_MAIN_ENTRY, transformed.clone())
        .context("failed to replace Discord main source")?;
    let output = archive
        .to_bytes()
        .context("failed to emit transformed ASAR")?;

    let verified =
        AsarArchive::parse(&output, limits).context("emitted ASAR did not revalidate")?;
    if verified.file(DISCORD_MAIN_ENTRY) != Some(transformed.as_slice())
        || verified.file(DISCORD_PACKAGE_MANIFEST) != Some(package_manifest.as_slice())
    {
        anyhow::bail!("emitted ASAR did not preserve the expected transformed package");
    }

    let mut output_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&arguments.output_asar)
        .with_context(|| {
            format!(
                "failed to create distinct output ASAR {}",
                arguments.output_asar.display()
            )
        })?;
    output_file
        .write_all(&output)
        .context("failed to write transformed ASAR")?;
    output_file
        .sync_all()
        .context("failed to durably flush transformed ASAR")?;

    let report = TransformReport {
        adapter_id: SMOKE_ADAPTER_ID,
        source_unit: DISCORD_MAIN_ENTRY,
        source_archive_sha256: sha256_digest(&input),
        source_sha256: sha256_digest(&source),
        transformed_source_sha256: sha256_digest(&transformed),
        output_archive_sha256: sha256_digest(&output),
        output_bytes: output.len(),
    };
    let stdout = io::stdout();
    let mut report_output = stdout.lock();
    serde_json::to_writer(&mut report_output, &report)
        .context("failed to serialize transform report")?;
    writeln!(&mut report_output).context("failed to finish transform report")?;
    Ok(())
}

fn reject_in_place_output(input: &Path, output: &Path) -> Result<()> {
    if output.exists() {
        anyhow::bail!("output ASAR already exists");
    }
    let canonical_input = input
        .canonicalize()
        .with_context(|| format!("failed to resolve input ASAR {}", input.display()))?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical_parent = parent
        .canonicalize()
        .with_context(|| format!("failed to resolve output parent {}", parent.display()))?;
    let file_name = output.file_name().context("output ASAR has no file name")?;
    let intended_output = canonical_parent.join(file_name);
    if paths_equal(&canonical_input, &intended_output) {
        anyhow::bail!("output ASAR must be distinct from the vendor input");
    }
    Ok(())
}

#[cfg(windows)]
fn paths_equal(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

#[cfg(not(windows))]
fn paths_equal(left: &Path, right: &Path) -> bool {
    left == right
}

fn sha256_digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}
