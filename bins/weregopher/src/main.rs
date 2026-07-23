//! Weregopher command-line entry point.

#![forbid(unsafe_code)]

use std::{
    io::{self, Write as _},
    path::PathBuf,
};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use weregopher_domain::{ApplicationFamilyId, Architecture, BuildFingerprint, InstallationKind};
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

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Fingerprint(arguments) => run_fingerprint(arguments),
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
