//! Read-only `OpenAI` package inventory behavior.

use sha2::{Digest as _, Sha256};
use weregopher_adapter_openai::{
    ExactPreloadPreparationError, OpenAiPackageAnalysisError, analyze_openai_package,
    prepare_exact_preload,
};
use weregopher_domain::{
    ApplicationFamilyId, Architecture, BuildFingerprint, G2ComponentEvidence, G2ComponentSource,
    G2PackagePath, InstallationKind, OpenAiPackageInventory, PackageIdentity, Sha256Digest,
};
use weregopher_fingerprint::{
    PackageFileKind, PackageFileRecord, PackageTreeManifest, build_package_manifest,
};

const DESKTOP_PATH: &str = "app/ChatGPT.exe";
const ARCHIVE_PATH: &str = "app/resources/app.asar";
const APP_SERVER_PATH: &str = "app/resources/codex.exe";

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn package_fixture(
    preload_source: &[u8],
) -> Result<(BuildFingerprint, PackageTreeManifest, Vec<u8>), Box<dyn std::error::Error>> {
    package_fixture_with_preloads(&[("preload.js", preload_source)])
}

fn package_fixture_with_preloads(
    preload_sources: &[(&str, &[u8])],
) -> Result<(BuildFingerprint, PackageTreeManifest, Vec<u8>), Box<dyn std::error::Error>> {
    let mut archive_members = vec![
        (
            "package.json",
            br#"{"name":"openai-desktop","main":"main.js"}"#.as_slice(),
        ),
        ("main.js", b"const ready = true;".as_slice()),
        (
            "index.html",
            b"<!doctype html><title>OpenAI fixture</title>".as_slice(),
        ),
    ];
    archive_members.extend_from_slice(preload_sources);
    let archive = fixture_archive(&archive_members)?;
    let files = vec![
        package_file(DESKTOP_PATH, b"desktop", PackageFileKind::Executable),
        package_file(ARCHIVE_PATH, &archive, PackageFileKind::Asar),
        package_file(APP_SERVER_PATH, b"app-server", PackageFileKind::Executable),
    ];
    let package_tree = build_package_manifest(files)?;
    let mut build = BuildFingerprint::minimal(
        ApplicationFamilyId::new("openai.chatgpt.windows")?,
        InstallationKind::Msix,
        Architecture::X86_64,
        *package_tree.package_tree_merkle(),
    );
    build.package_identity = Some(PackageIdentity {
        package_name: "OpenAI.Codex".to_owned(),
        package_family_name: "OpenAI.Codex_2p2nqsd0c76g0".to_owned(),
        package_full_name: "OpenAI.Codex_26.715.8383.0_x64__2p2nqsd0c76g0".to_owned(),
        publisher_id: "2p2nqsd0c76g0".to_owned(),
        application_ids: vec!["App".to_owned()],
    });
    build.package_version = Some("26.715.8383.0".to_owned());
    Ok((build, package_tree, archive))
}

fn package_file(path: &str, bytes: &[u8], kind: PackageFileKind) -> PackageFileRecord {
    PackageFileRecord {
        normalized_path: path.to_owned(),
        size: bytes.len() as u64,
        sha256: digest(bytes),
        executable: kind == PackageFileKind::Executable,
        kind,
        signer_thumbprint: None,
    }
}

fn component(
    source: G2ComponentSource,
    path: &str,
    bytes: &[u8],
) -> Result<G2ComponentEvidence, Box<dyn std::error::Error>> {
    Ok(G2ComponentEvidence::new(
        source,
        G2PackagePath::new(path)?,
        digest(bytes),
        u64::try_from(bytes.len())?,
    )?)
}

#[test]
fn package_inventory_binds_exact_package_and_archive_components()
-> Result<(), Box<dyn std::error::Error>> {
    let (build, tree, archive) = package_fixture(
        b"const { contextBridge } = require('electron'); contextBridge.exposeInMainWorld('desktop', {});",
    )?;
    let inventory = analyze_openai_package(&build, &tree, &archive)?;

    assert_eq!(inventory.desktop_entry().path().as_str(), DESKTOP_PATH);
    assert_eq!(
        inventory.application_archive().path().as_str(),
        ARCHIVE_PATH
    );
    assert_eq!(inventory.main_entry().path().as_str(), "main.js");
    assert_eq!(
        inventory.main_entry().source(),
        G2ComponentSource::ApplicationArchiveMember
    );
    assert_eq!(inventory.preload_candidates().len(), 1);
    assert_eq!(
        inventory
            .preload_candidates()
            .first()
            .ok_or("preload candidate is missing")?
            .path()
            .as_str(),
        "preload.js"
    );
    assert_eq!(inventory.renderer_candidates().len(), 1);
    assert_eq!(inventory.app_server().path().as_str(), APP_SERVER_PATH);
    Ok(())
}

#[test]
fn exact_preload_preparation_revalidates_and_binds_one_candidate()
-> Result<(), Box<dyn std::error::Error>> {
    let source =
        b"const { contextBridge } = require('electron'); contextBridge.exposeInMainWorld('desktop', Object.freeze({ ready: true }));";
    let (build, tree, archive) = package_fixture(source)?;
    let inventory = analyze_openai_package(&build, &tree, &archive)?;

    let prepared = prepare_exact_preload(&inventory, &archive)?;

    assert_eq!(prepared.source_byte_length(), source.len());
    assert!(!format!("{prepared:?}").contains("contextBridge"));
    assert_eq!(prepared.path().as_str(), "preload.js");
    assert_eq!(
        prepared.source_build_fingerprint_digest(),
        inventory.source_build_fingerprint_digest()
    );
    assert_eq!(
        prepared.preload_digest(),
        inventory
            .preload_candidates()
            .first()
            .ok_or("preload candidate is missing")?
            .sha256()
    );
    Ok(())
}

#[test]
fn exact_preload_preparation_fails_closed_for_ambiguous_candidates()
-> Result<(), Box<dyn std::error::Error>> {
    let first =
        b"const { contextBridge } = require('electron'); contextBridge.exposeInMainWorld('first', {});";
    let second =
        b"const { contextBridge } = require('electron'); contextBridge.exposeInMainWorld('second', {});";
    let (build, tree, archive) =
        package_fixture_with_preloads(&[("preload-a.js", first), ("preload-b.js", second)])?;
    let inventory = analyze_openai_package(&build, &tree, &archive)?;

    assert!(matches!(
        prepare_exact_preload(&inventory, &archive),
        Err(ExactPreloadPreparationError::AmbiguousPreloadCandidates { observed: 2 })
    ));
    Ok(())
}

#[test]
fn exact_preload_preparation_rejects_unbound_or_non_utf8_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let source =
        b"const { contextBridge } = require('electron'); contextBridge.exposeInMainWorld('desktop', {});";
    let (build, tree, archive) = package_fixture(source)?;
    let inventory = analyze_openai_package(&build, &tree, &archive)?;
    let shortened_archive = archive
        .get(..archive.len().saturating_sub(1))
        .ok_or("fixture archive unexpectedly empty")?;
    assert!(matches!(
        prepare_exact_preload(&inventory, shortened_archive),
        Err(ExactPreloadPreparationError::ApplicationArchiveLengthMismatch)
    ));
    let mut changed_archive = archive.clone();
    let last = changed_archive
        .last_mut()
        .ok_or("fixture archive unexpectedly empty")?;
    *last ^= 0x01;
    assert!(matches!(
        prepare_exact_preload(&inventory, &changed_archive),
        Err(ExactPreloadPreparationError::ApplicationArchiveDigestMismatch)
    ));

    let non_utf8 = b"const contextBridge = 1; exposeInMainWorld; const invalid = '\xff';";
    let (build, tree, archive) = package_fixture(non_utf8)?;
    let inventory = analyze_openai_package(&build, &tree, &archive)?;
    assert!(matches!(
        prepare_exact_preload(&inventory, &archive),
        Err(ExactPreloadPreparationError::PreloadSourceNotUtf8)
    ));
    Ok(())
}

#[test]
fn exact_preload_preparation_rechecks_bridge_discovery_signals()
-> Result<(), Box<dyn std::error::Error>> {
    let source = b"globalThis.ready = true;";
    let archive = fixture_archive(&[("preload.js", source)])?;
    let inventory = OpenAiPackageInventory::new(
        digest(b"build"),
        digest(b"identity"),
        component(G2ComponentSource::PackageFile, DESKTOP_PATH, b"desktop")?,
        component(G2ComponentSource::PackageFile, ARCHIVE_PATH, &archive)?,
        component(
            G2ComponentSource::ApplicationArchiveMember,
            "main.js",
            b"main",
        )?,
        [component(
            G2ComponentSource::ApplicationArchiveMember,
            "preload.js",
            source,
        )?],
        [component(
            G2ComponentSource::ApplicationArchiveMember,
            "index.html",
            b"renderer",
        )?],
        component(
            G2ComponentSource::PackageFile,
            APP_SERVER_PATH,
            b"app-server",
        )?,
    )?;

    assert!(matches!(
        prepare_exact_preload(&inventory, &archive),
        Err(ExactPreloadPreparationError::MissingBridgeSignals)
    ));
    Ok(())
}

#[test]
fn package_inventory_fails_closed_without_context_bridge_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let (build, tree, archive) = package_fixture(b"globalThis.preload = true;")?;
    let error = analyze_openai_package(&build, &tree, &archive)
        .err()
        .ok_or("missing contextBridge evidence must fail closed")?;
    assert!(matches!(
        error,
        OpenAiPackageAnalysisError::MissingPreloadCandidate
    ));
    Ok(())
}

#[test]
fn package_inventory_rejects_archive_bytes_not_bound_by_the_manifest()
-> Result<(), Box<dyn std::error::Error>> {
    let (build, tree, mut archive) = package_fixture(
        b"const { contextBridge } = require('electron'); contextBridge.exposeInMainWorld('desktop', {});",
    )?;
    let last = archive
        .last_mut()
        .ok_or("fixture archive unexpectedly empty")?;
    *last ^= 0x01;
    let error = analyze_openai_package(&build, &tree, &archive)
        .err()
        .ok_or("an unbound archive must fail closed")?;
    assert!(matches!(
        error,
        OpenAiPackageAnalysisError::ApplicationArchiveDigestMismatch
    ));
    Ok(())
}

fn fixture_archive(files: &[(&str, &[u8])]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut offset = 0_u64;
    let mut members = serde_json::Map::new();
    let mut body = Vec::new();

    for (path, bytes) in files {
        let hash = format!("{:x}", Sha256::digest(bytes));
        members.insert(
            (*path).to_owned(),
            serde_json::json!({
                "size": bytes.len(),
                "offset": offset.to_string(),
                "integrity": {
                    "algorithm": "SHA256",
                    "hash": hash,
                    "blockSize": 4_194_304,
                    "blocks": [hash],
                }
            }),
        );
        offset = offset
            .checked_add(u64::try_from(bytes.len())?)
            .ok_or("fixture offset overflow")?;
        body.extend_from_slice(bytes);
    }
    members.insert(
        "native-addon.node".to_owned(),
        serde_json::json!({
            "size": 4_096,
            "unpacked": true
        }),
    );

    let mut json = serde_json::to_vec(&serde_json::json!({"files": members}))?;
    let json_size = u32::try_from(json.len())?;
    while json.len() % 4 != 0 {
        json.push(0);
    }
    let padded_size = u32::try_from(json.len())?;

    let mut archive = Vec::new();
    archive.extend_from_slice(&4_u32.to_le_bytes());
    archive.extend_from_slice(&(padded_size + 8).to_le_bytes());
    archive.extend_from_slice(&(padded_size + 4).to_le_bytes());
    archive.extend_from_slice(&json_size.to_le_bytes());
    archive.extend_from_slice(&json);
    archive.extend_from_slice(&body);
    Ok(archive)
}
