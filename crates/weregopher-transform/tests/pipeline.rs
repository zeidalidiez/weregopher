//! End-to-end in-memory composition regression for the transform trust boundaries.

use std::{collections::BTreeMap, num::NonZeroU16};

use sha2::{Digest as _, Sha256};
use weregopher_domain::{
    AdapterId, AdapterTransformAuthority, ApplicationFamilyId, AuthorizedTransformRuleRef,
    GeneratedTransformOverlay, Sha256Digest, SourceUnitId, SourceUnitRef, TransformOverlayBinding,
    TransformRuleId,
};
use weregopher_transform::{
    MatchEvidenceLimits, MaterializationManifestError, MaterializationManifestLimits,
    PlannerLimits, SourceMapLimits, SourceUnitInput, StaticImportRewrite, TransformArtifactLimits,
    TransformBundleLimits, TransformEmissionLimits, assemble_transform_artifacts,
    emit_match_evidence, emit_source_map, emit_transformed_source,
    plan_content_addressed_materialization, plan_static_import_rewrite, verify_transform_artifacts,
};

const SOURCE: &[u8] = b"import pty from 'node-pty';\n";
const TRANSFORMED_SOURCE: &[u8] = b"import pty from \"compat:openai/conpty\";\n";

#[test]
fn exact_plan_composes_through_overlay_validation_and_artifact_verification()
-> Result<(), Box<dyn std::error::Error>> {
    let rule_id = TransformRuleId::new("main.replace-node-pty")?;
    let one = NonZeroU16::new(1).ok_or("test match count must be nonzero")?;
    let rule = StaticImportRewrite::new(
        "node-pty".to_owned(),
        "compat:openai/conpty".to_owned(),
        one,
    )?;
    let adapter_id = AdapterId::new("openai.desktop")?;
    let family = ApplicationFamilyId::new("openai.chatgpt.windows")?;
    let adapter_content_digest = digest(b"adapter");
    let authority = AdapterTransformAuthority::new(
        adapter_id.clone(),
        family.clone(),
        adapter_content_digest,
        BTreeMap::from([(
            rule_id.clone(),
            AuthorizedTransformRuleRef::new(rule.canonical_digest()),
        )]),
    )?;
    let source_ref =
        SourceUnitRef::new(SourceUnitId::new("module.main.bootstrap")?, digest(SOURCE));
    let plan = plan_static_import_rewrite(
        &authority,
        &rule_id,
        &rule,
        SourceUnitInput::new(source_ref, SOURCE),
        PlannerLimits::new(SOURCE.len(), 1, 64)?,
    )?;
    let transformed = emit_transformed_source(
        &plan,
        SOURCE,
        TransformEmissionLimits::new(SOURCE.len(), TRANSFORMED_SOURCE.len())?,
    )?;
    let match_evidence = emit_match_evidence(&plan, MatchEvidenceLimits::new(2_048)?)?;
    let source_map = emit_source_map(
        &transformed,
        SOURCE,
        SourceMapLimits::new(SOURCE.len(), TRANSFORMED_SOURCE.len(), 4, 2_048)?,
    )?;
    let bundle = assemble_transform_artifacts(
        SOURCE,
        &transformed,
        &match_evidence,
        &source_map,
        TransformBundleLimits::new(SOURCE.len(), 2_048, 8_192)?,
    )?;

    let source_build_digest = digest(b"source-build");
    let build_descriptor_digest = digest(b"build-descriptor");
    let overlay = GeneratedTransformOverlay::windows_x64(
        TransformOverlayBinding::new(
            source_build_digest,
            family,
            adapter_id,
            adapter_content_digest,
            authority.canonical_document_digest(),
            build_descriptor_digest,
        ),
        BTreeMap::from([(rule_id.clone(), bundle.rebinding().clone())]),
    )?;
    let structural_validation =
        overlay.validate_against(&authority, source_build_digest, build_descriptor_digest)?;
    let artifact_bytes = bundle.artifacts();
    let artifacts = BTreeMap::from([(rule_id, artifact_bytes)]);
    let verified = verify_transform_artifacts(
        structural_validation,
        &artifacts,
        TransformArtifactLimits::new(
            artifact_bytes.source().len(),
            artifact_bytes.match_evidence().len(),
            artifact_bytes.transformed_source().len(),
            artifact_bytes.source_map().len(),
            artifact_bytes.audit_log().len(),
            bundle.total_bytes(),
        )?,
    )?;

    assert_eq!(verified.overlay(), &overlay);
    assert_eq!(verified.rule_count(), 1);
    assert_eq!(verified.artifacts(), &artifacts);
    assert_eq!(verified.structural_validation().authority(), &authority);
    assert_materialization_manifest(&verified)?;
    Ok(())
}

fn assert_materialization_manifest(
    verified: &weregopher_transform::VerifiedTransformArtifacts<'_, '_, '_, '_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = plan_content_addressed_materialization(
        verified,
        MaterializationManifestLimits::new(1, 5, 5, 4_096)?,
    )?;
    assert_eq!(manifest.rule_count(), 1);
    assert_eq!(manifest.reference_count(), 5);
    assert_eq!(manifest.blob_count(), 5);
    assert_eq!(manifest.verified_artifacts().overlay(), verified.overlay());
    let parsed: serde_json::Value = serde_json::from_slice(manifest.bytes())?;
    assert_eq!(parsed["format_version"].as_str(), Some("1"));
    assert_eq!(parsed["layout"].as_str(), Some("sha256-fanout-v1"));
    assert_eq!(parsed["target"].as_str(), Some("windows-x86_64"));
    assert_eq!(parsed["rules"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        parsed["rules"][0]["artifacts"].as_array().map(Vec::len),
        Some(5)
    );
    assert_eq!(
        parsed["rules"][0]["artifacts"][0]["path"].as_str(),
        Some("sha256/3c/d297afb3f4857b9c794d2f8495f5c5ecc766bfd8d1fc3598e819d46cd929df")
    );
    assert_eq!(
        manifest.digest().to_string(),
        "sha256:11c9347d5e7dda52dd9e1831694166023bed103caf8a72e15a775a7dc8d7adf5"
    );
    for (blob_digest, bytes) in manifest.blobs() {
        assert_eq!(&digest(bytes), blob_digest);
    }
    assert!(
        plan_content_addressed_materialization(
            verified,
            MaterializationManifestLimits::new(1, 5, 5, manifest.bytes().len())?,
        )
        .is_ok()
    );
    assert!(matches!(
        plan_content_addressed_materialization(
            verified,
            MaterializationManifestLimits::new(1, 5, 5, manifest.bytes().len() - 1)?,
        ),
        Err(MaterializationManifestError::ManifestTooLarge {
            actual_bytes,
            max_bytes,
        }) if actual_bytes == manifest.bytes().len()
            && max_bytes == manifest.bytes().len() - 1
    ));
    assert!(matches!(
        plan_content_addressed_materialization(
            verified,
            MaterializationManifestLimits::new(1, 4, 5, 4_096)?,
        ),
        Err(MaterializationManifestError::ReferenceLimitExceeded { actual: 5, max: 4 })
    ));
    assert!(matches!(
        plan_content_addressed_materialization(
            verified,
            MaterializationManifestLimits::new(1, 5, 4, 4_096)?,
        ),
        Err(MaterializationManifestError::BlobLimitExceeded { max: 4 })
    ));
    let debug = format!("{manifest:?}");
    assert!(!debug.contains("node-pty"));
    assert!(
        !manifest
            .bytes()
            .windows(b"import pty".len())
            .any(|window| window == b"import pty")
    );
    assert!(debug.contains("manifest_digest"));
    assert_windows_materialization(&manifest, &parsed)?;
    Ok(())
}

#[cfg(windows)]
fn assert_windows_materialization(
    manifest: &weregopher_transform::MaterializationManifest<'_, '_, '_, '_, '_>,
    parsed: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;

    use tempfile::tempdir;

    let fixture = tempdir()?;
    let vendor_root = fixture.path().join("vendor");
    let store_root = fixture.path().join("store");
    fs::create_dir(&vendor_root)?;
    fs::create_dir(&store_root)?;
    let store = open_test_store(&store_root, &vendor_root)?;
    let limits = test_write_limits(manifest)?;
    assert_writer_limits_precede_filesystem_access(&store, manifest, &store_root)?;
    let total_blob_bytes: usize = manifest.blobs().values().map(|bytes| bytes.len()).sum();
    let first = store.materialize(manifest, limits)?;
    assert_eq!(first.created_blobs(), manifest.blob_count());
    assert_eq!(first.reused_blobs(), 0);
    assert_eq!(first.total_blob_bytes(), total_blob_bytes);
    assert_eq!(first.manifest_digest(), manifest.digest());
    assert_materialized_bytes(manifest, parsed, &store_root)?;

    let second = store.materialize(manifest, limits)?;
    assert_eq!(second.created_blobs(), 0);
    assert_eq!(second.reused_blobs(), manifest.blob_count());
    assert_no_temporary_paths(&store_root)?;
    assert_conflicting_blob_is_not_replaced(&store, manifest, parsed, limits, &store_root)?;
    assert_content_root_junction_is_rejected(manifest, limits, fixture.path())?;
    assert_concurrent_publication_is_idempotent(manifest, limits, fixture.path())?;
    Ok(())
}

#[cfg(windows)]
fn test_write_limits(
    manifest: &weregopher_transform::MaterializationManifest<'_, '_, '_, '_, '_>,
) -> Result<weregopher_transform::MaterializationWriteLimits, Box<dyn std::error::Error>> {
    let max_blob_bytes = manifest
        .blobs()
        .values()
        .map(|bytes| bytes.len())
        .max()
        .ok_or("the manifest must contain a blob")?;
    let total_blob_bytes = manifest
        .blobs()
        .values()
        .try_fold(0_usize, |total, bytes| total.checked_add(bytes.len()))
        .ok_or("test blob-byte total overflowed")?;
    Ok(weregopher_transform::MaterializationWriteLimits::new(
        manifest.blob_count(),
        max_blob_bytes,
        total_blob_bytes,
        8,
    )?)
}

#[cfg(windows)]
fn assert_writer_limits_precede_filesystem_access(
    store: &weregopher_transform::ManagedArtifactStore,
    manifest: &weregopher_transform::MaterializationManifest<'_, '_, '_, '_, '_>,
    store_root: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use weregopher_transform::{MaterializationStoreError, MaterializationWriteLimits};

    let max_blob_bytes = manifest
        .blobs()
        .values()
        .map(|bytes| bytes.len())
        .max()
        .ok_or("the manifest must contain a blob")?;
    let total_blob_bytes: usize = manifest.blobs().values().map(|bytes| bytes.len()).sum();
    let cases = [
        (
            MaterializationWriteLimits::new(
                manifest.blob_count() - 1,
                max_blob_bytes,
                total_blob_bytes,
                1,
            )?,
            "blob count",
        ),
        (
            MaterializationWriteLimits::new(
                manifest.blob_count(),
                max_blob_bytes - 1,
                total_blob_bytes,
                1,
            )?,
            "blob size",
        ),
        (
            MaterializationWriteLimits::new(
                manifest.blob_count(),
                max_blob_bytes,
                total_blob_bytes - 1,
                1,
            )?,
            "total size",
        ),
    ];
    for (limits, expected) in cases {
        let Err(error) = store.materialize(manifest, limits) else {
            return Err("undersized writer limit unexpectedly succeeded".into());
        };
        assert!(
            matches!(
                (&error, expected),
                (
                    MaterializationStoreError::BlobLimitExceeded { .. },
                    "blob count"
                ) | (MaterializationStoreError::BlobTooLarge { .. }, "blob size")
                    | (
                        MaterializationStoreError::TotalBytesExceeded { .. },
                        "total size"
                    )
            ),
            "unexpected writer-limit error: {error}"
        );
        assert!(!store_root.join("sha256").exists());
    }
    Ok(())
}

#[cfg(windows)]
fn assert_materialized_bytes(
    manifest: &weregopher_transform::MaterializationManifest<'_, '_, '_, '_, '_>,
    parsed: &serde_json::Value,
    store_root: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;

    for artifact in parsed["rules"][0]["artifacts"]
        .as_array()
        .ok_or("manifest artifacts must be an array")?
    {
        let relative = artifact["path"]
            .as_str()
            .ok_or("artifact path must be text")?;
        let digest_text = artifact["digest"]
            .as_str()
            .ok_or("artifact digest must be text")?;
        let expected = manifest
            .blobs()
            .iter()
            .find_map(|(digest, bytes)| (digest.to_string() == digest_text).then_some(*bytes))
            .ok_or("manifest digest must retain verified bytes")?;
        assert_eq!(fs::read(store_root.join(relative))?, expected);
    }
    Ok(())
}

#[cfg(windows)]
fn assert_conflicting_blob_is_not_replaced(
    store: &weregopher_transform::ManagedArtifactStore,
    manifest: &weregopher_transform::MaterializationManifest<'_, '_, '_, '_, '_>,
    parsed: &serde_json::Value,
    limits: weregopher_transform::MaterializationWriteLimits,
    store_root: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    use weregopher_transform::MaterializationStoreError;

    let conflict_relative = parsed["rules"][0]["artifacts"][0]["path"]
        .as_str()
        .ok_or("artifact path must be text")?;
    let conflict_path = store_root.join(conflict_relative);
    fs::write(&conflict_path, b"conflicting bytes")?;
    assert!(matches!(
        store.materialize(manifest, limits),
        Err(MaterializationStoreError::ExistingBlobMismatch { .. })
    ));
    assert_eq!(fs::read(conflict_path)?, b"conflicting bytes");
    Ok(())
}

#[cfg(windows)]
fn assert_content_root_junction_is_rejected(
    manifest: &weregopher_transform::MaterializationManifest<'_, '_, '_, '_, '_>,
    limits: weregopher_transform::MaterializationWriteLimits,
    fixture: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    use weregopher_transform::MaterializationStoreError;

    let junction_store_root = fixture.join("junction-store");
    let junction_vendor_root = fixture.join("junction-vendor");
    let junction_target = fixture.join("junction-target");
    fs::create_dir(&junction_store_root)?;
    fs::create_dir(&junction_vendor_root)?;
    fs::create_dir(&junction_target)?;
    let junction_store = open_test_store(&junction_store_root, &junction_vendor_root)?;
    let output = std::process::Command::new("cmd")
        .args(["/D", "/C", "mklink", "/J"])
        .arg(junction_store_root.join("sha256"))
        .arg(&junction_target)
        .output()?;
    if !output.status.success() {
        return Err("mklink /J failed".into());
    }
    assert!(matches!(
        junction_store.materialize(manifest, limits),
        Err(MaterializationStoreError::ReparsePoint { .. })
    ));
    Ok(())
}

#[cfg(windows)]
fn assert_concurrent_publication_is_idempotent(
    manifest: &weregopher_transform::MaterializationManifest<'_, '_, '_, '_, '_>,
    limits: weregopher_transform::MaterializationWriteLimits,
    fixture: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;

    let concurrent_store_root = fixture.join("concurrent-store");
    let concurrent_vendor_root = fixture.join("concurrent-vendor");
    fs::create_dir(&concurrent_store_root)?;
    fs::create_dir(&concurrent_vendor_root)?;
    let first_store = open_test_store(&concurrent_store_root, &concurrent_vendor_root)?;
    let second_store = open_test_store(&concurrent_store_root, &concurrent_vendor_root)?;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let (first, second) = std::thread::scope(|scope| {
        let first_barrier = std::sync::Arc::clone(&barrier);
        let second_barrier = std::sync::Arc::clone(&barrier);
        let first = scope.spawn(move || {
            first_barrier.wait();
            first_store.materialize(manifest, limits)
        });
        let second = scope.spawn(move || {
            second_barrier.wait();
            second_store.materialize(manifest, limits)
        });
        (first.join(), second.join())
    });
    let first = first.map_err(|_| "first concurrent materializer panicked")??;
    let second = second.map_err(|_| "second concurrent materializer panicked")??;
    assert_eq!(
        first.created_blobs() + second.created_blobs(),
        manifest.blob_count()
    );
    assert_eq!(
        first.reused_blobs() + second.reused_blobs(),
        manifest.blob_count()
    );
    assert_no_temporary_paths(&concurrent_store_root)?;
    Ok(())
}

#[cfg(windows)]
fn assert_no_temporary_paths(store_root: &std::path::Path) -> Result<(), std::io::Error> {
    for fanout in std::fs::read_dir(store_root.join("sha256"))? {
        let fanout = fanout?;
        for entry in std::fs::read_dir(fanout.path())? {
            let name = entry?.file_name();
            assert!(!name.to_string_lossy().starts_with(".weregopher-"));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn open_test_store(
    store_root: &std::path::Path,
    vendor_root: &std::path::Path,
) -> Result<weregopher_transform::ManagedArtifactStore, Box<dyn std::error::Error>> {
    Ok(weregopher_transform::ManagedArtifactStore::open(
        store_root,
        vendor_root,
        weregopher_transform::ManagedStoreRootLimits::new(64)?,
    )?)
}

#[cfg(not(windows))]
fn assert_windows_materialization(
    _manifest: &weregopher_transform::MaterializationManifest<'_, '_, '_, '_, '_>,
    _parsed: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let limits = weregopher_transform::ManagedStoreRootLimits::new(1)?;
    assert!(matches!(
        weregopher_transform::ManagedArtifactStore::open(
            std::path::Path::new("/tmp/store"),
            std::path::Path::new("/tmp/vendor"),
            limits,
        ),
        Err(weregopher_transform::MaterializationStoreError::UnsupportedPlatform)
    ));
    Ok(())
}

#[test]
fn materialization_manifest_limits_must_be_nonzero() {
    for limits in [(0, 1, 1, 1), (1, 0, 1, 1), (1, 1, 0, 1), (1, 1, 1, 0)] {
        assert_eq!(
            MaterializationManifestLimits::new(limits.0, limits.1, limits.2, limits.3),
            Err(MaterializationManifestError::InvalidLimits)
        );
    }
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}
