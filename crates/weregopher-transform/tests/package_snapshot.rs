//! Windows immutable package-snapshot publication and lease regressions.

#![cfg(windows)]

use std::{
    fs,
    io::Read as _,
    path::{Path, PathBuf},
    process::Command,
    sync::Barrier,
    thread,
};

use tempfile::tempdir;
use weregopher_domain::Sha256Digest;
use weregopher_fingerprint::{
    PackageFileKind, PackageFileRecord, PackageTreeObservationLimits, build_package_manifest,
    observe_package_tree,
};
use weregopher_transform::{
    ManagedArtifactStore, ManagedStoreRootLimits, PackageSnapshotError, PackageSnapshotLeaseLimits,
    PackageSnapshotWriteLimits,
};

type SnapshotPublicationCounts = (usize, usize, usize, usize);
type SnapshotPublicationResults =
    Result<Vec<SnapshotPublicationCounts>, Box<dyn std::error::Error>>;

#[test]
fn snapshot_survives_vendor_replacement_and_can_be_released()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let vendor = fixture.path().join("vendor");
    let store_root = fixture.path().join("store");
    fs::create_dir(&vendor)?;
    fs::create_dir(vendor.join("assets"))?;
    fs::create_dir(&store_root)?;
    fs::write(vendor.join("main.js"), b"main")?;
    fs::write(vendor.join("assets/icon.bin"), b"icon")?;

    let observation = observe_package_tree(
        &vendor,
        PackageTreeObservationLimits::new(16, 16, 8, 1_024, 4_096, 4_096)?,
    )?;
    let manifest = observation.manifest().clone();
    let store = ManagedArtifactStore::open(&store_root, &vendor, ManagedStoreRootLimits::new(64)?)?;

    let snapshot = store.snapshot_package(
        &observation,
        PackageSnapshotWriteLimits::new(16, 16, 1_024, 4_096, 16)?,
    )?;
    assert_eq!(
        snapshot.package_tree_merkle(),
        manifest.package_tree_merkle()
    );
    assert_eq!(snapshot.file_count(), 2);
    assert_eq!(snapshot.directory_count(), 2);
    assert_eq!(snapshot.total_file_bytes(), 8);
    assert_eq!(snapshot.created_blobs(), 2);
    assert_eq!(snapshot.created_links(), 2);
    assert_eq!(
        fs::read(snapshot.unrestricted_physical_root().join("main.js"))?,
        b"main"
    );
    assert_eq!(
        fs::read(
            snapshot
                .unrestricted_physical_root()
                .join("assets/icon.bin")
        )?,
        b"icon"
    );
    assert!(
        fs::write(
            snapshot.unrestricted_physical_root().join("main.js"),
            b"changed"
        )
        .is_err()
    );

    let reused = store.snapshot_package(
        &observation,
        PackageSnapshotWriteLimits::new(16, 16, 1_024, 4_096, 16)?,
    )?;
    assert_eq!(reused.created_blobs(), 0);
    assert_eq!(reused.reused_blobs(), 2);
    assert_eq!(reused.created_links(), 0);
    assert_eq!(reused.reused_links(), 2);
    drop(reused);
    let injected = snapshot.unrestricted_physical_root().join("injected.bin");
    fs::write(&injected, b"injected")?;
    assert_manifest_scoped_reader_ignores_injected_children(&snapshot)?;
    assert!(matches!(
        snapshot.verify_current_view(),
        Err(PackageSnapshotError::MembershipMismatch)
    ));
    assert!(matches!(
        store.lease_package_snapshot(
            &manifest,
            PackageSnapshotLeaseLimits::new(16, 16, 1_024, 4_096)?,
        ),
        Err(PackageSnapshotError::MembershipMismatch)
    ));
    fs::remove_file(injected)?;
    snapshot.verify_current_view()?;

    let snapshot_root = snapshot.unrestricted_physical_root().to_path_buf();
    drop(snapshot);
    drop(observation);
    fs::rename(&vendor, fixture.path().join("vendor-replaced"))?;

    let reopened = store.lease_package_snapshot(
        &manifest,
        PackageSnapshotLeaseLimits::new(16, 16, 1_024, 4_096)?,
    )?;
    assert_eq!(reopened.unrestricted_physical_root(), snapshot_root);
    assert_eq!(
        fs::read(reopened.unrestricted_physical_root().join("main.js"))?,
        b"main"
    );
    assert!(
        fs::write(
            reopened
                .unrestricted_physical_root()
                .join("assets/icon.bin"),
            b"changed"
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn snapshot_source_must_match_the_store_vendor_root() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let bound_vendor = fixture.path().join("bound-vendor");
    let other_vendor = fixture.path().join("other-vendor");
    let store_root = fixture.path().join("store");
    fs::create_dir(&bound_vendor)?;
    fs::create_dir(&other_vendor)?;
    fs::create_dir(&store_root)?;
    fs::write(other_vendor.join("main.js"), b"main")?;
    let observation = observe_package_tree(
        &other_vendor,
        PackageTreeObservationLimits::new(8, 8, 4, 128, 128, 128)?,
    )?;
    let store =
        ManagedArtifactStore::open(&store_root, &bound_vendor, ManagedStoreRootLimits::new(64)?)?;

    assert!(matches!(
        store.snapshot_package(
            &observation,
            PackageSnapshotWriteLimits::new(8, 8, 128, 128, 8)?,
        ),
        Err(PackageSnapshotError::SourceRootMismatch)
    ));
    assert!(!store_root.join("sha256").exists());
    assert!(!store_root.join("package-views").exists());
    Ok(())
}

#[test]
fn snapshot_persists_across_store_instances() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let vendor = fixture.path().join("vendor");
    let store_root = fixture.path().join("store");
    fs::create_dir(&vendor)?;
    fs::create_dir(&store_root)?;
    fs::write(vendor.join("main.js"), b"persistent")?;
    let observation = observe_package_tree(
        &vendor,
        PackageTreeObservationLimits::new(8, 8, 4, 128, 128, 128)?,
    )?;
    let manifest = observation.manifest().clone();
    let store = ManagedArtifactStore::open(&store_root, &vendor, ManagedStoreRootLimits::new(64)?)?;
    let snapshot = store.snapshot_package(
        &observation,
        PackageSnapshotWriteLimits::new(8, 8, 128, 128, 8)?,
    )?;
    drop(snapshot);
    drop(store);
    drop(observation);

    let reopened_store =
        ManagedArtifactStore::open(&store_root, &vendor, ManagedStoreRootLimits::new(64)?)?;
    let reopened = reopened_store
        .lease_package_snapshot(&manifest, PackageSnapshotLeaseLimits::new(8, 8, 128, 128)?)?;
    let mut bytes = Vec::new();
    reopened.open_file("main.js")?.read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"persistent");
    Ok(())
}

#[test]
fn snapshot_limits_fail_before_managed_writes() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let vendor = fixture.path().join("vendor");
    let store_root = fixture.path().join("store");
    fs::create_dir(&vendor)?;
    fs::create_dir(vendor.join("assets"))?;
    fs::create_dir(&store_root)?;
    fs::write(vendor.join("assets/icon.bin"), b"icon")?;
    let observation = observe_package_tree(
        &vendor,
        PackageTreeObservationLimits::new(8, 8, 4, 128, 128, 128)?,
    )?;
    let store = ManagedArtifactStore::open(&store_root, &vendor, ManagedStoreRootLimits::new(64)?)?;

    assert!(matches!(
        store.snapshot_package(
            &observation,
            PackageSnapshotWriteLimits::new(8, 1, 128, 128, 8)?,
        ),
        Err(PackageSnapshotError::DirectoryLimitExceeded { .. })
    ));
    assert!(matches!(
        store.snapshot_package(
            &observation,
            PackageSnapshotWriteLimits::new(8, 8, 3, 128, 8)?,
        ),
        Err(PackageSnapshotError::FileTooLarge { .. })
    ));
    assert!(matches!(
        store.snapshot_package(
            &observation,
            PackageSnapshotWriteLimits::new(8, 8, 128, 3, 8)?,
        ),
        Err(PackageSnapshotError::TotalBytesExceeded { .. })
    ));
    assert!(!store_root.join("sha256").exists());
    assert!(!store_root.join("package-views").exists());
    Ok(())
}

#[test]
fn conflicting_view_file_is_never_replaced() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let vendor = fixture.path().join("vendor");
    let store_root = fixture.path().join("store");
    fs::create_dir(&vendor)?;
    fs::create_dir(&store_root)?;
    fs::write(vendor.join("main.js"), b"expected")?;
    let observation = observe_package_tree(
        &vendor,
        PackageTreeObservationLimits::new(8, 8, 4, 128, 128, 128)?,
    )?;
    let poisoned_root =
        snapshot_view_root(&store_root, observation.manifest().package_tree_merkle())?;
    fs::create_dir_all(&poisoned_root)?;
    fs::write(poisoned_root.join("main.js"), b"poison")?;
    let store = ManagedArtifactStore::open(&store_root, &vendor, ManagedStoreRootLimits::new(64)?)?;

    assert!(matches!(
        store.snapshot_package(
            &observation,
            PackageSnapshotWriteLimits::new(8, 8, 128, 128, 8)?,
        ),
        Err(PackageSnapshotError::FileMismatch { .. })
    ));
    assert_eq!(fs::read(poisoned_root.join("main.js"))?, b"poison");
    Ok(())
}

#[test]
fn snapshot_lease_rejects_extra_membership() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let vendor = fixture.path().join("vendor");
    let store_root = fixture.path().join("store");
    fs::create_dir(&vendor)?;
    fs::create_dir(&store_root)?;
    fs::write(vendor.join("main.js"), b"main")?;
    let observation = observe_package_tree(
        &vendor,
        PackageTreeObservationLimits::new(8, 8, 4, 128, 128, 128)?,
    )?;
    let manifest = observation.manifest().clone();
    let store = ManagedArtifactStore::open(&store_root, &vendor, ManagedStoreRootLimits::new(64)?)?;
    let snapshot = store.snapshot_package(
        &observation,
        PackageSnapshotWriteLimits::new(8, 8, 128, 128, 8)?,
    )?;
    let root = snapshot.unrestricted_physical_root().to_path_buf();
    drop(snapshot);
    fs::write(root.join("extra.bin"), b"extra")?;

    assert!(matches!(
        store.lease_package_snapshot(&manifest, PackageSnapshotLeaseLimits::new(8, 8, 128, 128)?,),
        Err(PackageSnapshotError::MembershipMismatch)
    ));
    Ok(())
}

#[test]
fn concurrent_snapshot_publishers_converge() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    for round in 0..16 {
        let vendor = fixture.path().join(format!("vendor-{round}"));
        let store_root = fixture.path().join(format!("store-{round}"));
        fs::create_dir(&vendor)?;
        fs::create_dir(&store_root)?;
        fs::write(vendor.join("main.js"), format!("concurrent-{round}"))?;
        let observation = observe_package_tree(
            &vendor,
            PackageTreeObservationLimits::new(8, 8, 4, 128, 128, 128)?,
        )?;
        let store =
            ManagedArtifactStore::open(&store_root, &vendor, ManagedStoreRootLimits::new(64)?)?;

        let barrier = Barrier::new(9);
        let results = thread::scope(|scope| -> SnapshotPublicationResults {
            let mut handles = Vec::new();
            for _ in 0..8 {
                handles.push(scope.spawn(|| {
                    barrier.wait();
                    let lease = store.snapshot_package(
                        &observation,
                        PackageSnapshotWriteLimits::new(8, 8, 128, 128, 32)?,
                    )?;
                    Ok::<_, PackageSnapshotError>((
                        lease.created_blobs(),
                        lease.reused_blobs(),
                        lease.created_links(),
                        lease.reused_links(),
                    ))
                }));
            }
            barrier.wait();
            let mut results = Vec::new();
            for handle in handles {
                let result = handle
                    .join()
                    .map_err(|_| "snapshot publisher thread panicked")??;
                results.push(result);
            }
            Ok(results)
        })?;

        assert_eq!(results.iter().map(|counts| counts.0).sum::<usize>(), 1);
        assert_eq!(results.iter().map(|counts| counts.1).sum::<usize>(), 7);
        assert_eq!(results.iter().map(|counts| counts.2).sum::<usize>(), 1);
        assert_eq!(results.iter().map(|counts| counts.3).sum::<usize>(), 7);
    }
    Ok(())
}

#[test]
fn snapshot_lease_classifies_a_replaced_directory_as_a_file_mismatch()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let vendor = fixture.path().join("vendor");
    let store_root = fixture.path().join("store");
    fs::create_dir(&vendor)?;
    fs::create_dir(&store_root)?;
    fs::write(vendor.join("main.js"), b"main")?;
    let observation = observe_package_tree(
        &vendor,
        PackageTreeObservationLimits::new(8, 8, 4, 128, 128, 128)?,
    )?;
    let manifest = observation.manifest().clone();
    let store = ManagedArtifactStore::open(&store_root, &vendor, ManagedStoreRootLimits::new(64)?)?;
    let snapshot = store.snapshot_package(
        &observation,
        PackageSnapshotWriteLimits::new(8, 8, 128, 128, 8)?,
    )?;
    let main = snapshot.unrestricted_physical_root().join("main.js");
    drop(snapshot);
    fs::remove_file(&main)?;
    fs::create_dir(&main)?;

    assert!(matches!(
        store.lease_package_snapshot(
            &manifest,
            PackageSnapshotLeaseLimits::new(8, 8, 128, 128)?,
        ),
        Err(PackageSnapshotError::FileMismatch { normalized_path })
            if normalized_path == "main.js"
    ));
    Ok(())
}

#[test]
fn snapshot_view_root_rejects_a_junction() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let vendor = fixture.path().join("vendor");
    let store_root = fixture.path().join("store");
    let external = fixture.path().join("external");
    fs::create_dir(&vendor)?;
    fs::create_dir(&store_root)?;
    fs::create_dir(&external)?;
    fs::write(vendor.join("main.js"), b"main")?;
    let observation = observe_package_tree(
        &vendor,
        PackageTreeObservationLimits::new(8, 8, 4, 128, 128, 128)?,
    )?;
    let view_root = snapshot_view_root(&store_root, observation.manifest().package_tree_merkle())?;
    let identity_root = view_root
        .parent()
        .ok_or("snapshot view root did not have an identity parent")?;
    fs::create_dir_all(identity_root)?;
    create_junction(&view_root, &external)?;
    let store = ManagedArtifactStore::open(&store_root, &vendor, ManagedStoreRootLimits::new(64)?)?;

    assert!(matches!(
        store.snapshot_package(
            &observation,
            PackageSnapshotWriteLimits::new(8, 8, 128, 128, 8)?,
        ),
        Err(PackageSnapshotError::ReparsePoint { .. })
    ));
    Ok(())
}

#[test]
fn snapshot_deduplicates_equal_files_but_retains_each_path()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let vendor = fixture.path().join("vendor");
    let store_root = fixture.path().join("store");
    fs::create_dir(&vendor)?;
    fs::create_dir(&store_root)?;
    fs::write(vendor.join("alpha.bin"), b"shared")?;
    fs::write(vendor.join("beta.bin"), b"shared")?;
    let observation = observe_package_tree(
        &vendor,
        PackageTreeObservationLimits::new(8, 8, 4, 128, 128, 128)?,
    )?;
    let store = ManagedArtifactStore::open(&store_root, &vendor, ManagedStoreRootLimits::new(64)?)?;

    let snapshot = store.snapshot_package(
        &observation,
        PackageSnapshotWriteLimits::new(8, 8, 128, 128, 8)?,
    )?;
    assert_eq!(snapshot.created_blobs(), 1);
    assert_eq!(snapshot.created_links(), 2);
    assert_eq!(snapshot.file_count(), 2);
    assert_eq!(
        fs::read(snapshot.unrestricted_physical_root().join("alpha.bin"))?,
        b"shared"
    );
    assert_eq!(
        fs::read(snapshot.unrestricted_physical_root().join("beta.bin"))?,
        b"shared"
    );
    Ok(())
}

#[test]
fn snapshot_preserves_asar_native_module_and_executable_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let vendor = fixture.path().join("vendor");
    let store_root = fixture.path().join("store");
    fs::create_dir(&vendor)?;
    fs::create_dir(&store_root)?;
    fs::write(vendor.join("app.asar"), b"asar")?;
    fs::write(vendor.join("addon.node"), b"native")?;
    fs::write(vendor.join("helper.exe"), b"executable")?;
    let observation = observe_package_tree(
        &vendor,
        PackageTreeObservationLimits::new(8, 8, 4, 128, 128, 128)?,
    )?;
    let store = ManagedArtifactStore::open(&store_root, &vendor, ManagedStoreRootLimits::new(64)?)?;

    let snapshot = store.snapshot_package(
        &observation,
        PackageSnapshotWriteLimits::new(8, 8, 128, 128, 8)?,
    )?;
    assert_eq!(
        fs::read(snapshot.unrestricted_physical_root().join("app.asar"))?,
        b"asar"
    );
    assert_eq!(
        fs::read(snapshot.unrestricted_physical_root().join("addon.node"))?,
        b"native"
    );
    assert_eq!(
        fs::read(snapshot.unrestricted_physical_root().join("helper.exe"))?,
        b"executable"
    );
    Ok(())
}

#[test]
fn empty_package_snapshot_has_a_retained_empty_root() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let vendor = fixture.path().join("vendor");
    let store_root = fixture.path().join("store");
    fs::create_dir(&vendor)?;
    fs::create_dir(&store_root)?;
    let observation = observe_package_tree(
        &vendor,
        PackageTreeObservationLimits::new(8, 8, 4, 128, 128, 128)?,
    )?;
    let store = ManagedArtifactStore::open(&store_root, &vendor, ManagedStoreRootLimits::new(64)?)?;

    let snapshot = store.snapshot_package(
        &observation,
        PackageSnapshotWriteLimits::new(8, 8, 128, 128, 8)?,
    )?;
    assert_eq!(snapshot.file_count(), 0);
    assert_eq!(snapshot.directory_count(), 1);
    assert_eq!(snapshot.total_file_bytes(), 0);
    assert_eq!(
        fs::read_dir(snapshot.unrestricted_physical_root())?.count(),
        0
    );
    Ok(())
}

#[test]
fn snapshot_limits_must_be_nonzero() {
    assert!(matches!(
        PackageSnapshotWriteLimits::new(0, 1, 1, 1, 1),
        Err(PackageSnapshotError::InvalidLimits)
    ));
    assert!(matches!(
        PackageSnapshotLeaseLimits::new(1, 1, 1, 0),
        Err(PackageSnapshotError::InvalidLimits)
    ));
}

#[test]
fn snapshot_lease_rejects_windows_ambiguous_manifest_paths()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let vendor = fixture.path().join("vendor");
    let store_root = fixture.path().join("store");
    fs::create_dir(&vendor)?;
    fs::create_dir(&store_root)?;
    let store = ManagedArtifactStore::open(&store_root, &vendor, ManagedStoreRootLimits::new(64)?)?;

    for normalized_path in ["ambiguous.", "COM¹.txt", "LPT².log"] {
        let manifest = build_package_manifest(vec![PackageFileRecord {
            normalized_path: normalized_path.to_owned(),
            size: 1,
            sha256: Sha256Digest::from_bytes([7; 32]),
            executable: false,
            kind: PackageFileKind::Regular,
            signer_thumbprint: None,
        }])?;
        assert!(matches!(
            store.lease_package_snapshot(
                &manifest,
                PackageSnapshotLeaseLimits::new(8, 8, 128, 128)?,
            ),
            Err(PackageSnapshotError::UnsafeWindowsPath { .. })
        ));
    }
    assert!(!store_root.join("package-views").exists());
    Ok(())
}

fn assert_manifest_scoped_reader_ignores_injected_children(
    snapshot: &weregopher_transform::PackageSnapshotLease<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut listed = snapshot.open_file("main.js")?;
    let mut listed_bytes = Vec::new();
    listed.read_to_end(&mut listed_bytes)?;
    assert_eq!(listed_bytes, b"main");
    for unknown in ["injected.bin", "../main.js"] {
        assert!(matches!(
            snapshot.open_file(unknown),
            Err(PackageSnapshotError::UnknownFile { .. })
        ));
    }
    Ok(())
}

fn snapshot_view_root(
    store_root: &Path,
    digest: &weregopher_domain::Sha256Digest,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let digest = digest.to_string();
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or("SHA-256 text did not have its canonical prefix")?;
    Ok(store_root
        .join("package-views")
        .join(format!("sha256-{hex}"))
        .join("tree"))
}

fn create_junction(link: &Path, target: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("cmd")
        .args(["/D", "/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err("mklink /J failed".into())
    }
}
