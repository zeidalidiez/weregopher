//! Windows placement regressions for the managed transform-artifact store.

#![cfg(windows)]

use std::{fs, path::Path, process::Command};

use tempfile::tempdir;
use weregopher_transform::{
    ManagedArtifactLeaseLimits, ManagedArtifactStore, ManagedStoreRootLimits,
    MaterializationStoreError, MaterializationWriteLimits,
};

#[test]
fn managed_store_limits_and_root_paths_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    assert!(matches!(
        ManagedStoreRootLimits::new(0),
        Err(MaterializationStoreError::InvalidLimits)
    ));
    for limits in [(0, 1, 1, 1), (1, 0, 1, 1), (1, 1, 0, 1), (1, 1, 1, 0)] {
        assert!(matches!(
            MaterializationWriteLimits::new(limits.0, limits.1, limits.2, limits.3),
            Err(MaterializationStoreError::InvalidLimits)
        ));
    }
    for limits in [(0, 1, 1), (1, 0, 1), (1, 1, 0)] {
        assert!(matches!(
            ManagedArtifactLeaseLimits::new(limits.0, limits.1, limits.2),
            Err(MaterializationStoreError::InvalidLimits)
        ));
    }

    let fixture = tempdir()?;
    let vendor = fixture.path().join("vendor");
    fs::create_dir(&vendor)?;
    assert!(matches!(
        ManagedArtifactStore::open(
            Path::new("relative-store"),
            &vendor,
            ManagedStoreRootLimits::new(32)?,
        ),
        Err(MaterializationStoreError::InvalidRootPath {
            kind: "managed store",
            ..
        })
    ));
    Ok(())
}

#[test]
fn managed_store_root_must_be_disjoint_from_vendor_tree() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = tempdir()?;
    let outer = fixture.path().join("outer");
    let inner = outer.join("inner");
    fs::create_dir(&outer)?;
    fs::create_dir(&inner)?;
    let limits = ManagedStoreRootLimits::new(64)?;

    assert!(matches!(
        ManagedArtifactStore::open(&outer, &outer, limits),
        Err(MaterializationStoreError::StoreOverlapsVendor)
    ));
    assert!(matches!(
        ManagedArtifactStore::open(&inner, &outer, limits),
        Err(MaterializationStoreError::StoreOverlapsVendor)
    ));
    assert!(matches!(
        ManagedArtifactStore::open(&outer, &inner, limits),
        Err(MaterializationStoreError::StoreOverlapsVendor)
    ));
    Ok(())
}

#[test]
fn managed_store_root_rejects_junction_components() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let external = fixture.path().join("external");
    let vendor = fixture.path().join("vendor");
    let junction = fixture.path().join("junction");
    fs::create_dir(&external)?;
    fs::create_dir(&vendor)?;
    fs::create_dir(external.join("store"))?;
    create_junction(&junction, &external)?;

    assert!(matches!(
        ManagedArtifactStore::open(
            &junction.join("store"),
            &vendor,
            ManagedStoreRootLimits::new(64)?,
        ),
        Err(MaterializationStoreError::ReparsePoint { .. })
    ));
    Ok(())
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
