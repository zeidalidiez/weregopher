//! Behavior tests for canonical package scanning.

use std::fs;

use tempfile::tempdir;
#[cfg(unix)]
use weregopher_fingerprint::ManifestError;
use weregopher_fingerprint::{
    FingerprintError, FingerprintOptions, PackageTreeManifest, fingerprint_package,
};

#[test]
fn scanner_allows_an_empty_package_root() -> Result<(), Box<dyn std::error::Error>> {
    let package = tempdir()?;

    let manifest = fingerprint_package(package.path(), &FingerprintOptions::default())?;
    let bytes = serde_json::to_vec(&manifest)?;
    let round_tripped: PackageTreeManifest = serde_json::from_slice(&bytes)?;

    assert!(manifest.is_empty());
    assert_eq!(round_tripped, manifest);
    Ok(())
}

#[test]
fn scanner_output_round_trips_through_the_canonical_transport()
-> Result<(), Box<dyn std::error::Error>> {
    let package = tempdir()?;
    fs::create_dir(package.path().join("resources"))?;
    fs::write(
        package.path().join("resources/app.asar"),
        b"fixture package bytes",
    )?;

    let manifest = fingerprint_package(package.path(), &FingerprintOptions::default())?;
    let bytes = serde_json::to_vec(&manifest)?;
    let round_tripped: PackageTreeManifest = serde_json::from_slice(&bytes)?;

    assert_eq!(round_tripped, manifest);
    Ok(())
}

#[test]
fn scanner_rejects_a_nested_empty_directory() -> Result<(), Box<dyn std::error::Error>> {
    let package = tempdir()?;
    fs::create_dir(package.path().join("empty"))?;

    let Err(error) = fingerprint_package(package.path(), &FingerprintOptions::default()) else {
        return Err("scanner accepted a directory that manifest format v1 cannot represent".into());
    };
    assert!(matches!(
        error,
        FingerprintError::EmptyDirectory { normalized_path }
            if normalized_path == "empty"
    ));
    Ok(())
}

#[cfg(unix)]
#[test]
fn scanner_rejects_a_noncanonical_unix_entry_name() -> Result<(), Box<dyn std::error::Error>> {
    let package = tempdir()?;
    fs::write(package.path().join("bad:name"), b"fixture")?;

    let Err(error) = fingerprint_package(package.path(), &FingerprintOptions::default()) else {
        return Err("scanner emitted a package path rejected by its canonical transport".into());
    };
    assert!(matches!(
        error,
        FingerprintError::Manifest {
            source: ManifestError::InvalidPath { path },
        } if path == "bad:name"
    ));
    Ok(())
}
