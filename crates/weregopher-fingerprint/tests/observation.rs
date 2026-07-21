//! Windows package-file observation tests.

#![cfg(windows)]

use std::{
    fs,
    fs::OpenOptions,
    os::windows::fs::{OpenOptionsExt as _, symlink_file},
};

use tempfile::tempdir;
use weregopher_fingerprint::{
    ObservationError, ObservationLimits, PackageFileKind, observe_package_file,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};

#[test]
fn observation_hashes_a_locked_regular_file() -> Result<(), Box<dyn std::error::Error>> {
    const CONTENT: &[u8] = b"electron-package";

    let root = tempdir()?;
    let source = root.path().join("app.asar");
    let renamed = root.path().join("renamed.asar");
    fs::write(&source, CONTENT)?;

    let observation = observe_package_file(
        &source,
        "resources/app.asar",
        ObservationLimits::new(1_024)?,
    )?;
    let record = observation.record();
    assert_eq!(record.normalized_path, "resources/app.asar");
    assert_eq!(record.size, CONTENT.len() as u64);
    assert_eq!(record.kind, PackageFileKind::Asar);
    assert!(!record.executable);
    assert_eq!(
        record.sha256.to_string(),
        "sha256:28d30fb0f9687c1e532ef02947e6863010ca96df3432324875b0c862485dfb57"
    );

    assert!(OpenOptions::new().write(true).open(&source).is_err());
    assert!(fs::rename(&source, &renamed).is_err());

    drop(observation);
    fs::rename(&source, &renamed)?;
    Ok(())
}

#[test]
fn observation_accepts_empty_and_exact_limit_files() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempdir()?;
    for (name, contents, limit) in [
        ("empty.bin", &b""[..], 1_u64),
        ("exact.bin", &b"four"[..], 4_u64),
    ] {
        let path = root.path().join(name);
        fs::write(&path, contents)?;
        let observation = observe_package_file(&path, name, ObservationLimits::new(limit)?)?;
        assert_eq!(observation.record().size, contents.len() as u64);
    }
    Ok(())
}

#[test]
fn observation_rejects_invalid_limits_paths_and_entry_types()
-> Result<(), Box<dyn std::error::Error>> {
    assert!(matches!(
        ObservationLimits::new(0),
        Err(ObservationError::InvalidLimits)
    ));

    let root = tempdir()?;
    let source = root.path().join("main.js");
    fs::write(&source, b"bounded")?;

    assert!(matches!(
        observe_package_file(&source, "main.js", ObservationLimits::new(4)?),
        Err(ObservationError::FileTooLarge { .. })
    ));
    assert!(matches!(
        observe_package_file(&source, "../main.js", ObservationLimits::new(64)?),
        Err(ObservationError::InvalidRecord(_))
    ));
    assert!(matches!(
        observe_package_file(root.path(), "directory", ObservationLimits::new(64)?),
        Err(ObservationError::NotRegularFile { .. })
    ));
    Ok(())
}

#[test]
fn observation_refuses_a_file_already_open_for_writing() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempdir()?;
    let source = root.path().join("main.js");
    fs::write(&source, b"mutable")?;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    let _writer = options.open(&source)?;

    assert!(matches!(
        observe_package_file(&source, "main.js", ObservationLimits::new(64)?),
        Err(ObservationError::Io { .. })
    ));
    Ok(())
}

#[test]
fn observation_does_not_follow_a_symbolic_link() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempdir()?;
    let target = root.path().join("target.js");
    let link = root.path().join("link.js");
    fs::write(&target, b"target")?;
    symlink_file(&target, &link)?;

    assert!(matches!(
        observe_package_file(&link, "link.js", ObservationLimits::new(64)?),
        Err(ObservationError::ReparsePoint { .. })
    ));
    Ok(())
}

#[test]
fn retained_observation_blocks_parent_path_rebinding() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempdir()?;
    let package = root.path().join("package");
    let displaced = root.path().join("displaced");
    let source = package.join("main.js");
    fs::create_dir(&package)?;
    fs::write(&source, b"original")?;

    let observation = observe_package_file(&source, "main.js", ObservationLimits::new(64)?)?;
    observation.verify_current_path(&source)?;
    assert!(fs::rename(&package, &displaced).is_err());

    drop(observation);
    fs::rename(&package, &displaced)?;
    Ok(())
}

#[test]
fn final_path_check_uses_full_file_identity() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempdir()?;
    let source = root.path().join("source.js");
    let hard_link = root.path().join("hard-link.js");
    let distinct = root.path().join("distinct.js");
    fs::write(&source, b"identical bytes")?;
    fs::hard_link(&source, &hard_link)?;
    fs::write(&distinct, b"identical bytes")?;

    let observation = observe_package_file(&source, "source.js", ObservationLimits::new(64)?)?;
    observation.verify_current_path(&hard_link)?;
    assert!(matches!(
        observation.verify_current_path(&distinct),
        Err(ObservationError::PathIdentityChanged { .. })
    ));
    Ok(())
}
