//! Windows complete-tree observation tests.

#![cfg(windows)]

use std::{
    fs::{self, OpenOptions},
    io::Read as _,
    os::windows::fs::OpenOptionsExt as _,
    path::Path,
    process::Command,
};

use tempfile::tempdir;
use weregopher_fingerprint::{
    MAX_PACKAGE_FILE_RECORDS, MAX_PACKAGE_RECORD_PATH_BYTES, MAX_PACKAGE_TREE_DEPTH,
    MAX_PACKAGE_TREE_DIRECTORIES, ObservationError, PackageTreeObservationError,
    PackageTreeObservationLimits, observe_package_tree,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};

#[test]
fn tree_observation_retains_a_complete_nested_regular_file_tree()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let package = fixture.path().join("package");
    let resources = package.join("resources");
    let native = resources.join("native");
    fs::create_dir_all(&native)?;
    fs::write(package.join("main.js"), b"main")?;
    fs::write(resources.join("app.asar"), b"archive")?;
    fs::write(native.join("addon.node"), b"native")?;

    let observation = observe_package_tree(
        &package,
        PackageTreeObservationLimits::new(16, 16, 8, 1_024, 4_096, 4_096)?,
    )?;

    assert_eq!(observation.file_count(), 3);
    assert_eq!(observation.directory_count(), 3);
    assert_eq!(observation.total_file_bytes(), 17);
    assert_eq!(
        observation
            .manifest()
            .files()
            .iter()
            .map(|record| record.normalized_path.as_str())
            .collect::<Vec<_>>(),
        [
            "main.js",
            "resources/app.asar",
            "resources/native/addon.node",
        ]
    );
    observation.verify_current_tree()?;

    assert!(fs::write(package.join("main.js"), b"changed").is_err());
    let displaced = fixture.path().join("displaced");
    assert!(fs::rename(&package, &displaced).is_err());

    drop(observation);
    fs::rename(&package, &displaced)?;
    Ok(())
}

#[test]
fn tree_observation_reports_the_specific_file_limit() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let package = fixture.path().join("package");
    fs::create_dir(&package)?;
    fs::write(package.join("first.js"), b"first")?;
    fs::write(package.join("second.js"), b"second")?;
    fs::write(package.join("third.js"), b"third")?;

    assert!(matches!(
        observe_package_tree(
            &package,
            PackageTreeObservationLimits::new(1, 1, 2, 64, 128, 128)?,
        ),
        Err(PackageTreeObservationError::FileLimitExceeded { max: 1 })
    ));
    Ok(())
}

#[test]
fn tree_observation_rejects_a_preexisting_writable_directory_handle()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let package = fixture.path().join("package");
    fs::create_dir(&package)?;
    fs::write(package.join("main.js"), b"main")?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    let _writable_directory = options.open(&package)?;

    assert!(matches!(
        observe_package_tree(&package, generous_limits()?),
        Err(PackageTreeObservationError::Io { .. })
    ));
    Ok(())
}

#[test]
fn tree_observation_opens_an_exact_leased_file_reader() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let package = fixture.path().join("package");
    let expected = b"exact bytes";
    fs::create_dir(&package)?;
    fs::write(package.join("main.js"), expected)?;

    let observation = observe_package_tree(&package, generous_limits()?)?;
    let mut reader = observation.open_file("main.js")?;
    assert_eq!(reader.remaining(), expected.len() as u64);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    assert_eq!(bytes, expected);
    assert_eq!(reader.remaining(), 0);
    assert!(matches!(
        observation.open_file("missing.js"),
        Err(PackageTreeObservationError::UnknownFile { .. })
    ));
    Ok(())
}

#[test]
fn tree_limits_reject_zero_and_above_ceiling_values() {
    assert!(matches!(
        PackageTreeObservationLimits::new(0, 1, 1, 1, 1, 1),
        Err(PackageTreeObservationError::InvalidLimits { .. })
    ));
    assert!(matches!(
        PackageTreeObservationLimits::new(MAX_PACKAGE_FILE_RECORDS + 1, 1, 1, 1, 1, 1),
        Err(PackageTreeObservationError::InvalidLimits { .. })
    ));
    assert!(matches!(
        PackageTreeObservationLimits::new(1, 1, 1, 1, 1, MAX_PACKAGE_RECORD_PATH_BYTES + 1,),
        Err(PackageTreeObservationError::InvalidLimits { .. })
    ));
    assert!(matches!(
        PackageTreeObservationLimits::new(1, MAX_PACKAGE_TREE_DIRECTORIES + 1, 1, 1, 1, 1,),
        Err(PackageTreeObservationError::InvalidLimits { .. })
    ));
    assert!(matches!(
        PackageTreeObservationLimits::new(1, 1, MAX_PACKAGE_TREE_DEPTH + 1, 1, 1, 1),
        Err(PackageTreeObservationError::InvalidLimits { .. })
    ));
}

#[test]
fn tree_observation_accepts_an_empty_package_root() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let package = fixture.path().join("package");
    fs::create_dir(&package)?;

    let observation = observe_package_tree(&package, generous_limits()?)?;
    assert!(observation.manifest().is_empty());
    assert_eq!(observation.directory_count(), 1);
    observation.verify_current_tree()?;
    Ok(())
}

#[test]
fn tree_observation_rejects_a_nested_empty_directory() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let package = fixture.path().join("package");
    fs::create_dir_all(package.join("empty"))?;
    fs::write(package.join("main.js"), b"main")?;

    assert!(matches!(
        observe_package_tree(&package, generous_limits()?),
        Err(PackageTreeObservationError::EmptyDirectory { .. })
    ));
    Ok(())
}

#[test]
fn tree_observation_rejects_root_and_descendant_junctions() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = tempdir()?;
    let outside = fixture.path().join("outside");
    fs::create_dir(&outside)?;
    fs::write(outside.join("outside.js"), b"outside")?;

    let root_junction = fixture.path().join("root-junction");
    create_junction(&root_junction, &outside)?;
    assert!(matches!(
        observe_package_tree(&root_junction, generous_limits()?),
        Err(PackageTreeObservationError::ReparsePoint { .. })
    ));

    let direct_root = outside.join("direct-root");
    fs::create_dir(&direct_root)?;
    fs::write(direct_root.join("main.js"), b"main")?;
    assert!(matches!(
        observe_package_tree(&root_junction.join("direct-root"), generous_limits()?),
        Err(PackageTreeObservationError::ReparsePoint { .. })
    ));

    let package = fixture.path().join("package");
    fs::create_dir(&package)?;
    fs::write(package.join("main.js"), b"main")?;
    create_junction(&package.join("outside"), &outside)?;
    assert!(matches!(
        observe_package_tree(&package, generous_limits()?),
        Err(PackageTreeObservationError::ReparsePoint { .. })
    ));
    Ok(())
}

#[test]
fn tree_observation_is_independent_of_filesystem_creation_order()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let first = fixture.path().join("first");
    let second = fixture.path().join("second");
    fs::create_dir(&first)?;
    fs::create_dir(&second)?;

    for (name, bytes) in [("alpha.js", b"alpha".as_slice()), ("zeta.js", b"zeta")] {
        fs::write(first.join(name), bytes)?;
    }
    for (name, bytes) in [("zeta.js", b"zeta".as_slice()), ("alpha.js", b"alpha")] {
        fs::write(second.join(name), bytes)?;
    }

    let first_observation = observe_package_tree(&first, generous_limits()?)?;
    let second_observation = observe_package_tree(&second, generous_limits()?)?;
    assert_eq!(first_observation.manifest(), second_observation.manifest());
    Ok(())
}

#[test]
fn tree_observation_detects_new_directory_membership() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let package = fixture.path().join("package");
    fs::create_dir(&package)?;
    fs::write(package.join("main.js"), b"main")?;

    let observation = observe_package_tree(&package, generous_limits()?)?;
    fs::write(package.join("late.js"), b"late")?;
    assert!(matches!(
        observation.verify_current_tree(),
        Err(PackageTreeObservationError::ChangedDuringObservation { .. })
    ));
    Ok(())
}

#[test]
fn tree_observation_enforces_directory_and_depth_limits() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = tempdir()?;
    let package = fixture.path().join("package");
    fs::create_dir_all(package.join("nested"))?;
    fs::write(package.join("nested").join("main.js"), b"main")?;

    assert!(matches!(
        observe_package_tree(
            &package,
            PackageTreeObservationLimits::new(8, 1, 8, 64, 128, 128)?,
        ),
        Err(PackageTreeObservationError::DirectoryLimitExceeded { max: 1 })
    ));
    assert!(matches!(
        observe_package_tree(
            &package,
            PackageTreeObservationLimits::new(8, 8, 1, 64, 128, 128)?,
        ),
        Err(PackageTreeObservationError::DepthLimitExceeded {
            actual: 2,
            max: 1,
            ..
        })
    ));
    Ok(())
}

#[test]
fn tree_observation_enforces_per_file_and_aggregate_byte_limits()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let package = fixture.path().join("package");
    fs::create_dir(&package)?;
    fs::write(package.join("first.bin"), b"four")?;
    fs::write(package.join("second.bin"), b"more")?;

    assert!(matches!(
        observe_package_tree(
            &package,
            PackageTreeObservationLimits::new(8, 1, 2, 3, 128, 128)?,
        ),
        Err(PackageTreeObservationError::FileObservation {
            source: ObservationError::FileTooLarge { limit: 3, .. }
        })
    ));
    assert!(matches!(
        observe_package_tree(
            &package,
            PackageTreeObservationLimits::new(8, 1, 2, 8, 7, 128)?,
        ),
        Err(PackageTreeObservationError::TotalFileBytesExceeded { max: 7, .. })
    ));
    Ok(())
}

#[test]
fn tree_observation_accepts_zero_byte_files_at_the_exact_aggregate_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let package = fixture.path().join("package");
    fs::create_dir(&package)?;
    fs::write(package.join("full.bin"), b"x")?;
    fs::write(package.join("zero.bin"), b"")?;

    let observation = observe_package_tree(
        &package,
        PackageTreeObservationLimits::new(2, 1, 1, 1, 1, 128)?,
    )?;
    assert_eq!(observation.file_count(), 2);
    assert_eq!(observation.total_file_bytes(), 1);
    Ok(())
}

#[test]
fn tree_observation_enforces_aggregate_path_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let package = fixture.path().join("package");
    fs::create_dir(&package)?;
    fs::write(package.join("main.js"), b"main")?;

    assert!(matches!(
        observe_package_tree(
            &package,
            PackageTreeObservationLimits::new(1, 1, 1, 8, 8, 6)?,
        ),
        Err(PackageTreeObservationError::PathBytesExceeded { max: 6 })
    ));
    Ok(())
}

#[test]
fn tree_observation_rejects_relative_roots_and_redacts_absolute_paths()
-> Result<(), Box<dyn std::error::Error>> {
    assert!(matches!(
        observe_package_tree(Path::new("relative"), generous_limits()?),
        Err(PackageTreeObservationError::InvalidRootPath { .. })
    ));

    let fixture = tempdir()?;
    let package = fixture.path().join("package-secret-name");
    fs::create_dir(&package)?;
    fs::write(package.join("main.js"), b"main")?;
    let observation = observe_package_tree(&package, generous_limits()?)?;
    let debug = format!("{observation:?}");
    assert!(!debug.contains(&package.display().to_string()));
    assert!(!debug.contains("main.js"));
    assert!(debug.contains("file_count"));
    Ok(())
}

fn generous_limits() -> Result<PackageTreeObservationLimits, PackageTreeObservationError> {
    PackageTreeObservationLimits::new(64, 64, 16, 4_096, 64 * 4_096, 16_384)
}

fn create_junction(link: &Path, target: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("cmd")
        .args(["/D", "/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err("mklink /J failed".into())
    }
}
