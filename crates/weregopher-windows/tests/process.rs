//! Race-free Windows Job Object process-launch regressions.

#![cfg(windows)]

use std::{
    ffi::OsString, fs, io, os::windows::ffi::OsStrExt as _, path::Path, process::Command,
    time::Duration,
};

use tempfile::tempdir;
use weregopher_windows::{
    FileIdentityLease, JobLimits, KillOnCloseJob, LockedExecutable, ProcessLaunchLimits,
};

const PROCESS_MEMORY_LIMIT: u64 = 512 * 1024 * 1024;
const JOB_MEMORY_LIMIT: u64 = 1024 * 1024 * 1024;

#[test]
fn launch_limits_and_executable_paths_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    for limits in [
        ProcessLaunchLimits::new(0, 32, 64),
        ProcessLaunchLimits::new(1, 0, 64),
        ProcessLaunchLimits::new(1, 32, 0),
        ProcessLaunchLimits::new(1, 65, 64),
        ProcessLaunchLimits::new(1, 32, 32_768),
    ] {
        assert!(matches!(limits, Err(ref error) if error.kind() == io::ErrorKind::InvalidInput));
    }
    assert!(matches!(
        LockedExecutable::open(Path::new("relative.exe"), 8),
        Err(ref error) if error.kind() == io::ErrorKind::InvalidInput
    ));
    assert!(matches!(
        LockedExecutable::open(&std::env::current_exe()?, 0),
        Err(ref error) if error.kind() == io::ErrorKind::InvalidInput
    ));

    let executable_path = std::env::current_exe()?;
    assert!(matches!(
        LockedExecutable::open(&executable_path, 1),
        Err(ref error) if error.kind() == io::ErrorKind::InvalidInput
    ));

    let launch_error =
        KillOnCloseJob::create(JobLimits::new(1, PROCESS_MEMORY_LIMIT, JOB_MEMORY_LIMIT)?)?.launch(
            LockedExecutable::open(&executable_path, 64)?,
            &[OsString::from("one"), OsString::from("two")],
            ProcessLaunchLimits::new(1, 128, 1024)?,
        );
    assert!(matches!(
        launch_error,
        Err(ref error) if error.kind() == io::ErrorKind::InvalidInput
    ));

    let launch_error =
        KillOnCloseJob::create(JobLimits::new(1, PROCESS_MEMORY_LIMIT, JOB_MEMORY_LIMIT)?)?.launch(
            LockedExecutable::open(&executable_path, 64)?,
            &[OsString::from("12345")],
            ProcessLaunchLimits::new(1, 4, 128)?,
        );
    assert!(matches!(
        launch_error,
        Err(ref error) if error.kind() == io::ErrorKind::InvalidInput
    ));

    let executable_units = executable_path.as_os_str().encode_wide().count();
    let command_line_limit = executable_units
        .checked_add(4)
        .ok_or("path length overflow")?;
    let launch_error =
        KillOnCloseJob::create(JobLimits::new(1, PROCESS_MEMORY_LIMIT, JOB_MEMORY_LIMIT)?)?.launch(
            LockedExecutable::open(&executable_path, 64)?,
            &[OsString::from("1234")],
            ProcessLaunchLimits::new(1, executable_units, command_line_limit)?,
        );
    assert!(matches!(
        launch_error,
        Err(ref error) if error.kind() == io::ErrorKind::InvalidInput
    ));
    Ok(())
}

#[test]
fn locked_executable_rejects_a_junction_ancestor() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let external = fixture.path().join("external");
    let junction = fixture.path().join("junction");
    fs::create_dir(&external)?;
    let executable = external.join("helper.exe");
    fs::copy(std::env::current_exe()?, &executable)?;
    create_junction(&junction, &external)?;

    assert!(matches!(
        LockedExecutable::open(&junction.join("helper.exe"), 64),
        Err(ref error) if error.kind() == io::ErrorKind::InvalidInput
    ));
    Ok(())
}

#[test]
fn locked_executable_must_match_the_retained_file_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempdir()?;
    let expected_path = fixture.path().join("expected.exe");
    let substituted_path = fixture.path().join("substituted.exe");
    fs::copy(std::env::current_exe()?, &expected_path)?;
    fs::copy(std::env::current_exe()?, &substituted_path)?;
    let expected_identity = FileIdentityLease::from_file(fs::File::open(&expected_path)?)?;

    let locked = LockedExecutable::open_matching_identity(&expected_path, 64, &expected_identity)?;
    assert!(!format!("{locked:?}").contains(&expected_path.display().to_string()));
    assert!(matches!(
        LockedExecutable::open_matching_identity(&substituted_path, 64, &expected_identity),
        Err(ref error) if error.kind() == io::ErrorKind::InvalidData
    ));

    let prepared = locked.prepare_launch(&[], ProcessLaunchLimits::new(1, 1_024, 2_048)?)?;
    let mismatch =
        KillOnCloseJob::create(JobLimits::new(1, PROCESS_MEMORY_LIMIT, JOB_MEMORY_LIMIT)?)?
            .launch_prepared(LockedExecutable::open(&substituted_path, 64)?, prepared);
    assert!(matches!(
        mismatch,
        Err(ref error) if error.kind() == io::ErrorKind::InvalidInput
    ));
    Ok(())
}

#[test]
fn process_is_job_owned_before_the_primary_thread_runs() -> Result<(), Box<dyn std::error::Error>> {
    let executable_path = std::env::current_exe()?;
    let executable = LockedExecutable::open(&executable_path, 64)?;
    assert!(!format!("{executable:?}").contains(&executable_path.display().to_string()));

    let job = KillOnCloseJob::create(JobLimits::new(1, PROCESS_MEMORY_LIMIT, JOB_MEMORY_LIMIT)?)?;
    let process = job.launch(
        executable,
        &[
            OsString::from("--ignored"),
            OsString::from("--exact"),
            OsString::from("owned_launch_child_helper"),
            OsString::from("--test-threads=1"),
        ],
        ProcessLaunchLimits::new(4, 128, 1024)?,
    )?;

    assert!(process.id() != 0);
    assert!(process.is_in_job()?);
    assert_eq!(
        process.job_limits(),
        JobLimits::new(1, PROCESS_MEMORY_LIMIT, JOB_MEMORY_LIMIT)?
    );
    assert!(!format!("{process:?}").contains(&executable_path.display().to_string()));
    assert!(matches!(
        process.wait_for(Duration::from_millis(u64::from(u32::MAX))),
        Err(ref error) if error.kind() == io::ErrorKind::InvalidInput
    ));
    process.terminate(73)?;
    assert_eq!(process.wait_for(Duration::from_secs(5))?, Some(73));
    Ok(())
}

#[test]
fn resumed_process_runs_with_an_explicit_empty_environment()
-> Result<(), Box<dyn std::error::Error>> {
    let executable = LockedExecutable::open(&std::env::current_exe()?, 64)?;
    let job = KillOnCloseJob::create(JobLimits::new(1, PROCESS_MEMORY_LIMIT, JOB_MEMORY_LIMIT)?)?;
    let process = job.launch(
        executable,
        &[
            OsString::from("--ignored"),
            OsString::from("--exact"),
            OsString::from("empty_environment_child_helper"),
            OsString::from("--test-threads=1"),
        ],
        ProcessLaunchLimits::new(4, 128, 1024)?,
    )?;

    assert_eq!(process.wait_for(Duration::from_secs(5))?, Some(0));
    Ok(())
}

#[test]
#[ignore = "spawned by the suspended-launch integration tests"]
fn owned_launch_child_helper() {
    std::thread::sleep(Duration::from_mins(1));
}

#[test]
#[ignore = "spawned by the suspended-launch integration tests"]
fn empty_environment_child_helper() {
    if std::env::vars_os().next().is_some() {
        std::process::exit(74);
    }
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
