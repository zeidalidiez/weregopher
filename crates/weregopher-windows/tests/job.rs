//! Windows Job Object lifecycle and limit regressions.

#![cfg(windows)]

use std::{
    io,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use weregopher_windows::{JobLimits, KillOnCloseJob};

const PROCESS_MEMORY_LIMIT: u64 = 512 * 1024 * 1024;
const JOB_MEMORY_LIMIT: u64 = 1024 * 1024 * 1024;

#[test]
fn job_limits_reject_zero_inverted_and_unrepresentable_memory() {
    for limits in [
        JobLimits::new(0, PROCESS_MEMORY_LIMIT, JOB_MEMORY_LIMIT),
        JobLimits::new(1, 0, JOB_MEMORY_LIMIT),
        JobLimits::new(1, PROCESS_MEMORY_LIMIT, 0),
        JobLimits::new(1, JOB_MEMORY_LIMIT, PROCESS_MEMORY_LIMIT),
    ] {
        assert!(matches!(limits, Err(ref error) if error.kind() == io::ErrorKind::InvalidInput));
    }

    if usize::BITS < u64::BITS {
        let error = JobLimits::new(1, u64::MAX, u64::MAX);
        assert!(matches!(error, Err(ref source) if source.kind() == io::ErrorKind::InvalidInput));
    }
}

#[test]
fn dropping_a_job_terminates_its_assigned_child() -> Result<(), Box<dyn std::error::Error>> {
    let limits = test_limits()?;
    let job = KillOnCloseJob::create(limits)?;
    let mut child = spawn_helper()?;
    if let Err(error) = job.assign_child(&child) {
        stop_child(&mut child);
        return Err(error.into());
    }
    assert!(job.contains_child(&child)?);
    assert_eq!(job.limits(), limits);

    drop(job);
    let _ = wait_for_exit(&mut child)?;
    Ok(())
}

#[test]
fn explicit_job_termination_sets_the_child_exit_code() -> Result<(), Box<dyn std::error::Error>> {
    let job = KillOnCloseJob::create(test_limits()?)?;
    let mut child = spawn_helper()?;
    if let Err(error) = job.assign_child(&child) {
        stop_child(&mut child);
        return Err(error.into());
    }

    job.terminate(73)?;
    let status = wait_for_exit(&mut child)?;
    assert_eq!(status.code(), Some(73));
    Ok(())
}

#[test]
fn active_process_limit_rejects_a_second_child() -> Result<(), Box<dyn std::error::Error>> {
    let job = KillOnCloseJob::create(test_limits()?)?;
    let mut first = spawn_helper()?;
    if let Err(error) = job.assign_child(&first) {
        stop_child(&mut first);
        return Err(error.into());
    }

    let mut second = spawn_helper()?;
    let second_assignment = job.assign_child(&second);
    drop(job);
    let _ = wait_for_exit(&mut first);
    stop_child(&mut second);

    assert!(second_assignment.is_err());
    Ok(())
}

#[test]
#[ignore = "spawned by the Job Object integration tests"]
fn job_child_helper() {
    thread::sleep(Duration::from_mins(1));
}

fn test_limits() -> io::Result<JobLimits> {
    JobLimits::new(1, PROCESS_MEMORY_LIMIT, JOB_MEMORY_LIMIT)
}

fn spawn_helper() -> io::Result<Child> {
    Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "job_child_helper",
            "--test-threads=1",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

fn wait_for_exit(child: &mut Child) -> io::Result<std::process::ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        thread::sleep(Duration::from_millis(25));
    }

    stop_child(child);
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "assigned child did not exit after its Job Object closed",
    ))
}

fn stop_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}
