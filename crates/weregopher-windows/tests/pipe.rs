//! Current-user named-pipe transport regressions.

#![cfg(windows)]

use std::{
    io::{Read as _, Write as _},
    process::Command,
    time::Duration,
};

use weregopher_windows::{
    CurrentUserNamedPipeServer, JobLimits, KillOnCloseJob, NamedPipeAddress, connect_named_pipe,
};

const PROCESS_MEMORY_LIMIT: u64 = 256 * 1024 * 1024;
const JOB_MEMORY_LIMIT: u64 = 512 * 1024 * 1024;

#[test]
fn generated_addresses_are_canonical_and_unpredictable() -> Result<(), Box<dyn std::error::Error>> {
    let first = NamedPipeAddress::generate();
    let second = NamedPipeAddress::generate();
    assert_ne!(first, second);
    assert_eq!(first.as_str().parse::<NamedPipeAddress>()?, first);
    for invalid in [
        r"\\server\pipe\weregopher-runtime-00000000-0000-4000-8000-000000000000",
        r"\\.\pipe\other-00000000-0000-4000-8000-000000000000",
        r"\\.\pipe\weregopher-runtime-not-a-uuid",
        r"\\.\pipe\weregopher-runtime-00000000-0000-1000-8000-000000000000",
    ] {
        assert!(invalid.parse::<NamedPipeAddress>().is_err());
    }
    Ok(())
}

#[test]
fn server_accepts_only_the_expected_same_user_job_member() -> Result<(), Box<dyn std::error::Error>>
{
    let server = CurrentUserNamedPipeServer::bind(64 * 1024)?;
    let address = server.address().clone();
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "named_pipe_child_helper",
            "--test-threads=1",
            "--",
            address.as_str(),
        ])
        .spawn()?;
    let job = KillOnCloseJob::create(JobLimits::new(1, PROCESS_MEMORY_LIMIT, JOB_MEMORY_LIMIT)?)?;
    job.assign_child(&child)?;
    let mut connection = server.accept(&child, &job, Duration::from_secs(5))?;
    assert_eq!(connection.peer_process_id(), child.id());

    let mut request = [0_u8; 4];
    connection.read_exact(&mut request)?;
    assert_eq!(&request, b"ping");
    connection.write_all(b"pong")?;
    connection.flush()?;
    assert!(child.wait()?.success());
    Ok(())
}

#[test]
fn server_rejects_an_expected_process_outside_its_job() -> Result<(), Box<dyn std::error::Error>> {
    let server = CurrentUserNamedPipeServer::bind(64 * 1024)?;
    let address = server.address().clone();
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "named_pipe_child_helper",
            "--test-threads=1",
            "--",
            address.as_str(),
        ])
        .spawn()?;
    let unrelated_job =
        KillOnCloseJob::create(JobLimits::new(1, PROCESS_MEMORY_LIMIT, JOB_MEMORY_LIMIT)?)?;
    let result = server.accept(&child, &unrelated_job, Duration::from_secs(5));
    assert!(matches!(
        result,
        Err(ref error) if error.kind() == std::io::ErrorKind::PermissionDenied
    ));
    child.kill()?;
    let _ = child.wait()?;
    Ok(())
}

#[test]
#[ignore = "spawned by named-pipe integration tests"]
fn named_pipe_child_helper() -> Result<(), Box<dyn std::error::Error>> {
    let address = std::env::args()
        .next_back()
        .ok_or("missing named-pipe address")?
        .parse::<NamedPipeAddress>()?;
    let mut connection = connect_named_pipe(&address, Duration::from_secs(5))?;
    connection.write_all(b"ping")?;
    connection.flush()?;
    let mut response = [0_u8; 4];
    connection.read_exact(&mut response)?;
    if &response != b"pong" {
        return Err("unexpected named-pipe response".into());
    }
    Ok(())
}
