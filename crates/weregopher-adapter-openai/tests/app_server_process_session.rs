//! Portable supervised app-server process-session behavior.

use std::{
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use weregopher_adapter_openai::{
    AppServerInitializationPhase, AppServerJsonLimits, AppServerProcessError,
    AppServerProcessLimits, AppServerProcessOutcome, AppServerProcessSession,
    AppServerProcessState, AppServerProxyError, AppServerProxyLimits, AppServerQueueLimits,
    AppServerShutdownMode,
};

const INITIALIZE: &[u8] = br#" { "id":"init-secret", "method":"initialize", "params":{"clientInfo":{"name":"fixture","version":"1"}}, "unknown":true } "#;
const INITIALIZE_RESPONSE: &[u8] = br#" { "id":"init-secret", "result":{"serverInfo":{"name":"fixture"},"future":{"kept":true}}, "unknownTopLevel":9 } "#;
const INITIALIZED: &[u8] =
    br#"{ "method":"initialized", "params":{}, "futureInitializedField":true }"#;
const READY_NOTIFICATION: &[u8] =
    br#"{ "method":"fixture/ready", "params":{"unknown":true}, "futureField":7 }"#;
const SERVER_REQUEST: &[u8] = br#"{"id":"server-secret","method":"approval/request","params":{"reason":"fixture","unknown":true}}"#;
const CLIENT_RESPONSE: &[u8] =
    br#"{ "id":7, "result":{"newVariant":{"preserved":true}}, "unknownResponse":11 }"#;

fn proxy_limits(
    line_bytes: usize,
    timeout: Duration,
) -> Result<AppServerProxyLimits, AppServerProxyError> {
    AppServerProxyLimits::new(
        line_bytes,
        AppServerQueueLimits::new(16, 64 * 1_024)?,
        AppServerQueueLimits::new(16, 64 * 1_024)?,
        AppServerJsonLimits::new(32, 2_048)?,
        16,
        128,
        timeout,
    )
}

fn process_limits(
    initialization_timeout: Duration,
    runtime_timeout: Duration,
    shutdown_timeout: Duration,
) -> Result<AppServerProcessLimits, AppServerProcessError> {
    AppServerProcessLimits::new(
        4,
        64,
        initialization_timeout,
        runtime_timeout,
        shutdown_timeout,
        Duration::from_secs(1),
    )
}

fn spawn_fixture(mode: &str) -> Result<Child, Box<dyn std::error::Error>> {
    Ok(
        Command::new(env!("CARGO_BIN_EXE_weregopher-app-server-fixture"))
            .arg(mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    )
}

fn attach(
    mode: &str,
    line_bytes: usize,
    initialization_timeout: Duration,
    runtime_timeout: Duration,
    shutdown_timeout: Duration,
) -> Result<AppServerProcessSession, Box<dyn std::error::Error>> {
    attach_with_request_timeout(
        mode,
        line_bytes,
        Duration::from_secs(2),
        initialization_timeout,
        runtime_timeout,
        shutdown_timeout,
    )
}

fn attach_with_request_timeout(
    mode: &str,
    line_bytes: usize,
    request_timeout: Duration,
    initialization_timeout: Duration,
    runtime_timeout: Duration,
    shutdown_timeout: Duration,
) -> Result<AppServerProcessSession, Box<dyn std::error::Error>> {
    let now = Instant::now();
    Ok(AppServerProcessSession::attach_unverified_child(
        spawn_fixture(mode)?,
        proxy_limits(line_bytes, request_timeout)?,
        process_limits(initialization_timeout, runtime_timeout, shutdown_timeout)?,
        now,
    )?)
}

fn poll_until(
    session: &mut AppServerProcessSession,
    timeout: Duration,
    predicate: impl Fn(&AppServerProcessSession) -> bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or("test deadline overflowed")?;
    while !predicate(session) {
        if Instant::now() >= deadline {
            return Err("session fixture timed out".into());
        }
        session.poll(Instant::now())?;
        thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}

fn begin_initialized_session(
    mode: &str,
) -> Result<AppServerProcessSession, Box<dyn std::error::Error>> {
    complete_initialization(attach(
        mode,
        1_024,
        Duration::from_secs(2),
        Duration::from_secs(10),
        Duration::from_millis(200),
    )?)
}

fn complete_initialization(
    mut session: AppServerProcessSession,
) -> Result<AppServerProcessSession, Box<dyn std::error::Error>> {
    assert_eq!(
        session.state(),
        AppServerProcessState::Initializing(AppServerInitializationPhase::AwaitingInitialize)
    );
    session.send_client(INITIALIZE)?;
    poll_until(&mut session, Duration::from_secs(2), |session| {
        session.diagnostics().proxy().queued_to_client_messages() > 0
    })?;
    let response = session
        .next_for_client(Instant::now())?
        .ok_or("initialize response was not forwarded")?;
    assert_eq!(response.json_bytes(), INITIALIZE_RESPONSE);
    assert_eq!(
        session.state(),
        AppServerProcessState::Initializing(AppServerInitializationPhase::AwaitingInitialized)
    );
    session.send_client(INITIALIZED)?;
    poll_until(&mut session, Duration::from_secs(2), |session| {
        session.state() == AppServerProcessState::Ready
    })?;
    Ok(session)
}

#[test]
fn session_preserves_initialization_and_bidirectional_unknown_frames()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = begin_initialized_session("normal")?;
    poll_until(&mut session, Duration::from_secs(2), |session| {
        session.diagnostics().proxy().queued_to_client_messages() >= 2
    })?;

    let notification = session
        .next_for_client(Instant::now())?
        .ok_or("fixture notification was absent")?;
    assert_eq!(notification.json_bytes(), READY_NOTIFICATION);
    let server_request = session
        .next_for_client(Instant::now())?
        .ok_or("fixture server request was absent")?;
    assert_eq!(server_request.json_bytes(), SERVER_REQUEST);

    session.send_client(
        br#"{"id":"server-secret","result":{"approved":false},"unknownClientResponse":true}"#,
    )?;
    session.send_client(
        br#"{ "id":7, "method":"future/do", "params":{"value":1}, "unknownRequest":true }"#,
    )?;
    poll_until(&mut session, Duration::from_secs(2), |session| {
        session.diagnostics().proxy().queued_to_client_messages() > 0
    })?;
    let response = session
        .next_for_client(Instant::now())?
        .ok_or("fixture response was absent")?;
    assert_eq!(response.json_bytes(), CLIENT_RESPONSE);
    assert_eq!(session.diagnostics().proxy().unmatched_responses(), 0);
    poll_until(&mut session, Duration::from_secs(2), |session| {
        session.diagnostics().stderr_bytes() > 0
    })?;
    assert!(session.diagnostics().stderr_bytes() > 0);

    session.shutdown(AppServerShutdownMode::Graceful, Instant::now())?;
    poll_until(&mut session, Duration::from_secs(2), |session| {
        session.exit_report().is_some()
    })?;
    let report = session.exit_report().ok_or("exit report was absent")?;
    assert_eq!(report.outcome(), AppServerProcessOutcome::CleanShutdown);
    assert_eq!(report.exit_code(), Some(0));
    assert!(report.was_initialized());
    assert!(report.streams_drained());
    assert_eq!(report.abandoned_writer_frames(), 0);
    Ok(())
}

#[test]
fn session_rejects_messages_outside_the_initialization_sequence()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = attach(
        "silent",
        1_024,
        Duration::from_secs(2),
        Duration::from_secs(10),
        Duration::from_millis(100),
    )?;
    assert!(matches!(
        session.send_client(br#"{"id":1,"method":"thread/list","params":{}}"#),
        Err(AppServerProcessError::InitializationSequenceViolation)
    ));
    assert_eq!(session.state(), AppServerProcessState::ShuttingDown);
    poll_until(&mut session, Duration::from_secs(2), |session| {
        session.exit_report().is_some()
    })?;
    assert_eq!(
        session
            .exit_report()
            .ok_or("protocol-failure report was absent")?
            .outcome(),
        AppServerProcessOutcome::ProtocolFailure
    );
    Ok(())
}

#[test]
fn session_requires_initialize_response_delivery_before_initialized()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = attach(
        "normal",
        1_024,
        Duration::from_secs(2),
        Duration::from_secs(10),
        Duration::from_millis(100),
    )?;
    session.send_client(INITIALIZE)?;
    poll_until(&mut session, Duration::from_secs(2), |session| {
        session.diagnostics().proxy().queued_to_client_messages() > 0
    })?;
    assert_eq!(
        session.state(),
        AppServerProcessState::Initializing(AppServerInitializationPhase::InitializeResponseQueued)
    );
    assert!(matches!(
        session.send_client(INITIALIZED),
        Err(AppServerProcessError::InitializationSequenceViolation)
    ));
    poll_until(&mut session, Duration::from_secs(2), |session| {
        session.exit_report().is_some()
    })?;
    assert_eq!(
        session
            .exit_report()
            .ok_or("continuity-failure report was absent")?
            .outcome(),
        AppServerProcessOutcome::ProtocolFailure
    );
    Ok(())
}

#[test]
fn session_fails_closed_when_initialize_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = attach(
        "reject",
        1_024,
        Duration::from_secs(2),
        Duration::from_secs(10),
        Duration::from_millis(100),
    )?;
    session.send_client(INITIALIZE)?;
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(2))
        .ok_or("test deadline overflowed")?;
    let observed = loop {
        match session.poll(Instant::now()) {
            Err(AppServerProcessError::InitializeRejected) => break true,
            Ok(_) => {}
            Err(error) => return Err(error.into()),
        }
        if Instant::now() >= deadline {
            break false;
        }
        thread::sleep(Duration::from_millis(1));
    };
    assert!(observed);
    poll_until(&mut session, Duration::from_secs(2), |session| {
        session.exit_report().is_some()
    })?;
    assert_eq!(
        session
            .exit_report()
            .ok_or("initialize-rejection report was absent")?
            .outcome(),
        AppServerProcessOutcome::ProtocolFailure
    );
    Ok(())
}

#[test]
fn session_bounds_stdout_before_proxy_retention() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = attach(
        "oversized",
        256,
        Duration::from_secs(2),
        Duration::from_secs(10),
        Duration::from_millis(100),
    )?;
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(2))
        .ok_or("test deadline overflowed")?;
    let observed = loop {
        match session.poll(Instant::now()) {
            Err(AppServerProcessError::StdoutLineTooLarge) => break true,
            Ok(_) => {}
            Err(error) => return Err(error.into()),
        }
        if Instant::now() >= deadline {
            break false;
        }
        thread::sleep(Duration::from_millis(1));
    };
    assert!(observed);
    assert_eq!(session.diagnostics().proxy().accepted_server_messages(), 0);
    poll_until(&mut session, Duration::from_secs(2), |session| {
        session.exit_report().is_some()
    })?;
    assert_eq!(
        session
            .exit_report()
            .ok_or("transport-failure report was absent")?
            .outcome(),
        AppServerProcessOutcome::TransportFailure
    );
    Ok(())
}

#[test]
fn session_contains_process_crashes_after_initialization() -> Result<(), Box<dyn std::error::Error>>
{
    let mut session = begin_initialized_session("crash")?;
    poll_until(&mut session, Duration::from_secs(2), |session| {
        session.exit_report().is_some()
    })?;
    let report = session.exit_report().ok_or("crash report was absent")?;
    assert_eq!(report.outcome(), AppServerProcessOutcome::Crash);
    assert_eq!(report.exit_code(), Some(42));
    assert!(report.was_initialized());
    Ok(())
}

#[test]
fn session_distinguishes_unexpected_successful_exit() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = begin_initialized_session("exit")?;
    poll_until(&mut session, Duration::from_secs(2), |session| {
        session.exit_report().is_some()
    })?;
    let report = session
        .exit_report()
        .ok_or("unexpected-exit report was absent")?;
    assert_eq!(report.outcome(), AppServerProcessOutcome::UnexpectedExit);
    assert_eq!(report.exit_code(), Some(0));
    Ok(())
}

#[test]
fn session_bounds_post_exit_pipe_drain_without_hiding_loss()
-> Result<(), Box<dyn std::error::Error>> {
    let session = AppServerProcessSession::attach_unverified_child(
        spawn_fixture("linger-stdio")?,
        proxy_limits(1_024, Duration::from_secs(2))?,
        AppServerProcessLimits::new(
            4,
            64,
            Duration::from_secs(2),
            Duration::from_secs(10),
            Duration::from_millis(200),
            Duration::from_millis(50),
        )?,
        Instant::now(),
    )?;
    let mut session = complete_initialization(session)?;
    poll_until(&mut session, Duration::from_secs(2), |session| {
        session.exit_report().is_some()
    })?;
    let report = session
        .exit_report()
        .ok_or("bounded-drain report was absent")?;
    assert_eq!(report.outcome(), AppServerProcessOutcome::TransportFailure);
    assert!(!report.streams_drained());
    Ok(())
}

#[test]
fn session_forces_a_hung_process_after_the_graceful_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = begin_initialized_session("hang")?;
    session.shutdown(AppServerShutdownMode::Graceful, Instant::now())?;
    poll_until(&mut session, Duration::from_secs(2), |session| {
        session.exit_report().is_some()
    })?;
    assert_eq!(
        session
            .exit_report()
            .ok_or("forced-shutdown report was absent")?
            .outcome(),
        AppServerProcessOutcome::ForcedShutdown
    );
    Ok(())
}

#[test]
fn session_enforces_initialization_and_runtime_deadlines() -> Result<(), Box<dyn std::error::Error>>
{
    let mut initializing = attach(
        "silent",
        1_024,
        Duration::from_millis(25),
        Duration::from_secs(10),
        Duration::from_millis(100),
    )?;
    poll_until(&mut initializing, Duration::from_secs(2), |session| {
        session.exit_report().is_some()
    })?;
    assert_eq!(
        initializing
            .exit_report()
            .ok_or("initialization-timeout report was absent")?
            .outcome(),
        AppServerProcessOutcome::InitializationTimeout
    );

    let mut running = attach(
        "silent",
        1_024,
        Duration::from_secs(1),
        Duration::from_millis(25),
        Duration::from_millis(100),
    )?;
    poll_until(&mut running, Duration::from_secs(2), |session| {
        session.exit_report().is_some()
    })?;
    assert_eq!(
        running
            .exit_report()
            .ok_or("runtime-timeout report was absent")?
            .outcome(),
        AppServerProcessOutcome::RuntimeTimeout
    );
    Ok(())
}

#[test]
fn session_terminates_on_a_forwarded_request_deadline() -> Result<(), Box<dyn std::error::Error>> {
    let session = attach_with_request_timeout(
        "no-response",
        1_024,
        Duration::from_millis(25),
        Duration::from_secs(2),
        Duration::from_secs(10),
        Duration::from_millis(100),
    )?;
    let mut session = complete_initialization(session)?;
    session.send_client(br#"{"id":91,"method":"future/no-response","params":{}}"#)?;
    poll_until(&mut session, Duration::from_secs(2), |session| {
        session.exit_report().is_some()
    })?;
    assert_eq!(
        session
            .exit_report()
            .ok_or("request-timeout report was absent")?
            .outcome(),
        AppServerProcessOutcome::RequestTimeout
    );
    Ok(())
}

#[test]
fn session_limits_missing_stdio_and_debug_output_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    assert!(matches!(
        AppServerProcessLimits::new(
            0,
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        ),
        Err(AppServerProcessError::InvalidLimits)
    ));
    assert!(matches!(
        AppServerProcessLimits::new(
            5,
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        ),
        Err(AppServerProcessError::InvalidLimits)
    ));
    assert!(matches!(
        AppServerProcessLimits::new(
            1,
            1_025,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        ),
        Err(AppServerProcessError::InvalidLimits)
    ));
    assert!(matches!(
        AppServerProcessLimits::new(
            1,
            1,
            Duration::from_secs(301),
            Duration::from_hours(24),
            Duration::from_secs(30),
            Duration::from_secs(30),
        ),
        Err(AppServerProcessError::InvalidLimits)
    ));

    let child = Command::new(env!("CARGO_BIN_EXE_weregopher-app-server-fixture"))
        .arg("silent")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    assert!(matches!(
        AppServerProcessSession::attach_unverified_child(
            child,
            proxy_limits(1_024, Duration::from_secs(1))?,
            process_limits(
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
            )?,
            Instant::now(),
        ),
        Err(AppServerProcessError::MissingPipedStdio)
    ));

    let mut session = attach(
        "silent",
        1_024,
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_millis(100),
    )?;
    session.send_client(
        br#"{"id":"private-init-id","method":"initialize","params":{"token":"do-not-log"}}"#,
    )?;
    let debug = format!("{session:?}");
    assert!(!debug.contains("private-init-id"));
    assert!(!debug.contains("do-not-log"));
    session.shutdown(AppServerShutdownMode::Immediate, Instant::now())?;
    poll_until(&mut session, Duration::from_secs(2), |session| {
        session.exit_report().is_some()
    })?;
    assert_eq!(
        session
            .exit_report()
            .ok_or("immediate-shutdown report was absent")?
            .outcome(),
        AppServerProcessOutcome::ForcedShutdown
    );
    Ok(())
}

#[test]
fn session_rejects_a_backward_owner_clock() -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let mut session = AppServerProcessSession::attach_unverified_child(
        spawn_fixture("silent")?,
        proxy_limits(1_024, Duration::from_secs(1))?,
        process_limits(
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(1),
        )?,
        start,
    )?;
    session.poll(start + Duration::from_secs(1))?;
    assert!(matches!(
        session.poll(start + Duration::from_millis(500)),
        Err(AppServerProcessError::NonMonotonicClock)
    ));
    Ok(())
}
