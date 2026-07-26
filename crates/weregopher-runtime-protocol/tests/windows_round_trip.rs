//! Native Windows worker/controller protocol vertical slice.

#![cfg(windows)]

use std::{
    ffi::OsString,
    io::{Read as _, Write as _},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use uuid::Uuid;
use weregopher_domain::{
    AppInstanceId, CallAuthority, CallContext, CallTarget, CompatibilityAnalysisDigest,
    HeartbeatPolicy, OpaqueHandle, ProtocolFeatures, ProtocolLimits, ProtocolSessionId,
    ProtocolVersion, ProtocolVersionRange, RuntimeBackendId, RuntimeBackendIdentity, RuntimeCall,
    RuntimeCallResult, RuntimeCancel, RuntimeEvent, RuntimeHello, RuntimeId, RuntimeShutdown,
    RuntimeShutdownReason, RuntimeStreamData, RuntimeStreamOpen, RuntimeStreamWindow, Sha256Digest,
    WireValue,
};
use weregopher_runtime_protocol::{
    CallCompletion, FramedReader, FramedWriter, HostHandshake, NonceChallenge, PendingRequests,
    RequestCancellation, StreamCredit, WorkerHandshake, nonce_possession_proof,
};
use weregopher_windows::{
    CurrentUserNamedPipeServer, JobLimits, KillOnCloseJob, NamedPipeAddress, connect_named_pipe,
};

const PROCESS_MEMORY_LIMIT: u64 = 256 * 1024 * 1024;
const JOB_MEMORY_LIMIT: u64 = 512 * 1024 * 1024;
const NONCE_BYTES: [u8; 32] = [0x5a; 32];

fn runtime_id() -> RuntimeId {
    RuntimeId::from_uuid(Uuid::from_u128(1))
}

fn app_id() -> AppInstanceId {
    AppInstanceId::from_uuid(Uuid::from_u128(2))
}

fn backend() -> Result<RuntimeBackendIdentity, Box<dyn std::error::Error>> {
    Ok(RuntimeBackendIdentity::new(
        RuntimeBackendId::new("fixture.worker")?,
        "1.0.0",
    )?)
}

fn call_context() -> CallContext {
    CallContext {
        app: app_id(),
        renderer: None,
        frame: None,
        world: None,
        authority: CallAuthority::default(),
        deadline_ms: Some(2_000),
        trace_parent: None,
    }
}

fn echo_call(
    value: &str,
    limits: &ProtocolLimits,
) -> Result<RuntimeCall, Box<dyn std::error::Error>> {
    Ok(RuntimeCall::new(
        CallTarget::service("fixture.echo")?,
        "echo",
        vec![WireValue::String {
            value: value.to_owned(),
        }],
        call_context(),
        limits,
    )?)
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the single sequential scenario makes cross-process protocol ordering auditable"
)]
fn verified_worker_controller_round_trip_covers_g1_control_slice()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = ProtocolLimits::secure_default();
    let version = ProtocolVersion::new(1, 0)?;
    let server = CurrentUserNamedPipeServer::bind(64 * 1024)?;
    let address = server.address().clone();
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            OsString::from("--ignored"),
            OsString::from("--exact"),
            OsString::from("runtime_protocol_worker_helper"),
            OsString::from("--test-threads=1"),
            OsString::from("--"),
            OsString::from(address.as_str()),
        ])
        .stdin(Stdio::piped())
        .spawn()?;

    let job = KillOnCloseJob::create(JobLimits::new(1, PROCESS_MEMORY_LIMIT, JOB_MEMORY_LIMIT)?)?;
    job.assign_child(&child)?;
    assert!(job.contains_child(&child)?);
    let mut child_stdin = child
        .stdin
        .take()
        .ok_or("worker nonce channel was not created")?;
    child_stdin.write_all(&NONCE_BYTES)?;
    child_stdin.flush()?;
    drop(child_stdin);

    let connection = server.accept(&child, &job, Duration::from_secs(5))?;
    assert_eq!(connection.peer_process_id(), child.id());
    let peer_process_id = connection.peer_process_id();
    let read_transport = connection.try_clone()?;
    let mut reader = FramedReader::new(read_transport, version, limits)?;
    let mut writer = FramedWriter::new(connection, version, limits)?;

    let hello = reader.receive::<RuntimeHello>()?.into_payload();
    let welcome = HostHandshake::new(
        NonceChallenge::from_bytes(NONCE_BYTES)?,
        child.id(),
        runtime_id(),
        app_id(),
        backend()?,
        ProtocolVersionRange::g1()?,
        ProtocolFeatures::g1_control(),
        limits,
        ProtocolSessionId::from_uuid(Uuid::from_u128(3)),
        CompatibilityAnalysisDigest::new(Sha256Digest::from_bytes([0x33; 32])),
        HeartbeatPolicy::new(1_000, 5_000)?,
    )?
    .negotiate(&hello, peer_process_id)?;
    assert!(welcome.features().calls);
    assert!(welcome.features().cancellation);
    assert!(welcome.features().events);
    assert!(welcome.features().credit_streams);
    assert!(!welcome.features().sync_lane);
    assert!(!welcome.features().shared_buffers);
    writer.send(0, &welcome)?;

    let start = Instant::now();
    let mut pending = PendingRequests::new(limits.max_pending_requests)?;
    let first_request = pending.begin(start, Duration::from_secs(2))?;
    assert_eq!(first_request, 1);
    let first_call = echo_call("first", &limits)?;
    writer.send(first_request, &first_call)?;
    let first_result = reader.receive::<RuntimeCallResult>()?;
    assert_eq!(first_result.header().request_id, first_request);
    assert_eq!(
        first_result.payload().value(),
        &WireValue::String {
            value: "first".to_owned()
        }
    );
    assert_eq!(pending.complete(first_request)?, CallCompletion::Delivered);

    let cancelled_request = pending.begin(start, Duration::from_secs(2))?;
    let cancelled_call = echo_call("late", &limits)?;
    writer.send(cancelled_request, &cancelled_call)?;
    assert_eq!(
        pending.cancel(cancelled_request)?,
        RequestCancellation::NewlyCancelled
    );
    writer.send(cancelled_request, &RuntimeCancel::new(cancelled_request)?)?;
    let late_result = reader.receive::<RuntimeCallResult>()?;
    assert_eq!(late_result.header().request_id, cancelled_request);
    assert_eq!(
        pending.complete(cancelled_request)?,
        CallCompletion::DiscardedAfterCancellation
    );

    let event = reader.receive::<RuntimeEvent>()?;
    assert_eq!(event.header().request_id, 0);
    assert_eq!(event.payload().name(), "fixture.ready");

    let stream = OpaqueHandle::new(app_id(), 7, 1);
    writer.send(0, &RuntimeStreamOpen::new(stream.clone(), 5)?)?;
    let mut credit = StreamCredit::new(5)?;
    let first_data = reader.receive::<RuntimeStreamData>()?;
    assert_eq!(first_data.payload().stream(), &stream);
    credit.consume(
        first_data.payload().sequence(),
        u64::try_from(first_data.payload().bytes().len())?,
    )?;
    assert_eq!(first_data.payload().bytes(), b"hello");
    assert_eq!(credit.available(), 0);

    writer.send(0, &RuntimeStreamWindow::new(stream.clone(), 5)?)?;
    credit.grant(5)?;
    let second_data = reader.receive::<RuntimeStreamData>()?;
    credit.consume(
        second_data.payload().sequence(),
        u64::try_from(second_data.payload().bytes().len())?,
    )?;
    assert_eq!(second_data.payload().bytes(), b"world");
    assert_eq!(credit.available(), 0);

    writer.send(
        0,
        &RuntimeShutdown {
            reason: RuntimeShutdownReason::HostShutdown,
        },
    )?;
    assert!(child.wait()?.success());
    assert!(pending.is_empty());
    Ok(())
}

#[test]
#[ignore = "spawned by the native worker/controller integration test"]
fn runtime_protocol_worker_helper() -> Result<(), Box<dyn std::error::Error>> {
    let mut nonce_bytes = [0_u8; 32];
    std::io::stdin().read_exact(&mut nonce_bytes)?;
    let nonce = NonceChallenge::from_bytes(nonce_bytes)?;
    let address = std::env::args()
        .next_back()
        .ok_or("missing named-pipe address")?
        .parse::<NamedPipeAddress>()?;
    let connection = connect_named_pipe(&address, Duration::from_secs(5))?;
    let read_transport = connection.try_clone()?;
    let limits = ProtocolLimits::secure_default();
    let version = ProtocolVersion::new(1, 0)?;
    let mut reader = FramedReader::new(read_transport, version, limits)?;
    let mut writer = FramedWriter::new(connection, version, limits)?;

    let identity = backend()?;
    let hello = RuntimeHello::new(
        runtime_id(),
        app_id(),
        identity.clone(),
        ProtocolVersionRange::g1()?,
        nonce_possession_proof(
            &nonce,
            runtime_id(),
            app_id(),
            &identity,
            std::process::id(),
        ),
        ProtocolFeatures::g1_control(),
        limits,
    )?;
    let worker_handshake = WorkerHandshake::from_hello(&hello);
    writer.send(0, &hello)?;
    let welcome = reader.receive::<weregopher_domain::RuntimeWelcome>()?;
    worker_handshake.accept(welcome.payload())?;
    assert_eq!(welcome.payload().version(), version);

    let first_call = reader.receive::<RuntimeCall>()?;
    assert_eq!(first_call.payload().method(), "echo");
    writer.send(
        first_call.header().request_id,
        &RuntimeCallResult::new(first_call.payload().args()[0].clone(), &limits)?,
    )?;

    let late_call = reader.receive::<RuntimeCall>()?;
    let cancellation = reader.receive::<RuntimeCancel>()?;
    assert_eq!(
        cancellation.payload().request_id(),
        late_call.header().request_id
    );
    writer.send(
        late_call.header().request_id,
        &RuntimeCallResult::new(late_call.payload().args()[0].clone(), &limits)?,
    )?;
    writer.send(
        0,
        &RuntimeEvent::new(
            "fixture.ready",
            vec![WireValue::Bool { value: true }],
            &limits,
        )?,
    )?;

    let stream_open = reader.receive::<RuntimeStreamOpen>()?;
    let stream = stream_open.payload().stream().clone();
    let mut credit = StreamCredit::new(stream_open.payload().initial_credit())?;
    credit.consume(1, 5)?;
    writer.send(
        0,
        &RuntimeStreamData::new(stream.clone(), 1, b"hello".to_vec(), &limits)?,
    )?;
    let window = reader.receive::<RuntimeStreamWindow>()?;
    assert_eq!(window.payload().stream(), &stream);
    credit.grant(window.payload().additional_credit())?;
    credit.consume(2, 5)?;
    writer.send(
        0,
        &RuntimeStreamData::new(stream, 2, b"world".to_vec(), &limits)?,
    )?;

    let shutdown = reader.receive::<RuntimeShutdown>()?;
    assert_eq!(
        shutdown.payload().reason,
        RuntimeShutdownReason::HostShutdown
    );
    Ok(())
}
