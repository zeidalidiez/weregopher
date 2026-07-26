//! Native Windows packaged-renderer/authenticated-runtime G1 vertical slice.

#![cfg(windows)]

use std::{
    ffi::OsString,
    io::{Read as _, Write as _},
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

use serde::Deserialize;
use uuid::Uuid;
use weregopher_domain::{
    AppInstanceId, CompatibilityAnalysisDigest, HeartbeatPolicy, ProtocolFeatures, ProtocolLimits,
    ProtocolSessionId, ProtocolVersion, ProtocolVersionRange, RendererBridgeInvocation,
    RendererBridgeNonce, RendererBridgeReply, RendererId, RuntimeBackendId, RuntimeBackendIdentity,
    RuntimeCall, RuntimeCallResult, RuntimeHello, RuntimeId, RuntimeShutdown,
    RuntimeShutdownReason, Sha256Digest, WireValue,
};
use weregopher_renderer::{
    ImmutablePackage, PackageAsset, PackageOrigin, PackageOriginLimits, PrivateOrigin,
    RendererBridgeAuthority, RendererLifecycleState,
};
use weregopher_renderer_webview2::WebView2Fixture;
use weregopher_runtime_protocol::{
    FramedReader, FramedWriter, HostHandshake, NonceChallenge, WorkerHandshake,
    nonce_possession_proof,
};
use weregopher_windows::{
    CurrentUserNamedPipeServer, JobLimits, KillOnCloseJob, NamedPipeAddress, connect_named_pipe,
};

const WORKER_NONCE_BYTES: [u8; 32] = [0x5a; 32];
const RENDERER_NONCE_BYTES: [u8; 16] = [0x7c; 16];
const PROCESS_MEMORY_LIMIT: u64 = 256 * 1024 * 1024;
const JOB_MEMORY_LIMIT: u64 = 512 * 1024 * 1024;
const FIXTURE_TIMEOUT: Duration = Duration::from_secs(20);

fn runtime_id() -> RuntimeId {
    RuntimeId::from_uuid(Uuid::from_u128(1))
}

fn app_id() -> AppInstanceId {
    AppInstanceId::from_uuid(Uuid::from_u128(2))
}

fn renderer_id() -> RendererId {
    RendererId::new(7)
}

fn backend() -> Result<RuntimeBackendIdentity, Box<dyn std::error::Error>> {
    Ok(RuntimeBackendIdentity::new(
        RuntimeBackendId::new("fixture.renderer-worker")?,
        "1.0.0",
    )?)
}

fn package_origin() -> Result<PackageOrigin, Box<dyn std::error::Error>> {
    let limits = PackageOriginLimits::g1_fixture();
    let package = ImmutablePackage::new(
        vec![
            PackageAsset::new(
                "index.html",
                Arc::<[u8]>::from(include_bytes!("fixtures/index.html").as_slice()),
                &limits,
            )?,
            PackageAsset::new(
                "assets/main.js",
                Arc::<[u8]>::from(include_bytes!("fixtures/assets/main.js").as_slice()),
                &limits,
            )?,
        ],
        limits,
    )?;
    Ok(PackageOrigin::new(
        PrivateOrigin::for_app(app_id()),
        package,
    ))
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum FixtureObservation {
    FixtureObservation { value: String, origin: String },
    FixtureFailure { message: String },
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one sequential scenario keeps cross-process, renderer, and cleanup ordering auditable"
)]
fn packaged_renderer_uses_private_origin_authenticated_bridge_and_clean_shutdown()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = ProtocolLimits::secure_default();
    let version = ProtocolVersion::new(1, 0)?;
    let server = CurrentUserNamedPipeServer::bind(64 * 1024)?;
    let address = server.address().clone();
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            OsString::from("--ignored"),
            OsString::from("--exact"),
            OsString::from("renderer_runtime_worker_helper"),
            OsString::from("--test-threads=1"),
            OsString::from("--"),
            OsString::from(address.as_str()),
        ])
        .stdin(Stdio::piped())
        .spawn()?;
    let job = KillOnCloseJob::create(JobLimits::new(1, PROCESS_MEMORY_LIMIT, JOB_MEMORY_LIMIT)?)?;
    job.assign_child(&child)?;
    assert!(job.contains_child(&child)?);
    let mut nonce_channel = child
        .stdin
        .take()
        .ok_or("renderer worker nonce channel was not created")?;
    nonce_channel.write_all(&WORKER_NONCE_BYTES)?;
    nonce_channel.flush()?;
    drop(nonce_channel);

    let connection = server.accept(&child, &job, Duration::from_secs(5))?;
    let peer_process_id = connection.peer_process_id();
    let read_transport = connection.try_clone()?;
    let mut reader = FramedReader::new(read_transport, version, limits)?;
    let mut writer = FramedWriter::new(connection, version, limits)?;
    let hello = reader.receive::<RuntimeHello>()?.into_payload();
    let welcome = HostHandshake::new(
        NonceChallenge::from_bytes(WORKER_NONCE_BYTES)?,
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
    writer.send(0, &welcome)?;

    let package = package_origin()?;
    let private_origin = package.origin().clone();
    let entry_url = private_origin.entry_url("index.html")?;
    let renderer_nonce = RendererBridgeNonce::new(RENDERER_NONCE_BYTES)?;
    let mut fixture = WebView2Fixture::create(package, renderer_id())?;
    eprintln!("WebView2 runtime version: {}", fixture.browser_version());
    fixture.install_bridge(renderer_nonce)?;
    let generation = fixture.navigate(&entry_url, FIXTURE_TIMEOUT)?;
    assert_eq!(fixture.lifecycle_state(), RendererLifecycleState::Loaded);

    let message = fixture.wait_for_message(FIXTURE_TIMEOUT)?;
    let invocation: RendererBridgeInvocation = serde_json::from_str(message.json())?;
    let page_request_id = invocation.request_id();
    let mut authority = RendererBridgeAuthority::new(
        app_id(),
        renderer_id(),
        private_origin.clone(),
        generation.get(),
        renderer_nonce,
        "fixture.renderer",
        limits,
    )?;
    let authorized = authority.authorize(message.source(), &invocation)?;
    writer.send(page_request_id, authorized.call())?;
    let result = reader.receive::<RuntimeCallResult>()?;
    assert_eq!(result.header().request_id, page_request_id);
    let reply =
        RendererBridgeReply::success(page_request_id, result.payload().value().clone(), &limits)?;
    fixture.post_reply(&reply)?;

    let observation = fixture.wait_for_message(FIXTURE_TIMEOUT)?;
    match serde_json::from_str::<FixtureObservation>(observation.json())? {
        FixtureObservation::FixtureObservation { value, origin } => {
            assert_eq!(value, "from-renderer");
            assert_eq!(origin, private_origin.identity().serialized);
        }
        FixtureObservation::FixtureFailure { message } => {
            return Err(format!("renderer fixture failed: {message}").into());
        }
    }
    let dom_result = fixture.execute_script("document.body.dataset.result")?;
    assert_eq!(
        serde_json::from_str::<String>(&dom_result)?,
        "from-renderer"
    );

    let shutdown = fixture.close(FIXTURE_TIMEOUT)?;
    assert!(shutdown.browser_process_exited());
    assert!(shutdown.user_data_removed());
    assert_eq!(shutdown.final_state(), RendererLifecycleState::Closed);

    writer.send(
        0,
        &RuntimeShutdown {
            reason: RuntimeShutdownReason::HostShutdown,
        },
    )?;
    assert!(child.wait()?.success());
    Ok(())
}

#[test]
#[ignore = "spawned by the native packaged-renderer integration test"]
fn renderer_runtime_worker_helper() -> Result<(), Box<dyn std::error::Error>> {
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

    let call = reader.receive::<RuntimeCall>()?;
    assert_eq!(call.payload().method(), "echo");
    assert_eq!(call.payload().context().app, app_id());
    assert_eq!(call.payload().context().renderer, Some(renderer_id()));
    assert_eq!(
        call.payload()
            .context()
            .frame
            .as_ref()
            .map(|frame| frame.origin.serialized.as_str()),
        Some("https://app-00000000000000000000000000000002.weregopher.invalid")
    );
    assert_eq!(
        call.payload()
            .context()
            .world
            .as_ref()
            .map(|world| world.generation),
        Some(1)
    );
    writer.send(
        call.header().request_id,
        &RuntimeCallResult::new(call.payload().args()[0].clone(), &limits)?,
    )?;

    let shutdown = reader.receive::<RuntimeShutdown>()?;
    assert_eq!(
        shutdown.payload().reason,
        RuntimeShutdownReason::HostShutdown
    );
    Ok(())
}
