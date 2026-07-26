//! Portable handshake, request-lifecycle, and flow-control behavior.

use std::time::{Duration, Instant};

use uuid::Uuid;
use weregopher_domain::{
    AppInstanceId, CompatibilityAnalysisDigest, HeartbeatPolicy, ProtocolFeatures, ProtocolLimits,
    ProtocolSessionId, ProtocolVersionRange, RuntimeBackendId, RuntimeBackendIdentity,
    RuntimeHello, RuntimeId, Sha256Digest,
};
use weregopher_runtime_protocol::{
    CallCompletion, HostHandshake, NonceChallenge, PendingRequests, RequestCancellation,
    StreamCredit, StreamCreditError, WorkerHandshake, WorkerHandshakeError, nonce_possession_proof,
};

#[test]
fn handshake_binds_nonce_peer_and_every_runtime_identity() -> Result<(), Box<dyn std::error::Error>>
{
    let runtime = RuntimeId::from_uuid(Uuid::from_u128(1));
    let app = AppInstanceId::from_uuid(Uuid::from_u128(2));
    let backend = RuntimeBackendIdentity::new(RuntimeBackendId::new("fixture.worker")?, "1.0.0")?;
    let nonce = NonceChallenge::from_bytes([0x55; 32])?;
    let peer_pid = 4_242;
    let limits = ProtocolLimits::secure_default();
    let hello = RuntimeHello::new(
        runtime,
        app,
        backend.clone(),
        ProtocolVersionRange::g1()?,
        nonce_possession_proof(&nonce, runtime, app, &backend, peer_pid),
        ProtocolFeatures::g1_control(),
        limits,
    )?;
    let host = HostHandshake::new(
        nonce,
        peer_pid,
        runtime,
        app,
        backend,
        ProtocolVersionRange::g1()?,
        ProtocolFeatures::g1_control(),
        limits,
        ProtocolSessionId::from_uuid(Uuid::from_u128(3)),
        CompatibilityAnalysisDigest::new(Sha256Digest::from_bytes([0x66; 32])),
        HeartbeatPolicy::new(1_000, 5_000)?,
    )?;
    let worker = WorkerHandshake::from_hello(&hello);
    let welcome = host.negotiate(&hello, peer_pid)?;
    worker.accept(&welcome)?;
    assert_eq!(welcome.session().as_uuid(), Uuid::from_u128(3));
    assert!(welcome.features().calls);
    assert!(!welcome.features().sync_lane);
    assert!(!welcome.features().shared_buffers);

    let expanded_features = weregopher_domain::RuntimeWelcome::new(
        welcome.session(),
        welcome.version(),
        welcome.limits(),
        welcome.compatibility(),
        welcome.heartbeat(),
        ProtocolFeatures {
            sync_lane: true,
            ..welcome.features()
        },
    )?;
    assert!(matches!(
        WorkerHandshake::from_hello(&hello).accept(&expanded_features),
        Err(WorkerHandshakeError::FeaturesExpanded)
    ));
    let expanded_limits = weregopher_domain::RuntimeWelcome::new(
        welcome.session(),
        welcome.version(),
        ProtocolLimits {
            max_frame_bytes: limits.max_frame_bytes + 1,
            ..limits
        },
        welcome.compatibility(),
        welcome.heartbeat(),
        welcome.features(),
    )?;
    assert!(matches!(
        WorkerHandshake::from_hello(&hello).accept(&expanded_limits),
        Err(WorkerHandshakeError::LimitsExpanded)
    ));

    let wrong_nonce = NonceChallenge::from_bytes([0x56; 32])?;
    let bad = RuntimeHello::new(
        runtime,
        app,
        hello.backend().clone(),
        ProtocolVersionRange::g1()?,
        nonce_possession_proof(&wrong_nonce, runtime, app, hello.backend(), peer_pid),
        ProtocolFeatures::g1_control(),
        ProtocolLimits::secure_default(),
    )?;
    let host = HostHandshake::new(
        NonceChallenge::from_bytes([0x55; 32])?,
        peer_pid,
        runtime,
        app,
        hello.backend().clone(),
        ProtocolVersionRange::g1()?,
        ProtocolFeatures::g1_control(),
        ProtocolLimits::secure_default(),
        ProtocolSessionId::from_uuid(Uuid::from_u128(3)),
        CompatibilityAnalysisDigest::new(Sha256Digest::from_bytes([0x66; 32])),
        HeartbeatPolicy::new(1_000, 5_000)?,
    )?;
    assert!(host.negotiate(&bad, peer_pid).is_err());
    Ok(())
}

#[test]
fn pending_requests_bound_cancellation_deadlines_and_late_results()
-> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let mut pending = PendingRequests::new(2)?;
    let first = pending.begin(start, Duration::from_millis(100))?;
    let second = pending.begin(start, Duration::from_millis(200))?;
    assert!(pending.begin(start, Duration::from_millis(300)).is_err());
    assert_eq!(pending.cancel(first)?, RequestCancellation::NewlyCancelled);
    assert_eq!(
        pending.cancel(first)?,
        RequestCancellation::AlreadyCancelled
    );
    assert_eq!(
        pending.complete(first)?,
        CallCompletion::DiscardedAfterCancellation
    );
    assert_eq!(
        pending.expire(start + Duration::from_millis(250)),
        vec![second]
    );
    assert!(pending.is_empty());
    Ok(())
}

#[test]
fn stream_credit_never_allows_overrun_replay_or_overflow() -> Result<(), Box<dyn std::error::Error>>
{
    let mut credit = StreamCredit::new(8)?;
    credit.consume(1, 5)?;
    assert_eq!(credit.available(), 3);
    assert!(matches!(
        credit.consume(2, 4),
        Err(StreamCreditError::CreditExceeded {
            available: 3,
            requested: 4
        })
    ));
    assert!(matches!(
        credit.consume(1, 1),
        Err(StreamCreditError::UnexpectedSequence {
            expected: 2,
            actual: 1
        })
    ));
    credit.grant(5)?;
    credit.consume(2, 8)?;
    assert_eq!(credit.available(), 0);
    assert!(credit.grant(0).is_err());
    let mut maximum = StreamCredit::new(u64::MAX)?;
    assert!(matches!(
        maximum.grant(1),
        Err(StreamCreditError::CreditOverflow)
    ));
    Ok(())
}
