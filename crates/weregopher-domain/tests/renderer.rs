//! Renderer bridge domain contract tests.

use uuid::Uuid;
use weregopher_domain::{
    AppInstanceId, FrameIdentity, OpaqueHandle, OriginIdentity, ProtocolLimits,
    RendererBridgeInvocation, RendererBridgeNonce, RendererBridgeReply, RendererEnvelope,
    RendererId, ScriptWorldKind, WireValue, WorldIdentity,
};

fn app_id(value: u128) -> AppInstanceId {
    AppInstanceId::from_uuid(Uuid::from_u128(value))
}

fn identities(renderer: RendererId, generation: u32) -> (FrameIdentity, WorldIdentity) {
    let frame = FrameIdentity {
        renderer,
        frame_id: 1,
        generation,
        parent_frame_id: None,
        origin: OriginIdentity {
            serialized: "https://app-00000000000000000000000000000001.weregopher.invalid"
                .to_owned(),
            opaque: false,
        },
        is_main_frame: true,
    };
    let world = WorldIdentity {
        frame: frame.clone(),
        world_id: 1,
        generation,
        kind: ScriptWorldKind::Main,
    };
    (frame, world)
}

#[test]
fn renderer_envelope_binds_backend_authority_and_payload() -> Result<(), Box<dyn std::error::Error>>
{
    let limits = ProtocolLimits::secure_default();
    let renderer = RendererId::new(7);
    let (frame, world) = identities(renderer, 3);
    let nonce = RendererBridgeNonce::new([0x5a; 16])?;
    let envelope = RendererEnvelope::new(
        app_id(1),
        renderer,
        frame.clone(),
        world.clone(),
        3,
        nonce,
        WireValue::String {
            value: "ready".to_owned(),
        },
        &limits,
    )?;

    assert_eq!(envelope.app(), app_id(1));
    assert_eq!(envelope.renderer(), renderer);
    assert_eq!(envelope.frame(), &frame);
    assert_eq!(envelope.world(), &world);
    assert_eq!(envelope.navigation_generation(), 3);
    assert_eq!(envelope.nonce(), nonce);
    assert_eq!(
        envelope.payload(),
        &WireValue::String {
            value: "ready".to_owned()
        }
    );
    Ok(())
}

#[test]
fn renderer_contracts_reject_zero_or_inconsistent_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = ProtocolLimits::secure_default();
    assert!(RendererBridgeNonce::new([0; 16]).is_err());

    let renderer = RendererId::new(7);
    let other_renderer = RendererId::new(8);
    let (mut frame, world) = identities(renderer, 3);
    frame.renderer = other_renderer;
    assert!(
        RendererEnvelope::new(
            app_id(1),
            renderer,
            frame,
            world,
            3,
            RendererBridgeNonce::new([0x5a; 16])?,
            WireValue::Null,
            &limits,
        )
        .is_err()
    );

    let (frame, world) = identities(renderer, 3);
    assert!(
        RendererEnvelope::new(
            app_id(1),
            renderer,
            frame,
            world,
            4,
            RendererBridgeNonce::new([0x5a; 16])?,
            WireValue::Null,
            &limits,
        )
        .is_err()
    );

    let (frame, world) = identities(renderer, 3);
    assert!(
        RendererEnvelope::new(
            app_id(1),
            renderer,
            frame,
            world,
            3,
            RendererBridgeNonce::new([0x5a; 16])?,
            WireValue::Function {
                value: OpaqueHandle::new(app_id(2), 9, 1),
            },
            &limits,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn bridge_invocation_and_reply_are_bounded_closed_contracts()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = ProtocolLimits::secure_default();
    let nonce = RendererBridgeNonce::new([0x6b; 16])?;
    let invocation = RendererBridgeInvocation::new(
        nonce,
        41,
        "echo",
        vec![WireValue::String {
            value: "from-renderer".to_owned(),
        }],
        &limits,
    )?;
    assert_eq!(invocation.nonce(), nonce);
    assert_eq!(invocation.request_id(), 41);
    assert_eq!(invocation.method(), "echo");

    let reply = RendererBridgeReply::success(
        41,
        WireValue::String {
            value: "from-renderer".to_owned(),
        },
        &limits,
    )?;
    assert_eq!(reply.request_id(), 41);

    assert!(RendererBridgeInvocation::new(nonce, 0, "echo", Vec::new(), &limits).is_err());
    assert!(RendererBridgeInvocation::new(nonce, 1, "", Vec::new(), &limits).is_err());

    let mut serialized = serde_json::to_value(&invocation)?;
    serialized
        .as_object_mut()
        .ok_or("renderer invocation did not serialize as an object")?
        .insert("authority".to_owned(), serde_json::json!({"admin": true}));
    assert!(serde_json::from_value::<RendererBridgeInvocation>(serialized).is_err());

    for malformed in [
        serde_json::json!({"request_id": 41}),
        serde_json::json!({"request_id": 41, "result": null, "error": null}),
        serde_json::json!({
            "request_id": 41,
            "result": {"kind": "null"},
            "error": {"code": "fixture_failure", "message": "closed failure"}
        }),
    ] {
        assert!(
            serde_json::from_value::<RendererBridgeReply>(malformed).is_err(),
            "accepted a renderer reply without exactly one result or error"
        );
    }

    let failed = RendererBridgeReply::failure(42, "fixture_failure", "closed failure")?;
    let round_tripped: RendererBridgeReply =
        serde_json::from_value(serde_json::to_value(&failed)?)?;
    assert_eq!(round_tripped, failed);
    Ok(())
}
