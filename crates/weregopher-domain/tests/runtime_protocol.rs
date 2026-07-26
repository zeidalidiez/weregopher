//! Runtime-protocol contract behavior.

use serde_json::json;
use uuid::Uuid;
use weregopher_domain::{
    AppInstanceId, CallAuthority, CallContext, CallTarget, ProtocolFeatures, ProtocolLimits,
    ProtocolVersion, ProtocolVersionRange, RendererId, RuntimeBackendId, RuntimeBackendIdentity,
    RuntimeCall, RuntimeCancel, RuntimeHello, RuntimeId, RuntimeStreamData, RuntimeStreamOpen,
    RuntimeStreamWindow, ScriptWorldKind, StreamHandle, WireError, WireObjectEntry, WireValue,
    WorldIdentity, validate_wire_value_graph,
};
use weregopher_domain::{FrameIdentity, ObjectHandle, ObjectKind, OpaqueHandle, OriginIdentity};

#[test]
fn handshake_contracts_are_closed_bounded_and_negotiable() -> Result<(), Box<dyn std::error::Error>>
{
    let limits = ProtocolLimits::secure_default();
    let range =
        ProtocolVersionRange::new(ProtocolVersion::new(1, 0)?, ProtocolVersion::new(1, 2)?)?;
    let host_range =
        ProtocolVersionRange::new(ProtocolVersion::new(1, 1)?, ProtocolVersion::new(1, 3)?)?;
    assert_eq!(
        range.negotiate(&host_range),
        Some(ProtocolVersion::new(1, 2)?)
    );
    assert!(
        ProtocolVersionRange::new(ProtocolVersion::new(1, 2)?, ProtocolVersion::new(1, 1)?)
            .is_err()
    );
    assert!(
        ProtocolVersionRange::new(ProtocolVersion::new(1, 0)?, ProtocolVersion::new(2, 0)?)
            .is_err()
    );

    let hello = RuntimeHello::new(
        RuntimeId::from_uuid(Uuid::from_u128(1)),
        AppInstanceId::from_uuid(Uuid::from_u128(2)),
        RuntimeBackendIdentity::new(RuntimeBackendId::new("fixture.worker")?, "1.0.0")?,
        range,
        [0x44; 32],
        ProtocolFeatures::g1_control(),
        limits,
    )?;
    let value = serde_json::to_value(&hello)?;
    assert_eq!(
        serde_json::from_value::<RuntimeHello>(value.clone())?,
        hello
    );

    let mut unknown = value;
    unknown
        .as_object_mut()
        .ok_or("hello must serialize as an object")?
        .insert("authority".to_owned(), json!(true));
    assert!(serde_json::from_value::<RuntimeHello>(unknown).is_err());

    let mut invalid_proof = serde_json::to_value(&hello)?;
    invalid_proof["nonce_proof"] = serde_json::to_value([0_u8; 32])?;
    assert!(serde_json::from_value::<RuntimeHello>(invalid_proof).is_err());
    assert!(
        RuntimeBackendIdentity::new(RuntimeBackendId::new("fixture.worker")?, "x".repeat(129))
            .is_err()
    );
    Ok(())
}

#[test]
fn calls_are_bounded_and_use_host_issued_context() -> Result<(), Box<dyn std::error::Error>> {
    let limits = ProtocolLimits {
        max_frame_bytes: 4_096,
        max_graph_nodes: 8,
        max_object_depth: 3,
        max_string_bytes: 32,
        max_inline_buffer_bytes: 16,
        max_pending_requests: 4,
        max_remote_handles: 4,
        max_open_streams: 2,
        max_listener_count: 4,
    };
    let context = CallContext {
        app: AppInstanceId::from_uuid(Uuid::from_u128(2)),
        renderer: None,
        frame: None,
        world: None,
        authority: CallAuthority::default(),
        deadline_ms: Some(250),
        trace_parent: None,
    };
    let call = RuntimeCall::new(
        CallTarget::service("fixture.echo")?,
        "echo",
        vec![WireValue::String {
            value: "hello".to_owned(),
        }],
        context.clone(),
        &limits,
    )?;
    call.validate(&limits)?;
    assert_eq!(
        serde_json::from_value::<RuntimeCall>(serde_json::to_value(&call)?)?,
        call
    );
    let mut oversized_target = serde_json::to_value(&call)?;
    oversized_target["target"]["name"] = json!("x".repeat(256));
    assert!(serde_json::from_value::<RuntimeCall>(oversized_target).is_err());
    assert!(
        serde_json::from_value::<CallTarget>(json!({
            "kind": "service",
            "name": "x".repeat(256),
        }))
        .is_err()
    );

    assert!(
        RuntimeCall::new(
            CallTarget::service("fixture.echo")?,
            "echo",
            vec![WireValue::Array {
                values: vec![WireValue::Array {
                    values: vec![WireValue::Array {
                        values: vec![WireValue::Null],
                    }],
                }],
            }],
            context.clone(),
            &limits,
        )
        .is_err()
    );
    assert!(
        RuntimeCall::new(
            CallTarget::service("fixture.echo")?,
            "echo",
            vec![WireValue::Object {
                entries: vec![
                    WireObjectEntry {
                        key: "same".to_owned(),
                        value: WireValue::Null,
                    },
                    WireObjectEntry {
                        key: "same".to_owned(),
                        value: WireValue::Null,
                    },
                ],
            }],
            context,
            &limits,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn nested_runtime_contracts_reject_unknown_fields() -> Result<(), Box<dyn std::error::Error>> {
    let limits = ProtocolLimits::secure_default();
    let hello = RuntimeHello::new(
        RuntimeId::from_uuid(Uuid::from_u128(1)),
        AppInstanceId::from_uuid(Uuid::from_u128(2)),
        RuntimeBackendIdentity::new(RuntimeBackendId::new("fixture.worker")?, "1.0.0")?,
        ProtocolVersionRange::g1()?,
        [0x44; 32],
        ProtocolFeatures::g1_control(),
        limits,
    )?;
    let mut unknown_limit = serde_json::to_value(&hello)?;
    unknown_limit["requested_limits"]["unregistered_limit"] = json!(1);
    assert!(serde_json::from_value::<RuntimeHello>(unknown_limit).is_err());

    let call = RuntimeCall::new(
        CallTarget::service("fixture.echo")?,
        "echo",
        vec![WireValue::String {
            value: "hello".to_owned(),
        }],
        CallContext {
            app: AppInstanceId::from_uuid(Uuid::from_u128(2)),
            renderer: None,
            frame: None,
            world: None,
            authority: CallAuthority::default(),
            deadline_ms: Some(250),
            trace_parent: None,
        },
        &limits,
    )?;
    let mut unknown_context = serde_json::to_value(&call)?;
    unknown_context["context"]["caller_is_admin"] = json!(true);
    assert!(serde_json::from_value::<RuntimeCall>(unknown_context).is_err());

    let mut unknown_wire_field = serde_json::to_value(&call)?;
    unknown_wire_field["args"][0]["prototype"] = json!("polluted");
    assert!(serde_json::from_value::<RuntimeCall>(unknown_wire_field).is_err());
    Ok(())
}

#[test]
fn wire_values_preserve_empty_javascript_strings_and_property_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let values = vec![
        WireValue::String {
            value: String::new(),
        },
        WireValue::Object {
            entries: vec![WireObjectEntry {
                key: String::new(),
                value: WireValue::Null,
            }],
        },
        WireValue::RegExp {
            source: String::new(),
            flags: String::new(),
        },
        WireValue::Error {
            value: WireError {
                name: String::new(),
                message: String::new(),
                stack: Some(String::new()),
                code: Some(String::new()),
                kind: Some(String::new()),
                cause: None,
                data: [(String::new(), WireValue::Null)].into(),
            },
        },
    ];
    validate_wire_value_graph(&values, &ProtocolLimits::secure_default())?;
    Ok(())
}

#[test]
fn regular_expression_flags_are_unique_canonical_and_compatible()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = ProtocolLimits::secure_default();
    validate_wire_value_graph(
        &[WireValue::RegExp {
            source: "fixture".to_owned(),
            flags: "gim".to_owned(),
        }],
        &limits,
    )?;
    for flags in ["mi", "gg", "uv", "z"] {
        assert!(
            validate_wire_value_graph(
                &[WireValue::RegExp {
                    source: "fixture".to_owned(),
                    flags: flags.to_owned(),
                }],
                &limits,
            )
            .is_err(),
            "flags {flags:?} must fail"
        );
    }
    Ok(())
}

#[test]
fn call_context_frame_and_world_relationships_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let limits = ProtocolLimits::secure_default();
    let app = AppInstanceId::from_uuid(Uuid::from_u128(2));
    let renderer = RendererId::new(3);
    let other_renderer = RendererId::new(4);
    let frame = FrameIdentity {
        renderer,
        frame_id: 7,
        generation: 1,
        parent_frame_id: None,
        origin: OriginIdentity {
            serialized: "https://fixture.invalid".to_owned(),
            opaque: false,
        },
        is_main_frame: true,
    };
    let call = |context| {
        RuntimeCall::new(
            CallTarget::service("fixture.echo")?,
            "echo",
            Vec::new(),
            context,
            &limits,
        )
    };

    assert!(
        call(CallContext {
            app,
            renderer: None,
            frame: Some(frame.clone()),
            world: None,
            authority: CallAuthority::default(),
            deadline_ms: None,
            trace_parent: None,
        })
        .is_err()
    );

    let mut mismatched_frame = frame.clone();
    mismatched_frame.renderer = other_renderer;
    assert!(
        call(CallContext {
            app,
            renderer: Some(renderer),
            frame: Some(mismatched_frame),
            world: None,
            authority: CallAuthority::default(),
            deadline_ms: None,
            trace_parent: None,
        })
        .is_err()
    );

    let mut world_frame = frame.clone();
    world_frame.generation = 2;
    assert!(
        call(CallContext {
            app,
            renderer: Some(renderer),
            frame: Some(frame.clone()),
            world: Some(WorldIdentity {
                frame: world_frame,
                world_id: 9,
                generation: 1,
                kind: ScriptWorldKind::PreloadIsolated,
            }),
            authority: CallAuthority::default(),
            deadline_ms: None,
            trace_parent: None,
        })
        .is_err()
    );

    call(CallContext {
        app,
        renderer: Some(renderer),
        frame: Some(frame.clone()),
        world: Some(WorldIdentity {
            frame,
            world_id: 9,
            generation: 1,
            kind: ScriptWorldKind::PreloadIsolated,
        }),
        authority: CallAuthority::default(),
        deadline_ms: None,
        trace_parent: None,
    })?;
    Ok(())
}

#[test]
fn runtime_calls_reject_cross_application_targets_and_handles()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = ProtocolLimits::secure_default();
    let app = AppInstanceId::from_uuid(Uuid::from_u128(2));
    let other_app = AppInstanceId::from_uuid(Uuid::from_u128(3));
    let context = CallContext {
        app,
        renderer: None,
        frame: None,
        world: None,
        authority: CallAuthority::default(),
        deadline_ms: None,
        trace_parent: None,
    };
    let object = ObjectHandle {
        app: other_app,
        id: 7,
        generation: 1,
        kind: ObjectKind::BrowserWindow,
    };
    assert!(
        RuntimeCall::new(
            CallTarget::Object { handle: object },
            "show",
            Vec::new(),
            context.clone(),
            &limits,
        )
        .is_err()
    );
    assert!(
        RuntimeCall::new(
            CallTarget::service("fixture.echo")?,
            "echo",
            vec![WireValue::Function {
                value: OpaqueHandle::new(other_app, 9, 1),
            }],
            context.clone(),
            &limits,
        )
        .is_err()
    );
    RuntimeCall::new(
        CallTarget::service("fixture.echo")?,
        "echo",
        vec![WireValue::Function {
            value: OpaqueHandle::new(app, 9, 1),
        }],
        context,
        &limits,
    )?;
    Ok(())
}

#[test]
fn cancellation_and_stream_credit_contracts_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    assert!(RuntimeCancel::new(0).is_err());
    assert_eq!(RuntimeCancel::new(7)?.request_id(), 7);

    let stream = StreamHandle::new(AppInstanceId::from_uuid(Uuid::from_u128(2)), 9, 1);
    assert!(RuntimeStreamOpen::new(stream.clone(), 0).is_err());
    assert!(RuntimeStreamWindow::new(stream.clone(), 0).is_err());
    assert!(
        RuntimeStreamData::new(
            stream.clone(),
            1,
            vec![0_u8; 17],
            &ProtocolLimits {
                max_inline_buffer_bytes: 16,
                ..ProtocolLimits::secure_default()
            },
        )
        .is_err()
    );
    let data = RuntimeStreamData::new(
        stream,
        1,
        b"bounded".to_vec(),
        &ProtocolLimits::secure_default(),
    )?;
    assert_eq!(data.sequence(), 1);
    assert_eq!(data.bytes(), b"bounded");
    Ok(())
}
