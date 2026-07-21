//! Canonical frame, limit, authority, and wire-value protocol tests.

use serde_json::json;
use uuid::Uuid;
use weregopher_domain::{
    AppInstanceId, CallAuthority, CallContext, CapabilityGrantId, FRAME_HEADER_LEN, FrameHeader,
    FrameHeaderError, MessageKind, ProtocolLimits, RendererId, Sha256Digest, UserActivationId,
    WireValue,
};

#[test]
fn frame_header_has_a_stable_little_endian_wire_encoding() -> Result<(), Box<dyn std::error::Error>>
{
    let header = FrameHeader::new(
        0x0102_0304,
        1,
        2,
        MessageKind::Hello,
        0x0102_0304_0506_0708,
        0x1112_1314_1516_1718,
    );

    let encoded = header.encode();
    assert_eq!(encoded.len(), FRAME_HEADER_LEN);
    assert_eq!(&encoded[0..4], &[0x04, 0x03, 0x02, 0x01]);
    assert_eq!(&encoded[4..8], &[0x01, 0x00, 0x02, 0x00]);
    assert_eq!(encoded[8], MessageKind::Hello as u8);
    assert_eq!(encoded[9], 0);
    assert_eq!(&encoded[10..12], &[0, 0]);
    assert_eq!(FrameHeader::decode(&encoded)?, header);
    Ok(())
}

#[test]
fn frame_header_rejects_truncation_reserved_bits_unknown_flags_and_message_kinds() {
    let valid = FrameHeader::new(8, 1, 0, MessageKind::Heartbeat, 0, 1).encode();

    assert_eq!(
        FrameHeader::decode(&valid[..FRAME_HEADER_LEN - 1]),
        Err(FrameHeaderError::InvalidLength {
            actual: FRAME_HEADER_LEN - 1,
        })
    );

    let mut reserved = valid;
    reserved[10] = 1;
    assert_eq!(
        FrameHeader::decode(&reserved),
        Err(FrameHeaderError::ReservedBitsSet)
    );

    let mut unknown_flags = valid;
    unknown_flags[9] = 1;
    assert_eq!(
        FrameHeader::decode(&unknown_flags),
        Err(FrameHeaderError::UnknownFlags(1))
    );

    let mut unknown = valid;
    unknown[8] = 0xff;
    assert_eq!(
        FrameHeader::decode(&unknown),
        Err(FrameHeaderError::UnknownMessageKind(0xff))
    );
}

#[test]
fn frame_header_json_rejects_unregistered_flags() {
    let value = json!({
        "frame_length": 8,
        "protocol_major": 1,
        "protocol_minor": 0,
        "message_kind": "heartbeat",
        "flags": 1,
        "request_id": 0,
        "sequence": 1
    });

    assert!(serde_json::from_value::<FrameHeader>(value).is_err());
}

#[test]
fn protocol_limits_negotiate_to_the_lower_valid_bound() -> Result<(), Box<dyn std::error::Error>> {
    let requested = ProtocolLimits {
        max_frame_bytes: 8 * 1024 * 1024,
        max_graph_nodes: 100_000,
        max_object_depth: 128,
        max_string_bytes: 4 * 1024 * 1024,
        max_inline_buffer_bytes: 512 * 1024,
        max_pending_requests: 2_048,
        max_remote_handles: 20_000,
        max_open_streams: 512,
        max_listener_count: 4_096,
    };
    let hard_cap = ProtocolLimits::secure_default();

    let negotiated = requested.negotiate(&hard_cap)?;
    assert_eq!(negotiated.max_frame_bytes, hard_cap.max_frame_bytes);
    assert_eq!(negotiated.max_object_depth, hard_cap.max_object_depth);
    assert_eq!(
        negotiated.max_pending_requests,
        hard_cap.max_pending_requests
    );

    let mut invalid = hard_cap;
    invalid.max_frame_bytes = 0;
    assert!(invalid.validate().is_err());
    Ok(())
}

#[test]
fn call_context_uses_host_issued_authority_references() -> Result<(), Box<dyn std::error::Error>> {
    let context = CallContext {
        app: AppInstanceId::from_uuid(Uuid::from_u128(1)),
        renderer: Some(RendererId::new(7)),
        frame: None,
        world: None,
        authority: CallAuthority {
            capability: Some(CapabilityGrantId::from_uuid(Uuid::from_u128(2))),
            user_activation: Some(UserActivationId::from_uuid(Uuid::from_u128(3))),
        },
        deadline_ms: Some(500),
        trace_parent: None,
    };

    let value = serde_json::to_value(context)?;
    assert!(value.get("user_activation").is_none());
    assert_eq!(
        value["authority"]["user_activation"],
        json!("00000000-0000-0000-0000-000000000003")
    );
    Ok(())
}

#[test]
fn wire_value_uses_unambiguous_special_number_and_bigint_variants()
-> Result<(), Box<dyn std::error::Error>> {
    let value = WireValue::Array {
        values: vec![
            WireValue::NegativeZero,
            WireValue::NaN,
            WireValue::BigInt {
                negative: true,
                magnitude_be: vec![0x01, 0x02],
            },
            WireValue::Bytes {
                value: Sha256Digest::from_bytes([0x44; 32]).as_bytes().to_vec(),
            },
        ],
    };

    let json = serde_json::to_value(value)?;
    assert_eq!(json["kind"], json!("array"));
    assert_eq!(json["values"][0]["kind"], json!("negative_zero"));
    assert_eq!(json["values"][1]["kind"], json!("nan"));
    assert_eq!(json["values"][2]["magnitude_be"], json!([1, 2]));
    assert!(json["values"][2].get("magnitude").is_none());
    Ok(())
}
