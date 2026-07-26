//! Portable frame-codec behavior.

use std::io::Cursor;

use uuid::Uuid;
use weregopher_domain::{
    AppInstanceId, MessageKind, ProtocolFeatures, ProtocolLimits, ProtocolVersion,
    ProtocolVersionRange, RuntimeBackendId, RuntimeBackendIdentity, RuntimeHello, RuntimeId,
    RuntimeStreamData, StreamHandle,
};
use weregopher_runtime_protocol::{
    FrameReadError, FrameWriteError, FramedReader, FramedWriter, MessagePackBudget,
    ProtocolMessage, inspect_messagepack,
};

fn hello(limits: ProtocolLimits) -> Result<RuntimeHello, Box<dyn std::error::Error>> {
    Ok(RuntimeHello::new(
        RuntimeId::from_uuid(Uuid::from_u128(1)),
        AppInstanceId::from_uuid(Uuid::from_u128(2)),
        RuntimeBackendIdentity::new(RuntimeBackendId::new("fixture.worker")?, "1.0.0")?,
        ProtocolVersionRange::g1()?,
        [0x44; 32],
        ProtocolFeatures::g1_control(),
        limits,
    )?)
}

#[test]
fn named_messagepack_frames_round_trip_with_monotonic_sequences()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = ProtocolLimits::secure_default();
    let version = ProtocolVersion::new(1, 0)?;
    let expected = hello(limits)?;
    let mut encoded = Vec::new();
    let mut writer = FramedWriter::new(&mut encoded, version, limits)?;
    let first = writer.send(1, &expected)?;
    let second = writer.send(2, &expected)?;
    assert_eq!(first.message_kind, MessageKind::Hello);
    assert_eq!(first.sequence, 1);
    assert_eq!(second.sequence, 2);
    assert!(
        encoded
            .windows(b"runtime".len())
            .any(|part| part == b"runtime")
    );

    let mut reader = FramedReader::new(Cursor::new(encoded), version, limits)?;
    assert_eq!(reader.receive::<RuntimeHello>()?.payload(), &expected);
    assert_eq!(reader.receive::<RuntimeHello>()?.payload(), &expected);
    Ok(())
}

#[test]
fn declared_frame_limits_fail_before_payload_reads_or_allocation()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = ProtocolLimits {
        max_frame_bytes: 32,
        ..ProtocolLimits::secure_default()
    };
    let version = ProtocolVersion::new(1, 0)?;
    let header = weregopher_domain::FrameHeader::new(
        33,
        version.major(),
        version.minor(),
        MessageKind::Hello,
        1,
        1,
    )
    .encode();
    let mut reader = FramedReader::new(Cursor::new(header), version, limits)?;
    assert!(matches!(
        reader.receive::<RuntimeHello>(),
        Err(FrameReadError::FrameTooLarge {
            maximum: 32,
            actual: 33
        })
    ));
    Ok(())
}

#[test]
fn outbound_frame_limit_has_an_explicit_error_category() -> Result<(), Box<dyn std::error::Error>> {
    let limits = ProtocolLimits {
        max_frame_bytes: 32,
        ..ProtocolLimits::secure_default()
    };
    let mut encoded = Vec::new();
    assert!(matches!(
        FramedWriter::new(&mut encoded, ProtocolVersion::new(1, 0)?, limits)?
            .send(0, &hello(limits)?),
        Err(FrameWriteError::FrameTooLarge { maximum: 32 })
    ));
    Ok(())
}

#[test]
fn replay_wrong_kind_and_trailing_payload_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let limits = ProtocolLimits::secure_default();
    let version = ProtocolVersion::new(1, 0)?;
    let expected = hello(limits)?;
    let mut encoded = Vec::new();
    FramedWriter::new(&mut encoded, version, limits)?.send(1, &expected)?;

    let mut replay = encoded.clone();
    replay.extend_from_slice(&encoded);
    let mut reader = FramedReader::new(Cursor::new(replay), version, limits)?;
    let _ = reader.receive::<RuntimeHello>()?;
    assert!(matches!(
        reader.receive::<RuntimeHello>(),
        Err(FrameReadError::UnexpectedSequence {
            expected: 2,
            actual: 1
        })
    ));

    let mut wrong_kind = encoded.clone();
    wrong_kind[8] = MessageKind::Welcome as u8;
    let mut reader = FramedReader::new(Cursor::new(wrong_kind), version, limits)?;
    assert!(matches!(
        reader.receive::<RuntimeHello>(),
        Err(FrameReadError::UnexpectedMessageKind {
            expected: MessageKind::Hello,
            actual: MessageKind::Welcome
        })
    ));

    let payload_end = encoded.len();
    let mut trailing = encoded;
    trailing.push(0xc0);
    let payload_len = u32::try_from(payload_end - weregopher_domain::FRAME_HEADER_LEN + 1)?;
    trailing[0..4].copy_from_slice(&payload_len.to_le_bytes());
    let mut reader = FramedReader::new(Cursor::new(trailing), version, limits)?;
    assert!(reader.receive::<RuntimeHello>().is_err());
    Ok(())
}

#[test]
fn messagepack_preflight_enforces_graph_depth_nodes_strings_and_binary()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = ProtocolLimits {
        max_graph_nodes: 4,
        max_object_depth: 2,
        max_string_bytes: 3,
        max_inline_buffer_bytes: 2,
        ..ProtocolLimits::secure_default()
    };
    assert_eq!(
        inspect_messagepack(&[0x92, 0x01, 0x02], &limits)?,
        MessagePackBudget::new(3, 2)?
    );
    assert!(inspect_messagepack(&[0x91, 0x91, 0x91, 0xc0], &limits).is_err());
    assert!(inspect_messagepack(&[0xa4, b't', b'e', b'x', b't'], &limits).is_err());
    assert!(inspect_messagepack(&[0xc4, 0x03, 1, 2, 3], &limits).is_err());
    assert!(inspect_messagepack(&[0xd4, 1, 0], &limits).is_err());
    assert!(inspect_messagepack(&[0xc1], &limits).is_err());
    Ok(())
}

#[test]
fn inline_bytes_use_messagepack_binary_without_consuming_one_graph_node_per_byte()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = ProtocolLimits {
        max_frame_bytes: 4_096,
        max_graph_nodes: 32,
        max_inline_buffer_bytes: 256,
        ..ProtocolLimits::secure_default()
    };
    let version = ProtocolVersion::new(1, 0)?;
    let expected = RuntimeStreamData::new(
        StreamHandle::new(AppInstanceId::from_uuid(Uuid::from_u128(2)), 1, 1),
        1,
        vec![0x5a; 128],
        &limits,
    )?;
    let mut encoded = Vec::new();
    FramedWriter::new(&mut encoded, version, limits)?.send(0, &expected)?;

    let mut reader = FramedReader::new(Cursor::new(encoded), version, limits)?;
    assert_eq!(
        reader.receive::<RuntimeStreamData>()?.into_payload(),
        expected
    );
    Ok(())
}

#[test]
fn every_typed_payload_declares_one_exact_message_kind() {
    assert_eq!(RuntimeHello::KIND, MessageKind::Hello);
}
