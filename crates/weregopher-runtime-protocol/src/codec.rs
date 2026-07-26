//! Canonical bounded `MessagePack` framing.

use std::io::{self, Read, Write};

use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;
use weregopher_domain::{
    FRAME_HEADER_LEN, FrameHeader, FrameHeaderError, MessageKind, ProtocolLimitError,
    ProtocolLimits, ProtocolReject, ProtocolVersion, RuntimeCall, RuntimeCallError,
    RuntimeCallResult, RuntimeCancel, RuntimeEvent, RuntimeHello, RuntimeProtocolContractError,
    RuntimeShutdown, RuntimeStreamData, RuntimeStreamOpen, RuntimeStreamWindow, RuntimeWelcome,
};

/// A typed payload with one exact wire message kind and post-decode validation.
pub trait ProtocolMessage: Serialize + DeserializeOwned {
    /// Exact frame-header discriminator for this payload.
    const KIND: MessageKind;

    /// Revalidates relationships against the limits negotiated for this connection.
    ///
    /// # Errors
    ///
    /// Returns a contract error when the decoded message exceeds negotiated limits.
    fn validate_message(&self, limits: &ProtocolLimits)
    -> Result<(), RuntimeProtocolContractError>;
}

macro_rules! protocol_message {
    ($type:ty, $kind:ident, $validate:expr) => {
        impl ProtocolMessage for $type {
            const KIND: MessageKind = MessageKind::$kind;

            fn validate_message(
                &self,
                limits: &ProtocolLimits,
            ) -> Result<(), RuntimeProtocolContractError> {
                ($validate)(self, limits)
            }
        }
    };
}

protocol_message!(
    RuntimeHello,
    Hello,
    |message: &RuntimeHello, _limits: &ProtocolLimits| {
        message.requested_limits().validate()?;
        Ok(())
    }
);
protocol_message!(
    RuntimeWelcome,
    Welcome,
    |message: &RuntimeWelcome, _limits: &ProtocolLimits| {
        message.limits().validate()?;
        Ok(())
    }
);
protocol_message!(
    ProtocolReject,
    Reject,
    |_message: &ProtocolReject, _limits: &ProtocolLimits| Ok(())
);
protocol_message!(RuntimeCall, Call, RuntimeCall::validate);
protocol_message!(RuntimeCallResult, CallResult, RuntimeCallResult::validate);
protocol_message!(RuntimeCallError, CallError, RuntimeCallError::validate);
protocol_message!(
    RuntimeCancel,
    Cancel,
    |_message: &RuntimeCancel, _limits: &ProtocolLimits| Ok(())
);
protocol_message!(RuntimeEvent, Event, RuntimeEvent::validate);
protocol_message!(
    RuntimeStreamOpen,
    StreamOpen,
    |_message: &RuntimeStreamOpen, _limits: &ProtocolLimits| Ok(())
);
protocol_message!(
    RuntimeStreamWindow,
    StreamWindow,
    |_message: &RuntimeStreamWindow, _limits: &ProtocolLimits| Ok(())
);
protocol_message!(RuntimeStreamData, StreamData, RuntimeStreamData::validate);
protocol_message!(
    RuntimeShutdown,
    Shutdown,
    |_message: &RuntimeShutdown, _limits: &ProtocolLimits| Ok(())
);

/// Structural usage observed while preflighting one `MessagePack` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessagePackBudget {
    nodes: u32,
    maximum_depth: u16,
}

impl MessagePackBudget {
    /// Constructs a nonempty, internally consistent observed budget.
    ///
    /// # Errors
    ///
    /// Returns [`MessagePackError::InvalidObservedBudget`] for zero values or a
    /// depth greater than the number of nodes.
    pub const fn new(nodes: u32, maximum_depth: u16) -> Result<Self, MessagePackError> {
        if nodes == 0 || maximum_depth == 0 || maximum_depth as u32 > nodes {
            return Err(MessagePackError::InvalidObservedBudget);
        }
        Ok(Self {
            nodes,
            maximum_depth,
        })
    }

    /// Total `MessagePack` scalar and container nodes.
    #[must_use]
    pub const fn nodes(self) -> u32 {
        self.nodes
    }

    /// Deepest `MessagePack` value nesting, counting the root as depth one.
    #[must_use]
    pub const fn maximum_depth(self) -> u16 {
        self.maximum_depth
    }
}

/// A structurally invalid, unsupported, or over-budget `MessagePack` payload.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MessagePackError {
    /// The byte slice does not contain a root value.
    #[error("MessagePack payload is empty")]
    Empty,
    /// A marker or its declared body ended before all required bytes arrived.
    #[error("MessagePack payload ended unexpectedly at byte {offset}")]
    Truncated {
        /// First unavailable byte offset.
        offset: usize,
    },
    /// More than one root value was encoded.
    #[error("MessagePack payload has trailing bytes at offset {offset}")]
    TrailingBytes {
        /// First trailing byte offset.
        offset: usize,
    },
    /// `MessagePack` extension types are not part of the protocol codec.
    #[error("MessagePack extension marker 0x{marker:02x} is not supported")]
    ExtensionType {
        /// Rejected marker.
        marker: u8,
    },
    /// Marker `0xc1` is permanently unassigned by `MessagePack`.
    #[error("reserved MessagePack marker 0xc1 is invalid")]
    ReservedMarker,
    /// A string body was not valid UTF-8.
    #[error("MessagePack string at byte {offset} is not UTF-8")]
    InvalidUtf8 {
        /// String-body offset.
        offset: usize,
    },
    /// A declared collection length overflowed structural accounting.
    #[error("MessagePack child count overflowed")]
    ChildCountOverflow,
    /// Total encoded bytes exceeded the negotiated frame ceiling.
    #[error("MessagePack payload exceeds {maximum} bytes: {actual}")]
    FrameBytesExceeded {
        /// Negotiated ceiling.
        maximum: u32,
        /// Observed bytes.
        actual: usize,
    },
    /// Structural node usage exceeded the negotiated ceiling.
    #[error("MessagePack payload exceeds {maximum} nodes: {actual}")]
    NodesExceeded {
        /// Negotiated ceiling.
        maximum: u32,
        /// Observed nodes.
        actual: u32,
    },
    /// Structural nesting exceeded the negotiated ceiling.
    #[error("MessagePack payload exceeds depth {maximum}: {actual}")]
    DepthExceeded {
        /// Negotiated ceiling.
        maximum: u16,
        /// Observed depth.
        actual: u16,
    },
    /// A string exceeded the negotiated UTF-8 byte ceiling.
    #[error("MessagePack string exceeds {maximum} bytes: {actual}")]
    StringBytesExceeded {
        /// Negotiated ceiling.
        maximum: u32,
        /// Observed bytes.
        actual: u32,
    },
    /// A binary value exceeded the negotiated inline byte ceiling.
    #[error("MessagePack binary value exceeds {maximum} bytes: {actual}")]
    BinaryBytesExceeded {
        /// Negotiated ceiling.
        maximum: u32,
        /// Observed bytes.
        actual: u32,
    },
    /// Traversal storage could not be reserved.
    #[error("MessagePack traversal allocation failed")]
    BudgetAllocationFailed,
    /// A manually constructed observed budget was impossible.
    #[error("observed MessagePack budget must be nonzero and depth cannot exceed nodes")]
    InvalidObservedBudget,
    /// Protocol limits must all be nonzero.
    #[error(transparent)]
    InvalidLimits(#[from] ProtocolLimitError),
}

/// Preflights one complete `MessagePack` value before typed deserialization.
///
/// Extension markers are rejected because the G1 codec has no registered
/// extension namespace. Strings are validated as UTF-8 and all collection
/// traversal is iterative.
///
/// # Errors
///
/// Returns [`MessagePackError`] for malformed, unsupported, trailing, or
/// over-budget input.
pub fn inspect_messagepack(
    payload: &[u8],
    limits: &ProtocolLimits,
) -> Result<MessagePackBudget, MessagePackError> {
    limits.validate()?;
    let maximum_frame = usize::try_from(limits.max_frame_bytes).unwrap_or(usize::MAX);
    if payload.len() > maximum_frame {
        return Err(MessagePackError::FrameBytesExceeded {
            maximum: limits.max_frame_bytes,
            actual: payload.len(),
        });
    }
    if payload.is_empty() {
        return Err(MessagePackError::Empty);
    }

    let mut remaining_by_depth = Vec::new();
    remaining_by_depth
        .try_reserve_exact(usize::from(limits.max_object_depth))
        .map_err(|_| MessagePackError::BudgetAllocationFailed)?;
    remaining_by_depth.push(1_u64);

    let mut cursor = MessagePackCursor::new(payload);
    let mut nodes = 0_u32;
    let mut maximum_depth = 0_u16;

    loop {
        while remaining_by_depth.last() == Some(&0) {
            remaining_by_depth.pop();
        }
        let Some(remaining) = remaining_by_depth.last_mut() else {
            break;
        };
        *remaining -= 1;

        let depth = u16::try_from(remaining_by_depth.len()).map_err(|_| {
            MessagePackError::DepthExceeded {
                maximum: limits.max_object_depth,
                actual: u16::MAX,
            }
        })?;
        if depth > limits.max_object_depth {
            return Err(MessagePackError::DepthExceeded {
                maximum: limits.max_object_depth,
                actual: depth,
            });
        }
        maximum_depth = maximum_depth.max(depth);
        nodes = nodes
            .checked_add(1)
            .ok_or(MessagePackError::ChildCountOverflow)?;
        if nodes > limits.max_graph_nodes {
            return Err(MessagePackError::NodesExceeded {
                maximum: limits.max_graph_nodes,
                actual: nodes,
            });
        }

        let children = cursor.read_value(limits)?;
        if children != 0 {
            let child_depth = depth
                .checked_add(1)
                .ok_or(MessagePackError::DepthExceeded {
                    maximum: limits.max_object_depth,
                    actual: u16::MAX,
                })?;
            if child_depth > limits.max_object_depth {
                return Err(MessagePackError::DepthExceeded {
                    maximum: limits.max_object_depth,
                    actual: child_depth,
                });
            }
            remaining_by_depth.push(children);
        }
    }

    if cursor.offset != payload.len() {
        return Err(MessagePackError::TrailingBytes {
            offset: cursor.offset,
        });
    }
    MessagePackBudget::new(nodes, maximum_depth)
}

struct MessagePackCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> MessagePackCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_value(&mut self, limits: &ProtocolLimits) -> Result<u64, MessagePackError> {
        let marker = self.read_u8()?;
        match marker {
            0x00..=0x7f | 0xe0..=0xff | 0xc0 | 0xc2 | 0xc3 => Ok(0),
            0x80..=0x8f => Self::map_children(u32::from(marker & 0x0f)),
            0x90..=0x9f => Ok(u64::from(marker & 0x0f)),
            0xa0..=0xbf => {
                self.read_string(u32::from(marker & 0x1f), limits)?;
                Ok(0)
            }
            0xc1 => Err(MessagePackError::ReservedMarker),
            0xc4 => {
                let length = u32::from(self.read_u8()?);
                self.read_binary(length, limits)?;
                Ok(0)
            }
            0xc5 => {
                let length = u32::from(self.read_u16()?);
                self.read_binary(length, limits)?;
                Ok(0)
            }
            0xc6 => {
                let length = self.read_u32()?;
                self.read_binary(length, limits)?;
                Ok(0)
            }
            0xc7..=0xc9 | 0xd4..=0xd8 => Err(MessagePackError::ExtensionType { marker }),
            0xca | 0xce | 0xd2 => {
                self.skip(4)?;
                Ok(0)
            }
            0xcb | 0xcf | 0xd3 => {
                self.skip(8)?;
                Ok(0)
            }
            0xcc | 0xd0 => {
                self.skip(1)?;
                Ok(0)
            }
            0xcd | 0xd1 => {
                self.skip(2)?;
                Ok(0)
            }
            0xd9 => {
                let length = u32::from(self.read_u8()?);
                self.read_string(length, limits)?;
                Ok(0)
            }
            0xda => {
                let length = u32::from(self.read_u16()?);
                self.read_string(length, limits)?;
                Ok(0)
            }
            0xdb => {
                let length = self.read_u32()?;
                self.read_string(length, limits)?;
                Ok(0)
            }
            0xdc => Ok(u64::from(self.read_u16()?)),
            0xdd => Ok(u64::from(self.read_u32()?)),
            0xde => Self::map_children(u32::from(self.read_u16()?)),
            0xdf => Self::map_children(self.read_u32()?),
        }
    }

    fn map_children(entries: u32) -> Result<u64, MessagePackError> {
        u64::from(entries)
            .checked_mul(2)
            .ok_or(MessagePackError::ChildCountOverflow)
    }

    fn read_string(
        &mut self,
        length: u32,
        limits: &ProtocolLimits,
    ) -> Result<(), MessagePackError> {
        if length > limits.max_string_bytes {
            return Err(MessagePackError::StringBytesExceeded {
                maximum: limits.max_string_bytes,
                actual: length,
            });
        }
        let start = self.offset;
        let bytes = self.take(usize::try_from(length).unwrap_or(usize::MAX))?;
        std::str::from_utf8(bytes)
            .map(|_| ())
            .map_err(|_| MessagePackError::InvalidUtf8 { offset: start })
    }

    fn read_binary(
        &mut self,
        length: u32,
        limits: &ProtocolLimits,
    ) -> Result<(), MessagePackError> {
        if length > limits.max_inline_buffer_bytes {
            return Err(MessagePackError::BinaryBytesExceeded {
                maximum: limits.max_inline_buffer_bytes,
                actual: length,
            });
        }
        self.skip(usize::try_from(length).unwrap_or(usize::MAX))
    }

    fn read_u8(&mut self) -> Result<u8, MessagePackError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(MessagePackError::Truncated {
                offset: self.offset,
            })
    }

    fn read_u16(&mut self) -> Result<u16, MessagePackError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, MessagePackError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn skip(&mut self, length: usize) -> Result<(), MessagePackError> {
        self.take(length).map(|_| ())
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], MessagePackError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(MessagePackError::Truncated {
                offset: self.offset,
            })?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(MessagePackError::Truncated {
                offset: self.offset,
            })?;
        self.offset = end;
        Ok(value)
    }
}

/// Failure to encode or write one protocol frame.
#[derive(Debug, Error)]
pub enum FrameWriteError {
    /// Negotiated limits were invalid.
    #[error(transparent)]
    InvalidLimits(#[from] ProtocolLimitError),
    /// Message relationships exceeded negotiated limits.
    #[error(transparent)]
    InvalidMessage(#[from] RuntimeProtocolContractError),
    /// Named-field `MessagePack` encoding failed.
    #[error("could not encode protocol payload: {0}")]
    Encode(#[source] rmp_serde::encode::Error),
    /// Encoded payload exceeded the frame ceiling.
    #[error("encoded frame exceeds {maximum} bytes")]
    FrameTooLarge {
        /// Negotiated ceiling.
        maximum: u32,
    },
    /// Frame sequence space was exhausted.
    #[error("frame sequence space is exhausted")]
    SequenceExhausted,
    /// The transport write failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Monotonic framed writer using named-field `MessagePack` payloads.
pub struct FramedWriter<W> {
    output: W,
    version: ProtocolVersion,
    limits: ProtocolLimits,
    next_sequence: u64,
}

impl<W: Write> FramedWriter<W> {
    /// Creates a writer at outbound sequence one.
    ///
    /// # Errors
    ///
    /// Returns an error when any protocol limit is zero.
    pub fn new(
        output: W,
        version: ProtocolVersion,
        limits: ProtocolLimits,
    ) -> Result<Self, FrameWriteError> {
        limits.validate()?;
        Ok(Self {
            output,
            version,
            limits,
            next_sequence: 1,
        })
    }

    /// Validates, encodes, and writes one complete frame.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid message, an oversized or unencodable
    /// payload, sequence exhaustion, or a transport write failure.
    pub fn send<M: ProtocolMessage>(
        &mut self,
        request_id: u64,
        message: &M,
    ) -> Result<FrameHeader, FrameWriteError> {
        message.validate_message(&self.limits)?;
        let mut payload = BoundedPayload::new(self.limits.max_frame_bytes);
        if let Err(error) = rmp_serde::encode::write_named(&mut payload, message) {
            if payload.limit_exceeded {
                return Err(FrameWriteError::FrameTooLarge {
                    maximum: self.limits.max_frame_bytes,
                });
            }
            return Err(FrameWriteError::Encode(error));
        }
        let frame_length =
            u32::try_from(payload.bytes.len()).map_err(|_| FrameWriteError::FrameTooLarge {
                maximum: self.limits.max_frame_bytes,
            })?;
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(FrameWriteError::SequenceExhausted)?;
        let header = FrameHeader::new(
            frame_length,
            self.version.major(),
            self.version.minor(),
            M::KIND,
            request_id,
            self.next_sequence,
        );
        self.output.write_all(&header.encode())?;
        self.output.write_all(&payload.bytes)?;
        self.next_sequence = next_sequence;
        Ok(header)
    }

    /// Returns the wrapped transport.
    #[must_use]
    pub fn into_inner(self) -> W {
        self.output
    }
}

struct BoundedPayload {
    bytes: Vec<u8>,
    maximum: usize,
    limit_exceeded: bool,
}

impl BoundedPayload {
    fn new(maximum: u32) -> Self {
        Self {
            bytes: Vec::new(),
            maximum: usize::try_from(maximum).unwrap_or(usize::MAX),
            limit_exceeded: false,
        }
    }
}

impl Write for BoundedPayload {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let Some(new_length) = self.bytes.len().checked_add(buffer.len()) else {
            self.limit_exceeded = true;
            return Err(io::Error::other("protocol payload length overflowed"));
        };
        if new_length > self.maximum {
            self.limit_exceeded = true;
            return Err(io::Error::other("protocol payload exceeds frame limit"));
        }
        self.bytes
            .try_reserve_exact(buffer.len())
            .map_err(|_| io::Error::other("protocol payload allocation failed"))?;
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Failure to read, preflight, decode, or validate one protocol frame.
#[derive(Debug, Error)]
pub enum FrameReadError {
    /// Negotiated limits were invalid.
    #[error(transparent)]
    InvalidLimits(#[from] ProtocolLimitError),
    /// Header bytes were malformed.
    #[error(transparent)]
    InvalidHeader(#[from] FrameHeaderError),
    /// The declared payload length exceeded the ceiling before allocation.
    #[error("declared frame length exceeds {maximum} bytes: {actual}")]
    FrameTooLarge {
        /// Negotiated ceiling.
        maximum: u32,
        /// Declared bytes.
        actual: u32,
    },
    /// The frame did not use the exact negotiated protocol version.
    #[error(
        "unexpected protocol version {actual_major}.{actual_minor}; expected {expected_major}.{expected_minor}"
    )]
    UnexpectedVersion {
        /// Negotiated major.
        expected_major: u16,
        /// Negotiated minor.
        expected_minor: u16,
        /// Received major.
        actual_major: u16,
        /// Received minor.
        actual_minor: u16,
    },
    /// The per-direction sequence was not the next exact value.
    #[error("unexpected frame sequence {actual}; expected {expected}")]
    UnexpectedSequence {
        /// Next required sequence.
        expected: u64,
        /// Received sequence.
        actual: u64,
    },
    /// The typed receive operation did not match the frame discriminator.
    #[error("unexpected message kind {actual:?}; expected {expected:?}")]
    UnexpectedMessageKind {
        /// Required kind.
        expected: MessageKind,
        /// Received kind.
        actual: MessageKind,
    },
    /// Payload storage could not be reserved within the declared bound.
    #[error("could not reserve declared protocol payload")]
    PayloadAllocationFailed,
    /// The `MessagePack` payload failed structural preflight.
    #[error(transparent)]
    InvalidMessagePack(#[from] MessagePackError),
    /// Typed `MessagePack` decoding failed.
    #[error("could not decode protocol payload: {0}")]
    Decode(#[source] rmp_serde::decode::Error),
    /// Decoded relationships exceeded negotiated limits.
    #[error(transparent)]
    InvalidMessage(#[from] RuntimeProtocolContractError),
    /// Frame sequence space was exhausted.
    #[error("frame sequence space is exhausted")]
    SequenceExhausted,
    /// The transport read failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// One decoded payload and its authenticated framing metadata.
#[derive(Clone, Debug, PartialEq)]
pub struct ReceivedMessage<M> {
    header: FrameHeader,
    payload: M,
}

impl<M> ReceivedMessage<M> {
    /// Exact decoded frame header.
    #[must_use]
    pub const fn header(&self) -> FrameHeader {
        self.header
    }

    /// Validated typed payload.
    #[must_use]
    pub const fn payload(&self) -> &M {
        &self.payload
    }

    /// Consumes the envelope and returns its payload.
    #[must_use]
    pub fn into_payload(self) -> M {
        self.payload
    }
}

/// Monotonic bounded framed reader.
pub struct FramedReader<R> {
    input: R,
    version: ProtocolVersion,
    limits: ProtocolLimits,
    next_sequence: u64,
}

impl<R: Read> FramedReader<R> {
    /// Creates a reader expecting inbound sequence one.
    ///
    /// # Errors
    ///
    /// Returns an error when any protocol limit is zero.
    pub fn new(
        input: R,
        version: ProtocolVersion,
        limits: ProtocolLimits,
    ) -> Result<Self, FrameReadError> {
        limits.validate()?;
        Ok(Self {
            input,
            version,
            limits,
            next_sequence: 1,
        })
    }

    /// Reads exactly one payload of the requested message type.
    ///
    /// The declared frame limit, version, sequence, and kind are checked before
    /// payload allocation or reads.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed metadata, an oversized declaration,
    /// transport failure, structural/typed decode failure, or contract failure.
    pub fn receive<M: ProtocolMessage>(&mut self) -> Result<ReceivedMessage<M>, FrameReadError> {
        let mut header_bytes = [0_u8; FRAME_HEADER_LEN];
        self.input.read_exact(&mut header_bytes)?;
        let header = FrameHeader::decode(&header_bytes)?;

        if header.frame_length > self.limits.max_frame_bytes {
            return Err(FrameReadError::FrameTooLarge {
                maximum: self.limits.max_frame_bytes,
                actual: header.frame_length,
            });
        }
        if header.protocol_major != self.version.major()
            || header.protocol_minor != self.version.minor()
        {
            return Err(FrameReadError::UnexpectedVersion {
                expected_major: self.version.major(),
                expected_minor: self.version.minor(),
                actual_major: header.protocol_major,
                actual_minor: header.protocol_minor,
            });
        }
        if header.sequence != self.next_sequence {
            return Err(FrameReadError::UnexpectedSequence {
                expected: self.next_sequence,
                actual: header.sequence,
            });
        }
        if header.message_kind != M::KIND {
            return Err(FrameReadError::UnexpectedMessageKind {
                expected: M::KIND,
                actual: header.message_kind,
            });
        }

        let payload_length =
            usize::try_from(header.frame_length).map_err(|_| FrameReadError::FrameTooLarge {
                maximum: self.limits.max_frame_bytes,
                actual: header.frame_length,
            })?;
        let mut payload_bytes = Vec::new();
        payload_bytes
            .try_reserve_exact(payload_length)
            .map_err(|_| FrameReadError::PayloadAllocationFailed)?;
        payload_bytes.resize(payload_length, 0);
        self.input.read_exact(&mut payload_bytes)?;
        inspect_messagepack(&payload_bytes, &self.limits)?;
        let payload = rmp_serde::from_slice::<M>(&payload_bytes).map_err(FrameReadError::Decode)?;
        payload.validate_message(&self.limits)?;

        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(FrameReadError::SequenceExhausted)?;
        Ok(ReceivedMessage { header, payload })
    }

    /// Returns the wrapped transport.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.input
    }
}
