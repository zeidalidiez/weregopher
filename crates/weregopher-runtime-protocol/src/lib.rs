//! Bounded framing and session state for the Weregopher worker/host protocol.

#![forbid(unsafe_code)]

mod codec;
mod session;

pub use codec::{
    FrameReadError, FrameWriteError, FramedReader, FramedWriter, MessagePackBudget,
    MessagePackError, ProtocolMessage, ReceivedMessage, inspect_messagepack,
};
pub use session::{
    CallCompletion, HandshakeError, HostHandshake, NonceChallenge, NonceChallengeError,
    PendingRequestError, PendingRequests, RequestCancellation, StreamCredit, StreamCreditError,
    WorkerHandshake, WorkerHandshakeError, nonce_possession_proof,
};
