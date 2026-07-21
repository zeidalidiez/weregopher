//! Canonical platform-neutral Weregopher contracts.
//!
//! Public serialized types are defined here and generate the external schemas.

#![forbid(unsafe_code)]

mod build;
mod candidate;
mod certification;
mod digest;
mod ids;
mod protocol;
mod security;

pub use build::{Architecture, BuildFingerprint, InstallationKind, PackageIdentity};
pub use candidate::{
    CandidateChannelHint, CandidateProfile, CandidateTarget, initial_candidate_profiles,
};
pub use certification::{CertificationClass, PublicationStatus, TrustMode};
pub use digest::{Sha256Digest, Sha256DigestError};
pub use ids::{
    AdapterId, AppInstanceId, ApplicationFamilyId, BuildId, CapabilityGrantId, IdentifierError,
    ObjectId, ProfileId, ProtocolSessionId, RendererId, RuntimeId, ScenarioId, TraceId,
    UserActivationId, WindowId,
};
pub use protocol::{
    BufferStorage, CallAuthority, CallContext, ContentBlobId, FRAME_HEADER_LEN, FrameHeader,
    FrameHeaderError, FrameIdentity, MessageKind, MessagePortHandle, ObjectHandle, ObjectKind,
    OpaqueHandle, OriginIdentity, ProtocolLimitError, ProtocolLimits, RemoteFunctionHandle,
    RemotePromiseHandle, ScriptWorldKind, SharedBufferHandle, StreamHandle, TypedArrayKind,
    WireError, WireObjectEntry, WireValue, WorldIdentity,
};
pub use security::EffectiveSecurityPosture;
