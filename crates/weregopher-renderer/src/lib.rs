//! Portable packaged-renderer origin, lifecycle, and bridge authority.

#![forbid(unsafe_code)]

mod bridge;
mod lifecycle;
mod origin;

pub use bridge::{AuthorizedRendererCall, RendererBridgeAuthority, RendererBridgeError};
pub use lifecycle::{
    NavigationGeneration, RendererLifecycle, RendererLifecycleError, RendererLifecycleState,
};
pub use origin::{
    ImmutablePackage, PackageAsset, PackageOrigin, PackageOriginError, PackageOriginLimits,
    PackageOriginResponse, PrivateOrigin,
};
