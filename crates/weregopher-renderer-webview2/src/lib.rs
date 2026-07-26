//! Windows `WebView2` host used by the packaged-renderer G1 fixture.
//!
//! The crate exposes no raw platform handle or COM object. Its unsafe exception is limited to
//! documented Win32 and `WebView2` calls over owned objects in the Windows-only implementation.

#![cfg(windows)]
#![deny(unsafe_op_in_unsafe_fn)]

mod windows;

pub use windows::{
    ObservedWebMessage, WebView2Fixture, WebView2FixtureError, WebView2ShutdownObservation,
};
