# ADR-0004: Isolate full-width Windows file identity

- Status: Accepted
- Date: 2026-07-21

## Context

Race-resistant package evidence must compare the identity of an opened file with
the object currently named by its path while both handles remain alive. Rust
1.97.1 does not expose stable standard-library access to the full Windows
`FILE_ID_INFO` identity. Legacy volume/index pairs are insufficient on filesystems
such as ReFS, where identifiers can exceed 64 bits.

The fingerprint crate otherwise forbids unsafe Rust and must not weaken identity
checks or silently fall back to legacy identifiers.

## Decision

All direct Windows FFI for file identity is isolated in the
`weregopher-windows` crate. Its safe API consumes an owned `std::fs::File`, calls
`GetFileInformationByHandleEx` with `FileIdInfo`, and retains that file handle for
the lifetime of the captured identity.

The crate captures and compares the full volume serial number and 128-bit file
identifier while both owning leases remain alive. It does not expose copyable raw
identities. It fails closed when `FileIdInfo` is unavailable; there is no fallback
to the legacy 64-bit file index.

The unsafe exception is limited to the FFI call and initialization of its output
structure. The required invariants are:

1. the input `File` owns a live Windows handle;
2. the output pointer is aligned, writable, and exactly sized for `FILE_ID_INFO`;
3. the requested information class is `FileIdInfo`;
4. the output is read only after Windows reports success;
5. both identity leases remain open while their values are compared;
6. identities are process-local observation evidence and are not serialized as
   durable package identity.

No raw handle or pointer is exposed by the public API.

## Consequences

- NTFS and ReFS identities are compared without truncating the file ID.
- Unsupported filesystems or handles fail the observation rather than weakening
  its guarantees.
- The rest of the workspace, including domain and fingerprint crates, continues
  to forbid unsafe Rust.
- The Windows wrapper requires focused tests for distinct files and hard links,
  plus strict Clippy and Windows CI coverage.
