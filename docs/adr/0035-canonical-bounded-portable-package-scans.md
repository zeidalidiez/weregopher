# ADR 0035: Canonical bounded portable package scans

- Status: Accepted
- Date: 2026-07-25
- Extends: [ADR 0018](0018-bounded-package-tree-manifest-contract.md), [ADR 0019](0019-bounded-windows-package-tree-observation.md)

## Context

`fingerprint_package` performs a portable two-pass package scan for CLI evidence and
local diagnostics. It previously maintained an independent directory Merkle tree and
constructed `PackageTreeManifest` directly.

That producer could encode a non-root empty directory into its Merkle root even
though manifest format version 1 serializes only file/link records. Serializing and
canonically deserializing that result then failed because the directory could not be
reconstructed. The scanner also accepted platform paths outside the canonical
manifest grammar and allowed its caller-selected aggregate entry budget to exceed
the fixed file-record and path-byte ceilings without enforcing those hard limits
during acquisition.

A trusted producer emitting a value rejected by the canonical consumer violates the
single-authority decision in ADR 0018. Passing the current test suite did not detect
the mismatch because no scanner-to-canonical-parser round-trip was asserted.

## Decision

Portable package scans apply the following fail-closed rules:

1. Every normalized non-root entry path is validated with the canonical
   `PackageTreeManifest` path grammar before it is retained.
2. The caller-selected aggregate entry limit remains an additional bound and cannot
   relax fixed format-v1 ceilings.
3. File/link records are capped at 65,536 while scanning, before another file body
   is hashed or retained.
4. Aggregate UTF-8 bytes across all normalized non-root entry paths are capped at
   16 MiB while scanning. Counting directory paths as well as serialized records is
   intentionally stricter than the manifest parser and bounds scanner-only state.
5. Paths remain capped at 32,767 Unicode scalar values and 256 components.
6. A non-root empty directory is rejected with a typed `EmptyDirectory` error
   because format version 1 cannot bind its existence.
7. The scanner no longer hashes an independent package directory tree or constructs
   `PackageTreeManifest` directly. Every successful scan passes its observed
   file/link records to `build_package_manifest`.
8. Canonical builder failures remain available as typed `ManifestError` sources
   through `FingerprintError`.

The existing portable safe-relative symbolic-link profile remains unchanged. The
Windows retained package-tree observation continues to use its stricter direct-file
and no-reparse profile.

## Security and authority boundary

These changes ensure that scanner-produced manifests fit the canonical format and
bound retained record/path state. They do not turn two matching scans into an atomic
snapshot, retain package identities after return, prevent later namespace mutation,
authenticate a signer, establish compatibility, or authorize transformation or
execution.

Candidate verification must continue to avoid production state. Execution must
consume the separate retained Windows observation, managed snapshot, and live
authorization capabilities required by their respective ADRs.

## Verification

Regressions cover:

- scanner output serializing and deserializing through the canonical Rust contract;
- rejection of a nested empty directory;
- rejection of a Unix entry name outside the canonical path grammar;
- exact and maximum-plus-one aggregate entry, file-record, and path-byte budgets;
- path scalar-count and component-depth ceilings;
- CLI propagation of unrepresentable empty-directory failures; and
- all existing portable and native-Windows package observation suites.

## Consequences

- A successful portable scan cannot emit a manifest rejected by canonical
  deserialization for producer-controlled tree, path, record-count, or path-byte
  state.
- Empty-directory-sensitive packages remain unsupported until a later manifest
  version introduces directory records.
- The portable scanner and retained Windows observer now agree on the format-v1
  empty-directory boundary while preserving their distinct coherence and lease
  claims.
