# ADR-0014: Plan content-addressed materialization without filesystem effects

- Status: Accepted
- Date: 2026-07-21

## Context

The in-memory transform pipeline now produces and verifies complete five-artifact bundles, but filesystem materialization introduces separate root-selection, path traversal, reparse-point, race, atomicity, durability, and vendor-installation safety concerns. Those concerns must not be hidden inside byte verification or improvised from caller-provided filenames.

Before adding writes, Weregopher needs one deterministic manifest that binds the exact validated overlay identities and verified artifact bytes to a closed relative content-addressed layout. The planning step must retain the existing structural and byte-verification proof rather than accepting raw digests or an unchecked artifact map.

## Decision

`weregopher-transform` produces a non-serializable `MaterializationManifest` only from `VerifiedTransformArtifacts` and caller-selected nonzero limits for rules, rule-to-artifact references, unique blobs, and manifest bytes.

The canonical compact JSON manifest contains:

- format version `1`;
- layout `sha256-fanout-v1`;
- fixed target `windows-x86_64`;
- exact source-build, family, adapter, adapter-content, static-authority, and build-descriptor identities;
- every rule and source-unit identifier in canonical rule order; and
- fixed-order source, match-evidence, transformed-source, source-map, and audit-log records with digest, byte length, and generated relative store path.

Blob paths use exactly `sha256/<first digest byte as two lowercase hex digits>/<remaining 62 lowercase hex digits>`. They contain no caller-controlled path component, drive prefix, root, dot segment, separator variant, or filename extension.

Planning:

1. bounds rules and the exact five references per rule before record allocation;
2. obtains bytes only from the retained verified artifact map;
3. deduplicates blobs by digest in canonical order;
4. rejects distinct byte slices claiming the same digest;
5. enforces the unique-blob limit before retaining another blob;
6. constructs fixed relative paths with checked fallible string allocation;
7. counts canonical Serde JSON bytes without retaining a first serialization;
8. rejects manifest excess before exact-capacity output allocation; and
9. binds the resulting bytes to a SHA-256 manifest identity.

The manifest retains the exact `VerifiedTransformArtifacts` proof and digest-to-byte bindings. Debug output exposes only binding identities, counts, lengths, and the manifest digest.

This stage performs no filesystem access. It does not choose or validate a managed root, create directories, follow or reject links/reparse points, write blobs, rename files, flush storage, modify a vendor installation, authenticate adapter signatures, authorize execution, or certify compatibility.

## Consequences

- Identical verified overlays and artifact bytes produce byte-identical manifests, paths, blob ordering, and manifest digests.
- Later storage code receives a closed set of relative names and already verified bytes without re-associating caller-controlled paths or raw digests.
- Manifest planning cannot be invoked from an unchecked overlay or unverified artifact map through the safe API.
- The first filesystem-writing milestone must consume this manifest and independently establish a managed root, non-vendor placement, reparse/path safety, atomic create-or-verify behavior, bounded I/O, and post-write integrity.
