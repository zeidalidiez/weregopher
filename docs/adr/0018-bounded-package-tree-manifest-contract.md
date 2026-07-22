# ADR 0018: Bound the canonical package-tree manifest contract

- Status: Accepted
- Date: 2026-07-22

## Context

`PackageTreeManifest` is the canonical serialized evidence for a package-tree Merkle identity. Its original transport decoded `files` through a derived `Vec<PackageFileRecord>` and rejected malformed tree semantics only after that vector had been allocated. It also accepted unknown fields on the manifest and nested file records.

That was insufficient for a trust-boundary document. An untrusted manifest could force unbounded retained record and path allocation before semantic validation, and a future authority-like field could be silently ignored rather than rejected. Package-tree acquisition and immutable package views need a bounded canonical input before they can safely consume this contract.

## Decision

Format version 1 now applies fixed implementation limits:

- at most 65,536 file/link records;
- at most 16 MiB of aggregate UTF-8 bytes across normalized record paths; and
- the existing maximum of 32,767 Unicode scalar values for each normalized path.

`build_package_manifest` checks record count and aggregate path bytes before sorting, case-folding, tree construction, or Merkle hashing. It reports typed exact-count errors for trusted Rust callers.

Transport deserialization uses a custom Serde sequence visitor. The visitor:

1. rejects a disclosed sequence length above the record limit before reserving storage;
2. reserves no more than the record limit;
3. accumulates normalized-path bytes with checked arithmetic as records are retained;
4. rejects aggregate path excess immediately; and
5. consumes the first maximum-plus-one element as `IgnoredAny` before returning the record-limit error, so a malformed excess record is not domain-deserialized.

Both the outer manifest object and nested `PackageFileRecord` objects reject unknown fields. Generated JSON Schema declares `additionalProperties: false` at both levels and `maxItems: 65536` for `files`. Rust deserialization remains authoritative for the aggregate path-byte limit, which JSON Schema does not express.

The fixed limits are part of format-version-1 acceptance semantics. Weregopher is pre-release; tightening the previously unbounded parser is accepted as a fail-closed correction rather than introducing a format that preserves unsafe behavior.

## Security and authority boundary

These limits bound retained domain values. They do not bound bytes buffered by an outer JSON reader before Serde sees values; callers at an untrusted I/O boundary must still impose a transport-byte limit.

A package-tree manifest remains content-addressed evidence, not proof that files were obtained from a coherent filesystem snapshot, that an installation is immutable, that a signer is trusted, or that transformation or execution is authorized. Filesystem enumeration, reparse handling, exact file leases, snapshot publication, and live-view stability remain separate boundaries.

## Verification

Behavior tests cover:

- exact maximum and maximum-plus-one record counts;
- exact maximum and maximum-plus-one aggregate normalized-path bytes;
- a malformed first excess record producing the record-limit error;
- transport aggregate-path rejection;
- unknown outer and nested fields;
- schema cardinality and closed-object parity; and
- all existing canonical ordering, path, case-collision, metadata, and Merkle checks.

## Consequences

- Oversized trusted input fails before sort/tree amplification.
- Oversized transport retains no more than the fixed record and path-byte budgets.
- Unknown authority-like or metadata fields cannot disappear during parsing.
- Existing canonical manifests within the limits retain the same bytes and Merkle identities.
- Packages exceeding either limit require an explicit future contract revision rather than implicit unbounded behavior.
