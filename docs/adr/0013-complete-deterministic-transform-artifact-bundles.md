# ADR-0013: Assemble complete deterministic transform artifact bundles

- Status: Accepted
- Date: 2026-07-21

## Context

Transformed source, semantic-match evidence, and Source Map v3 artifacts are emitted independently from exact plans. A generated transform rebinding additionally requires a deterministic audit-log identity, and callers need one composition boundary that rejects cross-plan or cross-output artifact mixing before an overlay can be built.

## Decision

`weregopher-transform` assembles one complete in-memory artifact bundle from:

- exact source bytes;
- an `EmittedTransformedSource`;
- an `EmittedMatchEvidence`;
- an `EmittedSourceMap`; and
- caller-selected nonzero source, audit-log, and aggregate byte limits.

Assembly:

1. bounds source bytes before hashing;
2. requires match evidence to retain the same transform-plan content as the transformed source;
3. requires the source map to retain the same transformed-source content;
4. verifies the supplied source digest against the retained plan;
5. computes the exact canonical audit length and the aggregate five-artifact length with checked arithmetic;
6. rejects audit or aggregate excess before allocating audit output;
7. emits compact canonical JSON with no timestamp or ambient machine data; and
8. constructs the exact `TransformRebinding` from rule, source, match-evidence, transformed-source, source-map, and audit-log digests.

Equivalent independently emitted artifacts may compose when their retained plan and transformed-source content is identical. Rust object addresses are not evidence and are not part of the contract.

The audit record contains stable identifiers, content digests, operation kind, and edit count only. It does not contain source bytes, replacement contents, filesystem paths, environment data, or wall-clock time. Custom debug output likewise exposes only safe identities, lengths, counts, and digests.

The resulting bundle is generated correlation evidence. It does not authenticate the adapter authority, approve a generated overlay, prove semantic compatibility, materialize files, mutate a vendor installation, execute code, launch an application, or certify a result.

## Consequences

- One bounded API now produces all five in-memory artifact byte categories plus the exact generated rebinding needed to construct an overlay.
- Identical artifact inputs produce byte-identical audit logs, audit digests, aggregate lengths, and rebindings.
- Content equality, rather than pointer identity, permits deterministic independently emitted components to compose.
- Cross-plan evidence, cross-output source maps, source digest mismatches, oversized audit logs, oversized aggregate bundles, arithmetic failures, and allocation failures are typed fail-closed errors.
- Overlay construction, structural validation, artifact verification, and content-addressed materialization remain separate stages; an end-to-end in-memory composition regression is the next bounded integration checkpoint.
