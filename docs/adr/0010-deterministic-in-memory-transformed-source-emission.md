# ADR-0010: Emit transformed source deterministically in memory

- Status: Accepted
- Date: 2026-07-21

## Context

Parser-backed planning identifies exact static module-specifier edits but deliberately does not mutate or retain source bytes. The next transformation-runtime step needs to apply those edits deterministically while preserving the exact source identity and practical resource limits. Applying edits directly to files would cross the materialization boundary too early, and treating an output buffer as a complete transform artifact bundle would overclaim because match evidence, source maps, and audit records are not emitted yet.

## Decision

`weregopher-transform` exposes `emit_transformed_source` as a platform-neutral, in-memory operation over one `TransformPlan`, immutable source bytes, and caller-selected nonzero source/output limits.

Emission:

1. rejects source bytes above the source limit before hashing;
2. verifies the supplied bytes against the plan's exact `SourceUnitRef` digest;
3. defensively verifies that every retained edit is ordered, non-overlapping, forward, and within the exact source;
4. computes the exact transformed length with checked subtraction and addition;
5. rejects output above the transformed-source limit before allocation;
6. uses fallible exact-capacity reservation; and
7. copies unchanged ranges and canonical replacement literals in plan order.

Success returns a non-serializable `EmittedTransformedSource` retaining the exact plan, owned transformed bytes, and their SHA-256 digest. Debug output contains only safe identities, the transformed byte length, and the digest rather than source contents.

This operation is deterministic byte emission, not filesystem application. It does not authenticate the authority, adapter, plan, or source; create a generated overlay; emit match evidence, a source map, or an audit log; materialize content; mutate a vendor package; authorize execution or launch; or establish compatibility, security posture, efficiency, or certification.

## Consequences

- Identical plans and exact source bytes produce identical transformed bytes and digests.
- Source substitution, oversized input or output, arithmetic overflow, invalid edit ranges, and allocation failure are typed fail-closed errors.
- The original source remains immutable and no filesystem path is accepted by this API.
- A transformed-source result is not yet a complete transform artifact bundle and cannot by itself support overlay verification or materialization.
- Deterministic match-evidence, source-map, and audit emission remain the next bounded transformation milestone.
