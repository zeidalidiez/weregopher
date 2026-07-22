# ADR-0011: Emit canonical bounded static-match evidence

- Status: Accepted
- Date: 2026-07-21

## Context

Deterministic transformed-source emission retains the exact parser-backed plan but does not yet produce the match-evidence artifact referenced by a generated transform rebinding. Match evidence must identify what semantic matcher ran and which source byte ranges it selected without copying proprietary source text, depending on map insertion order, or allocating output before enforcing a practical bound.

## Decision

`weregopher-transform` emits one compact UTF-8 JSON representation for a `TransformPlan`. The versioned document records:

- the static-module-specifier matcher kind;
- the stable rule identifier and canonical rule digest;
- the source-unit identifier and exact source digest; and
- ordered inclusive-start/exclusive-end byte ranges for every planned match.

Field order, punctuation, lowercase digest encoding, decimal offsets, and match order are canonical. Stable identifiers can be written directly because their domain grammar admits only lowercase ASCII letters, digits, `.`, `-`, and `_`. The emitter computes the exact serialized length with checked arithmetic, rejects a zero or exceeded caller-selected limit before fallible exact-capacity allocation, writes without intermediate digest or number strings, verifies the emitted length, and returns the bytes plus their SHA-256 digest. Debug output omits the canonical byte buffer.

This evidence records planner output. It does not include source text, independently reparse the source, authenticate the authority or plan, prove compatibility or matcher correctness, authorize generated authority, materialize content, execute code, or certify a result.

## Consequences

- Identical plans produce byte-identical evidence and digests.
- Evidence remains correlated to exact source and rule identities without retaining source contents.
- Byte ranges remain auditable against the separately verified source artifact.
- A malformed, oversized, overflowed, or unallocatable evidence document fails closed with a typed error.
- Source-map and audit-record emission remain separate bounded milestones before a complete generated rebinding can be assembled.
