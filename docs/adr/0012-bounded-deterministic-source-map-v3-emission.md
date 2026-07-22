# ADR-0012: Emit bounded deterministic Source Map v3 artifacts

- Status: Accepted
- Date: 2026-07-21

## Context

Transformed-source and semantic-match-evidence emission identify exact changed byte ranges, but a complete generated transform rebinding also requires a source-map artifact. Copying `sourcesContent` would unnecessarily retain proprietary vendor source. Mapping byte offsets directly as columns would be incorrect for non-BMP Unicode, and treating the two bytes of CRLF as two lines would produce misleading debugger positions.

## Decision

`weregopher-transform` emits a compact deterministic Source Map v3 document from one `EmittedTransformedSource`, the exact digest-matched source bytes, and caller-selected nonzero limits for source bytes, transformed bytes, mapping segments, and final map bytes.

The emitter retains one segment at every generated line start and at both sides of every planned replacement. It:

1. enforces source and transformed-source bounds before hashing or scanning;
2. verifies the supplied source digest against the retained plan;
3. conservatively bounds line-start plus edit-boundary segments before allocating anchor storage;
4. validates ordered, non-overlapping edit and anchor invariants;
5. counts columns in UTF-16 code units;
6. treats CRLF as one line break and also recognizes CR, LF, U+2028, and U+2029;
7. emits canonical Base64 VLQ mappings with checked line, column, delta, and length arithmetic; and
8. rejects an oversized map before fallible exact-capacity output allocation.

The standard `sources` entry uses the stable source-unit identifier. `sourcesContent` and filesystem paths are omitted. A deterministic `x_weregopher` extension binds the document to the exact rule digest, source digest, and transformed-source digest. Debug output contains only safe identities, lengths, counts, and digests.

This map provides debugger correlation. Sparse replacement regions map their start and end to the corresponding original literal boundaries; it is not a character-by-character provenance proof. It does not authenticate authority, prove compatibility or semantic correctness, authorize a generated overlay, materialize files, execute code, launch an application, or certify a result.

## Consequences

- Identical plans, source bytes, and transformed bytes produce byte-identical Source Map v3 artifacts and digests.
- Non-BMP source columns and every ECMAScript line-terminator form have explicit deterministic handling.
- Vendor source content is not duplicated into the map.
- Oversized inputs, excessive segment requirements, malformed internal ranges, invalid UTF-8, arithmetic failures, and allocation failures are typed fail-closed errors.
- Audit-record emission and complete artifact-to-rebinding assembly remain the next bounded milestone.
