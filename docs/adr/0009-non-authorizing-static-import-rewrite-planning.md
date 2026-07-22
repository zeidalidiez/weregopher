# ADR-0009: Plan exact static module-specifier rewrites without execution authority

- Status: Accepted
- Date: 2026-07-21

## Context

Weregopher's transform authority contracts bind an authenticated adapter to exact rule identifiers and rule digests, but they intentionally do not execute matcher logic. The first executable semantic-transform primitive must establish that source bytes match their content identity, that a concrete rule matches the authenticated authority commitment, and that matches are syntax-aware rather than textual. A substring replacement would incorrectly match comments, ordinary strings, templates, dynamic `import()` expressions, and CommonJS `require()` calls, and could silently change application behavior.

Parser work also crosses a resource boundary. Decoded match-specifier bytes, source bytes, retained edit count, and canonical replacement bytes must be bounded before untrusted input can cause parser or amplified allocation work. Parser diagnostics and source bytes can contain proprietary application code and must not be retained in public proofs or routine debug output.

## Decision

The platform-neutral `weregopher-transform` crate provides a parser-backed planning primitive for one exact static ECMAScript module-specifier rewrite. Oxc parser crates are pinned to exact version `0.80.0` so parser behavior changes require an explicit dependency update and review. The reviewed parser graph satisfies the repository's unchanged MIT-only dependency policy. The Oxc semantic analyzer is deliberately excluded because its graph introduces a non-MIT dependency; this planner rejects parser diagnostics, including malformed regular-expression grammar, but does not claim complete ECMAScript semantic-program validity.

A `StaticImportRewrite` contains:

- one nonempty decoded module specifier to match;
- one distinct nonempty module specifier to emit; and
- one nonzero exact match count.

Control characters are rejected in both specifiers. The rule identity is SHA-256 over a versioned domain separator, big-endian `u32` byte lengths followed by each UTF-8 specifier, and a big-endian `u16` exact match count. Length framing prevents concatenation ambiguity and the versioned domain separates this rule family from other commitments.

Planning requires:

- an already authenticated `AdapterTransformAuthority` supplied by the caller;
- the selected `TransformRuleId` and concrete rule;
- a `SourceUnitRef` paired with immutable source bytes; and
- nonzero caller-selected source-byte, edit-count, and canonical-replacement-byte limits.

The source limit cannot exceed Oxc's `u32` span capacity. The decoded match specifier must fit inside the source limit, the rule's exact match count must fit the edit limit, and the deterministically quoted replacement must fit its byte limit before source processing begins. Planning then rejects oversized source, unknown rule identifiers, rule-digest mismatches, source-digest mismatches, invalid UTF-8, and any parser diagnostic before a plan can exist. Regular-expression grammar parsing is enabled explicitly. The bounded canonical replacement payload is allocated once and shared across edits, and planning stops at the first match beyond the exact committed cardinality rather than retaining further edits.

Oxc parses the input as a JavaScript ES module without JSX or TypeScript extensions and with regular-expression grammar validation enabled. Matching compares decoded string-literal values only for static `import` declarations and `export ... from` / `export * from` declarations. Because Oxc cannot losslessly represent lone UTF-16 surrogate escapes as UTF-8, planning also checks each raw static module literal and rejects an unpaired surrogate escape rather than allowing it to alias ordinary replacement-character text; valid surrogate pairs and escaped backslashes remain valid. Comments, ordinary strings, template literals, dynamic `import()`, CommonJS `require()`, and unrelated syntax are not matches. Each complete source literal span is replaced with one canonical double-quoted JavaScript literal; quotes, backslashes, and Unicode line separators are escaped deterministically.

Success returns a non-serializable in-memory `TransformPlan` retaining the exact rule identifier, canonical rule digest, source-unit identity, and exact-cardinality ordered non-overlapping byte edits. It does not retain source bytes or parser diagnostic text. `SourceUnitInput` debug formatting reports byte length rather than contents.

This primitive verifies structural identities and plans edits only. It does not authenticate signatures, mutate source, emit transformed bytes, produce match evidence, generate source maps or audit logs, materialize files, launch processes, authorize execution, establish compatibility, or certify an adapter.

## Consequences

- Static import and re-export matching is syntax-aware and deterministic rather than substring-based.
- Escaped source literals match by decoded semantic value while emitted literals have one canonical representation.
- Exact cardinality plus matcher, source, retained-edit, and replacement-byte limits make drift and unexpectedly broad or allocation-amplifying rules fail closed at the first excess match.
- Public planning outputs can feed a later deterministic executor without carrying proprietary source bytes.
- Updating Oxc is a reviewed behavior change because the parser dependencies are exactly pinned; a matcher-semantics change also requires a new rule-domain version.
- The next transform milestone must apply a verified plan to immutable bytes and emit content-addressed transformed source, match evidence, source maps, and audit records before artifact verification or materialization can consume them.
- Authentication, filesystem materialization, runtime launch, parity testing, and certification remain separate later boundaries.
