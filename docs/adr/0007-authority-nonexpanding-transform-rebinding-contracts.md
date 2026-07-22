# ADR-0007: Make generated transform rebindings authority-nonexpanding

- Status: Accepted
- Date: 2026-07-21

## Context

Compatibility analysis can establish that one exact source build and one exact target appear feasible, but it does not authorize edits or identify where authenticated semantic-transform rules apply in that build. Weregopher needs a canonical boundary between durable static adapter rules and replaceable per-build matching evidence before implementing matcher execution, transformed-overlay materialization, launch, or certification.

Generated data must not become a second source of adapter authority. A generated overlay that can add a rule, substitute different bytes under a known rule identifier, omit its source-build identity, or detach itself from the exact static authority artifact would permit replay or privilege expansion. Conversely, embedding complete fingerprints, rule programs, transformed source, source maps, or audit logs in this transport would create unnecessary and potentially unbounded input surfaces.

The initial transformation slice remains Windows x64. It is a contract-only milestone and does not establish that a matcher ran correctly, that every required rule was applied, that transformed output is safe to execute, or that an application is certified.

## Decision

`weregopher-domain` defines exact string format version `"1"` for two related canonical transports.

`AdapterTransformAuthority` declares the finite semantic-transform rule set associated with one exact static adapter artifact. It binds:

- a durable adapter identifier;
- a durable application family;
- the exact adapter artifact digest; and
- between 1 and 128 canonical transform-rule identifiers, each paired with a digest committing to that static rule's matcher, implementation, and assumptions.

The transport does not contain or prove a signature. A consumer must authenticate the exact authority artifact through the separate canonical authority path before relying on it. The term authority describes the authenticated artifact's role, not a trust claim made by deserialization. `canonical_document_digest` is defined as SHA-256 over the compact UTF-8 JSON bytes emitted for the format-v1 authority; validation computes this digest from the supplied authority object rather than trusting a separately supplied digest. That canonical encoding contains no insignificant whitespace, emits root fields in declaration order (`format_version`, `adapter_id`, `family`, `adapter_content_digest`, `rules`), emits rule identifiers in bytewise lexical order, and uses the canonical lowercase digest and stable-identifier spellings. Changing this encoding requires a new format version and migration.

`GeneratedTransformOverlay` is per-build evidence. Format version 1 is closed to `windows` and `x86_64`. Its immutable binding identifies:

- the exact source `BuildFingerprint` artifact digest;
- the durable application family and adapter identifier;
- the exact adapter artifact digest;
- the exact `AdapterTransformAuthority` document digest; and
- the exact source build-descriptor artifact digest.

An overlay contains between 1 and 128 canonical rule rebindings. Every rebinding identifies one exact source unit by stable source-unit identifier and source-content digest, repeats the authenticated static rule digest, and references immutable digests for semantic-match evidence, transformed source, source map, and audit log. Two rules may not target the same source-unit identifier in one format-v1 overlay; this avoids silently inventing transform composition or ordering semantics before those semantics have their own explicit contract.

Structural validation requires the caller's expected source-fingerprint and build-descriptor digests plus the static authority document, and verifies all of the following:

1. the overlay is bound to the expected source build and build descriptor;
2. adapter identifier, application family, and adapter artifact digest match the static authority;
3. the overlay references the computed canonical digest of the exact supplied authority document;
4. every generated rule identifier exists in the static authority; and
5. every generated rule digest equals the authenticated static rule digest for that identifier.

Successful validation returns a non-serializable, opaque `StructurallyValidatedTransformOverlay` borrowing the exact overlay and authority objects that were checked. Later transformation and materialization APIs must require this proof instead of accepting a raw generated overlay. The proof name and API deliberately describe structural conformance only: constructing it does not authenticate the authority or overlay and does not grant transformation, execution, launch, or certification authority.

Generated rule maps and rebinding maps use canonical ordered storage. Custom deserializers enforce collection limits while consuming input, reject oversized size hints before retaining entries, consume the first excess or duplicate value as `IgnoredAny`, reject duplicate JSON keys, and rerun semantic constructors. These visitors bound retained domain entries, not a caller-owned input buffer or every parser temporary; any trust-boundary reader must impose an outer byte/read limit before invoking Serde. Closed structs reject unknown fields. Generated Draft 2020-12 schemas mirror exact versions, Windows x64 closure, stable identifier and digest grammars, required fields, closed objects, and map cardinalities. Canonical Rust deserialization and structural validation remain authoritative for invariants such as duplicate JSON keys and unique source-unit targeting that JSON Schema cannot fully express.

These contracts deliberately contain no field for capabilities, native or helper content, privileged operations, state migrations, security exceptions, runtime or backend selection, replacement modules, executable source, launch authorization, transformation authorization, execution authorization, effective security posture, efficiency status, or certification.

## Consequences

- Structurally validated generated overlays can select source units only for already authenticated static rules; they cannot create adapter policy or substitute rule bytes.
- An overlay cannot be replayed across source builds, build descriptors, authority revisions, adapters, or application families without the required structural validation failing.
- Digests are immutable identities, not proof that referenced artifacts exist, are authentic, or were produced correctly.
- Successful structural validation proves only an authority-nonexpanding relationship. It does not prove matcher correctness, complete rule coverage, transform safety, behavioral compatibility, or launch eligibility.
- A subset of static rules may be represented because applicability and completeness remain later evidence-backed decisions. Execution authorization must independently require whatever complete rule coverage its policy demands.
- Transformed bytes, source maps, match evidence, and audit logs remain external content-addressed artifacts rather than embedded transport payloads.
- Existing fingerprint, discovery, compatibility, security-posture, and certification contracts are unchanged.
- Actual matcher execution, overlay materialization, runtime execution, and certification require later milestones and separate authority decisions.
- Breaking serialized changes require a new exact format version and migration.
