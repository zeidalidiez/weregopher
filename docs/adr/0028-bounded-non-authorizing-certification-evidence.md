# ADR 0028: Bounded non-authorizing certification evidence

- Status: Accepted
- Date: 2026-07-23
- Amends: [ADR 0006](0006-fail-closed-compatibility-analysis-contract.md)

## Context

Compatibility analysis determines whether a build has enough evidence to attempt a transformation. It is not evidence that the transformed application actually starts, preserves workflows, respects state boundaries, or satisfies the runtime security contract.

The repository previously defined certification classes but no canonical artifact from which a trusted certification decision could later be made. Allowing a producer to serialize a class, trust mode, publication status, or execution-authority bit in such an artifact would let generated evidence manufacture authority. Unbounded workflow maps, probe evidence, or JSON input would also expose trust boundaries to memory exhaustion.

## Decision

Introduce the format-`"1"` `CertificationEvidence` domain contract and generated `certification-evidence.schema.json`.

Each document binds exactly:

- one `CompatibilityAnalysisDigest`;
- one `ExecutionContractDigest`;
- one `ExecutionResolutionEvidenceDigest`;
- one `ExecutionArtifactSourceDigest`;
- one `ExecutableDigest`; and
- one separately resolvable `CertificationProfileDigest`.

These identities use role-specific Rust wrappers even though their wire representation remains the canonical SHA-256 string.

The document contains thirteen fixed check dimensions:

1. package identity;
2. entry-point resolution;
3. transform match cardinality and output identity;
4. module-graph load;
5. native dependencies;
6. runtime bootstrap;
7. renderer bootstrap;
8. preload handshake;
9. state safety;
10. helper lifecycle;
11. security contract;
12. resource scenario; and
13. declared exceptions.

It may also contain at most 128 canonically ordered `FeatureId` workflow checks. Every check has one status: `not_run`, `passed`, `failed`, or `not_applicable`. Resolved checks require at least one immutable evidence reference. A `not_run` check must contain no evidence. Evidence references are unique, canonically ordered, and limited to 64 per check.

The canonical bounded parser rejects serialized documents larger than 4 MiB before deserialization. Unknown fields, unsupported format versions, duplicate workflow identifiers, duplicate evidence references, invalid identifiers, contradictory status/evidence combinations, and collection overflows fail closed. The generated schema mirrors structural limits and status/evidence conditions, but Rust remains authoritative.

Canonical compact JSON bytes produce a role-specific `CertificationEvidenceDigest`. Equivalent map insertion orders therefore identify the same exact-target evidence document, while any serialized semantic change changes the content identity. Evidence, profile, and artifact digest wrappers are not substitutable in Rust.

`CertificationEvidence::disposition` derives only `incomplete`, `blocked`, or `complete`. The document does **not** serialize or derive a certification class from a producer-selected scope. Mapping complete evidence to `CertificationClass` requires a later trusted lookup of the exact profile digest plus decision policy.

The evidence contract contains no publication status, trust mode, timestamps, mutable registry state, transformation authority, execution authority, or `certified` boolean. It is evidence, not a capability or trust decision.

## Security invariants

1. The compatibility analysis, static execution contract, generated resolution, artifact source, and executable cannot be rebound independently.
2. A profile identity cannot be paired with an attacker-selected serialized certification scope.
3. A failed check dominates unresolved checks in the aggregate disposition.
4. An unresolved check prevents the aggregate from becoming complete.
5. A resolved check without immutable evidence is invalid.
6. Generated schema is transport assistance; constructors and bounded deserializers are authoritative.
7. Complete evidence does not by itself grant certification class, trust, publication, transformation, or execution authority.

## Consequences

- Certification evidence can now be content-addressed, persisted, compared, and independently audited without manufacturing authority.
- Different probe orders serialize identically.
- Canonical profile definition and structural profile/evidence binding are specified by [ADR 0029](0029-canonical-certification-profiles.md); trusted profile approval and class assignment remain explicit later boundaries.
- The concrete disposable-state certification runner, artifact retention, profile registry, signatures, trust policy, and publication workflow remain future work.
