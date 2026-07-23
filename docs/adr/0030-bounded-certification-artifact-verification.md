# ADR 0030: Bounded certification artifact verification

- Status: Accepted
- Date: 2026-07-23
- Extends: [ADR 0028](0028-bounded-non-authorizing-certification-evidence.md) and [ADR 0029](0029-canonical-certification-profiles.md)

## Context

Structurally validated certification evidence contains role-specific digests for immutable reports, probes, traces, and fixtures, but a digest reference is not proof that corresponding bytes were supplied. Class assignment or publication must not proceed from producer-declared statuses while referenced evidence is missing, substituted, oversized, or accompanied by unreferenced material.

Certification evidence may contain repeated references when one artifact supports multiple checks. Verification therefore needs exact unique coverage without permitting repeated references to multiply authority. It must also bound count, per-artifact bytes, aggregate bytes, and reference-index allocation before hashing attacker-controlled inputs.

## Decision

Add `verify_certification_artifacts` to the transform boundary. It consumes one opaque `StructurallyValidatedCertificationEvidence` and borrows a canonically ordered map from `CertificationArtifactRef` to exact bytes.

The verifier:

1. rejects more supplied entries than any valid certification document can reference;
2. builds a bounded unique index of every artifact referenced by the structurally validated evidence;
3. rejects missing and unexpected artifacts;
4. checks each byte length and checked aggregate arithmetic before hashing any supplied artifact;
5. hashes every supplied byte slice and compares it with the role-specific `CertificationArtifactDigest`; and
6. returns an opaque `VerifiedCertificationArtifacts` retaining the structural proof and the exact borrowed byte map.

The implementation ceilings are:

- 16 MiB per artifact;
- 128 MiB for unique supplied artifacts in aggregate; and
- 9,024 unique references, derived from thirteen fixed checks plus 128 workflows, each admitting at most 64 references.

Caller-selected byte limits may tighten but cannot raise those ceilings. Zero limits fail closed. Repeated references to the same kind-and-digest pair require one supplied artifact and contribute once to the aggregate.

The returned proof is non-serializable. Its debug representation reports only target/profile identities, artifact count, and aggregate length; it does not print artifact bytes.

## Security invariants

1. Every referenced artifact has exactly one supplied kind-and-digest binding.
2. Supplied but unreferenced bytes fail closed.
3. Coverage and all byte limits are established before any supplied artifact is hashed.
4. Checked arithmetic prevents aggregate-length wraparound.
5. The proof retains the exact borrowed map, preventing substitution through this API after verification.
6. Verification establishes digest conformance only. It does not validate artifact semantics, authenticate the producer or profile, approve target applicability, assign a certification class, publish a result, or authorize transformation or execution.
7. Job Objects, process ownership, or certification artifacts are not sandbox claims.

## Consequences

- Later certification policy can require an opaque byte-conformance proof instead of trusting digest references alone.
- Shared evidence remains deduplicated while exact artifact-kind bindings are preserved.
- Concrete probe execution, artifact persistence, semantic report validation, trusted runner identity, profile approval, target applicability, class assignment, signatures, and publication remain later boundaries.
