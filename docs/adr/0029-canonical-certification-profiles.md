# ADR 0029: Canonical certification profiles

- Status: Accepted
- Date: 2026-07-23
- Extends: [ADR 0028](0028-bounded-non-authorizing-certification-evidence.md)

## Context

Certification evidence binds a `CertificationProfileDigest`, but a digest alone does not define which fixed checks must pass, which checks are genuinely not applicable, which application workflows are mandatory, or which certification class the profile is intended to support.

Allowing evidence producers to choose those requirements inside each evidence document would make results self-scoping. Reusing the shared `CertificationClass` type directly for an untrusted profile declaration would also make it too easy to confuse declared intent with a trusted decision.

## Decision

Introduce the format-`"1"` `CertificationProfile` domain contract and generated `certification-profile.schema.json`.

A profile contains exactly:

- one role-distinct `CertificationProfileClass` declaration;
- one expected status for each of the thirteen fixed certification dimensions; and
- one canonically ordered set of at most 128 mandatory `FeatureId` workflows.

A fixed expectation is either `passed` or `not_applicable`. It cannot ask for `not_run` or `failed`. Every mandatory workflow must pass.

Profile classes deliberately use a distinct Rust type with only `structural_verified`, `smoke_verified`, `contract_verified`, and `exact_certified`. There is no direct conversion from this untrusted declaration to the shared `CertificationClass` vocabulary. `provisional` and `blocked` remain decision outcomes rather than successful profile declarations.

Canonical JSON bytes determine `CertificationProfileDigest`. The bounded parser rejects inputs larger than 128 KiB before deserialization. Unsupported versions, unknown fields, duplicate workflow identifiers, invalid identifiers, and collection overflow fail closed.

`CertificationEvidence::validate_against_profile` consumes one evidence document and one profile, then verifies:

1. the profile's canonical digest equals the role-specific digest embedded in the evidence;
2. every fixed evidence status exactly matches the corresponding profile expectation;
3. the evidence workflow key set exactly equals the profile's mandatory workflow set; and
4. every mandatory workflow status is `passed`.

Successful validation returns an opaque, non-serializable `StructurallyValidatedCertificationEvidence` that retains the exact profile and evidence. This proves structural binding only. It does not authenticate the profile, validate referenced evidence bytes, approve the target, assign a trusted certification class, publish a result, or authorize transformation or execution.

## Security invariants

1. Evidence cannot substitute a different profile after structural validation.
2. Missing, additional, failed, not-run, or not-applicable mandatory workflows fail closed.
3. A fixed check marked `not_applicable` is accepted only when the exact profile requires that status.
4. Profile requirements and class intent are content-addressed together.
5. Untrusted profile class declarations remain type-distinct from trusted certification classes.
6. Caller-selected limits cannot raise the profile byte or workflow ceilings.
7. Generated schema is transport assistance; bounded Rust parsing and validation remain authoritative.
8. Structural validation does not grant trust, publication, transformation, or execution authority.

## Consequences

- Certification profiles can be stored, signed, reviewed, and approved by exact digest without allowing evidence producers to redefine the suite.
- Equivalent workflow insertion orders produce the same canonical profile identity.
- Trusted profile-registry resolution, target applicability, signature policy, referenced-artifact verification, certification-class assignment, and publication remain later boundaries.
- Concrete disposable-state probes and application-specific profile documents remain future work.
