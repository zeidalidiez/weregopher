# ADR 0031: Generation-aware local certification policy resolution

- Status: Accepted
- Date: 2026-07-23
- Extends: [ADR 0028](0028-bounded-non-authorizing-certification-evidence.md), [ADR 0029](0029-canonical-certification-profiles.md), and [ADR 0030](0030-bounded-certification-artifact-verification.md)

## Context

Canonical profiles, structurally matching evidence, and exact referenced artifact bytes are descriptive inputs. None authenticates who approved the profile or evidence, establishes target applicability, or converts a producer-declared profile class into the trusted `CertificationClass` vocabulary.

The first trusted resolver must not accept a class from evidence, infer applicability from a familiar target, or lose the exact artifact-byte proof. It must bind mutable local approval and revocation to exact target, profile, evidence, and class identities. A policy replacement or revocation must invalidate previously issued decisions without depending on callers to compare revision labels themselves.

## Decision

Add a platform-neutral in-memory `LocalCertificationPolicyStore` as the initial local certification trust root. Construction of a `LocalCertificationPolicy` is a trusted caller operation; it is not a public untrusted-document parser or a signed registry decision.

Each policy pins:

1. the complete `CertificationTarget`, including compatibility-analysis, execution-contract, resolution-evidence, artifact-source, and executable identities;
2. the exact canonical `CertificationProfileDigest`;
3. the exact canonical `CertificationEvidenceDigest`;
4. one explicitly approved trusted `CertificationClass`; and
5. a role-specific `CertificationPolicyRevisionDigest`.

`assign_local_certification` consumes `VerifiedCertificationArtifacts`. It requires complete evidence, recomputes the canonical profile and evidence identities, compares every policy pin, and converts `CertificationProfileClass` to `CertificationClass` only when the declared and explicitly approved classes are exactly equal. `blocked` is represented by policy revocation; `provisional` is not assignable from this exact verified-evidence boundary.

The mutable store starts at generation one. Replacement and revocation atomically advance the generation. Revocation evidence uses a role-distinct `CertificationPolicyRevocationDigest`, and a replacement clears prior revocation only by creating a new generation.

A successful decision returns opaque `LocallyCertifiedArtifacts`. It is non-cloneable and non-serializable, retains the exact structural proof and borrowed verified artifact map, and records the issuing policy and generation. `current_class` and `verify_current_policy` fail closed after replacement, revocation, store loss, or synchronization failure.

Currentness checks are point-in-time observations. Any future publication or other policy-controlled commit must hold an appropriate current-policy guard through its own commit point rather than treating a copied class value as authority.

## Security invariants

1. A trusted class is assigned only after exact target, profile, evidence, and class pins match one current local policy generation.
2. Producer-controlled evidence never serializes or directly selects a trusted class.
3. A profile declaration converts to the trusted class vocabulary only inside the policy-authenticated resolver.
4. The resolver consumes and retains exact artifact-byte verification; callers cannot substitute a different map through this API.
5. Replacement and revocation invalidate every older decision, including byte-equal replacement policies.
6. Policy revision and revocation-evidence digests are distinct Rust types.
7. Debug output does not include retained artifact bytes.
8. A local certification decision is not publication, a signature, registry trust, transformation authority, execution authorization, or a sandbox claim.

## Consequences

- Exact locally approved certification results can now carry a generation-aware trusted class without making evidence or profiles authoritative by themselves.
- Downstream publication can require `LocallyCertifiedArtifacts` and add its own atomic current-policy commit protocol.
- Registry signatures, durable policy persistence, semantic report parsing, trusted runner identity, remote revocation, publication, and the concrete certification runner remain separate later boundaries.
