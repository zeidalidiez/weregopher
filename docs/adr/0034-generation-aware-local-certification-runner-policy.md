# ADR 0034: Generation-aware local certification-runner policy

- Status: Accepted
- Date: 2026-07-23
- Extends: [ADR 0033](0033-bounded-canonical-certification-runner-identity.md)

## Context

The canonical certification-runner identity is deliberately descriptive and non-authorizing. Parsing and hashing it does not make the named runner trusted, authenticate the external component descriptors represented by its role digests, or prove that a certification run occurred.

Before a later run-attestation boundary can rely on a runner identity, trusted local configuration needs to approve one exact canonical identity while preserving mutable replacement and revocation. A copied approval must not remain current after policy replacement, revocation, store loss, or synchronization failure.

## Decision

Add a platform-neutral in-memory `LocalCertificationRunnerPolicyStore` as the first local trust root for certification-runner identity manifests. Constructing `LocalCertificationRunnerPolicy` is a trusted in-process configuration operation, not an untrusted document parser or a signature-verification result.

Each policy pins:

1. one exact `CertificationRunnerIdentityDigest`; and
2. one role-specific `CertificationRunnerPolicyRevisionDigest`.

`approve_local_certification_runner` consumes the canonical identity document, recomputes its role-specific digest, and requires exact equality with the current policy. A successful decision returns opaque `LocallyApprovedCertificationRunner`, which retains the exact identity document and the issuing policy generation. It is non-cloneable and non-serializable.

The mutable store starts at generation one. Replacement and revocation atomically advance the generation. Revocation evidence uses a distinct `CertificationRunnerPolicyRevocationDigest`; replacement clears previous revocation only by creating a new generation. Byte-equal replacement still invalidates older approvals.

`verify_current_policy` fails closed after replacement, revocation, store loss, or synchronization failure. This method is a point-in-time currentness observation. A later run-attestation or other policy-controlled effect must retain an appropriate policy guard through its own commit point.

## Security invariants

1. Local approval is issued only when the recomputed canonical identity equals the exact digest pinned by one current, non-revoked policy generation.
2. The returned approval consumes and retains the exact identity document; callers cannot substitute another manifest while retaining the approval.
3. Replacement and revocation invalidate every older approval, including approvals from a byte-equal policy.
4. Policy revision and revocation-evidence identities are distinct Rust types.
5. Approval is non-cloneable, non-serializable, and carries no certification class or execution authority.
6. Debug output identifies only the aggregate runner identity and policy metadata, not all component-role identities.
7. Local approval does not verify external component-descriptor bytes or provenance, prove execution, establish freshness, bind reports, validate semantics, authorize publication, or authorize execution.

## Consequences

- Later descriptor-verification and run-attestation boundaries can require an opaque, generation-current approval rather than accepting a producer-supplied identity digest or boolean.
- Policy replacement and revocation have explicit monotonic invalidation semantics.
- Component-descriptor verification, authenticated per-run attestation, challenge/freshness management, semantic report validation, and integration with certification-class assignment remain separate later boundaries.
