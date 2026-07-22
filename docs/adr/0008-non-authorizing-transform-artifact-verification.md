# ADR-0008: Verify transform artifacts without granting authority

- Status: Accepted
- Date: 2026-07-21

## Context

A generated transform overlay commits to exact source, semantic-match evidence, transformed source, source map, and audit-log digests. Those references do not prove that artifact bytes exist, match their claimed identities, were produced by an authenticated adapter, are safe to materialize, or may be executed.

The next materialization stages need a narrow integrity boundary that checks actual bytes before any filesystem writes. Transform artifacts are untrusted and may be large, so verification must fail closed on incomplete or surplus rule coverage and must bound all byte inputs before spending work hashing them. This boundary must not turn structural digest conformance into adapter authentication, transformation authorization, launch authorization, or certification.

## Decision

The platform-neutral `weregopher-transform` crate verifies borrowed artifact bytes against one canonical `GeneratedTransformOverlay`, but accepts that overlay only through the opaque `StructurallyValidatedTransformOverlay` proof returned by domain validation. This makes exact source/build identity and authority-nonexpansion checks a type-level prerequisite to artifact verification without treating either input as authenticated.

For every rebinding, the caller supplies exactly one bundle containing:

- original source-unit bytes;
- semantic-match evidence bytes;
- transformed-source bytes;
- source-map bytes; and
- transform audit-log bytes.

Bundles use a `BTreeMap` keyed by canonical `TransformRuleId`. Verification first requires exact key-set equality with the overlay: missing and unexpected rule bundles fail closed. Since the overlay contract contains at most 128 unique rebindings, successful coverage also bounds the number of bundles processed.

The caller must provide nonzero limits for each artifact category and for the aggregate bytes across every bundle. Verification checks complete rule coverage, then all per-artifact and aggregate lengths, and only then computes SHA-256 digests. Addition is checked. This ordering avoids hashing oversized inputs before rejection and lets different trust-boundary readers select limits appropriate to their outer bounded transport without embedding arbitrary product policy in the integrity primitive.

Original source bytes must match the `SourceUnitRef` source digest. Match evidence, transformed source, source map, and audit-log bytes must each match their corresponding rebinding digest. Every mismatch identifies the exact rule and artifact category.

Successful verification returns an opaque borrowed `VerifiedTransformArtifacts` value that retains the structural-conformance proof and exact artifact map checked by the function. The value proves only structural conformance plus byte-for-digest conformance under the supplied limits. It is not serializable and carries no adapter authentication, transform authorization, materialization authorization, execution authorization, launch authorization, effective-security claim, efficiency claim, or certification.

Debug formatting reports artifact byte lengths rather than artifact contents so routine diagnostics do not copy proprietary source, match evidence, transformed code, source maps, or audit records into logs.

This increment performs no matcher execution, transformation, filesystem access, content-addressed storage, package mutation, or launch.

## Consequences

- Later content-addressed materialization can consume one exact, already bounded set of bytes without re-associating artifacts by an unchecked rule identifier.
- Missing, surplus, oversized, aggregate-over-limit, and digest-mismatched artifact sets fail closed before a verification proof exists.
- No vendor installation can be modified because this crate has no filesystem behavior.
- Authentication of the exact static authority and adapter artifact remains a separate prerequisite before any execution policy may rely on the overlay.
- A verified artifact set may still be malicious, semantically incorrect, incomplete for an application workflow, or unsafe to execute; digest identity alone cannot establish those claims.
- Content-addressed storage, materialization, transform execution, source-map consumption, runtime execution, parity testing, and certification remain later bounded milestones.
