# ADR 0023: Bounded execution target and resolution contracts

- Status: Superseded by [ADR 0026](0026-execution-contract-v2-and-pre-authorized-launch-plans.md)
- Date: 2026-07-23

## Context

> This ADR records the original format-version-1 decision. ADR 0026 replaces its target and
> resolution wire contracts after adversarial review; version 1 is no longer accepted.

Static execution authority identifies each target contract only by digest, while generated execution overlays identify resolution evidence only by digest. Live authorization cannot safely interpret opaque bytes or infer command-line, environment, state, capability, compatibility, user-policy, resource, artifact-locator, trust-evidence, or provenance semantics from those digest labels alone.

The target and resolution documents must remain distinct. A static adapter target contract declares bounded policy and selection intent. Build-specific resolution evidence records the exact locator and content identities selected from that intent. Neither document is authenticated merely because it parses or hashes, and neither document may serialize a reusable launch authorization.

## Decision

Weregopher defines two exact format-version-1 domain contracts and generated JSON Schemas:

- `ExecutionTargetContract` binds an `ExecutionTargetId`, target kind, exact source-tagged artifact locator, and one `ExecutionLaunchPolicy`.
- `ExecutionResolutionEvidence` binds the same target and locator to role-named target-contract, artifact-source, executable, artifact-trust-evidence, and provenance-evidence digests.

Package locators are bounded normalized forward-slash paths. Managed locators are exact SHA-256 blob identities. Runtime construction and deserialization reject empty, absolute-like, parent, dot, Windows-separator, drive-prefixed, trailing-dot/space, overlong, and over-depth package locators. The later retained package lease still performs the authoritative manifest allowlist lookup before joining any physical root.

Format version 1 launch policy is deliberately narrow:

- at most 64 fixed UTF-8 arguments, with 8 KiB per argument and 16 KiB aggregate limits;
- an explicit empty Unicode environment;
- no inherited handles;
- no console;
- the retained executable's parent as working directory;
- an explicit effective security posture and disposable-or-production state mode;
- nonzero coherent active-process, per-process-memory, and aggregate Job-memory limits;
- exact compatibility-analysis, capability-policy, state-policy, and user-policy document digests.

All constructor digest groups are role-named structs. Hostile sequence parsing stops at the first excess argument without deserializing its value. Canonical content identity is SHA-256 over deterministic compact JSON emitted by the validated Rust contract. Debug formatting reports argument counts and byte totals rather than argument contents.

## Authority boundary

These contracts and schemas are non-authorizing evidence. They do not:

- authenticate the adapter, authority document, target contract, resolution document, signer/trust evidence, or provenance evidence;
- establish current revocation state or user consent;
- establish that referenced policy or compatibility documents were retrieved and validated;
- prove that a retained executable matches the locator or digest;
- authorize execution, containment, process creation, or resume;
- claim that Job Object limits are a sandbox.

A live authorizer must compare both canonical document identities against the authenticated static authority and exact generated overlay, validate every cross-document field, resolve current policy and revocation state, and consume an identity-bound retained executable capability.

## Consequences

- Target contract and resolution evidence are independently cacheable and content-addressed.
- Static policy cannot be silently replaced by generated resolution, and generated resolution cannot change launch semantics.
- Exact arguments and policy evidence become explicit launch-decision inputs instead of ambient supervisor state.
- Format version 1 intentionally excludes inherited environments, inherited handles, consoles, dynamic argument patterns, and arbitrary working directories. Supporting them requires a new reviewed contract version or an additive contract with equally explicit bounds.

## Verification

Domain regressions cover canonical round trips, stable document digests, debug redaction, package-locator limits, coherent resource limits, exact argument-count acceptance, malformed first-excess rejection through a streaming JSON deserializer, aggregate argument-byte rejection, unknown fields, and unsupported versions. Schema regressions require closed roots and nested objects, fixed versions, exact required fields, argument and resource bounds, digest references, closed locator variants, and absence of live authorization fields.
