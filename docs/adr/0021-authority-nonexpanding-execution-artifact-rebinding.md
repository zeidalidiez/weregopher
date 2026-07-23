# ADR-0021: Separate static execution authority from generated build-bound artifact evidence

- Status: Accepted
- Date: 2026-07-23

## Context

Weregopher can now retain an observed package tree, publish it into a managed content-addressed view, retain exact manifest-listed file identities, publish transformed artifacts, lease exact managed blobs, own a bounded Windows process tree, and create its primary process suspended before atomically assigning it to that tree. Those capabilities do not yet establish which runtime, helper, or ABI island an adapter may nominate for one source build.

The durable policy and the replaceable build analysis must remain separate. A generated build overlay that can invent an execution target, substitute a target contract, switch from a managed artifact to arbitrary filesystem content, or replay a resolution across source builds, package trees, adapters, or execution environments would become an unreviewed authority source. Conversely, treating a digest relationship as a live launch decision would skip adapter authentication, revocation, retained-artifact verification, command-line and environment policy, capability resolution, compatibility gates, and process containment.

This increment therefore defines authority-nonexpanding execution-artifact rebinding only. It deliberately stops before authenticated execution authorization, executable leasing, process launch, supervision, sandbox claims, or certification.

## Decision

`weregopher-domain` defines exact string format version `"1"` for two related canonical transports under the initial Windows x64 release profile.

### Static adapter execution authority

`AdapterExecutionAuthority` identifies:

- the durable adapter identifier;
- the application family;
- the exact adapter-content digest; and
- between 1 and 64 canonical execution-target identifiers.

Each `AuthorizedExecutionTargetRef` carries only:

- a closed target role: Weregopher main runtime, vendor helper, ABI island, or specialized helper;
- a closed managed source class: package snapshot or managed artifact; and
- the digest of the complete static target contract.

The referenced target contract is expected to contain the authenticated artifact-selection and launch-policy semantics. The authority transport neither embeds nor interprets those bytes. In particular, the `VendorHelper` role is available only for an independently designed vendor executable; it cannot be used to relabel a vendor's complete Electron application tree as a helper.

The word *authority* describes the role these bytes may have after authentication. Parsing, constructing, hashing, or structurally validating this object does not prove a signature, trust mode, freshness, or revocation state. Before using the document in a launch decision, a later authority verifier must retrieve the exact adapter and target-contract bytes, verify their content identities, authenticate the applicable trust chain, and check revocation.

`canonical_document_digest` is SHA-256 over the compact UTF-8 JSON emitted for the format-v1 authority. Root fields are emitted in declaration order, target identifiers use bytewise lexical order from `BTreeMap`, and identifiers, enums, and digests use their canonical spellings. The implementation tests this digest against SHA-256 of actual serializer output. Any encoding change requires a new format version and migration.

### Generated execution overlay

`GeneratedExecutionOverlay` is replaceable per-build resolution evidence. Its immutable binding identifies:

- the exact source build-fingerprint artifact;
- the exact observed package-tree Merkle identity;
- the exact execution-environment descriptor;
- the exact build descriptor;
- the application family and adapter identifier;
- the exact adapter-content digest; and
- the computed canonical digest of the static execution-authority document.

The overlay contains between 1 and 64 canonical target bindings. Each `ExecutionArtifactBinding` repeats the static target-contract digest and binds:

- the package-tree or managed-manifest identity containing the executable;
- the exact executable-byte digest; and
- the exact generated resolution-evidence digest.

Resolution evidence remains an external content-addressed artifact. It may describe the normalized executable selection, signer or provenance observations, and target-contract resolution, but this transport only binds its digest; it does not parse, trust, or authorize those claims. Command lines, environments, capabilities, privileged operations, state migrations, native-content grants, security exceptions, and launch booleans are intentionally absent.

### Structural validation

`GeneratedExecutionOverlay::validate_against` first compares caller-supplied source-build, package-tree, execution-environment, and build-descriptor identities. It then verifies adapter, family, adapter-content, and computed static-authority identities. Finally it rejects unknown target identifiers and substituted target-contract digests. A package-snapshot target must bind the overlay's exact package-tree Merkle identity; a managed-artifact target may bind a distinct content-addressed managed manifest that a later stage must retrieve and verify.

Successful validation returns a non-serializable `StructurallyValidatedExecutionOverlay` borrowing the exact overlay and static authority objects that were checked. This proof establishes only structural conformance and authority non-expansion. It is not an authenticated authority, compatibility result, executable lease, execution authorization, launch token, containment proof, security-posture claim, efficiency result, or certification.

Generated overlays may select a subset of statically authorized targets. Target completeness and required process topology remain authenticated policy and later launch-decision concerns; generated evidence may not add a target.

### Bounded transport and schema

Both maps use canonical ordered storage. Custom Serde visitors reject oversized disclosed map lengths before retaining entries, retain at most the fixed limit, reject duplicate JSON keys before constructing their values, consume the first duplicate or excess value as `IgnoredAny`, and rerun the semantic constructors. These visitors bound retained domain entries, not a caller-owned transport buffer or every parser temporary. Hostile inputs therefore also require an outer byte/read limit before Serde parsing.

Every nested object is closed to unknown fields. Generated Draft 2020-12 schemas are separate roots for the authority and overlay and mirror the exact string version, Windows x64 vocabulary, stable identifier grammar, digest grammar, required fields, closed nested objects, and map bounds. Canonical Rust deserialization and structural validation remain authoritative for duplicate-key and cross-object invariants.

## Consequences

- Generated build evidence cannot create an execution target, change its role or managed source class, or substitute its static target contract.
- Structural validation detects replay across source builds, package trees, build descriptors, execution environments, adapters, application families, adapter revisions, and static-authority revisions.
- A digest is immutable identity, not proof that referenced bytes exist, remain current, are authentic, or were resolved correctly.
- Package-snapshot execution consumers must use manifest-scoped, identity-verified file capabilities. An unrestricted physical snapshot root is diagnostic and cannot be treated as a closed namespace or execution authority.
- A later live execution-authorization capability must authenticate and revocation-check authority, retrieve and validate target contracts and resolution evidence, verify exact retained package or managed-artifact leases, resolve command line, environment, capabilities, compatibility, and state policy, and emit an explicit allow-or-deny decision bound to those live capabilities.
- Live authorization remains separate from Job Object ownership, suspended process creation, process resume, runtime supervision, compatibility, security posture, efficiency, and certification.
- Job Objects remain lifecycle and accounting controls, not sandboxes. Vendor helpers, Bun processes, and ABI islands remain unrestricted same-user processes unless an independently tested OS sandbox proves otherwise.
- Existing discovery, fingerprint, transformation, materialization, process, compatibility, security-posture, and certification contracts are unchanged.
- Breaking serialized changes require a new exact format version and migration.
