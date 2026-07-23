# ADR 0024: Revocation-current local live execution authorization

- Status: Accepted
- Date: 2026-07-23

> Amended by [ADR 0026](0026-execution-contract-v2-and-pre-authorized-launch-plans.md): current
> compatibility and consent are live policy inputs rather than static target fields, and exact
> Windows launch representability is prepared before authorization issuance.

## Context

Static execution authority, generated overlay validation, bounded target and resolution documents, and retained executable capabilities establish separate pieces of evidence. None jointly decides whether a concrete executable may run now. Reconnecting those pieces through ambient paths, positional digests, or an unbounded policy callback would lose the exact identities established by the earlier boundaries.

The first live authorizer also needs an explicit trust boundary. Registry signatures and forensic override authorization are not implemented yet. Treating either mode as equivalent to a local digest pin would silently claim trust semantics that do not exist. Local developer execution must not gain production-state authority.

An authorization decision can become stale immediately after issuance. Revocation and policy replacement therefore need a monotonic invalidation mechanism, and a later launch consumer must be able to recheck it without reconstructing the decision from serialized data.

## Decision

The Windows transform runtime defines an initial local live authorization boundary:

- `LocalExecutionPolicy` is a trusted supervisor input for exactly one target. Role-named pin groups bind the adapter and authority document; source build, package tree, execution environment, and build descriptor; target and resolution documents; artifact-trust and provenance evidence; compatibility, capability, state, and user-policy evidence; effective security posture; state mode; and local policy revision.
- `LocalExecutionPolicyStore` owns one current policy generation. Atomic replacement or revocation increments that generation. Outstanding authorizations retain only a weak reference and the generation that issued them.
- `authorize_execution` consumes a structurally validated overlay proof and one identity-bound retained executable capability. It canonical-hashes typed documents, hashes caller-supplied evidence under explicit per-document and aggregate byte limits that callers may tighten but cannot raise above the 1 MiB/document and 4 MiB/decision implementation ceilings, compares every role to its local pin and cross-document binding, requires a complete compatibility disposition, verifies the exact retained locator and source/executable identities, rejects unsupported required security posture or launch semantics, prepares a Windows launch plan bound to the exact live executable-lock instance, revalidates the retained current view, and confirms that policy did not change during evaluation.
- `AuthorizedExecution` is opaque, non-cloneable, and non-serializable. It owns the retained executable capability, a complete clone of the exact bounded `ExecutionLaunchPolicy`, and the opaque prevalidated Windows launch plan; diagnostics redact argument and evidence contents. Its logical context digest binds the authenticated authority, build/environment context, target, resolution, artifact, compatibility, policy evidence, trust mode, policy revision, and issuing generation. It deliberately excludes local absolute paths, Windows lock-instance identity, and the ambient dependency namespace and is not an exact physical-launch identity.
- The initial process primitive accepts only explicitly declared vendor-default ambient dependency loading and vendor-default ambient state. Manifest-closed dependencies and disposable/production state fail before authorization because the low-level owner does not yet retain an immutable dependency namespace or state lease.
- Local and developer trust are the only recognized local-policy modes. Developer policy requires disposable state, which the current low-level process primitive deliberately rejects until a retained disposable-state lease exists. Registry-trusted and forensic-override requests fail closed until their independent trust engines exist.

The issued value is a conditional live authorization, not process-launch proof. `launch_authorized_execution` consumes it exactly once, holds the issuing policy generation stable, repeats retained current-view validation immediately before process creation, establishes Job containment, creates the process suspended, assigns it, and resumes only after all prior operations succeed.

## Security and authority boundary

This decision does not:

- prove that the caller loaded `LocalExecutionPolicy` from an authentic system policy source;
- implement registry signature verification, publisher-key authorization, forensic approval, or remote revocation retrieval;
- make ordinary package directories immutable or prevent later same-user dependency insertion;
- grant authority to unmanifested package children or to a managed digest absent from its retained manifest;
- authorize Job creation, process creation, assignment, resume, runtime IPC, privileged effects, or state migration;
- turn Job Object limits into a sandbox;
- make a point-in-time current-view check persistent.

Policy loading and persistence remain supervisor responsibilities. Unknown or unavailable trust semantics fail closed rather than being represented by a misleading successful authorization.

## Consequences

- Exact static, generated, policy, compatibility, and filesystem evidence now converge at one typed boundary without reopening an executable path.
- Replacement and revocation invalidate previously issued values without mutating or serializing them.
- The complete launch policy travels with the authorization, preventing later supervisor code from rebuilding arguments, environment, working-directory, console, handle, state, posture, or resource semantics from ambient configuration.
- The consuming launch API operates without widening the public visibility of retained Windows handles.
- Registry trust, durable policy storage, durable supervisor protocol integration, compatibility certification, and runtime effect authorization remain separate milestones.

## Verification

Windows regressions cover successful package-snapshot authorization, complete launch-policy retention and diagnostic redaction, revocation before and after issuance, delayed revocation during bounded blocking supervision, policy replacement and store loss, incomplete compatibility denial despite exact pinning, evidence-content and byte-limit rejection, retained locator and source mismatches, supported trust modes, and developer production-state denial. Native and Linux-target strict Clippy ensure the Windows-only boundary does not regress the portable workspace surface.
