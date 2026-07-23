# ADR 0022: Identity-bound retained executable capabilities

- Status: Accepted
- Date: 2026-07-23

## Context

The Windows launch primitive retains an executable path and every ancestor against rebinding, but path locking alone does not prove that the selected file is the exact object and bytes retained by a managed-artifact or package-snapshot lease. Conversely, those leases retain exact identities and digests but previously exposed no executable capability suitable for a later live authorization boundary.

Returning a raw path would discard the logical package allowlist. Returning a locked path without borrowing the complete lease would permit package and managed-manifest retention to end before authorization or process lifetime. Neither result may be mistaken for adapter authentication, execution authorization, launch authorization, a closed dependency namespace, or sandboxing.

## Decision

`weregopher-windows::LockedExecutable` adds `open_matching_identity`. It performs the existing bounded absolute-path, non-reparse, direct-file and ancestor locking, then compares the opened executable's full Windows identity with a caller-supplied retained `FileIdentityLease`. A mismatch fails closed without exposing the path in the error.

The Windows-only transform runtime adds two opaque non-authorizing capabilities:

- `PackageSnapshotExecutable` is obtained only by an exact manifest-relative allowlist lookup. It borrows the complete `PackageSnapshotLease`, retains the manifest digest and normalized logical path, and owns an identity-matched `LockedExecutable`.
- `ManagedArtifactExecutable` is obtained only for a digest already present in one `ManagedArtifactLease`. It borrows that complete lease, retains the executable digest, and owns an identity-matched `LockedExecutable`.

Both acquisition paths verify the retained managed root before and after locking. Package executable resolution does not join the physical root until the allowlist lookup succeeds. The capabilities expose safe logical identities for correlation and redact physical paths from `Debug` output. Their locked handles remain private for consumption by a later authority-bearing execution layer.

## Security and authority boundary

These capabilities prove composition of already-retained filesystem identity with a locked launch path. They do not:

- authenticate an adapter, authority document, target contract, generated overlay, signer, or revocation state;
- validate resolution evidence, compatibility, state, capability, environment, argument, or user policy;
- authorize execution, process creation, or resume;
- prevent an unrestricted same-user process from adding an unmanifested package child;
- freeze DLLs or other files opened later by a child;
- create an OS sandbox or improve the declared effective security posture.

A live authorizer must consume one of these exact capabilities together with authenticated and revocation-checked authority, validated target and resolution contracts, complete compatibility and policy evidence, and immediate package-view revalidation. Job ownership and process launch remain subsequent boundaries.

## Consequences

- A higher layer no longer needs to reconnect an approved digest to an ambient filesystem path.
- The complete source lease is retained by the type system for at least as long as the executable capability.
- Package targets cannot resolve an unlisted injected child through this API.
- Low-level `LockedExecutable::open` remains a deliberately non-authorizing lifecycle primitive; callers must not bypass the authority-bearing layer and infer approval from path stability.
- Ordinary Windows directories still do not provide a coherent immutable dependency namespace.

## Verification

Windows regressions cover exact identity acceptance, distinct-file rejection, path-redacted diagnostics, package allowlist rejection, package executable digest retention, managed-manifest membership rejection, managed executable digest retention, strict Clippy, and the complete affected workspace suite.
