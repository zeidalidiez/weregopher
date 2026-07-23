# ADR 0020: Content-addressed Windows package snapshots

- Status: Accepted
- Date: 2026-07-22

## Context

Weregopher must preserve an observed installed package outside the vendor installation so later
transformation, compatibility, and rollback work does not float to an updater's replacement tree.
A package-tree manifest alone is not sufficient: publication must consume the retained live
observation, copy the exact declared bytes, compose a complete deterministic namespace, and reject
existing conflicting objects without modifying vendor files.

The managed content store already provides create-new staging, exact content verification,
no-replace hard-link publication, and retained blob leases. Package snapshots need a separate
package-tree identity namespace and explicit limits for both publication and leasing.

Windows directory handles do not make a child namespace immutable. In particular, denying write
sharing on a retained directory object does not stop an unrestricted same-user process from adding a
new child. Job Objects are likewise lifecycle controls rather than sandboxes. The snapshot boundary
must therefore state exactly what is reverified and must not turn filesystem retention into an
execution-authorization or sandbox claim.

## Decision

The initial Windows snapshot implementation will:

1. accept a completed `PackageTreeObservation`, not a caller-supplied manifest by itself;
2. require the observation's caller-selected source root to equal the vendor root bound to the
   `ManagedArtifactStore`;
3. validate all file, implied-directory, per-file, aggregate-content, aggregate-directory-path, path
   component, Windows-name, and temporary-publication limits before managed writes;
4. reject symbolic links, reparse points, unsupported entry kinds, Windows reserved aliases
   (including superscript DOS-device digits), trailing spaces or periods, and noncanonical paths;
5. open every observed source through its bounded identity-verified reader, publish exactly the
   declared length into SHA-256 blobs, and reject both early EOF and surplus bytes;
6. keep source blobs under the managed `sha256/<fanout>/<digest-tail>` namespace and compose physical
   views under `package-views/sha256-<package-tree-merkle>/tree`;
7. hard-link only from reverified managed blobs, never from vendor-controlled files;
8. use create-or-verify convergence: an existing link is accepted only when its full digest, size,
   regular-file kind, and file identity match the expected managed blob, and no conflicting object is
   replaced;
9. permit an incomplete view directory to remain after interruption, but never return it as a lease
   until every expected directory and file exists and exact recursive membership has been verified;
10. retain managed-root ancestors, every view directory identity, and every exact file identity for
    the lease lifetime, with represented files opened without write or delete sharing;
11. rehash every represented file twice around metadata checks when a lease is acquired;
12. expose `verify_current_view` so a consumer can repeat managed-root, directory identity, exact
    file-content, file-identity, and complete-membership verification immediately before physical-path
    use; and
13. support empty package roots as one retained root directory with zero files.

The canonical package-tree manifest keeps its serialized fields but exposes only read-only public
accessors. Normalized package paths have a fixed 256-component ceiling in addition to the existing
32,767-scalar per-path, 65,536-record, and 16 MiB aggregate path budgets.

Publication and leasing use independent caller-provided file, directory, per-file, aggregate-byte,
and temporary-attempt limits. Implied directory paths additionally share the canonical 16 MiB
aggregate path ceiling so prefix expansion cannot create an unbounded retained namespace.

## Acceptance boundary

Publication is incremental and convergent rather than a single directory rename. The acceptance
boundary is the successfully returned lease, after complete membership, all content, and all retained
identities have been verified. Callers must not treat the mere existence of a digest-named directory
as a completed snapshot.

A lease prevents ordinary replacement or new write opens for represented files and prevents ordinary
replacement of retained directories. It does not:

- prevent an unrestricted same-user process from injecting a new child after membership validation;
- defeat a writable mapping or privileged handle created before the lease;
- authorize adapter selection, transformation, execution, privileged effects, or process launch;
- sandbox Bun, Electron helpers, native modules, or any other same-user process; or
- certify functional compatibility, security posture, or efficiency.

Consumers of the physical view must keep the lease alive and call `verify_current_view` at the closest
available pre-use boundary. A future VFS/package-view layer should prefer manifest-scoped operations
over unconstrained pathname lookup and will define the stronger logical namespace used by execution.

## Consequences

- Vendor installations are never modified.
- Equal file bytes deduplicate across package snapshots, while package-tree Merkle values retain exact
  path and file-kind identity.
- A vendor package can be replaced after snapshot publication and the managed snapshot can still be
  reopened from its manifest.
- Concurrent publishers converge without replacing existing correct bytes or links.
- ASAR files, native modules, executables, and ordinary files retain their canonical file-kind records
  while sharing the same verified byte-publication mechanism.
- Snapshot publication remains separate from transformation overlays, execution authorization,
  supervisor policy, garbage collection, and certification evidence.
- The first implementation is Windows-only; non-Windows builds expose the contract and fail with an
  explicit unsupported-platform error.
