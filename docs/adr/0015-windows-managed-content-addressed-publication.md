# ADR 0015: Windows managed content-addressed publication and leasing

- Status: Accepted
- Date: 2026-07-21

## Context

ADR 0014 stops after producing a canonical, bounded, filesystem-free materialization manifest. The next boundary must place the manifest's already verified artifact bytes in a managed store without modifying a vendor installation, following caller-controlled relative paths, replacing existing content, or treating a successful write as execution authority.

On Windows, path checks alone are insufficient. Junctions and other reparse points can redirect path traversal, names can be rebound between checks, concurrent publishers can race, and a pre-existing digest path may contain conflicting bytes. Publication also needs an explicit resource and durability policy.

## Decision

`weregopher-transform` exposes a separate Windows-only `ManagedArtifactStore` capability plus bounded `materialize` and `lease_manifest` operations.

### Root acquisition

- The caller supplies an existing managed-store root and the associated existing vendor-installation root.
- Both roots must be absolute non-verbatim Windows paths within a caller-selected component bound.
- Every live path component is opened directly with `FILE_FLAG_OPEN_REPARSE_POINT`, checked as a directory, and rejected when it is a reparse point.
- The store's ancestor handles are retained without delete sharing for the complete capability lifetime. Root identity is rechecked before and after publication.
- The vendor chain is retained only while comparing live directory identities. The store root may not equal, contain, or be contained by the vendor root. Vendor handles are then released so the capability does not block vendor updates.
- The managed root must already exist. Root provisioning and access-control policy are separate administrative operations.

### Input and path closure

- Blob count, each blob length, aggregate blob bytes, and temporary-name attempts have independent nonzero writer limits.
- Count and byte limits are checked before filesystem access. Every retained digest-to-byte association is rehashed before writes.
- Destination names remain the fixed ADR 0014 layout, `sha256/<first digest byte>/<remaining digest bytes>`. No caller-provided artifact path is joined to the root.
- The `sha256` directory and each fanout directory are create-or-open operations followed by direct-handle reparse and directory checks. Their handles remain live while descendant publication occurs.

### Atomic create-or-verify publication

For a missing blob:

1. Create a bounded-attempt, process-generated UUID temporary name in the final fanout directory with create-new semantics.
2. Write the exact retained bytes, call `sync_all`, and verify direct-file metadata plus two complete SHA-256 reads.
3. Transition from the writable handle to an identity-checked read-only handle that denies later write and delete sharing.
4. Atomically create the final name with a no-replace hard link in the same directory.
5. Reopen the final name without following a reparse point, verify that it identifies the staged file object, and repeat byte and metadata verification.
6. Close the temporary handles and remove the temporary name.

A pre-existing final name is never replaced. It is reused only when it is a direct regular file with the exact expected length, stable handle metadata, and two matching SHA-256 reads. Conflicting or unstable content fails closed.

Concurrent publishers use the same create-or-verify behavior. Exactly one hard-link publication can create a missing final name; racing publishers verify and reuse the winner. The read-only handle transition prevents the winner's former writable handle from causing sharing violations after the final name becomes visible.

Normal failures remove the exact internally generated temporary path after all handles close. A process crash can leave an inert `.weregopher-*.tmp` name, but it cannot leave a partially written canonical digest path. Age-based orphan scavenging is deferred because deleting another live publisher's temporary file requires a separately designed lease policy.

### Execution-time artifact lease

`lease_manifest` independently applies blob-count, per-blob, and aggregate-byte limits before filesystem access and rechecks the manifest's digest-to-byte associations. It performs no filesystem writes. The operation reopens the existing `sha256` and fanout directories directly, opens every required canonical blob without following a reparse point, verifies each file twice by length, metadata, and SHA-256, and retains the directory and file identity handles.

The returned non-serializable `ManagedArtifactLease` borrows the store capability, exposes paths only for digests present in the reverified manifest, and keeps file handles open without write or delete sharing. This keeps canonical names stable and denies new writers while a later consumer uses those paths. Missing, conflicting, unstable, non-file, or reparse-backed blobs fail closed. Dropping the lease releases all retained handles.

### Claims and non-claims

- `sync_all` establishes the file-content durability attempt before publication. This boundary does not claim that hard-link directory metadata is durably committed across sudden power loss on every filesystem. A later invocation recovers through create-or-verify behavior.
- A receipt reports integrity observed at publication completion. `ManagedArtifactLease` extends that observation by retaining direct handles and denying new write/delete opens, but it is not an OS sandbox and cannot neutralize a writable mapping or handle that predates lease acquisition. Same-user processes remain unrestricted.
- Hard-link support is required from the selected Windows store filesystem. Unsupported filesystems fail closed.
- Non-Windows callers receive an explicit unsupported-platform error.
- Publication does not authenticate adapter authority, launch a process, sandbox anything, certify compatibility, or grant execution authority.

## Consequences

- Verified transform artifacts can now be materialized outside vendor installations with bounded I/O, closed paths, no-replace atomic visibility, concurrent-publisher convergence, and post-write integrity evidence.
- Store operations retain ancestor handles temporarily and may therefore block renames of the managed-root chain while an operation is active.
- Reparse-backed store or vendor paths are conservatively rejected even when a particular redirection might be benign.
- Crash-orphan scavenging, immutable package views, and bounded launch remain later milestones.

## Verification

Behavior tests cover:

- complete manifest publication and exact on-disk bytes;
- idempotent reuse;
- independent pre-filesystem writer limits;
- conflicting pre-existing bytes without replacement;
- vendor/store equality and ancestor overlap;
- junction-backed roots and content directories;
- repeated concurrent publication races;
- bounded execution-time reverification, missing-blob rejection, closed digest-to-path lookup, and retained write/delete denial;
- Windows and non-Windows compilation boundaries.
