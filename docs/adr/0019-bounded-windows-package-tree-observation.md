# ADR 0019: Retain bounded Windows package-tree observations

- Status: Accepted
- Date: 2026-07-22

## Context

`PackageTreeManifest` format version 1 can bind canonical regular-file records, but accepting pre-observed records does not prove that they came from one package root, that enumeration stayed beneath that root, or that the named files still identify the bytes that were hashed. Immutable package views need a Windows acquisition boundary that fails closed before copying package bytes into managed storage.

Path-only recursive traversal is insufficient. An updater or same-user process can replace ancestors, directories, or files while traversal is in progress; a reparse point can redirect a lexical descendant outside the intended root; and unconstrained directory breadth, depth, paths, or file content can amplify work before a manifest is available.

Format version 1 also has no directory records. A non-root empty directory therefore cannot be reconstructed from its file records and must not silently disappear from a purported complete observation.

## Decision

The fingerprint crate provides `observe_package_tree` on Windows. Callers must supply explicit nonzero ceilings for:

- regular-file count, capped by the 65,536-record manifest limit;
- directory count including the package root, capped at 65,536;
- root-relative depth, capped at 256 components;
- bytes in one regular file;
- aggregate regular-file bytes; and
- aggregate UTF-8 bytes across normalized file and directory paths, capped by the 16 MiB manifest path budget.

The initial acquisition profile accepts only direct regular files and directories. It rejects all reparse points, unsupported filesystem entry types, noncanonical or non-Unicode names, Windows-reserved or lossy names, conservative case-insensitive path collisions, and non-root empty directories. Supporting symlink or other reparse semantics requires a later versioned contract rather than traversal through an unbound target.

Observation proceeds as follows:

1. require an absolute drive or UNC root with bounded component count;
2. open every root ancestor from the volume/share toward the package root with `FILE_FLAG_OPEN_REPARSE_POINT` and no write or delete sharing;
3. reject any opened ancestor or package directory that is not a direct non-reparse directory;
4. enumerate entries iteratively within file, directory, depth, and path budgets;
5. open every child directory directly and retain its full-width Windows file identity;
6. observe each regular file through the existing bounded, direct, non-reparse file observer, retaining the exact handle and checking the aggregate byte budget;
7. build the canonical package manifest from the retained file records;
8. re-open and compare every directory identity, re-enumerate membership, and revalidate every retained file path before returning;
9. retain the absolute root once and retain package-relative normalized paths for entries, deriving absolute paths only for bounded operations; and
10. derive collision keys with the invariant Windows uppercase mapping and reject DOS device aliases that use ASCII or superscript digits.

The returned `PackageTreeObservation` owns the root-ancestor, directory, and file leases. Its debug representation includes only the Merkle identity, counts, byte total, and declared limits, not absolute source paths or normalized package paths. `verify_current_tree` repeats directory-membership and identity checks.

`open_file` accepts only an exact canonical manifest path. It opens a fresh read-only direct handle, compares that handle with the retained full-width file identity, and wraps it in a bounded reader that starts at byte zero and does not expose the operating-system handle. This is the narrow capability through which the next managed-snapshot milestone can copy exact observed bytes without exposing or re-resolving an unverified source path.

Directory-object and file handles deny new write and delete opens to those retained objects. This rejects acquisition when a compatible writable object handle already exists, but it does not prevent namespace additions beneath a retained directory. The observation detects visible membership changes rather than claiming to freeze a vendor installation.

## Security and authority boundary

A successful result is a bounded live-tree observation with retained identities. It is not a coherent filesystem snapshot, an immutable package view, a build lease, adapter authority, launch authorization, sandboxing, or certification.

The final membership pass detects changes visible during that pass, and callers can revalidate later. It cannot prevent a new child from being created after validation because ordinary directory handles are not a package-wide mutation lock. Weregopher must copy only manifest-listed leased files into a distinct managed snapshot and validate the resulting immutable view before making an immutability or execution claim.

The initial profile intentionally rejects package trees containing reparse semantics or non-root empty directories. It does not weaken those cases into path-following behavior or silently omit them.

## Verification

Windows behavior tests cover:

- nested regular-file manifests and canonical path ordering;
- an empty package root while rejecting unrepresentable nested empty directories;
- retained file and root identities preventing write, rename, or replacement;
- pre-existing writable directory-handle rejection;
- exact manifest-path lookup returning a bounded identity-verified reader;
- exact file-count error reporting;
- zero and hard-ceiling limit rejection;
- directory, depth, per-file, aggregate-file-byte, and aggregate-path-byte limits;
- zero-byte files at an exactly consumed aggregate byte budget;
- root and descendant junction rejection;
- ASCII and superscript DOS-device-name rejection;
- post-observation membership additions;
- relative-root rejection; and
- debug-path redaction.

A non-Windows contract test records that complete-tree observation is explicitly unsupported. Linux cross-target Clippy verifies that the public API remains portable even though acquisition is Windows-only.

## Consequences

- Weregopher can derive a canonical manifest directly from one bounded Windows package-root traversal while retaining every observed identity.
- Vendor installation bytes are read but never modified by this capability.
- Reparse traversal, unsupported entries, unrepresentable directory state, and resource excess fail closed.
- Handle consumption is bounded by the declared file and directory ceilings plus a fixed root-ancestor ceiling.
- Root-path storage is constant per observation rather than multiplied by the entry count, and externally visible manifest accessors cannot desynchronize canonical records from their Merkle root.
- Packages requiring symlink/reparse semantics or empty-directory preservation remain unsupported until a versioned entry contract exists.
- Immutable managed package-view composition remains the next separate milestone.
