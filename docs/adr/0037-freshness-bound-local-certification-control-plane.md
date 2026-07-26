# ADR 0037: Freshness-bound local certification control plane

- Status: Accepted
- Date: 2026-07-25
- Extends: [ADR 0032](0032-atomic-local-certification-publication.md),
  [ADR 0033](0033-bounded-canonical-certification-runner-identity.md),
  [ADR 0034](0034-generation-aware-local-certification-runner-policy.md), and
  [ADR 0036](0036-discord-disposable-smoke-certification-slice.md)

## Context

The first Discord certification slice produces one semantically validated report and
can assign a local smoke class only after an operator repeats the run with the exact
report identity pinned. The generic certification layers verify the report bytes,
bind them to a profile and exact target, hold local certification policy current
through an in-memory receipt commit, and separately approve one canonical runner
identity.

Those boundaries intentionally remain disconnected. In particular:

1. runner-identity component digests do not prove that their descriptor preimages or
   named artifacts were retrieved and verified;
2. a runner approval is not retained through a certification publication;
3. no challenge proves that approval preceded the run or that a result is fresh and
   single-use;
4. the local publication receipt does not name the runner or a run attestation;
5. policy and receipt state disappear at process exit; and
6. the Discord command launches a mutable staged pathname rather than a retained
   content-addressed package view.

Treating a timestamp, producer-selected nonce, digest-named directory, or serialized
`trusted: true` field as a solution would move trust into attacker-controlled data.
Similarly, a local hash chain without an independently pinned head cannot prevent a
same-user rollback. Remote registry signatures also require a key lifecycle,
authenticated metadata, and revocation design that does not exist yet.

## Decision

Implement one local certification control plane with four connected boundaries:
bounded runner-component verification, a pre-run single-use freshness capability,
atomic attested local publication, and an append-only durable local ledger. Integrate
the complete boundary into the Discord disposable-smoke workflow and retain the
launched transformed package through the existing content-addressed snapshot API.

This remains local trust. It does not claim remote registry authentication, a
same-user sandbox, full application compatibility, or execution authority.

### Canonical runner-component descriptors

Add format-`"1"` `CertificationRunnerComponentDescriptor`. Each descriptor has one
closed `CertificationRunnerComponentRole` corresponding to exactly one role in
`CertificationRunnerIdentity`, a bounded component identifier and version, one
role-specific provenance identity, and a canonically ordered set of exact artifacts.
Each artifact has a bounded logical name, SHA-256 identity, and byte length.

The contract has these fixed ceilings:

- 256 KiB serialized descriptor bytes;
- 64 artifacts per descriptor;
- 256 UTF-8 bytes per component identifier, version, or artifact name;
- 16 KiB aggregate artifact-name bytes; and
- nonzero artifact lengths no larger than 512 MiB.

The root type omits generic `Deserialize`. Its authoritative parser enforces the
serialized ceiling before deserialization, rejects unknown fields, unsupported
versions, invalid text, duplicate names, empty artifact sets, and all collection or
arithmetic overflow. Compact UTF-8 JSON in declaration and canonical collection order
is the format-v1 identity. The closed on-disk bundle loader additionally requires
stored identity and descriptor bytes to equal that canonical encoding exactly.

`verify_certification_runner_components` consumes a generation-current opaque runner
approval plus exactly one descriptor for every runner-identity role. It:

1. hashes each canonical descriptor and compares it with the corresponding
   role-specific runner-identity digest;
2. requires the descriptor role to match the occupied manifest slot;
3. rejects missing or unexpected descriptors and artifacts;
4. enforces caller-tightened per-artifact and aggregate limits beneath fixed
   implementation ceilings;
5. verifies every named artifact's exact length and SHA-256 bytes; and
6. returns a non-cloneable, non-serializable proof retaining the approval,
   descriptors, and borrowed artifact bytes.

For local policy, independently retrieved descriptor and artifact bytes are
authenticated only by their exact identities being transitively pinned by the
trusted local runner policy. This is not signature or registry authentication.

### Pre-run freshness capability

`begin_local_certification_run` consumes the verified runner proof before the
diagnostic process starts. It generates a cryptographically random UUID challenge,
pins one exact semantic-report artifact reference, records a monotonic `Instant`, and
returns a non-cloneable, non-serializable pending run. The caller selects a nonzero
whole-millisecond maximum elapsed time no greater than ten minutes.

The pending value cannot be reconstructed from transport bytes and is consumed once.
Wall-clock time is not an authority input. Completion uses monotonic elapsed time and
fails closed when:

- the maximum elapsed time is exceeded;
- the semantic report reference is absent from the exact verified evidence artifacts;
- report bytes or any certification identity differ;
- runner or certification policy changed, was revoked, disappeared, or became
  unavailable; or
- challenge, count, or duration fields cannot be represented canonically.

Random challenge uniqueness plus linear consumption prevents same-process replay.
The serialized attestation remains historical evidence and cannot itself recreate
the consumed capability.

### Atomic attested local publication

Add format-`"1"` `LocalCertificationRunAttestation`. It binds:

- the freshness challenge and exact elapsed/maximum duration;
- runner identity and verified descriptor-set identities;
- runner policy revision and generation;
- the semantic-report artifact reference;
- exact certification target, profile, evidence, and verified artifact-set
  identities;
- trusted certification class, policy revision, and generation; and
- verified artifact count and aggregate byte length.

Attested publication consumes the pending run and the opaque local certification
decision. Lock order is fixed as runner policy, certification policy, then destination
store. Both policy read guards remain held through insertion of the attestation and
historical local receipt as one in-memory record. Exact duplicates converge; the
store remains hard bounded.

The attestation's canonical SHA-256 identity is role-specific. Neither its fields nor
its local publication status authorize transformation, execution, privileged
effects, or external publication.

### Durable local certification ledger

Add format-`"1"` `LocalCertificationLedgerRecord` and a bounded filesystem ledger.
Every record binds a one-based sequence number, the exact previous-record identity,
and one closed event:

- `genesis`, containing the exact local runner and certification policy snapshots
  plus the first attested publication;
- `publication`, containing one later attestation and receipt;
- `policy_replacement`, installing exact next-generation local policy snapshots;
- `certification_revocation`; or
- `runner_revocation`.

Policy revisions, generations, revocation evidence, attestation identities, receipts,
and control-plane targets retain distinct Rust roles. Record parsing enforces a
256 KiB ceiling and closed relationships; filesystem replay additionally requires
stored bytes to equal their canonical encoding. The ledger permits at most 4,096
records and 256 MiB total record bytes.

Records are named only by a fixed-width sequence number and created with
create-new semantics. A file is synchronized before a successful append returns.
Opening a ledger:

1. rejects symbolic links, non-files, unknown names, gaps, duplicates, and excess
   entries;
2. reads every file through fixed per-record and aggregate ceilings;
3. requires stored bytes to equal their canonical encoding;
4. recomputes every record identity and previous-record link;
5. validates event relationships and monotonic policy generations;
6. rejects publication under revoked or mismatched policy;
7. rejects repeated freshness challenges; and
8. requires the caller's independently supplied exact head identity.

The sequence-only create-new filename serializes concurrent appenders: a stale writer
cannot create a second record at the same sequence. A crash may leave an incomplete
final file; reopening then fails closed instead of silently rolling back.

The expected head is the rollback anchor. A ledger path by itself is not trusted.
Moving both ledger bytes and the expected head backward remains possible to an
unrestricted same-user actor, so callers must keep the expected head in separately
trusted configuration. Ledger records are local historical evidence, not signed
registry records.

### Discord integration and retained transformed package

The Discord candidate output additionally reports the exact local runner identity,
verified descriptor-set identity, and semantic-report artifact reference. A trusted
second run must pin the runner identity as well as the certification report.

The challenge is created only after exact runner-component verification and before
process creation. After the process tree exits, the semantic report is constructed,
the generic certification artifacts are verified, and the attested publication is
committed. The command either creates a new ledger with a genesis event or opens an
existing ledger using an exact expected head and appends a publication. The returned
machine-readable result includes the attestation and new ledger-head identities.

The transformed staged tree is observed and published into the existing
content-addressed package-snapshot store before launch. The snapshot lease and
identity-matched executable capability remain alive through process termination,
report construction, final complete-view revalidation, and attested publication.
Revalidation occurs before any certification or ledger commit. The physical snapshot
root remains an unrestricted same-user namespace; launching the copied vendor
Electron runtime is still an explicitly uncertified diagnostic action guarded by the
existing flag.

Before staging, canonical overlap checks require the managed package, marker,
disposable user data, snapshot store, and optional ledger to be mutually disjoint and
disjoint from both the vendor package and runner bundle. Caller-selected
control-plane state therefore cannot modify either source tree in place.

## Security invariants

1. Vendor installations are never modified in place.
2. Every runner-identity role has one exact verified descriptor preimage and bounded
   artifact-byte set.
3. Descriptor verification cannot be replaced by a producer-supplied boolean or
   aggregate digest alone.
4. A freshness challenge is generated after runner approval and consumed exactly
   once after the run.
5. Runner and certification policy remain current through the same in-memory
   attestation/receipt commit.
6. An attestation binds one exact semantic report, target, evidence set, runner,
   policies, and challenge.
7. Durable ledger history is hash chained, sequence serialized, byte bounded, and
   accepted only with an independently pinned exact head.
8. Corruption, partial writes, history gaps, forks, replayed challenges, rollback,
   replacement, or revocation fail closed.
9. Job Objects and ordinary snapshot directories are never described as sandboxes.
10. Local attestation and durable persistence do not create registry signatures,
    remote revocation trust, execution authority, full Discord compatibility,
    production-state safety, or efficiency evidence.

## Consequences

- The Discord smoke result becomes attributable to one locally approved and
  component-verified runner under a single-use pre-run challenge.
- Exact local policy and attested receipts can survive process restart without
  accepting an unpinned ledger head.
- The transformed process is launched from a retained content-addressed view rather
  than the mutable staging tree.
- Certification policy, runner policy, attestation, receipt, and ledger identities
  are explicit and independently revocable.
- Remote signer/key management, authenticated registry distribution, transparency
  logs, external revocation feeds, general scenario execution, replacement-runtime
  parity, production-state validation, and efficiency certification remain later
  work.
