# ADR 0033: Bounded canonical certification-runner identity

- Status: Accepted
- Date: 2026-07-23
- Extends: [ADR 0028](0028-bounded-non-authorizing-certification-evidence.md), [ADR 0031](0031-generation-aware-local-certification-policy.md), and [ADR 0032](0032-atomic-local-certification-publication.md)

> Extended by [ADR 0034](0034-generation-aware-local-certification-runner-policy.md): trusted local
> configuration can now approve one exact manifest identity under generation-aware replacement and
> revocation without treating that approval as component authentication or run attestation.

## Context

Certification artifacts cannot become semantically trustworthy merely because their bytes match digests declared by an evidence document. A later semantic verifier must know exactly which runner image, host environment, runtimes, tools, probe assets, source revision, and exception-provenance set produced the candidate reports. Reusing one undifferentiated SHA-256 type for those roles would also permit accidental transposition in Rust.

This identity layer must precede runner attestation and semantic report validation, but it must not claim that a run occurred, that a producer is authentic, or that the local certification policy trusts the runner.

## Decision

Add the format-`"1"` `CertificationRunnerIdentity` contract as a bounded, canonical, non-authorizing manifest of immutable runner inputs.

The initial format fixes the runner platform to Windows and architecture to x86-64. It contains three closed groups:

1. `environment`: runner image, host image/build descriptor, host patch set, Electron runtime, and language-runtime set identities;
2. `tooling`: toolchain set, host agent, verifier, and probe-asset set identities; and
3. `provenance`: source-revision and approved exception-provenance-set identities.

Every component identity is a distinct Rust wrapper around canonical SHA-256 wire bytes. Aggregate component-set digests identify complete exact descriptors, including their versions and artifact identities. This contract deliberately does not define or trust those external descriptor preimages: a later runner-policy verifier must retrieve the exact descriptor bytes, verify their role-specific canonical formats and content identities, and authenticate their provenance before relying on them.

The public root type implements `Serialize` but not generic `Deserialize`. Its authoritative slice and reader parsers reject input larger than 32 KiB before deserialization, reject unsupported versions and unknown or missing fields, and accept only the closed format-v1 platform and architecture. The reader buffers at most the implementation ceiling plus one byte.

Canonical identity is SHA-256 over compact UTF-8 JSON emitted in declaration order. Format-v1 bytes have no BOM, insignificant whitespace, or trailing newline. The checked-in golden fixture has identity:

```text
sha256:b68268114751079bf85d12b5fe38b23c870c56927d41ef1b584872cc946672a1
```

Any field-order, grouping, spelling, or digest-encoding change requires a new format version.

## Security invariants

1. Runner, host, runtime, tooling, probe, source, exception, and complete-manifest digests are distinct Rust roles.
2. Callers cannot disable or raise the 32 KiB parser ceiling.
3. Generic deserialization cannot bypass the authoritative root parser.
4. The root canonical identity commits to every required format-v1 component role.
5. Missing, unknown, unsupported, or malformed transport data fails closed.
6. Constructing, parsing, hashing, or publishing a runner identity does not authenticate a runner, prove a run occurred, establish freshness, bind reports to a run, assign a certification class, or authorize transformation or execution.

## Consequences

- Trusted runner policy and run-attestation contracts can now pin one exact, role-separated runner-manifest identity instead of an ambiguous digest bag.
- A later attestation must bind this identity, the exact certification target and evidence/artifact identities, freshness material, and authenticated producer/verifier identities.
- Semantic report parsing remains non-authorizing until that attestation and current trusted policy are verified.
- External component descriptors, signing, freshness, durable publication, and the disposable-state runner remain separate increments.
