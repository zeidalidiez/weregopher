# ADR 0032: Atomic generation-current local certification publication

- Status: Accepted
- Date: 2026-07-23
- Extends: [ADR 0031](0031-generation-aware-local-certification-policy.md)

## Context

ADR 0031 deliberately makes `LocallyCertifiedArtifacts` a point-in-time, generation-bound decision rather than publication authority. Checking currentness and then inserting a receipt under a separate lock would leave a replacement/revocation race: the policy could change after the check but before publication became visible.

A local publication receipt must also retain the complete logical decision without copying proprietary evidence bytes into logs or pretending that an evidence-document digest is a distinct verified-artifact-set identity. The initial destination must be bounded and explicit about its lack of durability, registry authentication, and signature trust.

## Decision

Add a platform-neutral prepared-publication boundary and a bounded in-memory `LocalCertificationPublicationStore`.

### Preparation

`prepare_local_certification_publication` consumes one non-cloneable `LocallyCertifiedArtifacts` value after a point-in-time currentness check. The resulting non-cloneable `PreparedLocalCertificationPublication` retains that exact decision until commit.

Preparation computes `CertificationArtifactSetDigest`, a role-specific SHA-256 identity for the exact unique artifact-reference set whose bytes were verified. Its canonical framing is:

1. ASCII domain tag `weregopher.certification.artifact-set.v1` followed by one NUL byte;
2. the reference count as little-endian `u64`;
3. each `BTreeMap`-ordered reference as one kind tag byte followed by its 32 raw digest bytes.

Kind tags are fixed in declaration order:

| Tag | Kind |
| ---: | --- |
| 0 | `package_identity` |
| 1 | `static_analysis` |
| 2 | `runtime_probe` |
| 3 | `renderer_probe` |
| 4 | `state_probe` |
| 5 | `security_probe` |
| 6 | `workflow_probe` |
| 7 | `resource_probe` |
| 8 | `helper_probe` |
| 9 | `exception_verification` |

The frozen two-reference fixture (`static_analysis` SHA-256 of `fixed-proof`, then `workflow_probe` SHA-256 of `workflow-proof`) has artifact-set identity:

```text
sha256:9bc569125e337161b0aeb9f463f5a6b5c73b44871e4e59f3e6260658acc0716f
```

### Receipt

A committed `LocalCertificationPublicationReceipt` binds:

1. the complete `CertificationTarget`;
2. canonical profile identity;
3. canonical evidence identity;
4. verified artifact-set identity;
5. trusted certification class;
6. local policy revision identity;
7. local policy generation;
8. unique artifact count and checked aggregate artifact bytes; and
9. `PublicationStatus::LocalOnly`.

The receipt is non-serializable. It is historical evidence that this decision was current at one local commit point, not proof that the policy remains current.

### Atomic commit

`publish_local_certification` consumes the prepared plan. It upgrades the retained weak policy-store reference, obtains the policy read lock, checks revocation, generation, and exact policy equality, and retains that read guard while obtaining the publication-store write lock and either verifying an exact duplicate or inserting the new receipt. Policy replacement and revocation require the policy write lock and therefore linearize after a successful publication commit or before a failed currentness check; they cannot occur between final verification and receipt visibility.

The lock order is always policy read lock before publication-store write lock. Publication-store query and construction paths never acquire the policy lock.

The caller chooses a nonzero receipt limit no greater than the implementation ceiling of 4,096. Exact duplicate receipts converge without consuming another slot, including when the store is full. A distinct receipt at the selected limit fails closed, and allocation is fallible.

## Security invariants

1. A receipt cannot commit from a replaced, revoked, unavailable, or poisoned issuing policy generation.
2. Policy currentness is held continuously through the local publication linearization point.
3. The receipt binds exact target, profile, evidence, artifact-set, class, revision, and generation identities.
4. Verified artifact bytes are neither copied into the receipt nor exposed by debug output.
5. The artifact-set digest is role-distinct from profile, evidence, artifact, policy, and execution digests.
6. Store growth is hard bounded; callers may tighten but not disable the ceiling.
7. Exact duplicates are idempotent; different receipts never overwrite one another.
8. Publication does not grant transformation or execution authority.

## Consequences

- Generation-current local decisions can now become bounded local-only historical receipts without a check-to-commit revocation race.
- Later registry serialization and signing can consume exact receipt fields but must define a separate canonical transport, trusted signer policy, remote revocation model, and durable transaction protocol.
- A later policy change does not erase historical receipts and does not make them current; consumers requiring current trust must resolve policy again.
- This increment does not provide durable storage, authenticated registry publication, signatures, trusted-runner identity, semantic report validation, artifact persistence, or a disposable-state certification runner.
