# ADR-0006: Make compatibility analysis exact-target and fail closed

- Status: Accepted
- Date: 2026-07-21

## Context

Discovery and candidate verification establish what package was observed and whether its maintained fixed layout is present. They do not establish that a selected Weregopher runtime, renderer, adapter contract, and execution environment can preserve application behavior, security, or state. Weregopher needs a canonical compatibility-analysis result before implementing transformations, execution, or certification, but that result must not become replayable across targets or become an alternate authorization mechanism.

The initial compatibility contract is a Windows x64 feasibility slice. Compatibility conclusions must be tied to one exact source-build fingerprint artifact, one exact target configuration, declared application workflows, and immutable evidence. Unknown data, unsupported targets, unresolved dimensions, contradictory results, missing evidence, and oversized collections must fail closed.

## Decision

`weregopher-domain` defines format version `"1"` of `CompatibilityAnalysis`. The version is encoded as an exact string token so canonical Rust deserialization and Draft 2020-12 JSON Schema reject the same numeric, fractional, and alternate textual spellings.

Each analysis binds these immutable identities:

- the SHA-256 digest of the canonical source `BuildFingerprint` artifact;
- the resolved static adapter-contract digest;
- the selected main-runtime contract and artifact-descriptor digest;
- the selected renderer-backend contract and artifact-descriptor digest;
- the canonical execution-environment descriptor digest.

The target also carries closed, single-value format-v1 enums for `windows` and `x86_64`. Other platforms and architectures require a later contract version rather than being silently accepted. The source fingerprint is referenced by digest instead of embedding its variable-length package metadata, so this transport cannot inherit unbounded package identity strings or application-ID collections.

Every analysis contains fixed assessments for package structure, main runtime, renderer, preload, Electron API, Node API, native modules, helpers, state, and security. It may additionally contain at most 128 application workflow assessments keyed by canonical `FeatureId` values. Every assessment has one of four statuses:

- `unknown`;
- `satisfied`;
- `unsatisfied`;
- `not_applicable`.

A resolved status (`satisfied`, `unsatisfied`, or `not_applicable`) requires at least one immutable, content-addressed evidence reference. An assessment may contain at most 64 unique evidence references. Evidence categories describe what was observed; they do not grant authority or turn a digest into trusted evidence by themselves.

The derived disposition is deliberately not serialized:

1. any `unsatisfied` fixed dimension or declared workflow yields `blocked`;
2. otherwise, any `unknown` result yields `incomplete`;
3. only a fully resolved analysis yields `complete`.

Canonical ordered maps and sets make serialization independent of insertion order. Custom collection visitors reject oversized size hints before allocating collection storage, retain no more than the fixed limits, consume the first excess entry as `IgnoredAny` rather than constructing a domain value, and reject duplicate workflow keys before deserializing their assessment. Closed transport structs reject unknown fields, and custom deserialization re-runs semantic constructors. Generated JSON Schema mirrors the same exact version, target vocabulary, identifier/digest grammar, cardinality, uniqueness, and resolved-evidence rules; Rust validation remains authoritative.

A compatibility analysis is an evidence-bearing assessment only. It does not serialize or imply transformation authorization, execution authorization, certification class, effective security posture, or efficiency status. Those remain separate later-stage decisions and artifacts.

## Consequences

- A family-level claim or familiar package layout cannot substitute for an exact source fingerprint and target identity.
- A complete result cannot be replayed for another adapter, runtime, renderer backend, or execution environment without changing the canonical analysis bytes.
- Empty workflow scope is valid, but every declared workflow contributes to the fail-closed disposition.
- `not_applicable` is a resolved claim and therefore requires evidence.
- Unknown fields and unsupported platform, architecture, or version values cannot be silently ignored.
- Existing `BuildFingerprint`, `PackageIdentity`, and `CandidateInstallationEvidence` transport contracts are unchanged by this decision.
- Producers can add analyzers later without changing the canonical result semantics; breaking serialized changes require a new format version and migration.
- Generated schemas are suitable for transport validation, but consumers must still deserialize through the canonical Rust contract before making decisions.
- Completing compatibility analysis does not permit transformation or execution and is not certification.
