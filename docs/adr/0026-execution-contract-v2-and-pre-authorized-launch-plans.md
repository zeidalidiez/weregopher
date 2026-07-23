# ADR 0026: Execution-contract v2 and pre-authorized Windows launch plans

- Status: Accepted
- Date: 2026-07-23
- Supersedes: target/resolution portions of ADR 0023; amends ADR 0024 and ADR 0025

## Context

Adversarial review of the first execution-target contract found accepted states that were unsuitable as a live-authorization foundation:

- a managed locator and its independently named executable digest could contradict each other while still serializing and hashing;
- the static target contract embedded current compatibility-analysis and user-consent identities, so either live update changed the statically authorized target digest and required a newly authenticated adapter authority;
- a target declared an *effective* security posture before any enforcing launch mechanism had established that result;
- domain-valid UTF-8 arguments could expand past the `CreateProcessW` command-line ceiling after Windows quoting, so authorization could issue a capability that launch could never consume;
- direct Serde entry points did not provide an outer hostile-document read bound; and
- package paths and generated schemas did not expose all Windows lexical and cross-field constraints; and
- caller-selected live-policy evidence limits could be raised to `usize::MAX`, defeating the claimed authorization bound.

These are contract defects, not merely implementation inconveniences. Silent reinterpretation under format version 1 would make old and corrected documents share the same wire identity.

## Decision

Weregopher replaces execution-target and execution-resolution format version 1 with exact format version 2. Version 1 is rejected rather than guessed or upgraded in place.

### Static requirements versus live evidence

`ExecutionLaunchPolicy` now carries:

- `required_security_posture`, represented by `RequiredSecurityPosture`;
- fixed argument, environment, inherited-handle, console, working-directory, loader-dependency, state-mode, and resource-limit requirements; and
- `ExecutionPolicyRequirements`, containing only exact capability-policy and state-policy requirements that the authenticated static adapter is allowed to constrain.

Current compatibility-analysis and user-policy/consent identities no longer occur in the static target contract. They remain independently hashed, locally pinned, generation-tracked live-authorization inputs. They may change after the generated and local evidence is refreshed without changing or re-signing the static target contract.

A required posture is not an achieved result. The live policy provides the separately typed `EffectiveSecurityPosture`, and authorization checks that it satisfies the target requirement. The initial local Windows authorizer accepts only `vendor-equivalent-full-trust`; broker-mediated and OS-contained targets fail before authorization until an enforcing boundary exists.

### Resolution and path validity

`ExecutionResolutionEvidence::new` is fallible. Managed-artifact construction and deserialization require the locator blob digest to equal the role-named executable digest. Contradictory evidence cannot be content-addressed as a valid domain value.

Execution-contract, resolution, artifact-source, executable, trust, provenance, compatibility, capability-policy, state-policy, and user-policy identities use distinct transparent digest wrapper types in Rust. Their canonical JSON remains an ordinary SHA-256 string, while compile-time role separation prevents field swaps inside domain and live-policy construction.

Executable identity is not dependency-closure identity. Format v2 names this distinction: the current full-trust launcher accepts only `vendor_default_ambient`, which permits unsealed Windows loader resolution and makes neither an immutable-package dependency claim nor a claim that relocation preserves package-relative dependency behavior. `manifest_closed` is a durable requirement that fails authorization until an independently enforced immutable dependency namespace exists.

Package locators use `ExecutionPackagePath`. Runtime validation additionally rejects Windows forbidden characters, control characters, trailing dots/spaces, and reserved DOS device aliases, including extension forms, superscript aliases, and console/clock pseudo-device aliases. The generated schema exposes conservative syntax plus explicit Weregopher extension keywords for UTF-8-byte, component-count, Windows-alias, document-size, and cross-field limits. Rust validation remains authoritative where portable JSON Schema cannot express byte or digest-equality relations.

Hostile readers use `ExecutionTargetContract::from_json_slice` / `from_json_reader` and the corresponding resolution APIs. Reader entry points cap bytes before invoking Serde. Canonical golden fixtures freeze format-v2 bytes and SHA-256 identities, including non-ASCII and escaped argument content.

Live policy evidence has hard implementation ceilings of 1 MiB per document and 4 MiB in aggregate. A caller may select tighter limits for a decision but cannot disable those ceilings.

### Prepared launch plan

Before returning `AuthorizedExecution`, `authorize_execution` now:

1. verifies the fixed launch semantics and required/effective posture;
2. converts exact resource limits into a validated `JobLimits` value;
3. converts exact arguments with the sole Windows quoting implementation;
4. validates the executable path, working directory, per-value UTF-16 limits, quoting expansion, and complete NUL-terminated command-line ceiling; and
5. stores an opaque `PreparedProcessLaunch` bound to the retained executable's absolute path, full-width Windows file identity, and private live lock-instance identity.

The prepared plan is non-cloneable and non-serializable. `KillOnCloseJob::launch_prepared` checks path, file identity, and the private lock-instance binding before any process-creation call. Dropping the preparing lock, rebinding its parent, hard-linking the same file object at the same textual path, and opening a new lock therefore cannot consume the plan. The one-shot launch consumer performs only revocation/current-view revalidation, Job creation, and consumption of that already validated exact plan; it does not rebuild arguments or reopen the executable.

The current primitive also accepts only `state_mode = vendor_default`. `disposable` and `production` require a retained state-namespace capability and fail authorization until that higher-level runtime mechanism exists. `SupervisedExecution` is therefore a low-level Job-owned process capability, not yet an `AppInstanceId`/`RuntimeId`/state-lease owner and not a complete production application supervisor.

## Authority boundary

Format-v2 contracts, bounded parsing, structural equality, and prepared launch representability are prerequisites, not authorization by themselves. They do not authenticate adapter authority, establish current consent, prove compatibility, create a sandbox, authorize privileged effects, or make package-relative dependencies immutable.

## Consequences

- Existing execution target and resolution documents with format version 1 must be regenerated and re-authorized as version 2.
- Compatibility and consent can advance under current generation-tracked policy without a new static target signature.
- No live authorization can be issued for a command line that the current Windows consumer cannot represent.
- Unsupported security mechanisms are rejected before a one-shot authorization capability exists.
- Generated schema consumers can discover nonstandard byte and relation constraints explicitly instead of mistaking code-point/item limits for full runtime parity.

## Verification

Regressions cover contradictory managed evidence at construction and deserialization; format-v2 canonical golden bytes and digests; compile-fail digest-role swaps; bounded slice/reader entry points; worst-case escaped valid documents; Windows-ambiguous package names; schema extension limits; hard live-evidence ceilings; mutable current consent and compatibility with an unchanged static target digest; unsupported required posture; domain-valid but Windows-unrepresentable quoted arguments; prepared-plan path/file-identity substitution and same-file parent rebinding through a newly opened lock; successful package and managed-artifact Job-owned launch; and managed-manifest mismatch rejection.
