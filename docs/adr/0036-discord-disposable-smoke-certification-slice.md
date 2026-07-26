# ADR 0036: Discord disposable-smoke certification slice

- Status: Accepted
- Date: 2026-07-25
- Extends: [ADR 0017](0017-atomic-windows-job-owned-process-launch.md), [ADR 0028](0028-bounded-non-authorizing-certification-evidence.md), [ADR 0029](0029-canonical-certification-profiles.md), [ADR 0030](0030-bounded-certification-artifact-verification.md), [ADR 0031](0031-generation-aware-local-certification-policy.md), [ADR 0032](0032-atomic-local-certification-publication.md)

## Context

ADRs 0028 through 0032 established platform-neutral certification evidence, profiles,
artifact-byte verification, local class assignment, and atomic local-only publication.
They deliberately did not define an application-specific probe report or connect those
layers to an installed package.

The existing Discord development adapter injects an opt-in marker into the packaged
main-process source. Its Windows live-smoke command stages a disjoint managed copy and
launches that copy under a kill-on-close Job Object with disposable user data. The
command previously returned diagnostic facts only. It did not produce one canonical
semantic report, derive generic compatibility and certification documents, or require
an operator-pinned report before assigning a trusted local class.

This probe executes the copied vendor Discord/Electron runtime. It is useful for
testing the adapter transform and staging boundary, but it is not the Weregopher
replacement runtime and must not be presented as application compatibility, an
optimized transformed form, a helper, or an ABI island.

## Decision

Implement the first deliberately narrow end-to-end certification slice for workflow
`discord.smoke-marker`.

### Canonical adapter report

`DiscordSmokeCertificationReport` format `"1"` contains exactly one static observation
and one runtime observation. Its authoritative parser enforces a 64 KiB ceiling before
deserialization, rejects unknown fields and unsupported versions, and revalidates all
fixed relationships. The public report and observation types do not expose generic
`Deserialize`.

The static observation binds:

1. the domain-separated adapter-contract identity;
2. source and transformed `resources/app.asar` identities;
3. the source package-manifest identity; and
4. source and transformed main-entry identities.

Construction receives the actual manifest and source bytes, reruns
`transform_smoke_source`, and requires the supplied transformed bytes to equal that
exact output. Source and transformed archive and main-entry identities must differ.
The version-2 marker adapter uses create-new marker writes and exits immediately after
a successful marker write, before the retained vendor main JavaScript can execute.
Without the private marker argument, control continues into the byte-exact retained
vendor source.

The runtime observation is constructed only after the live command has checked Job
membership, exact marker bytes, disposable state, confirmed primary-process
termination, and post-probe vendor-source stability. Kill-on-close ownership of the
complete Job remains live through report construction and is released before the
command returns. It binds the transformed managed
package Merkle root, executable digest, file and byte counts, post-probe source-ASAR
digest, marker digest, timeout, fixed Job and command-line limits, and the two exact
reviewed mutable-path omissions.

The report cross-checks the pre-transform and post-probe vendor ASAR identities.
Canonical report bytes are compact UTF-8 in declaration order with no BOM,
insignificant whitespace, or trailing newline. `DiscordSmokeCertificationReportDigest`
is SHA-256 of those exact bytes. A checked-in golden byte vector and SHA-256 vector
freeze format `"1"`. The generated JSON Schema is transport assistance; bounded Rust
construction and parsing remain authoritative.

### Staging and probe boundary

The command continues to require a new managed root disjoint from the vendor
installation, a new marker path, a new sibling user-data directory, and
`--allow-uncertified-local-smoke`.

Staging omits only:

- `modules/discord_dispatch-1/discord_dispatch/dispatch.log`, which must be a file; and
- `modules/discord_krisp-1/discord_krisp/KMS/logs`, which must be an empty directory.

Content under the reviewed Krisp directory fails closed. Managed directories are
created only for retained files, so the unrepresentable empty state directory does not
enter package-manifest format 1. All other retained files are copied to the managed
root, the ASAR transform is rebuilt and reparsed, and the managed package is
fingerprinted twice before launch. The vendor ASAR is hashed again after the process
tree terminates.

The Job applies an active-process ceiling of 16, a 2 GiB per-process memory ceiling, a
4 GiB aggregate memory ceiling, and kill-on-close. The launch accepts at most eight
arguments, 8 KiB of aggregate argument bytes, and 32,767 UTF-16 command-line units.
The canonical report accepts a timeout from one through 60 seconds.

Job Objects provide lifecycle and accounting, not a security sandbox. The command
launches the copied vendor Electron process tree and therefore remains an explicitly
uncertified local diagnostic launch even when its resulting report later receives a
local smoke decision.

### Generic certification mapping

One validated report deterministically derives:

1. an adapter-scoped exact-target `CompatibilityAnalysis`;
2. a `smoke_verified` `CertificationProfile`;
3. complete `CertificationEvidence`; and
4. exact report, compatibility, profile, and evidence identities.

For this one marker workflow, package identity, entry-point resolution, transform
matching, runtime bootstrap, state safety, security-contract checks, resource limits,
and `discord.smoke-marker` pass. Module graph, native dependencies, renderer,
preload, helper lifecycle, and declared exceptions are `not_applicable` because they
are outside this profile, not because Discord lacks those requirements. Compatibility
dimensions use the same narrow interpretation: package, main runtime, Node marker
write, disposable state, launch security checks, and the marker workflow are
satisfied; renderer, preload, Electron API parity, native modules, and helpers are
outside scope.

Every generic evidence reference points to the canonical semantic report under its
specific artifact kind. The existing structural-profile and byte-for-digest
verification boundaries consume those references before local policy resolution.
This verifies the exact report bytes and same-process semantic construction; it does
not independently retrieve the proprietary package bytes named by the report.

### Two-pass local trust

A run without trust inputs emits a deterministic candidate report and assigns no
class. A local smoke decision requires both:

- `--expected-certification-report`, pinning the exact candidate report digest; and
- `--local-policy-revision`, identifying trusted local policy configuration.

Supplying only one input is rejected by the CLI. The second run must reproduce the
exact report digest before the existing generation-aware local policy may assign
`CertificationClass::SmokeVerified` and atomically publish a
`PublicationStatus::LocalOnly` in-memory receipt. The receipt summary exposes the
report, compatibility, profile, evidence, policy-revision, and verified artifact-set
identities plus generation, artifact count, and aggregate bytes.

Trust resolution occurs only after the diagnostic process has terminated.
`SmokeVerified` therefore does not authorize that launch retroactively or authorize
any future transformation or execution. The explicit uncertified-launch flag remains
mandatory on both passes.

## Security invariants

1. The vendor installation is never modified in place.
2. Production application state is never used by candidate verification.
3. Mutable-path exceptions are exact and cannot expand from generated input.
4. Marker bytes, transform output, source stability, execution limits, and report
   relationships fail closed.
5. Paths, process identifiers, timestamps, and exit codes remain diagnostic output
   and do not make otherwise identical report identities nondeterministic.
6. No trusted class is assigned from a producer-selected report digest; the exact
   digest must arrive through trusted local CLI configuration.
7. Local publication is in-memory, local-only, non-authorizing, and generation-bound.
8. Job ownership is never described as an OS sandbox.
9. The copied vendor Electron tree is never described as a Weregopher helper, ABI
   island, optimized runtime, or certified application adapter.
10. Proprietary package bytes and raw probe traces are not committed to the
    repository.

## Verification

Regression tests cover exact transform reconstruction, canonical round trips, the
golden bytes and digest, unknown/tampered semantic rejection, the 64 KiB ceiling,
exact mutable-path handling, content beneath the reviewed empty directory, complete
generic document derivation, exact report pinning, local-only publication, and paired
CLI trust inputs. The complete flow is exercised on native Windows in addition to
portable unit tests and strict Clippy.

A local validation against installed Discord `1.0.9249` produced the same report
identity on two clean disposable-state runs. The second run pinned that identity and
published a generation-one `smoke_verified`, `local_only` receipt. Managed package,
marker, and user-data paths were removed and verified absent after both runs. No
vendor package bytes or raw traces are retained in the repository.

## Consequences

- Weregopher now has one real application-specific semantic report connected through
  compatibility analysis, certification validation, exact local policy, and
  local-only publication.
- The result certifies only the Discord marker adapter workflow under the copied
  vendor runtime. `Certified adapters` remains `None`.
- The staged package identity is exact, but staging is not an immutable vendor-package
  snapshot or retained source lease.
- The report producer is trusted same-process code. Component-descriptor
  authentication, canonical runner approval integration, per-run attestation,
  challenge/freshness proof, signed registry publication, durable policy and receipt
  persistence, external revocation, and independent retrieval of named package
  artifacts remain future boundaries.
- Renderer/preload parity, complete module and native dependency analysis, helper
  behavior, production-state compatibility, sandbox strength, application workflows,
  security posture beyond the narrow launch checks, and efficiency are untested and
  cannot be inferred from this result.
