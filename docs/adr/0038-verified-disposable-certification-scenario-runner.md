# ADR 0038: Verified disposable certification-scenario runner

- Status: Accepted
- Date: 2026-07-26
- Extends: [ADR 0017](0017-atomic-windows-job-owned-process-launch.md),
  [ADR 0020](0020-content-addressed-windows-package-snapshots.md),
  [ADR 0036](0036-discord-disposable-smoke-certification-slice.md), and
  [ADR 0037](0037-freshness-bound-local-certification-control-plane.md)

## Context

The freshness-bound local certification control plane authenticates exact runner
component bytes, creates a single-use challenge before a run, keeps both local policy
generations current through publication, and records the result in a pinned-head
ledger. The first Discord slice also proves one useful installed-package workflow.

The process-driving portion of that slice is still application-specific. It hard
codes the Discord executable, marker and user-data arguments, Job limits, polling,
success-file validation, termination, and snapshot revalidation directly in the CLI.
That prevents a second adapter from reusing the same lifecycle boundary and leaves
the runner's verified probe-asset set disconnected from the behavior actually
executed.

Accepting an arbitrary command document would be unsafe. A producer-selected scenario
must not:

- choose production or ambient state paths;
- expand capabilities, privileged effects, native/helper content, or security
  exceptions;
- claim that Job ownership is a sandbox;
- substitute a mutable executable path for the retained package snapshot;
- create a freshness challenge before all fallible preparation is complete; or
- serialize process IDs, paths, wall-clock values, or other unstable diagnostics into
  semantic evidence.

The complete parity language in Appendix C of the architecture specification includes
fixtures, UI Automation, semantic events, resource assertions, vendor-oracle
comparison, and extension hooks. Implementing that language here would combine too
many trust boundaries. The next reusable increment is intentionally smaller: one
closed disposable-state process scenario with one exact success file.

## Decision

Introduce canonical disposable-scenario and successful-result contracts, verify each
scenario as an exact probe asset of an already approved runner, and provide one shared
Windows executor over an identity-matched package-snapshot executable. Migrate the
Discord marker workflow to that shared path.

This runner produces diagnostic evidence. It does not authorize execution, assign a
certification class, authenticate bundle distribution, prove same-user containment,
or implement the Appendix C parity DSL.

### Canonical disposable-scenario contract

Add format-`"1"` `DisposableCertificationScenario` with a 64 KiB serialized ceiling.
The document binds:

- one scenario ID, application-family ID, adapter ID, and workflow ID;
- one manifest-relative package executable;
- between one and sixteen canonically ordered logical state roots;
- between one and thirty-two ordered literal or logical-state-path arguments; and
- exact time, argument, command-line, process-count, and memory limits.

The root set must contain exactly one `success_file`. That root binds an exact SHA-256
identity, exact byte length, and read ceiling no greater than 1 MiB. Every other root
is a new empty directory. Every declared root must appear in exactly one state-path
argument, and an argument cannot reference an undeclared root. The document contains
no absolute state paths.

Format 1 fixes these execution postures:

- `state_mode = disposable`;
- `security_posture = vendor_equivalent_full_trust`; and
- `dependency_policy = vendor_default_ambient`.

It admits a nonzero whole-millisecond scenario deadline no greater than ten minutes,
poll and shutdown intervals no greater than sixty seconds, at most sixty-four launch
arguments, and at most 32,767 complete Windows command-line UTF-16 units. Constructor
validation additionally checks aggregate argument bytes, root uniqueness, exact root
coverage, one success file, duration relationships, and representable limits.

The authoritative byte parser applies the serialized ceiling before JSON
deserialization and rejects unknown fields, unsupported versions, invalid
identifiers, duplicate or unbound roots, unsupported posture, and limit violations.
Generic deserialization exists only so the same validated type can be nested inside
another already byte-bounded canonical document; it is not an unbounded ingress API.
Compact UTF-8 JSON with canonical root ordering is the identity preimage.

### Verified scenario selection

`verify_disposable_certification_scenario` consumes the complete opaque
`VerifiedCertificationRunnerComponents` proof and one exact logical artifact name.
It selects bytes only from the verified `probe_asset_set`, parses them through the
bounded scenario parser, requires the stored bytes to equal the canonical compact
encoding, computes a role-specific scenario digest, and returns a non-cloneable,
non-serializable proof retaining the complete runner proof.

The function rejects missing, malformed, oversized, and noncanonical scenario
artifacts. It does not treat the artifact name, parsed fields, or digest as trust by
themselves. An adapter must still require the exact scenario definition it supports.

### Shared Windows execution boundary

`execute_disposable_certification_scenario` consumes:

- the verified scenario proof;
- either candidate mode or an exact semantic-report reference plus freshness limit;
- one `PackageSnapshotExecutable` retained from the complete package snapshot;
- an exact map from every logical root ID to a caller-selected absolute path; and
- a selected whole-millisecond timeout no greater than the scenario ceiling.

The executable capability's manifest-relative path must equal the scenario
executable. State bindings must exactly cover the declared roots. Every path must be
absolute and new, use an unambiguous non-device Windows leaf, be mutually disjoint
under Windows ordinal case semantics, and remain outside the package snapshot; its
existing parent is canonicalized before use. Empty roots are created in a second
phase, checked as direct non-reparse directories, and followed by another absence
check for the success file. The caller remains responsible for the wider source,
runner-bundle, store, and ledger isolation checks because those paths are outside
this generic capability.

The executor then:

1. revalidates the complete retained snapshot;
2. creates the declared empty directories and resolves the closed argument list;
3. constructs the exact process and Job limits;
4. rechecks runner policy for candidate mode, or consumes the verified runner proof
   into a single-use freshness capability after preparation and immediately before
   launch for attested mode;
5. creates the primary process atomically inside a kill-on-close Job with an empty
   environment and no inherited handles;
6. confirms primary Job membership and waits only through the selected monotonic
   deadline, including when the primary exits before a Job child produces the result;
7. opens the unique success file without following reparse points or sharing write
   access, then completes its declared type, length, bounded-read, and SHA-256 checks
   before the deadline;
8. terminates the complete Job process tree, confirms primary-process exit through
   the bounded shutdown interval, and revalidates the complete snapshot;
9. rechecks runner policy after candidate execution; and
10. returns the canonical successful report plus the optional still-linear pending
    attestation capability.

Any error drops Job ownership and fails without a successful report. Job limits and
termination are lifecycle/accounting controls only. The launched package and its
children remain unrestricted same-user processes.

### Canonical successful-result contract

Add format-`"1"` `DisposableCertificationScenarioReport` with a 128 KiB serialized
ceiling. It embeds the exact scenario and binds:

- package-tree Merkle identity and executable SHA-256 identity;
- nonzero package file count and aggregate bytes;
- selected timeout in exact milliseconds;
- successful Job membership, whole-Job termination, primary exit, and final snapshot
  revalidation checks; and
- the logical success root plus exact observed file identity and length.

Paths, process IDs, exit codes, wall-clock timestamps, monotonic elapsed time, and
freshness challenges are diagnostics or separate control-plane evidence and do not
enter this semantic result. The report constructor accepts only exact success bytes
matching the embedded scenario. Its byte-bounded parser revalidates every nested
relationship, and compact canonical bytes have a role-specific report digest.

### Discord migration and report format 2

The Discord adapter owns one exact built-in scenario and requires its canonical bytes
at:

`scenarios/discord.smoke-marker.scenario.json`

inside the verified runner's `probe_asset_set`. The scenario selects `Discord.exe`,
the exact marker success root, one new user-data directory, adapter-marker and
`--user-data-dir` arguments, the existing sixty-second timeout, and the existing Job
and launch limits.

`DiscordSmokeCertificationReport` advances to format `"2"`. Its runtime observation
embeds the shared format-`"1"` scenario report and separately binds the exact scenario
digest plus Discord-specific post-probe vendor-ASAR stability and reviewed mutable
path omissions. The adapter rejects any nested scenario other than its exact built-in
definition. Historical format-`"1"` Discord reports remain historical vectors and are
not accepted as current reports.

The CLI verifies the named scenario asset after complete runner-component
verification, compares it with the adapter-owned definition, and passes the retained
snapshot executable and logical marker/user-data bindings to the shared executor. It
retains the package snapshot through one more complete-view check immediately before
any attestation or ledger commit. Candidate output includes both scenario and
scenario-report identities in addition to the adapter report and runner identities.

## Security invariants

1. Scenario bytes are executable inputs only after transitive verification through
   the exact locally approved runner identity and probe-asset descriptor.
2. A scenario artifact cannot select production state, arbitrary absolute paths,
   unsupported posture, or undeclared state roots.
3. The caller supplies every physical state path separately, and every path is new
   and outside the package snapshot.
4. The launched executable is the identity-matched manifest member retained by the
   complete package-snapshot lease.
5. The attested-mode freshness capability is generated after preparation and before
   process creation, then remains single-use.
6. Success requires exact bounded file bytes, whole-Job termination, confirmed
   primary exit, and a final complete snapshot revalidation.
7. Candidate execution checks runner-policy currentness both before and after the
   run; attested publication retains its existing dual-policy commit checks.
8. Semantic report identity excludes unstable paths, PIDs, exit codes, and clocks.
9. Job Objects, snapshot directories, disposable paths, local policies, and local
   ledgers are never described as same-user sandboxes or remote trust.
10. Scenario/report parsing, verification, and execution do not grant transformation,
    execution, privileged-effect, certification, registry, or publication authority.

## Consequences

- Additional adapters can reuse one tested lifecycle and result contract without
  duplicating process-control code.
- Runner probe assets now bind the exact scenario that is actually launched.
- The Discord report identity changes to format 2 and is intentionally incompatible
  with historical format-1 bytes.
- The native Windows regression suite executes a compiled fixture through the full
  verified-scenario, retained-snapshot, Job, success-file, termination, and
  revalidation path. It also rejects a late result and accepts an on-time result from
  a Job child after the primary exits.
- The implemented runner supports only closed single-process-entry scenarios with
  logical disposable roots and one exact success file.
- UI Automation, semantic events, fixtures with authority, vendor-oracle comparison,
  multiple outcomes, trace normalization, production-state testing, resource
  certification, authenticated bundle distribution, signed registry publication,
  and the full Appendix C parity DSL remain later work.
