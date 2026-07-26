# Discord local certification control plane

This guide exercises the narrow `discord.smoke-marker` diagnostic workflow described
by [ADR 0036](../adr/0036-discord-disposable-smoke-certification-slice.md) through the
freshness-bound local control plane in
[ADR 0037](../adr/0037-freshness-bound-local-certification-control-plane.md) and the
verified disposable-scenario runner in
[ADR 0038](../adr/0038-verified-disposable-certification-scenario-runner.md).

The command transforms a new copy of an installed Discord package and launches a
content-addressed snapshot of that copy. It never modifies the vendor installation.
The launched tree is still the vendor Electron runtime, and the explicit
`--allow-uncertified-local-smoke` flag remains mandatory. A successful result is not
full Discord compatibility, execution authority, an OS sandbox, a registry signature,
production-state evidence, or an efficiency claim.

## Closed runner bundle

Runner inputs are provisioned outside the repository and use this exact layout:

```text
runner-bundle/
  identity.json
  components/
    runner_image.json
    host_image.json
    host_patch_set.json
    electron_runtime.json
    language_runtime_set.json
    toolchain_set.json
    host_agent.json
    verifier.json
    probe_asset_set.json
    source_revision.json
    exception_provenance.json
  artifacts/
    runner_image/<descriptor artifact names>
    host_image/<descriptor artifact names>
    host_patch_set/<descriptor artifact names>
    electron_runtime/<descriptor artifact names>
    language_runtime_set/<descriptor artifact names>
    toolchain_set/<descriptor artifact names>
    host_agent/<descriptor artifact names>
    verifier/<descriptor artifact names>
    probe_asset_set/<descriptor artifact names>
    source_revision/<descriptor artifact names>
    exception_provenance/<descriptor artifact names>
```

`identity.json` and every component descriptor must be its compact canonical JSON
encoding with no trailing newline. Each descriptor artifact name is a normalized
relative path beneath its role directory. Unknown files or directories, missing
roles, symbolic links/reparse points, noncanonical documents, unsafe names, excessive
bytes, and unstable reads fail closed. The transform layer then requires the
descriptor role and canonical digest to match the corresponding runner-identity slot
and verifies every exact artifact length and SHA-256 value.

For this workflow, `probe_asset_set` must contain the exact canonical adapter-owned
scenario at:

```text
artifacts/probe_asset_set/scenarios/discord.smoke-marker.scenario.json
```

The matching descriptor must bind that logical name, exact byte length, and SHA-256
identity, and the runner identity must bind the descriptor digest. The stored
scenario must be compact canonical JSON with no trailing newline. Its current
format-`"1"` golden bytes are
`crates/weregopher-domain/tests/fixtures/disposable-certification-scenario-v1.golden.json`
(strip the repository line ending). The command rejects a missing, noncanonical, or
different scenario even when the rest of the runner bundle is valid.

The bundle path and its bytes are evidence, not trust. Trusted local configuration
must independently supply both `--expected-runner-identity` and
`--runner-policy-revision`. Do not commit proprietary runner artifacts, package bytes,
tokens, traces, or local policy material to this repository.

## Prepare disjoint state

Create an existing snapshot-store directory that is disjoint from the vendor package
and runner bundle, and select new paths for the staged package, marker, and sibling
disposable user-data directory. Every mutable state path must be mutually disjoint;
the optional ledger must also be disjoint from both source trees and every other
state root. Canonical overlap checks run before staging. Each pass requires fresh
stage and marker paths.

The examples use placeholders:

```powershell
$vendor = "$env:LOCALAPPDATA\Discord\app-1.0.9249"
$runner = "C:\trusted\weregopher-runner"
$snapshots = "C:\weregopher-state\snapshots"
$runnerIdentity = "sha256:<64 lowercase hex characters>"
$runnerPolicy = "sha256:<64 lowercase hex characters>"
```

The snapshot store must already exist. The ledger root itself must not exist for its
genesis run, but its parent directory must exist.

## First pass: candidate report

The first pass verifies the complete runner bundle and emits the exact candidate
report plus runner and descriptor-set identities. It assigns no certification class.

```powershell
weregopher live-smoke-discord `
  $vendor `
  C:\weregopher-state\stage-candidate `
  C:\weregopher-state\marker-candidate `
  --allow-uncertified-local-smoke `
  --runner-bundle $runner `
  --expected-runner-identity $runnerIdentity `
  --runner-policy-revision $runnerPolicy `
  --snapshot-store-root $snapshots
```

Persist and independently review at least:

- `scenario_sha256`;
- `scenario_report_sha256`;
- `certification_report_sha256`;
- `runner_identity_sha256`;
- `runner_descriptor_set_sha256`; and
- the selected local certification-policy revision.

Paths, process identifiers, exit codes, and timestamps are diagnostic and do not
enter the semantic report identity.

## Second pass: attest and create genesis

Use new stage and marker paths. Pin the exact first-pass report, identify the trusted
certification-policy revision, and select a new ledger root:

```powershell
weregopher live-smoke-discord `
  $vendor `
  C:\weregopher-state\stage-trusted `
  C:\weregopher-state\marker-trusted `
  --allow-uncertified-local-smoke `
  --runner-bundle $runner `
  --expected-runner-identity $runnerIdentity `
  --runner-policy-revision $runnerPolicy `
  --snapshot-store-root $snapshots `
  --expected-certification-report "sha256:<candidate report>" `
  --local-policy-revision "sha256:<certification policy revision>" `
  --certification-ledger C:\weregopher-state\certification-ledger
```

The command verifies the exact scenario asset, retains the snapshot executable,
checks and prepares its closed disposable-state bindings, and only then generates the
challenge immediately before process creation. The default maximum monotonic age is
300 seconds and can be tightened with `--certification-freshness-seconds`; zero,
non-whole-millisecond, over-ten-minute, expired, or unrepresentable windows fail
closed. A successful shared result requires exact marker bytes, complete Job
termination, confirmed primary exit, and final snapshot revalidation. Marker
verification must complete through a direct non-reparse, no-write-sharing file handle
before the selected monotonic deadline.

Successful local output includes the exact semantic-report reference, runner and both
policy identities/generations, challenge and elapsed interval, attestation identity,
artifact-set identity, `smoke_verified` class, `local_only` publication status,
ledger sequence, record count, and new ledger-head identity.

## Later passes: supply the pinned head

An existing ledger is accepted only when the caller supplies its independently
persisted exact head:

```powershell
  --certification-ledger C:\weregopher-state\certification-ledger `
  --expected-ledger-head "sha256:<previous ledger_head_sha256>"
```

After every append, replace the separately trusted head pin with the newly returned
`ledger_head_sha256`. Keeping the head only inside the ledger directory does not
protect against rollback. Moving both the directory and head pin backward remains
possible to an unrestricted same-user actor; the pin must live in separately trusted
configuration.

Ledger replay rejects unknown entries, symbolic links, non-files, sequence gaps,
noncanonical or malformed records, hash-chain breaks, policy-generation violations,
revoked or mismatched publication, repeated freshness challenges, excessive records
or bytes, and a wrong head. Each next fixed-width sequence file uses create-new
semantics and is synchronized before append succeeds. A partial final file causes
future open to fail closed.

## Implementation traceability

| Requirement | Implementation | Primary regression evidence |
|---|---|---|
| Closed bounded component contracts | `weregopher-domain::certification_control_plane` and generated schemas | Domain golden/negative tests and schema tests |
| Exact 11-role descriptor/artifact verification | `weregopher-transform::certification_runner_components` | `certification_control_plane` transform behavior tests |
| Canonical disposable scenario and result contracts | `weregopher-domain::certification_scenario` and generated schemas | Domain golden, bounded-parser, relationship, and schema tests |
| Exact probe-asset selection | `weregopher-transform::certification_scenario` | Missing and noncanonical probe-asset behavior tests |
| Shared retained-snapshot scenario execution | `weregopher-transform::certification_scenario` | Native Windows compiled-fixture success, late-result rejection, post-primary Job-child success, whole-Job termination, and snapshot-revalidation test |
| Single-use monotonic pre-run challenge | `weregopher-transform::certification_attestation` | Fresh publication and revocation-race behavior tests |
| Atomic runner-policy → certification-policy → store commit | `weregopher-transform::certification_attestation` | Dual-revocation behavior test |
| Canonical pinned-head durable replay | `weregopher-transform::certification_ledger` | Reopen, corruption, gap, link, replay, revocation, and stale-writer tests |
| Closed runner-bundle loading | `bins/weregopher/src/runner_bundle.rs` | Canonical bundle and unknown/noncanonical entry tests |
| Vendor/runner state isolation | `bins/weregopher/src/live_smoke.rs` | Canonical mutable-path overlap regression |
| Snapshot-retained Discord adapter over shared runner | `bins/weregopher/src/live_smoke.rs` | Native Windows scenario-runner and installed-Discord proofs |
| Report → attestation → ledger integration | `bins/weregopher/src/discord_certification.rs` | Application end-to-end attested-ledger unit test |

Remote signer/key management, authenticated bundle or registry distribution,
transparency logging, external revocation feeds, the full parity scenario DSL,
replacement-runtime parity, production-state validation, and efficiency certification
remain later work.
