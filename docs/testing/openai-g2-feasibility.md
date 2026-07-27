# OpenAI G2 feasibility testing

This runbook separates public synthetic coverage from exact installed-package
evidence. It is intentionally staged: do not run Windows and WSL Cargo workloads at
the same time, and do not run the exact package probe until the portable and hosted
CI lanes are clean.

G2 is an evidence gate, not a compatibility or certification result. Its aggregate
can be:

- `incomplete` when at least one exact lane has not run;
- `blocked` when an exact lane fails; or
- `feasible` only when package, preload/bridge, and app-server evidence all pass for
  the same source build.

## Test lanes

| Lane | Host and data | Current command or test | Result scope |
| --- | --- | --- | --- |
| Portable contracts | Linux/WSL or Windows; synthetic fixtures only | Focused domain, ASAR, OpenAI adapter, CLI, and schema tests | Contract and parser correctness; no Windows or vendor-package evidence |
| Native synthetic preload | GitHub-hosted `windows-latest`; repository fixtures only | `cargo test -p weregopher-renderer-webview2 --test g2_preload` | WebView2 isolated-world mechanism only; report scope is `synthetic_fixture` |
| Native process primitives | GitHub-hosted `windows-latest`; repository fixtures only | Workspace Windows tests | Atomic Job-owned standard-I/O launch and explicit child environment; no vendor-package evidence |
| Exact static inventory | User-controlled Windows 10/11 x64; installed package read-only | `weregopher feasibility open-ai` | Exact package lane; app-server and preload lanes remain `not_run` |
| Exact app-server | User-controlled Windows 10/11 x64; exact bundled executable | Same command with both app-server flags | Exact package and app-server lanes; preload remains `not_run` |
| Exact preload/bridge | User-controlled Windows 10/11 x64; exact package-derived preload | Runner not implemented yet | Required before G2 can become `feasible` |

Public CI must never fetch an installed OpenAI package or upload proprietary package
bytes. The last three lanes are final, serial tests on a licensed installation in a
disposable standard-user Windows account or clean VM under the tester's control.

## Before an exact Windows run

Use a native Windows clone in a disposable standard-user account or clean VM. Install
or register the candidate package for that test account, and do not copy production
OpenAI state into it. An explicit child environment redirects conventional state
paths but cannot stop unrestricted same-user code from consulting registry,
credential-store, filesystem, or network resources. Never run the exact probe from a
day-to-day production account.

Stop WSL builds and other memory-heavy work first. Confirm:

- the branch commit passed Ubuntu and `windows-latest` CI;
- the current account/VM is disposable and contains no production OpenAI state;
- the installed package is the maintained Windows x64 MSIX family;
- no application update is in progress;
- sufficient temporary disk space and memory are available; and
- the tester accepts that the bundled app-server is unrestricted same-user code.

The inventory command reads and hashes the installed package tree. The optional
app-server lane then launches three exact-binary phases sequentially. Each phase has
bounded process count, memory, output, and time, but neither the Job Object nor the
explicit environment is a sandbox. Do not run these commands in parallel or from WSL
on a constrained shared host.

## Exact static inventory

From a native Windows repository clone:

```powershell
$env:CARGO_BUILD_JOBS = "1"
cargo run --locked -p weregopher -- feasibility open-ai
```

The command queries only the bounded current-user package catalog, chooses the sole
matching Codex package, fingerprints it read-only, validates the maintained exact
identity and layout, and writes canonical JSON to standard output. It does not launch
the package or app-server. The expected aggregate disposition is `incomplete`, with:

```text
package       = passed
preload_bridge = not_run
app_server    = not_run
```

If multiple matching versions are registered, select one exact full name:

```powershell
Get-AppxPackage -Name OpenAI.Codex | Select-Object -ExpandProperty PackageFullName
cargo run --locked -p weregopher -- feasibility open-ai `
  --package-full-name "<exact PackageFullName>"
```

Do not weaken the maintained identity checks to make an unexpected package pass.
Treat a missing component, identity mismatch, changed layout, ASAR error, or absent
bounded preload candidate as a blocked feasibility finding.

## Exact app-server schema and initialization

Run only after the static inventory succeeds:

```powershell
$env:CARGO_BUILD_JOBS = "1"
cargo run --locked -p weregopher -- feasibility open-ai `
  --probe-app-server `
  --allow-unrestricted-same-user-probe
```

The explicit acknowledgement is required because the exact vendor binary has the
user's ordinary ambient network and same-user process authority. The probe:

1. rechecks the executable length, SHA-256 digest, and Windows file identity;
2. generates exact-version TypeScript definitions into disposable state;
3. generates exact-version JSON Schemas into disposable state;
4. hashes the bounded schema bundle;
5. requires a pre-initialize request to be rejected;
6. completes `initialize` followed by `initialized`; and
7. terminates the Job-owned process and removes disposable files.

The expected aggregate remains `incomplete`: package and app-server are `passed`,
while preload/bridge is `not_run`. A successful app-server probe does not establish a
transparent proxy, application login, network workflow, or Codex feature
compatibility.

## Exact preload report boundary

The command accepts `--preload-report <path>` only for a canonical exact-package
report whose:

- source build-fingerprint digest equals the current inventory;
- preload digest equals one retained package preload candidate;
- scope is `exact_package`; and
- required bridge checks are all present.

The repository does not yet generate that exact report. Do not edit the synthetic
fixture output, copy digests into a hand-authored report, or relabel
`synthetic_fixture` evidence. The next implementation milestone is an exact
package-derived preload execution path that can produce this report without vendor
installation mutation or production-state access.

## Client Windows matrix

After the exact preload runner exists, exercise one pinned package fingerprint
serially on:

| Platform | Account | Required evidence |
| --- | --- | --- |
| Windows 10 x64 | Disposable standard user/VM | Static inventory, exact app-server, exact preload, cleanup |
| Windows 11 x64 | Disposable standard user/VM | Static inventory, exact app-server, exact preload, cleanup |

Use the same package fingerprint where the vendor catalog permits it. If Windows 10
and Windows 11 receive different package builds, report them as separate exact
candidates rather than treating the results as one matrix row. ARM64, elevated
execution, cross-user behavior, and interactive UI are outside this G2 slice.

## Evidence handling

Record only:

- Windows edition, release, build, and architecture;
- standard or elevated token status;
- installed WebView2 runtime version for preload runs;
- `rustc -vV`;
- commit SHA and exact test command;
- package full name and canonical evidence digests; and
- pass/fail with a sanitized error category.

Keep canonical JSON locally if it is needed for the next lane. Do not commit or upload
package bytes, generated proprietary schemas, raw protocol traces, tokens, usernames,
absolute installation/profile paths, or unsanitized process output.
