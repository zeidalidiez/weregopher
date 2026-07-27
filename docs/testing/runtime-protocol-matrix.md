# Runtime and renderer testing matrix

This matrix separates portable correctness from evidence that requires the native
Windows kernel. Running Linux Cargo inside WSL is useful, but it does not test Windows
named pipes, access tokens, process identity, Job Objects, COM, or WebView2.

## Validation lanes

| Lane | When | What it proves | What it does not prove |
| --- | --- | --- | --- |
| Ubuntu CI | Every push and pull request | Domain contracts, immutable-origin/path closure, renderer lifecycle/authority, MessagePack preflight/framing, handshake/session state, G2 evidence contracts, read-only ASAR/package and exact-preload preparation, bounded app-server initialization, transparent proxy, redacted controls/ownership labels, and repository process-session behavior, schemas, and platform-neutral regressions | Any Windows API, WebView2 behavior, installed-package evidence, exact-binary launch/identity, Job-owned proxy process trees, exact-schema semantic derivation, or vendor compatibility |
| `windows-latest` CI | Every push and pull request | Clean native Windows build; all portable proxy, redacted control/ownership, and repository process-session behavior; DACL-backed pipe; PID, SID, Job, explicit-environment, and inherited-standard-I/O checks; hidden WebView2 G1 round trip; synthetic G2 isolated-world/projection behavior; package-derived preload runner engine with repository source and synthetic scope; browser-exit and ephemeral-profile cleanup | An installed OpenAI package, exact vendor preload/app-server behavior, authorized connection of the proxy to a Job-owned exact binary, exact-schema semantic derivation, Windows 10/11 client-specific behavior, interactive desktop/UI behavior, or cross-user policy |
| WSL to native Windows | Optional final developer preflight on a suitably resourced host | The developer's current Windows kernel executes the focused PE test binaries while the source remains in WSL | A second clean machine or supported-client-OS matrix |
| User-controlled exact OpenAI package | Final G2 candidate phase, after public CI, in a disposable Windows account/VM | Read-only package identity/inventory and, when explicitly enabled, exact package-derived preload plus bundled app-server schema/initialization evidence | Configured-preload entry resolution, vendor renderer or real IPC compatibility, broader application compatibility, security posture, efficiency, or certification |
| Windows 10 x64 standard user | Milestone/release candidate | Supported Windows 10 client behavior, installed Evergreen WebView2 behavior, and cleanup without elevation | Windows 11 and ARM64 |
| Windows 11 x64 standard user | Milestone/release candidate | Supported Windows 11 client behavior, installed Evergreen WebView2 behavior, and cleanup without elevation | Windows 10 and ARM64 |
| Windows 10/11 second local user | Milestone/release security check | A different user cannot open the current-user-only pipe | Remote-host policy beyond the separate remote-client flag |

`windows-latest` is an automated clean-host gate, not a substitute for client Windows
10 and Windows 11 milestone testing. ARM64 is not yet an implemented or certified
target.

## Resource-safe local sequencing

On a development machine, complete the portable Linux/WSL lane before starting any
native Windows lane. Do not run Linux Cargo and Windows Cargo concurrently: WSL and
the Windows host share CPU, memory, and storage bandwidth even when they use separate
target directories.

For a machine with adequate memory, one Cargo build job and one Rust test thread
reduce concurrency:

```bash
export CARGO_BUILD_JOBS=1
cargo test <focused-package-or-test> -- --test-threads=1
```

Keep focused portable tests in the edit loop. Run the full portable gate once the
implementation is otherwise ready, then run native Windows validation as a separate
final phase. CI lanes may remain parallel because each lane runs on an isolated
runner.

Exact installed-package G2 testing is always part of that final Windows phase. The
inventory hashes the package tree; the optional exact preload probe performs two
WebView2 navigations and completes browser/profile cleanup; and the optional exact
app-server probe launches three sequential Job-owned processes. When both probes are
requested, preload finishes before app-server execution starts. Do not overlap this
work with WSL Cargo, another Windows Cargo build, or a second package probe.

`CARGO_BUILD_JOBS=1` limits Cargo scheduling; it does not cap the peak memory of one
compiler, linker, test, or Rustdoc process. On a constrained WSL host, run only the
focused portable tests needed for the change. Do not run the full workspace gate or
drive native Windows Cargo from that host. Push a draft branch and let isolated
Ubuntu and Windows CI runners perform the complete gate instead.

## Portable Linux/WSL gate

From the repository root:

```bash
export CARGO_BUILD_JOBS=1
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features -- --test-threads=1
cargo xtask schema --check
```

This lane executes the portable renderer origin/lifecycle/bridge tests plus
`framing.rs` and `session.rs`. It covers immutable asset/path bounds, exact-origin
closure, stale navigation rejection, backend-derived renderer authority, frame
ceilings before payload reads, exact versions/kinds/sequences, malformed MessagePack,
nonce/identity binding, request bounds/deadlines/cancellation, late-result discard,
and stream credit. It also covers G2 evidence invariants, strict versus read-only ASAR
semantics, exact OpenAI package-contract analysis over synthetic bytes, fail-closed
exact-preload source preparation and binding, deterministic schema-bundle hashing, and
the bounded app-server initialization state machine. It also covers the transparent
proxy's exact-byte unknown-message preservation, independent bidirectional request
spaces, FIFO backpressure, recursive JSON limits, request deadlines/history, late and
unmatched responses, explicit closure, and debug redaction. The repository process
fixture additionally covers real piped stdio ownership, initialization delivery
continuity, request/session deadlines, crash/exit classification, graceful and forced
shutdown, bounded post-exit pipe drain, prepared-frame admission, exact deny-only
rules, bounded redacted event loss accounting, and diagnostic redaction. Portable
control tests separately cover observer-local correlation tokens and non-authorizing
thread/turn/item resource labels.
Windows-only test binaries are compiled as empty targets on Linux and provide no
native Windows evidence there.

## Portable transparent app-server proxy scenario

The OpenAI adapter's `app_server_proxy` tests require:

- valid unknown requests, notifications, responses, fields, variants, whitespace,
  number spelling, and key order to retain their exact delimiter-free bytes;
- client-to-server and server-to-client queues to remain independently bounded FIFO
  queues with atomic rejection and no notification coalescing or silent drops;
- recursive duplicate keys, excessive depth/nodes, invalid identities, ambiguous
  message shapes, and embedded line delimiters to fail closed;
- client-origin and server-origin request identities to correlate independently;
- response-before-forwarding, active-request exhaustion, session-local identity
  reuse, and bounded history exhaustion to fail explicitly;
- request deadlines to begin only when a frame leaves its queue;
- a backward-moving caller clock to fail before a deadline or queue transition;
- completed/expired identities to remain digest-only history so late responses cannot
  satisfy a newer logical request;
- genuinely unmatched and known-late responses to remain forwardable and separately
  counted; and
- closure and every `Debug`/diagnostic surface to omit payloads, methods, and request
  identities.

This scenario is entirely in memory. It does not launch the app-server, own
standard-I/O or WebSocket transport, enforce long-lived initialization, implement
semantic interceptors, infer thread/turn/helper ownership, mediate approvals, or
establish exact-build compatibility.

## Portable app-server controls and ownership scenario

The OpenAI adapter's `app_server_controls` and `app_server_ownership` tests require:

- preparation to retain exact valid bytes while leaving queue, correlation, history,
  deadline, and diagnostic state unchanged;
- admission to recheck current queue capacity and fail atomically after intervening
  state changes;
- accepted, forwarded, blocked, and expired-request events to use monotonic local
  ordering and request tokens without retaining payloads, raw methods, or wire IDs;
- equal token sequence numbers from separate journals to remain non-interchangeable;
- bounded event pressure to evict only the oldest redacted event, advance an explicit
  counter, and leave protocol forwarding unchanged;
- exact direction/kind/method rules to have only forward or block results;
- unknown methods to remain transparent and response transformation/replacement to be
  unavailable;
- thread/turn/item identifiers to be bounded, hierarchical, and debug-redacted;
- request-token binding, helper/MCP/command/worktree/browser labeling, duplicates,
  rebinding, unknown or foreign-journal tokens, and registry capacity to fail closed;
- item, turn-descendant, thread-descendant, and complete-session label release to
  remain distinct; and
- every returned resource to remain a label/cleanup candidate without a PID, handle,
  effect, or sandbox claim.

These tests use explicit synthetic semantic identities. They do not parse unknown
app-server payloads or prove exact OpenAI thread/turn/item fields, helper causality,
resource identity, approval semantics, cleanup execution, or persisted audit traces.

## Portable app-server process-session scenario

The OpenAI adapter's `app_server_process_session` tests launch only the
`weregopher-app-server-fixture` repository binary and require:

- an already-launched child without piped stdin, stdout, and stderr to fail
  attachment and be terminated;
- stdin, stdout, stderr discard/accounting, and primary-process reaping to run on
  separate bounded workers while the owner poll remains nonblocking;
- the exact `initialize` request and unknown success-response bytes to cross real
  JSONL stdio unchanged;
- `initialized` to fail before the matching initialize response leaves the
  client-facing FIFO, even when stdout already delivered it to the proxy;
- initialize rejection and every other premature client/server shape to terminate
  the session explicitly before candidate admission;
- valid unknown notifications, bidirectional requests, responses, fields, and result
  variants to remain transparent after readiness;
- an oversized stdout line to fail before proxy retention;
- initialization, complete-runtime, and forwarded-request deadlines to terminate the
  primary process with distinct outcomes;
- a nonzero exit to classify as a crash while an unrequested zero exit remains
  distinct;
- graceful shutdown to drain admitted writes and close stdin, with a hung fixture
  forced after the configured grace;
- stdout/stderr handles inherited by a short-lived fixture descendant to hit the
  bounded post-exit drain and report `streams_drained = false` instead of a clean
  result; and
- an exact server request rule to block before admission, terminate distinctly, and
  retain only a redacted event;
- a two-event journal ceiling to report eviction while exact peer bytes remain
  unchanged; and
- diagnostics, errors, exit reports, and `Debug` to omit payloads, method names,
  request identities, and stderr content.

This is real portable process I/O but not an exact OpenAI process test. Attachment
does not authorize or fingerprint the fixture, and the session owns only the primary
`std::process::Child`. Hosted Windows execution proves the standard-library mechanism
on a clean Windows runner; it does not prove Windows Job adaptation, descendant-tree
termination, disposable vendor state, exact package identity, or compatibility.

## Native Windows from WSL

Use Windows PowerShell and Windows `cargo.exe`, with a Windows-native target directory
that is separate from Linux `target/`. Substitute the WSL distribution and repository
path:

```powershell
powershell.exe -NoProfile -NonInteractive -Command '
  $env:CARGO_TARGET_DIR = Join-Path $env:LOCALAPPDATA "Temp\weregopher-win-target"
  $env:CARGO_BUILD_JOBS = "1"
  $manifest = "\\wsl.localhost\<Distro>\home\<user>\projects\weregopher\Cargo.toml"
  cargo test --manifest-path $manifest -p weregopher-windows --test pipe -- --test-threads=1
  cargo test --manifest-path $manifest -p weregopher-runtime-protocol --test windows_round_trip -- --test-threads=1
  cargo test --manifest-path $manifest -p weregopher-adapter-openai --test app_server_process_session -- --test-threads=1
  cargo test --manifest-path $manifest -p weregopher-renderer-webview2 --test g1_renderer -- --test-threads=1 --nocapture
'
```

Do not reuse one target directory between Linux and Windows Cargo: Linux ELF and
Windows PE artifacts, build scripts, and incremental state are not interchangeable.

For the full native gate:

```powershell
$env:CARGO_TARGET_DIR = Join-Path $env:LOCALAPPDATA "Temp\weregopher-win-target"
$env:CARGO_BUILD_JOBS = "1"
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features -- --test-threads=1
cargo test --workspace --doc -- --test-threads=1
$env:RUSTDOCFLAGS = "-D warnings"
cargo doc --workspace --no-deps
cargo xtask schema --check
cargo build --workspace --all-features --locked --release
```

A native Windows clone, such as `C:\src\weregopher`, is preferred for release
qualification. The WSL UNC path is supported for focused developer feedback.

## Native protocol scenarios

The automated pipe tests require:

- two generated addresses are distinct and only canonical local version-4 UUID
  addresses parse;
- the expected same-user child connects and exchanges bytes only after Job assignment;
- an expected child outside the supplied Job is rejected; and
- every accept operation has a finite timeout.

The worker/controller test additionally requires:

- the nonce travels through inherited standard input, not arguments, environment, or
  the named pipe;
- the pipe-reported PID equals the launched child and the host verifies SID and fresh
  PID Job membership before decoding hello;
- version, feature, and limit negotiation succeeds;
- async call/result and request correlation round-trip;
- cancellation is idempotent and a deliberately late result is discarded;
- an ordered event arrives;
- two stream chunks consume exactly two receiver-granted windows; and
- graceful shutdown produces a successful child exit.

## Native packaged-renderer scenario

The automated WebView2 G1 scenario additionally requires:

- a fresh exclusive ephemeral user-data folder and hidden ordinary controller;
- all WebView2 resource requests to be intercepted, with the entry document and script
  served only from the immutable in-memory package;
- native host objects, developer tools, default context menus, browser extensions, and
  OS-primary-account single sign-on to remain disabled;
- a document-start nonce and exact backend-reported private-origin source before the
  page invocation is accepted;
- application, renderer, frame, world, origin, service, deadline, and capabilities to
  be derived by the host rather than accepted from page JSON;
- the page call to traverse the authenticated Job-owned worker protocol and its result
  to update the fixture DOM;
- controller close to be followed by the exclusive browser-process exit event;
- the ephemeral user-data directory to be removed; and
- the worker to accept graceful shutdown and exit successfully.

This scenario deliberately does not show a window or test input, IME, accessibility,
GPU/media behavior, authentication, profile reuse, subframes, service workers,
preload/`contextBridge`, or vendor package behavior. Those require separate G2 or
release-candidate evidence.

## Native synthetic G2 preload scenario

The hosted-Windows renderer `g2_preload` fixture and the OpenAI adapter's
package-derived runner-engine test additionally require:

- the preload bootstrap to be installed at document start in a named WebView2
  isolated world;
- isolated and page code to receive separate global objects;
- page prototype mutation not to affect the isolated preload world;
- the page-visible projection to be frozen;
- a function call to round-trip between the projected page API and isolated world;
- navigation to invalidate the previous projection/handle generation; and
- a forged package-source observation with the wrong host nonce to be ignored; and
- browser-process exit and ephemeral-profile cleanup to complete.

Both resulting reports are explicitly `synthetic_fixture` evidence. They validate the
current WebView2 mechanism and the exact runner engine against repository source but
cannot satisfy the exact OpenAI preload/bridge gate. Public CI contains no OpenAI
package bytes.

## Exact installed OpenAI G2 phase

The read-only exact package inventory and optional preload/app-server probes run only
on a user-controlled native Windows installation after public CI passes, inside a
disposable standard-user account or clean VM with no production OpenAI state. Do not
drive this phase through WSL on a constrained shared host. The app-server is
unrestricted same-user code; Job Objects and explicit state/environment are lifecycle
and accounting controls, not a registry, credential-store, filesystem, or network
sandbox. The preload runs in a hidden WebView2 isolated world against a closed
repository page; this is not independent sandbox or security-posture evidence.

Follow the [OpenAI G2 feasibility runbook](openai-g2-feasibility.md) for commands,
expected dispositions, Windows 10/11 serial sequencing, and evidence handling. The
exact runner executes only one unambiguous digest-bound candidate and deliberately
does not load the vendor renderer, forward real IPC, or prove that packaged main logic
selects that candidate.

For the second-local-user check, run the server fixture as a standard user and attempt
to open the printed non-secret pipe address from a second signed-in local account.
The open must fail with access denied. Do not weaken the DACL or run both processes
under the same elevated token to make this check convenient.

## Tester evidence

Record only:

- Windows edition, release, build, and architecture;
- installed WebView2 runtime version for renderer runs;
- whether the shell/token was standard or elevated;
- `rustc -vV`;
- commit SHA;
- exact test command; and
- pass/fail plus the failing test name and sanitized error category; and
- for exact G2 runs, the package full name and canonical evidence digests.

Do not commit nonce bytes, raw protocol traces, package bytes, tokens, usernames,
absolute user paths, or unsanitized process diagnostics.

## Implementation traceability and remaining work

| Requirement | Current evidence | Status |
| --- | --- | --- |
| Spec 27.2/27.5 transport authentication and handshake | Portable identity/nonce tests plus native PID/SID/Job fixture | Implemented for synthetic G1 |
| Spec 27.3 framing/versioning | Domain frame tests plus portable framing tests | Implemented for G1 |
| Spec 27.6–27.9 values, calls, ordering, and cancellation | Closed nested-contract, JavaScript-value fidelity, call-context/app-handle binding, portable session, and native round-trip tests | Implemented for async control slice |
| Spec 27.11 credit streams | Portable overflow/replay tests and native two-window round trip | Implemented for inline fixture data |
| WP-D named-pipe transport and wire codec | Native pipe tests plus portable framing, native-binary byte-buffer, malformed-input, and outbound-bound tests | Implemented for G1 |
| WP-D sync lane and deadlock fixture | No dedicated lane or wait-graph detector | Not implemented; feature is false |
| WP-D shared buffers/handle lifecycle | No authenticated duplicated-handle transport | Not implemented; feature is false |
| WP-D protocol fuzzing and large-data stress | Deterministic malformed vectors and small credit fixture only | Not implemented |
| Production worker launch | Existing atomic no-inheritance launch plus test-only nonce stdin path | Integration still required |
| ADR 0002 G1 standalone protocol fixture | Native worker/controller scenario | Implemented |
| ADR 0002/ADR 0040 G1 packaged renderer fixture | Portable origin/lifecycle/authority tests plus hidden native WebView2 → authenticated worker → DOM → browser-exit/profile-cleanup scenario | Implemented |
| ADR 0002/ADR 0041 G2 canonical evidence | Package, preload/bridge, app-server, gate, and aggregate Rust contracts plus generated schemas | Implemented |
| ADR 0041 G2 exact package inventory | Maintained x64 MSIX identity and fixed package/ASAR component analysis; explicit native-Windows CLI | Implemented; exact user-controlled run pending |
| ADR 0041 G2 app-server protocol | Portable bounded JSONL/schema-bundle tests plus atomic Job-owned exact-binary schema/initialize runner | Implemented; hosted process primitives pass, exact user-controlled run pending |
| ADR 0041 G2 preload mechanism | Hosted-Windows document-start isolated-world/projection/navigation fixtures plus ASAR/member-revalidating exact package-derived runner | Implemented; hosted engine passes with synthetic scope, exact user-controlled run pending |
| ADR 0002 G2 aggregate feasibility | Fail-closed three-lane aggregate bound to one source build | Incomplete until all exact lanes pass |
| ADR 0042 transparent app-server proxy core | Exact-byte unknown-message tests; recursive JSON bounds; independent bounded FIFO queues; bidirectional request/deadline/history correlation; payload-free diagnostics | Implemented as the portable in-memory core |
| ADR 0043 portable app-server process session | Repository child over bounded real stdio; initialization-delivery continuity; request/session deadlines; crash/exit/drain classification; graceful/forced shutdown; redaction | Implemented as a build-agnostic portable prerequisite; exact authorized Job-owned binary integration pending |
| ADR 0044 app-server controls and ownership labels | Non-mutating exact candidates; dynamic admission; bounded redacted pull events with explicit loss; exact deny-only rules; thread/turn/item correlation and resource-label scope release | Implemented as build-agnostic non-authorizing primitives; exact-schema derivation, approval mediation, resource capabilities/effects, and persisted traces pending |

With both G1 synthetic fixtures passing, G1 is complete. G2 now has its bounded
evidence contracts and exact package, preload, and app-server workflows, but it is not
complete until the final serial user-controlled Windows matrix produces passing exact
evidence for one pinned build. Public native CI covers repository-only mechanisms,
including the exact-preload engine with synthetic scope. The portable proxy core is a
build-agnostic prerequisite; the repository process session and redacted
control/ownership primitives add no exact-build evidence. None means that a pinned G3
preview has begun. Exact schema-derived semantics remain gated on G2, and the
incomplete WP-D hardening rows remain independently open.
