# ADR 0041: Bounded G2 OpenAI target-feasibility evidence

- Status: Accepted
- Date: 2026-07-26
- Extends: [ADR 0002](0002-initial-release-profile.md) and
  [ADR 0040](0040-immutable-g1-webview2-renderer-fixture.md)

## Context

G2 asks whether one exact installed OpenAI desktop package presents boundaries that
Weregopher can plausibly preserve: a recognized package and entry layout, preload and
`contextBridge` behavior, and the exact bundled Codex app-server schema and
initialization protocol. G1's synthetic renderer and worker fixtures do not answer
those package-specific questions.

The answers must remain separable. Static discovery can identify likely preload
members without proving which member Electron executes. A synthetic isolated-world
fixture can validate a WebView2 mechanism without proving compatibility with vendor
preload code. An app-server handshake can pass without proving the packaged shell,
renderer, state, helpers, or complete Codex workflow. None of those observations
authorizes transformation or execution.

The installed package is proprietary evidence. Public CI cannot contain or fetch its
bytes, and native Windows package testing must remain a separate, user-controlled
phase rather than a workload driven concurrently from WSL on a constrained host.

## Decision

Implement G2 as three content-addressed evidence lanes plus one fail-closed aggregate
report:

1. exact installed-package inventory;
2. preload/bridge fidelity;
3. exact bundled app-server schema and initialization; and
4. an aggregate disposition of `incomplete`, `blocked`, or `feasible`.

Every lane is `not_run`, `failed`, or `passed`. A completed lane carries the digest of
its canonical evidence. The aggregate is `feasible` only when all three required
lanes pass for one source build. Feasibility is not compatibility, certification,
launch authorization, security posture, or efficiency.

### Package inventory

The initial maintained family target is the registered Windows x64 MSIX identity
`OpenAI.Codex_2p2nqsd0c76g0`. Discovery uses the bounded current-user package catalog;
selection fails closed when no package or more than one package matches unless the
caller supplies an exact package full name.

The package is fingerprinted read-only and the inventory binds:

- the canonical build-fingerprint and package-identity digests;
- the desktop entry, application ASAR, and exact bundled app-server package files;
- the ASAR `package.json` main entry;
- bounded preload candidates containing the maintained `contextBridge` and
  `exposeInMainWorld` signals; and
- bounded packaged renderer HTML candidates.

The ASAR read-only index validates packed offsets, sizes, integrity, path closure, and
resource ceilings while tolerating unpacked files, links, and empty directories for
discovery. The stricter writable archive model remains unchanged and continues to
reject unsupported entries. Static signal discovery does not decide which preload
candidate executes.

### App-server lane

The portable probe implements the documented JSONL standard-I/O state machine. It
first requires an ordinary request to fail before initialization, then sends exactly
one `initialize` request followed by `initialized`. Matching responses have bounded
line and message counts. Unknown notifications and additive response fields do not
cause rejection.

The native exact-package probe rechecks the bundled executable length, digest, and
Windows file identity. It runs the following phases sequentially:

```text
app-server generate-ts
app-server generate-json-schema
app-server initialize/initialized
```

Each phase is atomically launched suspended into a bounded kill-on-close Job with an
explicit disposable environment and exactly inherited standard-I/O handles. Schema
files and output streams are bounded; generated files are content-hashed and removed
with the temporary state. Raw output and protocol traces are not retained in the
canonical report.

The exact binary remains an unrestricted same-user process. The explicit environment,
timeouts, handle list, memory/process limits, and Job ownership are lifecycle and
accounting controls, not a sandbox. Running this lane therefore requires an explicit
same-user-risk acknowledgement.

### Preload/bridge lane

The hosted-Windows synthetic fixture injects a document-start script into a named
WebView2 isolated world and projects a frozen API into the main world. It verifies:

- document-start installation;
- separate global objects;
- prototype-pollution isolation;
- a frozen page projection;
- a function round trip; and
- stale-handle invalidation after navigation.

That report is permanently marked `synthetic_fixture` and cannot satisfy the exact
package gate.

An exact report must bind both the source build-fingerprint digest and one preload
candidate digest from the package inventory, carry `exact_package` scope, and pass
every required check. The aggregate command can import such a canonical report or
produce one directly with the exact package-derived runner.

Before execution, the runner rechecks the captured application ASAR length and digest,
reparses its complete integrity-checked packed body, and rechecks the selected member's
length and digest. Static discovery still does not establish the configured Electron
preload entry, so the initial runner accepts only an inventory with one candidate and
fails closed when candidate selection is ambiguous. Source must be valid UTF-8, is
bounded to 16 MiB during analysis, and must fit the WebView2 fixture's 4 MiB complete
document-start program ceiling.

The exact candidate runs at document start in a named WebView2 isolated world against
a closed repository-owned page on an immutable private origin. A bounded shim supplies
the sandboxed-preload subset needed by this lane: `contextBridge`, inert
`ipcRenderer`, limited `events`, `timers`, and `url` modules, and explicit renderer
`process` metadata. It copies and freezes bounded primitive, array, and plain-object
projections, converts functions to generation-scoped handles, rejects dangerous keys,
cycles, unsupported prototypes and values, and oversized graphs/messages, and proves
one harness function round trip without invoking vendor-exposed functions. The
`ipcRenderer` surface deliberately performs no real IPC.

Two sequential navigations must both execute the exact source and project at least one
API. The closed page verifies document-start execution, distinct globals, prototype
isolation, recursive freezing, the harness round trip, and rejection of the prior
navigation's randomized function handle. Browser exit and exclusive ephemeral-profile
removal must also complete. The backend digest covers only the fixed runner assets;
the separate preload digest identifies the exact vendor bytes. JavaScript
compatibility failures that remain observable produce a failed canonical report
without retaining source, values, error text, or raw messages.

### Explicit command and test separation

`weregopher feasibility open-ai` performs bounded read-only discovery, exact package
selection, fingerprinting, and inventory construction on native Windows. App-server
execution occurs only with both `--probe-app-server` and
`--allow-unrestricted-same-user-probe`. Exact preload execution similarly requires
both `--probe-preload` and the acknowledgement; direct execution conflicts with an
imported `--preload-report`. When both exact probes are selected, preload execution
finishes before the app-server phases begin. Off Windows, the command fails closed.

Portable contract, ASAR, package-analysis, and protocol tests run on Linux and
Windows. Public `windows-latest` CI covers native process primitives, the original
synthetic isolated-world fixture, and the package-derived runner engine using
repository source while retaining `synthetic_fixture` scope. It never acquires a
vendor package. Exact installed-package lanes run only at the final user-controlled
Windows stage, inside a disposable standard-user account or clean VM with no
production OpenAI state, as described by the testing matrix. The app-server's
explicit child environment alone is not a registry, credential-store, filesystem, or
network sandbox, and the WebView2 fixture is not treated as independent
security-posture evidence.

## Security invariants

1. Vendor installations are read and fingerprinted, never modified in place.
2. Package identity, package-tree evidence, ASAR bytes, component digests, and probe
   scope must agree before exact evidence is accepted.
3. Synthetic evidence cannot be promoted to exact-package evidence.
4. Unknown transport fields are not authority, and unexpected protocol states,
   paths, entries, output sizes, process outcomes, or report bindings fail closed.
5. Candidate verification runs only in a disposable Windows account/VM and uses
   disposable child state, so no production state is present to read or modify.
6. Bun, vendor helpers, the bundled app-server, WebView2, and any future ABI island
   remain unrestricted same-user processes unless an independent OS sandbox is
   implemented and tested.
7. Public CI and repository artifacts contain no proprietary package bytes, raw
   traces, secrets, tokens, or absolute user paths.
8. Exact preload execution uses captured digest-bound bytes, a closed private origin,
   bounded bridge values/messages, and serial navigations; no vendor renderer asset or
   real IPC endpoint is loaded.

## Nonclaims

This decision does not establish:

- that the packaged main entry selects the sole statically discovered candidate as its
  configured Electron preload;
- complete Electron `contextBridge`, `ipcRenderer`, Node preload, subframe, callback,
  event, promise, error, typed-array, synchronous-return, or remote-object fidelity;
- real IPC behavior or correctness of any vendor-exposed function;
- a transparent app-server proxy or any post-initialization Codex method;
- packaged main-process or renderer execution through Weregopher;
- Chat, Work, or Codex workflow compatibility;
- production state compatibility, migration, authentication, helper ownership,
  sandbox/WSL behavior, update tolerance, or certification;
- a security sandbox, improved security posture, reduced resource use, or permission
  to launch an installed application.

## Consequences

- G2 now has canonical, generated-schema-backed evidence contracts and an explicit
  exact-candidate command instead of an informal manual checklist.
- Public CI can validate the portable protocol and native mechanism without
  distributing proprietary package data.
- A user-controlled disposable Windows test account/VM can produce exact package,
  preload, and app-server evidence without copying production state into the test
  account.
- G2 remains operationally `incomplete` until one final serial disposable-Windows run
  produces passing exact evidence for all three lanes on the same build. A failure in
  any exact lane makes it `blocked`.
- G3 cannot begin on a pinned build merely because static inventory or the synthetic
  fixture passes; the complete G2 aggregate must first be feasible.

## References

- [Electron: contextBridge](https://www.electronjs.org/docs/latest/api/context-bridge/)
- [Electron: process sandboxing and preload behavior](https://www.electronjs.org/docs/latest/tutorial/sandbox)
- [OpenAI Developers: Codex app-server](https://developers.openai.com/codex/app-server)
- [G2 OpenAI feasibility testing](../testing/openai-g2-feasibility.md)
- [Runtime and renderer testing matrix](../testing/runtime-protocol-matrix.md)
