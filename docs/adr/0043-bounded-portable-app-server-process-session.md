# ADR 0043: Bounded portable app-server process session

- Status: Accepted
- Date: 2026-07-27
- Extends: [ADR 0002](0002-initial-release-profile.md) and
  [ADR 0042](0042-bounded-transparent-app-server-proxy-core.md)

## Context

ADR 0042 established exact-byte protocol validation, bounded FIFO queues,
bidirectional correlation, request deadlines, and payload-free diagnostics. It
deliberately left process lifetime, standard-I/O ownership, initialization continuity,
crash observation, and graceful shutdown to an outer owner.

Those mechanisms can be validated before selecting a pinned OpenAI build. A
repository-only child can exercise the same portable Rust standard-I/O and process
APIs on Linux and Windows without acquiring proprietary package bytes or running an
exact installed application.

The boundary must not imply more than it proves. A portable `std::process::Child` is
not executable authorization, exact package identity, a Windows Job-owned process
tree, disposable state, or an OS sandbox. Primary-process termination also does not
prove descendant ownership. The exact G2 matrix remains the gate for selecting a G3
candidate.

## Decision

Implement `AppServerProcessSession` in `weregopher-adapter-openai` as a single-owner
portable process/session layer around `TransparentAppServerProxy`.

### Attachment boundary

`attach_unverified_child` consumes an already-launched `std::process::Child`. All
three standard streams must be piped. The method takes ownership of them and
terminates the primary process if stream acquisition or worker creation fails.

The method name is intentionally explicit:

- it does not resolve or launch an executable;
- it does not verify a package, file identity, digest, signer, version, or schema;
- it does not create or prove Windows Job membership;
- it does not construct a disposable state namespace or explicit child environment;
  and
- it does not authenticate the client that invokes the Rust API.

A future exact-build integration must supply those controls before adapting its
process owner to this session mechanism.

### Bounded nonblocking workers

Four dedicated workers separate blocking operating-system operations from the
single-owner poll surface:

1. a stdin worker writes one exact proxy frame plus one line-feed and flushes it;
2. a stdout worker incrementally assembles delimiter-free lines and rejects a line
   above the proxy ceiling before admitting it to the proxy;
3. a stderr worker discards content while retaining only a saturating byte count; and
4. a process worker observes, terminates, waits for, and reaps the primary child.

`poll` uses only nonblocking channel operations, monotonic bookkeeping, and joins of
workers already known to have finished. It never blocks on a pipe read, pipe write,
process wait, or live worker join.

Each stdin and stdout channel initially and maximally retains four frames. Combined
with the proxy's hard 16 MiB line ceiling, either worker channel can retain at most
64 MiB of frame data. The default proxy line ceiling keeps the initial bound at
4 MiB per channel. A caller cannot raise the channel count above four.

One poll consumes at most 64 events from each bounded worker source. The fixed hard
maximum is 1,024 events from each source. Channel pressure blocks only the owning
worker and therefore propagates pressure to the operating-system pipe instead of
allocating an unbounded intermediate queue.

Stderr bytes are never retained. Standard-I/O and process errors expose only a fixed
worker role and `io::ErrorKind`; they do not expose payloads, arguments, environment,
paths, or raw operating-system messages.

### Initialization continuity

The session enforces the documented sequence:

```text
AwaitingInitialize
→ InitializeQueued
→ AwaitingInitializeResponse
→ InitializeResponseQueued
→ AwaitingInitialized
→ InitializedQueued
→ Ready
```

Before readiness:

- the client may send exactly one request whose method is `initialize`;
- server notifications remain forward-compatible and pass through in FIFO order;
- the only server response accepted is the response matching that released
  initialize request;
- an error response fails initialization;
- a success response does not permit `initialized` merely because the stdout worker
  observed it—the response must first leave the client-facing proxy FIFO;
- the client may then send exactly one `initialized` notification; and
- no other client request, notification, or response is accepted.

The session becomes ready when the initialized notification is released to the
bounded stdin worker. Repeated `initialize` or `initialized` methods fail closed.
Method-specific result contents remain opaque; this layer validates sequencing and
correlation, not exact-version semantic fields.

An initialization-order violation is terminal. The transparent proxy already admitted
the structurally valid frame atomically, so the session closes rather than attempting
an unsafe rollback.

### Deadlines, exit, and shutdown

Initial and hard lifecycle limits are:

| Dimension | Initial | Hard maximum |
| --- | ---: | ---: |
| Initialization | 30 seconds | 5 minutes |
| Complete attached session | 24 hours | 24 hours |
| Graceful shutdown | 2 seconds | 30 seconds |
| Post-exit stdout/stderr drain | 2 seconds | 30 seconds |

The caller supplies monotonic `Instant` observations. A backward value fails before
poll, queue-release, deadline, or shutdown mutation.

Forwarded request expiry is a terminal session action. The proxy first records the
expired request in digest history, then the process session requests termination and
reports `RequestTimeout`. This owner does not invent a protocol response or silently
continue with ambiguous peer state.

Graceful shutdown:

1. stops accepting new client input;
2. releases already-admitted client frames in FIFO order;
3. waits for their bounded writer acknowledgements;
4. closes stdin; and
5. requests primary-process termination if the grace deadline expires.

Immediate shutdown requests termination without draining client input. Drop also
closes proxy state, disconnects stdin, and requests primary-process termination, but
never waits synchronously for a live worker.

After primary-process exit, the session continues consuming bounded stdout and stderr
workers until both reach EOF or the configured drain deadline expires. A clean process
exit with inherited or otherwise undrained pipe handles becomes `TransportFailure`;
the report sets `streams_drained = false` instead of hiding potential message loss.
Frames dispatched to stdin but lacking a write acknowledgement are separately
reported.

Terminal outcomes distinguish:

- clean caller-requested shutdown;
- forced shutdown;
- unexpected successful exit;
- crash/nonzero exit;
- initialization timeout;
- complete-session runtime timeout;
- protocol failure;
- transport failure; and
- forwarded-request timeout.

Exit reports retain only the portable exit code, initialization completion flag,
stdout/stderr byte counts, stream-drain status, unacknowledged writer-frame count, and
the payload-free proxy closure report.

### Validation boundary

Portable integration tests launch only a repository fixture and cover:

- exact unknown-field and exact-byte preservation through real stdin/stdout;
- the complete initialization sequence and response-delivery continuity;
- bidirectional request/response correlation after readiness;
- premature client traffic and initialize rejection;
- stdout oversize rejection before proxy retention;
- forwarded-request, initialization, and complete-runtime deadlines;
- backward owner-clock rejection and hard limit construction;
- nonzero crash containment and unexpected successful exit classification;
- graceful exit and forced termination of a hung primary process;
- bounded post-exit drain when a short-lived fixture descendant inherits output
  handles;
- missing piped streams and invalid limits; and
- payload, method, request-identity, and stderr-content redaction.

The fixture contains no vendor code, package bytes, tokens, production state, or
network behavior. The inherited-handle fixture descendant exits after two seconds and
exists only to make the drain deadline observable.

No canonical serialized domain contract changes. All process-session types are
in-process Rust mechanisms, so generated schemas remain unchanged.

## Security invariants

1. Attaching a child never grants launch authority or claims executable/package
   identity.
2. The attached child remains unrestricted same-user code unless its external owner
   independently proves a stronger sandbox.
3. Standard-output lines are bounded before proxy retention; worker channels and poll
   work are fixed-bounded.
4. Unknown valid protocol bytes remain opaque and confer no capability or privileged
   effect.
5. Initialization ordering, initialize-response identity, and client-facing response
   delivery are fail-closed.
6. Request, initialization, runtime, shutdown, and output-drain deadlines cannot be
   extended with a backward caller clock.
7. Primary-process exit, crash, undrained handles, and unacknowledged writes remain
   distinct observable facts.
8. Stderr and protocol payloads are never retained in diagnostics, errors, exit
   reports, or `Debug`.
9. Primary-process termination is not represented as descendant-tree ownership,
   sandboxing, or crash recovery.
10. Repository fixtures never consume exact package bytes or production OpenAI state.

## Nonclaims

This decision does not implement:

- exact bundled app-server resolution, identity revalidation, launch authorization,
  schema binding, or connection to the G2 exact-binary runner;
- Windows Job adaptation, descendant-tree termination, resource accounting, or an OS
  sandbox;
- a durable supervisor service, authenticated transport, WebSocket ownership,
  restart/recovery, or session persistence;
- semantic validation of exact-version initialize results or post-initialization
  methods;
- observers, interceptors, transformations, replacement responses, or persisted
  traces;
- thread/turn/item ownership, approval mediation, helper/MCP attribution, or
  privileged-effect authorization;
- packaged main logic, renderer IPC, Codex workflows, or application compatibility;
  or
- completion of G2, selection of a G3 build, certification, security posture, or
  efficiency evidence.

## Consequences

- The proxy now has a real portable process/session composition tested on both hosted
  operating systems without vendor code.
- Exact-build work can later focus on adapting an authorized Job-owned process and
  disposable state rather than reimplementing JSONL, backpressure, initialization,
  or terminal accounting.
- The four-worker design spends a small fixed thread budget to keep the caller-facing
  owner nonblocking without adding an async runtime.
- A process tree that outlives the primary can retain inherited pipes. This mechanism
  drops queued receiver frames, bounds and reports the condition, and cannot
  synchronously cancel a portable blocking read. One stdout worker can therefore
  retain at most one bounded partial line until the last inherited handle closes.
  Terminating that tree requires a stronger external owner.
- G2 remains operationally incomplete until the serial exact Windows 10/11 matrix
  passes for one pinned build.

## References

- [ADR 0042: Bounded transparent app-server proxy core](0042-bounded-transparent-app-server-proxy-core.md)
- [Architecture specification: transparent app-server proxy](../spec/weregopher-electron-transformation-runtime-spec.md#3611-transparent-app-server-proxy)
- [Runtime and renderer testing matrix](../testing/runtime-protocol-matrix.md)
