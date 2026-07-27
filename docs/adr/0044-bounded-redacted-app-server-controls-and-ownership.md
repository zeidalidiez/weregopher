# ADR 0044: Bounded redacted app-server controls and ownership labels

- Status: Accepted
- Date: 2026-07-27
- Extends: [ADR 0042](0042-bounded-transparent-app-server-proxy-core.md) and
  [ADR 0043](0043-bounded-portable-app-server-process-session.md)

## Context

ADR 0042 preserves and correlates exact app-server bytes under fixed bounds. ADR
0043 connects that core to an already-launched portable child and owns initialization,
standard I/O, deadlines, exit, and shutdown. The next build-agnostic boundary needs to
observe message lifecycle, deny explicitly selected traffic, and correlate later
helper/resource evidence without:

- retaining raw payloads in diagnostics;
- executing arbitrary observer callbacks on the transport path;
- admitting a frame before a deny decision;
- transforming unknown protocol data;
- treating thread, turn, item, or helper labels as effect authority; or
- claiming exact-version semantics before the exact G2 gate selects a pinned build.

The existing one-step proxy ingestion API validates and admits a frame atomically.
That is correct for transparent forwarding but leaves no pre-admission point for an
authority-reducing rule. Applying a rule after ingestion would require rollback of
queue and correlation state. It could also let a blocked request affect deadlines or
identity history.

Observer pressure must not alter transport behavior. An unbounded history is not
acceptable, and invoking user callbacks from serialized process-session methods would
allow a slow, reentrant, or panicking observer to become a new transport authority.
Silently dropping observation data would make the history unsuitable for diagnosing
loss.

Thread, turn, item, helper, MCP, command, worktree, and browser attribution also need
a narrow claim. Generic transport metadata cannot prove where exact-version payload
fields live or what their lifecycle means. A portable registry can retain explicit
semantic evidence and produce cleanup candidates, but it cannot infer that evidence
from unknown JSON or own the resources it labels.

## Decision

Implement four connected in-process mechanisms in
`weregopher-adapter-openai`.

### Prepared exact frames

`TransparentAppServerProxy` gains a two-step path:

```text
prepare_client / prepare_server
→ AppServerProxyCandidate
→ admit
```

Preparation:

1. applies the existing line, recursive JSON, duplicate-key, method, request-identity,
   and structural-message bounds;
2. retains the original delimiter-free bytes and the existing bounded observation;
3. does not mutate a queue, correlation map, request history, deadline, clock, or
   diagnostic counter; and
4. returns a non-authorizing candidate with payload-redacted `Debug`.

Admission requires the same proxy limits that prepared the candidate and rechecks
current lifecycle, queue capacity, request correlation, request history, and
diagnostic arithmetic immediately before mutation. A candidate prepared while a
queue had space can therefore still fail atomically if another frame fills that queue
before admission.

The original `ingest_client` and `ingest_server` methods remain equivalent to prepare
followed immediately by admit. Preparation is not adapter authentication, semantic
validation, policy approval, or effect authority.

### Bounded pull event journal

`AppServerSessionEventJournal` records fixed-shape events for:

- successful proxy admission;
- release from a proxy queue toward its peer;
- an exact rule block before admission; and
- forwarded-request expiration.

Events contain only:

- a journal-local monotonic sequence;
- direction and structural message kind;
- exact delimiter-free byte length;
- a domain-separated SHA-256 method fingerprint and original method byte length;
- a journal-local monotonic request correlation token when the lifecycle is
  unambiguous; and
- a local block-rule identity for denied candidates.

Events do not retain payload bytes, parsed parameter/result/error values, raw method
names, or wire request identities. A method fingerprint is pseudonymous comparison
data, not secrecy, authorization, or evidence that a method is understood.

Request tokens are created only for accepted requests. Each token combines an opaque
in-process journal identity with a monotonic journal-local sequence, so equal sequence
numbers from different sessions do not compare equal. The same token labels that
request's forwarded event, the first completing response's accepted/forwarded events,
and expiration. Unmatched and late responses do not invent a correlation.
Private correlation state contains only active requests and completing responses
waiting to leave their proxy queue. Proxy closure clears that state without
discarding already-retained redacted events.

The journal initially retains 2,048 events and cannot retain more than 65,536. It
exposes a serialized FIFO pull method and runs no callback. When full, it evicts the
oldest fixed-shape event, increments an exact visible eviction counter, and admits the
new event. It never blocks, drops, transforms, or reorders a protocol frame. Any
consumer that needs complete audit evidence must require an eviction count of zero;
this in-memory journal is not itself a persisted audit trace.

### Authority-reducing interception

`AppServerInterceptionPolicy` accepts at most 256 unique exact rules with at most
64 KiB of aggregate method text. Each rule selects exactly:

- one direction;
- request or notification kind; and
- one bounded method name.

Evaluation has only two results:

```rust
enum AppServerInterceptionDecision {
    Forward,
    Block(AppServerInterceptRuleId),
}
```

Unknown methods and unmatched selectors forward unchanged. Responses cannot be rule
targets because they carry no method. Rules cannot validate payloads, transform
bytes, synthesize or replace responses, grant approvals, expand capabilities, or
perform privileged effects.

`AppServerProcessSession::attach_unverified_child_with_controls` composes a validated
policy and event limit with the existing process owner. The original attachment
method uses the initial event limit and an empty pass-through policy.

For both directions the session:

1. prepares and structurally validates the exact frame;
2. validates initialization ordering;
3. evaluates the exact block policy;
4. records a redacted block and begins terminal shutdown if denied; or
5. admits the exact candidate and records its accepted lifecycle.

A block is terminal and classified separately. The session neither forwards the
candidate nor invents a peer response. Initialization-order rejection now also occurs
against the prepared candidate before queue admission; this amends ADR 0043's
statement that such a valid-but-premature frame had already entered the proxy.

### Non-authorizing ownership labels

`CodexExecutionIdentity` retains optional thread, turn, and item strings. Present
identifiers are nonempty, contain no control text, and are at most 256 bytes. A turn
requires a thread; an item requires both a thread and turn. Application scope has no
identifiers. `Debug` exposes only identifier lengths.

`AppServerOwnershipRegistry` is used per app-server session. Its first request
binding pins the originating in-process journal identity; tokens from every other
journal then fail closed even when their numeric sequences match. It initially and
maximally bounds both semantic request bindings and resource labels:

| Dimension | Initial | Hard maximum |
| --- | ---: | ---: |
| Request-token bindings | 4,096 | 65,536 |
| Resource labels | 4,096 | 65,536 |

A schema-aware adapter may explicitly bind one journal-local request token to one
structurally valid execution identity. Bindings cannot be replaced. A helper, MCP
process, command process, worktree, browser session, or remote MCP connection can then
inherit that identity from the token or be registered with independently derived
semantic evidence.

Resource identities are nonzero caller-local labels. They are not operating-system
PIDs or handles. The registry stores no process, filesystem, browser, or network
capability and performs no cleanup action.

Completing an item releases exact-item labels. Completing a turn also releases
descendant item labels. Completing a thread also releases descendant turn/item
labels. Application-scoped labels require explicit session close. Returned labels
are ordered cleanup candidates, not permission to terminate or mutate a resource.
The actual owner must independently retain and validate the relevant capability.

The registry deliberately does not parse protocol payloads. Unknown transport data
cannot create an execution identity or ownership binding. Exact schema-derived
method/field interpretation remains a family-adapter responsibility after the G2
gate.

### Validation boundary

Portable deterministic tests cover:

- preparation without queue/correlation/diagnostic mutation;
- exact candidate-byte preservation and payload-redacted `Debug`;
- dynamic queue revalidation at admission;
- request lifecycle correlation across accepted, forwarded, response, and expiration
  events;
- event FIFO order, explicit bounded eviction, and raw payload/method/wire-ID
  redaction;
- exact policy forward/block decisions and process-session block-before-admission;
- unchanged exact bytes under event pressure;
- execution-identity hierarchy and debug redaction;
- bounded correlation/resource registration, duplicate/rebinding rejection, and
  unknown/foreign-journal token rejection;
- turn/thread/session scope release behavior; and
- the complete pre-existing proxy and real-standard-I/O process-session suites.

No canonical serialized domain contract changes. Candidate, event, policy, and
ownership types are in-process Rust mechanisms, so generated schemas remain
unchanged.

## Security invariants

1. Candidate preparation never mutates live proxy state or grants admission.
2. Admission revalidates every dynamic queue and correlation condition.
3. A block rule can only reduce traffic; it cannot transform, replace, approve, or
   perform an effect.
4. Unknown valid methods continue to pass through unless trusted local configuration
   names the exact method, direction, and structural kind.
5. Blocked frames do not enter a proxy queue, create request correlations, start
   deadlines, or reach a peer.
6. No arbitrary observer callback runs on the process-session transport path.
7. Event pressure is bounded and loss is explicit; it never drops a protocol frame.
8. Redacted events omit payloads, raw methods, and wire request identities.
9. Execution identities are explicit semantic inputs, not facts inferred from
   unknown transport data.
10. One ownership registry cannot mix request tokens from multiple session journals.
11. Ownership records are labels and cleanup candidates, not resource handles,
    sandbox evidence, authorization, or effect authority.
12. Process attachment remains unverified and the child remains unrestricted
    same-user code absent an independently proven sandbox.
13. Repository tests use only synthetic fixtures and do not consume package bytes,
    secrets, production state, or raw vendor traces.

## Nonclaims

This decision does not implement:

- exact generated-schema ingestion or method/field decoding for a pinned OpenAI
  build;
- automatic thread/turn/item derivation from app-server payloads;
- proof that a labeled helper, MCP server, command, worktree, or browser resource is
  the actual operating-system object;
- process-tree ownership, Job adaptation, resource accounting, cleanup execution, or
  sandboxing;
- `Validate`, `Transform`, or `Replace` interceptor modes, WebAssembly transforms, or
  synthesized responses;
- approval parsing, decision rendering, cancellation/automatic-resolution semantics,
  or response mediation;
- durable or canonical persisted traces, trace encryption, or complete audit
  evidence;
- exact bundled app-server resolution, authorized launch, disposable state,
  restart/recovery, WebSocket transport, or authenticated packaged-client transport;
- packaged main/renderer integration or a Codex workflow; or
- completion of G2, selection of a G3 build, application compatibility,
  certification, security posture, or efficiency evidence.

## Consequences

- A later exact schema adapter has one rollback-free point at which to inspect a
  structurally valid candidate and can rely on unchanged bytes if it forwards.
- Read-only consumers can pull bounded redacted lifecycle evidence without becoming
  transport callbacks. Complete-audit users must fail closed on any reported
  eviction.
- Trusted local policy can deny a known request or notification before it affects
  peer or proxy state, but cannot accidentally grant new authority.
- Schema-aware code can attach validated execution identities to helper/resource
  labels without mixing operating-system handles into the portable adapter crate.
- The next semantic milestone is blocked on exact G2 evidence and a pinned generated
  schema: generic code cannot safely infer thread/turn/item fields or reproduce
  approval decisions from unknown payloads.

## References

- [ADR 0042: Bounded transparent app-server proxy core](0042-bounded-transparent-app-server-proxy-core.md)
- [ADR 0043: Bounded portable app-server process session](0043-bounded-portable-app-server-process-session.md)
- [Architecture specification: app-server boundary](../spec/weregopher-electron-transformation-runtime-spec.md#369-app-server-boundary)
- [Runtime and renderer testing matrix](../testing/runtime-protocol-matrix.md)
