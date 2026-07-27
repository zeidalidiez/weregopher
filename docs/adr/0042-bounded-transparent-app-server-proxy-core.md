# ADR 0042: Bounded transparent app-server proxy core

- Status: Accepted
- Date: 2026-07-27
- Extends: [ADR 0002](0002-initial-release-profile.md) and
  [ADR 0041](0041-bounded-g2-openai-target-feasibility-evidence.md)

## Context

The G2 harness can discover and initialize the exact bundled Codex app-server, but it
deliberately stops after schema generation and the `initialize`/`initialized`
exchange. G3 requires a long-lived transparent proxy between preserved packaged logic
and that server. The proxy must tolerate additive protocol evolution without turning
unknown methods, fields, or result variants into compatibility failures.

Transparency does not mean unbounded pass-through. Newline-delimited JSON is a trust
boundary: a peer can send oversized input, deep structures, duplicate keys,
ambiguous request shapes, colliding request identities, or more data than the other
side can consume. Unknown content is not authority, and exact forwarding must not
silently drop a request, response, or notification.

G3 still cannot select a pinned OpenAI build until the final exact G2 matrix passes.
However, the platform-neutral forwarding and correlation mechanism is independent of
that build and can be validated against repository-only inputs without launching
vendor code, touching Windows, or using production state.

## Decision

Implement `TransparentAppServerProxy` in `weregopher-adapter-openai` as a
platform-neutral, single-owner in-memory session core.

### Exact-byte JSONL boundary

The caller supplies one delimiter-free line at a time. Before retaining it, the proxy:

1. rejects empty input, embedded carriage returns/newlines, and a line above the
   configured byte ceiling;
2. parses exactly one top-level JSON object;
3. applies recursive depth and value-node ceilings;
4. rejects duplicate keys at every object depth;
5. classifies the object as a request, notification, success response, or error
   response; and
6. validates only the method and request identity that the proxy actively interprets.

Valid original bytes are stored and returned unchanged. The proxy does not
re-serialize a message, so unknown fields, result variants, key order, whitespace,
and numeric spelling remain intact. The parsed value tree is discarded after bounded
metadata classification.

Initial and hard ceilings are:

| Dimension | Initial | Hard maximum |
| --- | ---: | ---: |
| One JSON line | 1 MiB | 16 MiB |
| JSON depth | 64 | 128 |
| JSON value nodes | 65,536 | 1,048,576 |
| Method bytes | 1,024 | 1,024 |
| Text request-identity bytes | 256 | 256 |

Methods must be nonempty bounded strings without control characters. Request
identities may be bounded strings or signed/unsigned integers; fractional, null
request, object, array, boolean, and oversized identities fail closed. A null
identity is tolerated only on an otherwise valid uncorrelated response.

### Bidirectional bounded queues

Client-to-server and server-to-client queues have independent message and aggregate
byte limits. Each initially permits 256 messages and 8 MiB, with hard maxima of 4,096
messages and 64 MiB.

Queue admission is atomic. When either dimension is full, the input is rejected
without changing request state or counters. The core never silently drops or
coalesces notifications, and it never prioritizes a response past an earlier queued
message. An outer transport owner must stop reading or terminate the session when
backpressure prevents admission.

The returned frame excludes the newline delimiter. The transport owner appends
exactly one newline when writing it to the peer.

### Correlation and deadlines

Requests can originate from either side, so client and server request identities have
independent namespaces. A response is matched only against a request originating in
the opposite direction.

The proxy distinguishes:

- queued requests, which have not reached the peer;
- pending requests, whose frame was released;
- completed or expired request identities retained in bounded history;
- late responses matching that history; and
- unmatched responses with no known identity.

A response to a still-queued request is impossible relative to the proxy's observed
ordering and fails closed. An unknown response remains forwardable and increments an
explicit unmatched counter.

The initial active-request maximum is 1,024, with a hard maximum of 4,096. A request
deadline starts only when the request leaves its queue, so time spent behind
backpressure does not consume its peer-response interval. The initial timeout is five
minutes and the hard maximum is 24 hours. Caller-supplied `Instant` values are
monotonic session state; a value earlier than one already observed fails before a
queue or deadline transition. Expiration returns the exact in-memory identity to the
session owner so it can perform an explicit timeout action; a later wire response is
still forwarded but classified as late.

Wire identity reuse in one direction is prohibited for the session. Without this
rule, a duplicate late response could incorrectly complete a newer logical request
using the same wire identity. Completed and expired identities are retained only as
domain-separated SHA-256 digests. The initial total request-history ceiling is
65,536, with a hard maximum of 1,048,576. When history is full, the owner must close
and replace the session rather than discard correlation evidence.

The same wire identity may exist simultaneously in the opposite direction because
the two protocol namespaces are independent. Request identities and method names are
observation metadata, never execution authority.

### Lifecycle and diagnostics

The initial lifecycle is deliberately small:

```text
Open → Closed
```

`close` is idempotent, clears both queues, all live request values, and digest-only
history, and returns counts for abandoned messages, bytes, and live requests plus
cleared history. A closed proxy rejects new input and returns no frames.

Diagnostics contain only:

- accepted message/byte counts by origin;
- forwarded message counts by destination;
- current and peak queue message/byte counts;
- pending request counts by origin;
- digest-history counts by origin; and
- expired, late, and unmatched response counts.

They contain no payloads, method names, request identities, source paths, errors,
tokens, or protocol values. `Debug` implementations similarly redact frames and all
request identities. Any outer trace implementation remains responsible for its own
explicit redaction policy.

### Validation boundary

Portable behavior tests cover:

- exact byte and FIFO preservation for unknown messages;
- independent bidirectional request namespaces;
- response completion and response-before-forwarding rejection;
- queue message/byte and line ceilings with atomic rejection;
- recursive duplicate-key, depth, node, framing, and message-shape failures;
- deadline activation only on forwarding;
- rejection of a backward-moving monotonic clock;
- expiration, late response, unmatched response, and request-history behavior;
- active/history exhaustion and request-identity reuse;
- bounded multi-message accounting; and
- closure plus debug redaction.

The proxy adds no canonical serialized contract, so no generated schema changes. Its
public Rust API is an in-process mechanism that later runtime and adapter layers can
compose.

## Security invariants

1. Valid unknown protocol content is forwarded exactly but grants no capability,
   launch permission, filesystem authority, approval decision, or privileged effect.
2. Input is bounded before retention and recursively checked before the proxy
   interprets method or identity fields.
3. Duplicate object keys, line smuggling, ambiguous response shapes, fractional
   identities, request-ID reuse, impossible response ordering, and resource
   exhaustion fail explicitly.
4. Requests and responses are never silently dropped. Backpressure and expiry require
   an outer owner to take an explicit action.
5. Bidirectional request namespaces remain separate, and completed/expired identities
   cannot be confused with a later request in the same session.
6. A backward-moving caller clock cannot extend or reorder request deadlines.
7. Diagnostics and `Debug` output retain no raw message, method, or request identity.
8. No vendor package, executable, production state, secret, token, or raw trace is
   required by public tests or retained in repository artifacts.

## Nonclaims

This decision does not implement:

- process launch, standard-I/O/WebSocket transport ownership, pipe authentication, or
  a durable supervisor;
- connection of the proxy to the exact bundled app-server;
- initialization-phase enforcement for a long-lived session;
- observer or interceptor registration, transformations, replacement responses, or
  method-specific semantic validation;
- thread/turn/item ownership inference, approval mediation, helper/MCP lifecycle
  attribution, crash/restart recovery, or graceful app-server shutdown;
- payload trace redaction for a caller that chooses to persist returned frames;
- packaged main logic, renderer IPC, Codex thread/turn workflows, or application
  compatibility; or
- completion of G2, selection of a pinned G3 build, certification, security posture,
  or efficiency evidence.

Those layers require passing exact G2 evidence and separate bounded implementation
milestones.

## Consequences

- The forward-compatible app-server transport core can be tested on Linux and Windows
  without a vendor package or native process.
- Later process integration can concentrate on authenticated/supervised lifetime,
  nonblocking I/O, shutdown, and exact-build binding instead of reimplementing
  framing, backpressure, and correlation.
- Session-local request history intentionally trades bounded memory and eventual
  session rotation for unambiguous late-response handling.
- G2 remains operationally incomplete until the final exact Windows 10/11 matrix
  passes; this build-agnostic prerequisite does not bypass that gate.

## References

- [ADR 0041: Bounded G2 OpenAI target-feasibility evidence](0041-bounded-g2-openai-target-feasibility-evidence.md)
- [Architecture specification: transparent app-server proxy](../spec/weregopher-electron-transformation-runtime-spec.md#3611-transparent-app-server-proxy)
- [Runtime and renderer testing matrix](../testing/runtime-protocol-matrix.md)
