# ADR 0039: Authenticated G1 runtime control protocol

- Status: Accepted
- Date: 2026-07-26
- Extends: [ADR 0002](0002-initial-release-profile.md) and
  [ADR 0017](0017-atomic-windows-job-owned-process-launch.md)

## Context

The initial release profile requires a standalone worker/shell protocol fixture before
the packaged renderer fixture. The domain crate already defined a 28-byte frame header,
protocol limits, authoritative call context, generation-protected handles, and the
closed `WireValue` graph. It did not define connection messages, select a wire codec,
authenticate a Windows transport peer, or execute a cross-process control scenario.

The architecture specification locks the semantic protocol but intentionally leaves
MessagePack as an implementation choice. Selecting a codec without a structural
preflight would let declared collection sizes, deep nesting, extension types, or
trailing values reach generic deserialization before Weregopher applied its own
limits. Using a named pipe with its default security descriptor would also be
incorrect: pipe defaults are broader than the exact current-user boundary required by
the runtime protocol.

Transport authentication is not effect authorization or process containment. A
same-user worker remains an unrestricted same-user process, a Job Object remains a
lifecycle/accounting control, and decoded caller data remains untrusted until the host
validates authoritative call context and capability grants.

## Decision

Implement protocol generation 1, minor 0 as a bounded control slice in a new portable
`weregopher-runtime-protocol` crate plus a narrow Windows named-pipe primitive.

### Canonical contracts and frame codec

The Rust domain types remain authoritative. Add closed, validated contracts for:

- version range, backend identity, feature negotiation, hello, welcome, and reject;
- asynchronous call, result, error, cancellation, and ordered event;
- stream open, credit window, ordered stream data, and graceful shutdown; and
- bounded wire-value graph validation without recursive Rust calls.

Register each new top-level serialized contract with the schema generator. Generated
JSON Schemas are outputs and are never edited manually.

Closed-field handling applies recursively to protocol metadata, call context, handles,
and tagged wire-value variants. Only fields whose semantics explicitly carry
application data, such as `WireValue::Object` entries and `WireError::data`, admit
application-selected keys.

Every frame retains the existing exact 28-byte little-endian header:

```text
payload bytes | major | minor | kind | flags | reserved | request ID | sequence
    u32          u16     u16     u8      u8       u16        u64         u64
```

Flags and reserved bits are zero in generation 1. Sequence numbers start at one and
must increase by exactly one independently in each direction. A typed receive accepts
only its registered message kind.

Payloads use named-field MessagePack maps through exact dependency
`rmp-serde = 1.3.1`. Before typed deserialization, an iterative preflight:

- applies the frame-byte ceiling before payload allocation or reads;
- requires exactly one complete root value with no trailing bytes;
- limits structural nodes, depth, UTF-8 string bytes, and inline binary bytes;
- validates string UTF-8; and
- rejects the reserved `0xc1` marker and every extension marker because generation 1
  has no extension namespace.

Semantic byte-vector fields use MessagePack binary values, so byte length is governed
by the inline-byte ceiling rather than consuming one graph node per byte. Fixed-size
identity and digest arrays retain their fixed-width contract representation.

Outgoing encoding uses a bounded writer so serialization cannot grow beyond the
negotiated frame ceiling. Typed messages are revalidated against negotiated limits
after decode.

### Authenticated handshake

The host creates a nonzero random 256-bit nonce outside the named-pipe transport. The
worker presents:

```text
SHA-256(
  "weregopher.runtime-protocol.nonce-proof.v1\0" ||
  nonce ||
  runtime UUID ||
  app UUID ||
  length-prefixed backend ID ||
  length-prefixed backend version ||
  peer PID as little-endian u32
)
```

The host-side verifier is consumed by negotiation so one verifier cannot accept two
hellos. It requires exact agreement on the transport-observed PID, runtime, app, and
backend identity before negotiating the highest common protocol version, the
intersection of features, and the lower value of every limit.

The synthetic G1 fixture advertises asynchronous calls, idempotent cancellation,
ordered events, and credit-controlled streams. It explicitly advertises neither the
synchronous lane nor shared buffers. Those features require additional transport and
deadlock/handle-authentication work and must not be inferred from this slice.

### Windows named-pipe boundary

Each server generates a local name with a random version-4 UUID and requests the first
and only instance. The address is a rendezvous coordinate, not a secret.

The server constructs an explicit protected DACL containing one full-control ACE for
the current process token's user SID. It also enables
`PIPE_REJECT_REMOTE_CLIENTS`. Before exposing a connected stream, it requires:

1. the kernel-reported pipe client PID equals the expected launched child PID;
2. the connected process token user SID equals the host process token user SID;
3. the expected child process handle belongs to the required Job Object; and
4. a fresh query handle for the kernel-reported client PID belongs to that same Job.

Only after those checks may the protocol layer decode and authenticate `RuntimeHello`.
Unknown bytes or transport identity are never authority to perform host effects.

The fixture receives its nonce through an inherited anonymous standard-input handle,
not through arguments, environment, or the named pipe. It blocks on that handle, and
the controller delivers the nonce only after assigning the child to the Job.

This `std::process::Command` spawn-then-assign path is test orchestration, not a
production-launch claim. Before a production runtime worker can use this protocol,
the atomic suspended launch from ADR 0017 must be extended with an explicit inherited
nonce handle list while preserving pre-resume Job membership.

### Bounded session state

Pending requests have a configured maximum, monotonic nonzero IDs, nonzero relative
deadlines, idempotent cancellation, deterministic expiry, and explicit late-result
discard. Stream state requires exact one-based data sequences and receiver-granted
byte credit; failed transitions do not consume sequence or credit, and grants fail on
zero or overflow.

Call validation preserves empty JavaScript strings and property keys while keeping
protocol identifiers nonempty. It requires canonical compatible regular-expression
flags, consistent renderer/frame/world identities, and application ownership for
object targets and nested remote handles.

## Security invariants

1. Declared frame size is rejected before payload allocation or reads.
2. Malformed headers, wrong versions or kinds, replayed/gapped sequences, unsupported
   MessagePack markers, and trailing payload bytes fail closed.
3. A pipe connection is not accepted on address knowledge alone.
4. PID, user SID, Job membership, and nonce possession are independent checks.
5. A Job Object controls lifecycle/accounting and is not described as a sandbox.
6. The handshake establishes peer/session identity; it grants no application
   capability, privileged effect, state migration, or security exception.
7. Cancellation cannot resurrect a request, and a late completion is discarded.
8. Stream data cannot exceed receiver-granted credit.
9. Runtime calls reject cross-application object targets and nested remote handles.
10. Shared buffers, raw OS-handle transfer, synchronous calls, UI integration, and
   production worker launch are not claimed by this decision.

## Consequences

- The portable codec/session suite runs on Linux and Windows.
- A native Windows cross-process fixture exercises authenticated handshake, call,
  cancellation with late result, event, two stream-credit windows, and graceful
  shutdown over the protected pipe.
- A separate native negative fixture rejects a connected expected process that is not
  in the required Job.
- WSL can drive these tests only by invoking native Windows `cargo.exe`; Linux Cargo
  under WSL does not execute Windows APIs.
- The standalone worker/shell protocol half of G1 is present. The packaged renderer
  fixture is still required to complete G1.
- The remaining WP-D work includes a production atomic nonce-handle launch path,
  synchronous lane and deadlock fixture, authenticated shared buffers/handle
  lifecycle, production session binding for non-call handle-bearing messages, broader
  forged-client cases, large-data stress, and protocol fuzzing.

## References

- [Microsoft: Named Pipe Security and Access Rights](https://learn.microsoft.com/windows/win32/ipc/named-pipe-security-and-access-rights)
- [Microsoft: CreateNamedPipe](https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-createnamedpipew)
- [Microsoft: GetNamedPipeClientProcessId](https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid)
- [rmp-serde 1.3.1](https://docs.rs/rmp-serde/1.3.1/rmp_serde/)
