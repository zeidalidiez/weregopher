# ADR 0040: Immutable G1 WebView2 renderer fixture

- Status: Accepted
- Date: 2026-07-26
- Extends: [ADR 0002](0002-initial-release-profile.md) and
  [ADR 0039](0039-authenticated-g1-runtime-control-protocol.md)

## Context

G1 requires a packaged renderer fixture and deterministic shutdown in addition to the
standalone authenticated worker/shell protocol. The fixture must exercise the package
and renderer boundaries without becoming a public-web wrapper, reading a vendor
package, touching production state, or implying that a synthetic bridge establishes
preload or Electron compatibility.

WebView2 can intercept every resource request and replace it with an application
response. It also exposes a JSON web-message transport. Both are useful for the
fixture, but neither is authority by itself. A page can request arbitrary URLs and
send arbitrary messages. The host must therefore keep package selection, application
identity, renderer/frame/world identity, origin, target service, deadlines, and
capabilities outside page control.

WebView2 uses COM and Win32 APIs that require an explicit unsafe interoperability
boundary. Linux Cargo under WSL cannot compile or execute that boundary as native
Windows evidence, and this project must not drive a resource-constrained Windows host
in parallel with its WSL build.

## Decision

Complete G1 with a portable `weregopher-renderer` crate and a Windows-only
`weregopher-renderer-webview2` fixture crate.

### Immutable package origin

The portable origin binds one application launch to:

```text
https://app-<opaque application UUID>.weregopher.invalid/
```

The synthetic package is a closed, immutable map of canonical relative paths to
bounded `Arc<[u8]>` assets. Construction rejects empty packages, duplicate or
ambiguous paths, traversal, control characters, over-count packages, oversized
assets, and aggregate-byte overflow. Assets receive explicit MIME types and SHA-256
ETags.

Only exact-origin `GET` and `HEAD` requests are accepted. URL and decoded-path bytes
are bounded before retention. Invalid escaping, encoded separators, fragments,
userinfo, ports, alternate schemes/hosts, traversal, and backslashes fail closed.
Missing canonical assets return a deterministic 404.

The Windows fixture registers a wildcard `WebResourceRequested` filter. Every
successful response comes from the immutable map through an in-memory COM stream;
every malformed or out-of-origin request receives a fixed denial response. There is
no filesystem or network fallback.

### Fixture WebView2 environment

The fixture uses the installed Evergreen WebView2 runtime, a hidden ordinary windowed
controller, and a newly created exclusive ephemeral user-data folder. It disables
native host objects, developer tools, default context menus, browser extensions, and
OS-primary-account single sign-on. Script and WebView2 JSON messaging remain enabled
because they are the behavior under test.

The raw JSON messaging surface is treated as untrusted transport. This decision does
not use `AddHostObjectToScript`, expose a native pointer, or claim that WebView2 web
messaging is a security boundary. Backend-delivered source and JSON strings are
rejected above fixed byte ceilings before JSON deserialization; WebView2's own
allocation of callback strings remains inside the unrestricted same-user browser
process boundary rather than becoming a host-allocation claim.

### Renderer bridge authority

A document-start script captures a nonzero 128-bit per-navigation nonce in a closure
and exposes one frozen asynchronous fixture API. Its invocation contract contains only
the nonce, a nonzero page-local request ID, a bounded method, and bounded semantic
arguments. It cannot name an application, renderer, frame, world, origin, service,
deadline, user activation, or capability.

The host accepts a message only when:

1. the WebView2-reported source belongs to the active exact private origin;
2. the nonce matches the active navigation;
3. the request ID has not been accepted already; and
4. the accepted-request budget remains within negotiated protocol limits.

The host then derives the application, renderer, synthetic main frame/main world,
origin, navigation generation, fixed fixture service, empty capability authority, and
bounded deadline. It retains a validated `RendererEnvelope` as evidence and produces
a canonical `RuntimeCall`. Cross-application handles in the envelope fail closed.
Replies are closed contracts with exactly one non-null result or sanitized error.

The native integration test carries that call over ADR 0039's authenticated,
current-user named pipe to a Job-owned worker and returns the worker result to the
page. The page updates the DOM and reports a synthetic observation.

### Lifecycle and shutdown

The portable lifecycle accepts only:

```text
Creating → Initialized → Navigating → DOMContentLoaded → Loaded
                                                 ↓
                              any live state → Closing → Closed
```

Navigation generations are nonzero and monotonic. Stale or out-of-order events fail
closed. An abnormal exit has a separate `Crashed` state.

Shutdown removes fixture event handlers, closes and releases the controller and
webview, destroys the hidden window, waits for the exclusive WebView2 browser-process
exit event, releases the environment, removes the ephemeral user-data directory, and
only then records `Closed`. The authenticated worker receives a graceful runtime
shutdown and must exit successfully.

### Platform boundary and validation

The Windows fixture crate is the sole new unsafe exception. Each unsafe block
documents the COM/Win32 ownership or ABI invariant, and no platform handle escapes its
public API. The portable crate forbids unsafe code.

Portable origin, lifecycle, bridge, and schema tests run on Linux and Windows. The
native WebView2/runtime scenario runs on `windows-latest` CI and the final Windows
10/11 tester matrix. Native Windows validation is a separate final phase; it is not
run concurrently with WSL builds on a shared constrained host.

## Security invariants

1. Package bytes are immutable and manifest-scoped; the fixture never reads arbitrary
   host paths or reaches the public network.
2. Backend-observed source and host state, not page JSON, establish application,
   renderer, frame, world, origin, target, deadline, and capability context.
3. Nonce possession limits bridge use to the active document-start bootstrap but does
   not grant a privileged effect.
4. Unknown messages, origins, methods, fields, handles, lifecycle events, and reply
   shapes fail closed.
5. WebView2, the runtime worker, and the fixture page remain unrestricted same-user
   code. The hidden window, COM boundary, named pipe, and Job Object are not sandboxes.
6. No vendor installation or production state is read or modified.

## Nonclaims

This decision does not establish:

- a production shell, shared UDF/profile manager, renderer recovery manager, or fixed
  WebView2 distribution;
- a general ASAR/VFS origin, range requests, service-worker policy, media behavior, or
  arbitrary package compatibility;
- Electron preload compilation, `contextBridge`, isolated worlds, subframe authority,
  sync IPC, remote-function lifecycle, callbacks, events, shared buffers, or full
  `WireValue` page conversion;
- interactive windowing, input, IME, accessibility, GPU, media, authentication, or
  client-Windows parity;
- a WebView2 sandbox, improved security posture, reduced resource use, or vendor
  behavioral compatibility; or
- CEF support or a decision that WebView2 is suitable for any particular installed
  application build.

Those claims require G2 and later compatibility, security, efficiency, and
certification evidence.

## Consequences

- The synthetic G1 vertical slice now spans immutable package bytes, private renderer
  origin, document-start invocation, backend-derived authority, authenticated worker
  call/result, DOM observation, and deterministic renderer/worker shutdown.
- G1 is complete when the native hosted-Windows scenario and the existing repository
  gates pass.
- The next delivery gate is G2 target feasibility: installed OpenAI-family discovery,
  exact package identity, preload/`contextBridge` fidelity, and exact bundled
  app-server discovery/handshake.
- WP-D still requires production worker launch integration, sync/deadlock handling,
  authenticated shared buffers, non-call session binding, broader hostile transport
  tests, large-data stress, and fuzzing.

## References

- [Microsoft: Web resource requested event](https://learn.microsoft.com/microsoft-edge/webview2/reference/win32/icorewebview2webresourcerequestedeventargs)
- [Microsoft: Create a web resource response](https://learn.microsoft.com/microsoft-edge/webview2/reference/win32/icorewebview2environment#createwebresourceresponse)
- [Microsoft: WebView2 user data folders](https://learn.microsoft.com/microsoft-edge/webview2/concepts/user-data-folder)
- [webview2-com 0.39.1](https://docs.rs/webview2-com/0.39.1/webview2_com/)
