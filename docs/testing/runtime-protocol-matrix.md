# Runtime protocol testing matrix

This matrix separates portable correctness from evidence that requires the native
Windows kernel. Running Linux Cargo inside WSL is useful, but it does not test Windows
named pipes, access tokens, process identity, or Job Objects.

## Validation lanes

| Lane | When | What it proves | What it does not prove |
| --- | --- | --- | --- |
| Ubuntu CI | Every push and pull request | Domain contracts, MessagePack preflight/framing, handshake/session state, schemas, and platform-neutral regressions | Any Windows API behavior |
| `windows-latest` CI | Every push and pull request | Clean native Windows build; DACL-backed pipe; PID, SID, and Job checks; native worker/controller round trip | Windows 10/11 client-specific behavior, interactive desktop/UI behavior, or cross-user policy |
| WSL to native Windows | Optional final developer preflight on a suitably resourced host | The developer's current Windows kernel executes the focused PE test binaries while the source remains in WSL | A second clean machine or supported-client-OS matrix |
| Windows 10 x64 standard user | Milestone/release candidate | Supported Windows 10 client behavior without elevation | Windows 11 and ARM64 |
| Windows 11 x64 standard user | Milestone/release candidate | Supported Windows 11 client behavior without elevation | Windows 10 and ARM64 |
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

This lane executes `framing.rs` and `session.rs`. It covers frame ceilings before
payload reads, exact versions/kinds/sequences, malformed MessagePack, nonce/identity
binding, request bounds/deadlines/cancellation, late-result discard, and stream
credit. Windows-only test binaries are compiled as empty targets on Linux and provide
no native Windows evidence there.

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

For the second-local-user check, run the server fixture as a standard user and attempt
to open the printed non-secret pipe address from a second signed-in local account.
The open must fail with access denied. Do not weaken the DACL or run both processes
under the same elevated token to make this check convenient.

## Tester evidence

Record only:

- Windows edition, release, build, and architecture;
- whether the shell/token was standard or elevated;
- `rustc -vV`;
- commit SHA;
- exact test command; and
- pass/fail plus the failing test name and sanitized error category.

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
| ADR 0002 G1 packaged renderer fixture | No packaged WebView2/renderer scenario yet | Next G1 milestone |

The next product milestone is the packaged renderer fixture. Protocol hardening can
continue in parallel, but completing G1 still requires renderer bootstrap, bridge use,
deterministic shutdown, and the same explicit separation between compatibility,
security posture, and efficiency evidence.
