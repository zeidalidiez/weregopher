# ADR 0017: Atomic Windows Job-owned process launch

- Status: Accepted
- Date: 2026-07-21

## Context

ADR 0016 added bounded kill-on-close Job Object ownership, but its `assign_child` adoption path accepts an already-running process. That leaves a spawn-before-assignment interval in which executable code or descendants can run outside the new Job Object. A runtime launch boundary must establish ownership before the primary thread can execute.

The same boundary must avoid executable-path rebinding and ambient handle/environment inheritance. Those properties are distinct from executable authorization, dependency/DLL verification, package-view construction, sandboxing, and compatibility certification.

## Decision

`weregopher-windows` adds three safe Windows-only capabilities:

- `LockedExecutable` accepts only a bounded absolute disk or UNC path, opens every ancestor directly without following reparse points, and retains the regular-file handle plus ancestor handles. The executable is opened without write or delete sharing so its selected path cannot be rewritten or rebound while retained.
- `ProcessLaunchLimits` validates a nonzero argument-count limit, per-argument UTF-16 limit, and aggregate command-line limit. The aggregate includes the terminating NUL and cannot exceed the 32,767-code-unit `CreateProcessW` boundary.
- `OwnedJobProcess` owns the resumed primary process, the locked executable capability, and the sole kill-on-close Job Object capability. It supports bounded waits, membership queries, and explicit whole-tree termination without exposing raw handles.

`KillOnCloseJob::launch` consumes both the configured Job Object and locked executable. It:

1. validates and Windows-quotes all arguments before creating a process;
2. initializes `STARTUPINFOEXW` with `PROC_THREAD_ATTRIBUTE_JOB_LIST` containing the Job Object handle;
3. calls `CreateProcessW` with an exact `lpApplicationName`, `CREATE_SUSPENDED`, `EXTENDED_STARTUPINFO_PRESENT`, `CREATE_UNICODE_ENVIRONMENT`, and `CREATE_NO_WINDOW`;
4. supplies an explicit empty double-NUL Unicode environment block;
5. disables handle inheritance and supplies no standard-I/O handles;
6. uses the retained executable parent as the child working directory;
7. verifies Job Object membership while the primary thread remains suspended;
8. resumes only when the initial suspension count is exactly one; and
9. directly terminates the process and terminates/closes the job on every post-creation failure.

The Job List process attribute associates the new process during `CreateProcessW`, before the primary thread is permitted to run. `CREATE_SUSPENDED` then gives the wrapper a fail-closed membership-verification point before resume. This is stronger than spawning normally and later calling `AssignProcessToJobObject`.

All raw pointers and handles remain private inside `weregopher-windows`. Attribute-list storage is aligned and retained through process creation, each returned handle is adopted exactly once, and errors are captured before cleanup APIs can overwrite thread-local Windows error state.

## Argument model

The command line always includes the exact locked executable path as `argv[0]`. Arguments are encoded as Windows UTF-16 and quoted using the Microsoft C-runtime backslash/quote convention, including empty arguments, embedded quotes, and trailing backslashes. Interior NUL values, excessive cardinality, oversized values, checked-length overflow, and aggregate overflow fail before `CreateProcessW`.

This convention provides deterministic conventional `argv` behavior. It does not claim that every executable uses the C-runtime parser; applications that interpret `GetCommandLineW` directly remain adapter-specific.

## Authority boundary and non-claims

`LockedExecutable` proves path stability and direct regular-file shape only. It does **not** establish:

- an allowed executable identity, content digest, signer, architecture, or adapter decision;
- a complete immutable package or DLL dependency view;
- mitigation policy, token restriction, AppContainer, filesystem/network isolation, or sandboxing;
- compatibility with an empty environment, absent inherited handles, no console, or the selected working directory;
- authenticated IPC, output bounds, graceful shutdown, state migration, or runtime certification.

The launch API is therefore a low-level lifecycle primitive. An authority-bearing execution layer must first bind an approved executable and complete package/artifact view, then select explicit environment, standard-I/O, handle, dependency, mitigation, and compatibility policies. The empty-environment/no-inheritance baseline intentionally fails closed rather than inheriting ambient supervisor authority.

Keeping an executable file and its ancestor paths stable does not freeze DLLs or other files opened later by the child. No caller may treat this milestone as complete package-view immutability.

## Alternatives rejected

- `std::process::Command` followed by `assign_child` leaves executable code running before ownership.
- Calling `CreateProcessW(CREATE_SUSPENDED)` and then `AssignProcessToJobObject` can still fail because of job compatibility after a process object exists; the Job List attribute makes association part of creation.
- Passing a path without retained handles permits pathname rebinding between authorization and launch.
- Inheriting the supervisor environment or every inheritable handle silently expands ambient authority.
- Exposing raw process, thread, Job Object, or attribute-list handles spreads unsafe lifetime reasoning into higher layers.
- Treating Job Object membership as sandboxing overstates a lifecycle/accounting mechanism.

## Consequences

- Weregopher now has a tested Windows primitive that starts a primary process inside its bounded kill-on-close Job Object before user code runs.
- Failed post-creation setup cannot intentionally leave an unowned running child; cleanup terminates both the direct process and job tree.
- The default primitive is intentionally austere and unsuitable for a production application until higher-level authority and compatibility policy supply the complete launch contract.
- Windows versions lacking `PROC_THREAD_ATTRIBUTE_JOB_LIST` fail process setup rather than falling back to a racy launch.

## Verification

Windows tests cover:

- zero, inverted, oversized, cardinality, per-argument, aggregate command-line, and finite-wait limits;
- relative and excessive-component executable paths plus debug path redaction;
- conventional Windows quoting for empty values, embedded quotes, backslashes before quotes, and quoted trailing backslashes;
- successful process creation, pre-resume Job Object membership, explicit tree termination, and exit-code observation;
- an explicit empty child environment;
- strict Clippy and Rustdoc checks over the public safe API and isolated unsafe boundary.
