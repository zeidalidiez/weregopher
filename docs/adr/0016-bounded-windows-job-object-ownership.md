# ADR 0016: Bounded kill-on-close Windows Job Object ownership

- Status: Accepted
- Date: 2026-07-21

## Context

Weregopher must own helper and runtime process trees so grandchildren do not escape accounting or outlive their application owner. The architecture requires Windows Job Objects where compatible, but Job Objects are lifecycle and accounting controls rather than security sandboxes.

The repository previously had no process-tree ownership primitive. A later launch boundary will also need suspended process creation, explicit handle inheritance, environment and DLL policy, executable authority, and artifact/package-view proofs. Those concerns must not be smuggled into a low-level Job Object wrapper or inferred from successful assignment.

## Decision

`weregopher-windows` exposes two safe, Windows-only types:

- `JobLimits` validates a nonzero active-process count, a nonzero per-process committed-memory ceiling, and a nonzero aggregate job-memory ceiling. Per-process memory cannot exceed aggregate job memory, and both values must fit Windows `SIZE_T`.
- `KillOnCloseJob` owns one unnamed Job Object configured with `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`, `JOB_OBJECT_LIMIT_PROCESS_MEMORY`, `JOB_OBJECT_LIMIT_JOB_MEMORY`, and `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` in one `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` update.

The wrapper:

1. creates the object with default, non-inheritable handle semantics;
2. applies every required limit before returning the capability;
3. accepts `std::process::Child` references for assignment and membership queries so no raw handle crosses the public API;
4. supports explicit whole-job termination with a caller-selected exit code;
5. closes its owned handle on drop, causing Windows to terminate processes still associated with the job.

No breakaway flag is enabled. Descendants created after successful assignment therefore remain in the same job unless an independently documented Windows compatibility condition prevents assignment.

All raw-handle and pointer operations remain isolated in `weregopher-windows`, the workspace's explicit unsafe-code exception. Each unsafe block documents live-handle, ownership, pointer, structure-layout, and initialization invariants.

## Assignment boundary

`assign_child` adopts an **already running** `Child`. This is sufficient for lifecycle tests and some supervised adoption paths, but it does not close the spawn-before-assignment race: the process can execute or create descendants before assignment.

A later authority-bearing launch path must instead:

1. resolve and verify an authorized executable and package/artifact view;
2. build a closed environment, working directory, standard-I/O set, and inherited-handle list;
3. call Windows process creation with the primary thread suspended;
4. assign the process to a preconfigured Job Object;
5. fail closed and terminate the suspended process if assignment fails;
6. resume only after ownership is established.

This ADR does not authorize generic process launch and does not claim that `std::process::Command` plus `assign_child` is race-free.

## Claims and non-claims

- The capability bounds active process count plus per-process and aggregate committed memory and owns assigned process-tree lifetime.
- Drop and explicit termination are lifecycle controls, not graceful shutdown protocols.
- Job Objects do not sandbox same-user processes, restrict filesystem/network access, sanitize environment state, establish signer/hash authority, configure mitigations, or prevent all breakaway behavior on every nested-job configuration.
- Assignment can fail when Windows job compatibility, process state, or configured limits reject it. Callers must fail closed.
- Non-Windows targets expose no Job Object API.

## Alternatives rejected

- Tracking only the direct child PID does not own grandchildren and is vulnerable to PID reuse.
- Launching normally and treating later assignment as a secure launch gate leaves executable code running before ownership.
- Enabling breakaway by default defeats process-tree ownership.
- Exposing raw handles would spread unsafe Windows lifetime and inheritance reasoning into platform-neutral crates.
- Calling a Job Object a sandbox would collapse lifecycle control into an unsupported security claim.

## Consequences

- Weregopher now has a tested Windows process-tree ownership primitive for later suspended launch and helper supervision.
- Higher layers still need executable authority, race-free suspended creation, explicit inherited handles, graceful shutdown, output bounds, accounting evidence, and compatibility policy.
- The configured memory ceilings are hard operational limits and must eventually come from bounded adapter/runtime policy rather than arbitrary untrusted transport values.

## Verification

Windows integration tests cover:

- zero, inverted, and platform-width-invalid limits;
- successful assignment and membership query;
- kill-on-close child termination;
- explicit whole-job termination and exit-code propagation;
- rejection of a second process when the active-process limit is one.
