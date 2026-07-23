# ADR 0027: Bounded blocking execution supervision

- Status: Accepted
- Date: 2026-07-23
- Amends: [ADR 0025](0025-atomic-authorization-consumption-and-job-owned-launch.md)

## Context

The one-shot launch boundary returns `SupervisedExecution`, which retains the complete package or managed-artifact lease, the kill-on-close Job owner, exact launch semantics, target identity, authorization-context identity, and the issuing policy generation. It exposes current-policy checks and whole-Job termination, but callers could previously forget to poll or could terminate only after an unbounded delay.

Job ownership is lifecycle and accounting control, not a sandbox. Runtime revocation enforcement therefore needs a bounded owner loop without implying state isolation, dependency immutability, privileged-effect authorization, compatibility, or certification.

## Decision

On Windows, `supervise_execution` consumes one `SupervisedExecution` and blocks until the primary process exits, current policy becomes invalid, or a stricter local runtime deadline expires.

`SupervisionLimits` requires:

- a policy polling interval from one millisecond through 60 seconds;
- a nonzero runtime no greater than 24 hours; and
- a polling interval no longer than the runtime.

The supervisor:

1. rechecks the issuing store, policy generation, and revocation state before each bounded wait;
2. waits for at most the smaller of the poll interval and remaining runtime;
3. reports a natural primary-process exit while dropping the owner, so kill-on-close still terminates any surviving Job members;
4. on policy invalidation or runtime expiry, terminates the complete Job with a supervisor-reserved exit code;
5. requires primary-process termination confirmation within a fixed five-second bound; and
6. returns a terminal report carrying the exact `ExecutionTargetId`, role-distinct `AuthorizationContextDigest`, monotonic elapsed duration, and outcome.

Wait, termination, or confirmation failures return an explicit error. The consumed owner is dropped on every error, preserving kill-on-close cleanup.

This API is intentionally blocking. Concurrent runtimes must dedicate an owned runtime thread rather than detaching lifecycle ownership from the retained authority chain.

## Security boundary

This supervisor provides bounded local currentness polling and whole-Job lifecycle enforcement. It does not:

- make a Job Object a sandbox;
- seal ambient DLL, resource, helper, configuration, filesystem, registry, network, or IPC namespaces;
- assign `AppInstanceId`, `RuntimeId`, workflow, user-activation, or state-lease ownership;
- persist or remotely refresh trust policy;
- authorize privileged effects after launch;
- provide graceful protocol shutdown; or
- produce compatibility or certification evidence.

Higher-level runtime orchestration must bind those identities and capabilities and may attempt bounded graceful shutdown before forced whole-Job termination. Unknown policy currentness continues to fail closed.

## Verification

Windows integration regressions cover delayed post-launch revocation, exact target and authorization-context reporting, whole-Job forced termination through the existing Job primitive, stricter runtime deadlines, natural primary exit, and invalid supervision limits. Native and Linux-target strict Clippy preserve the Windows-only API boundary.

## Consequences

- Launched execution no longer depends on each caller inventing its own revocation polling loop.
- Polling and runtime delay are explicit, bounded operational policy rather than ambient thread behavior.
- The returned report is diagnostic evidence, not serialized authority or certification.
- Durable supervisor services, runtime protocol ownership, graceful shutdown, state capabilities, remote policy refresh, and certification remain later milestones.
