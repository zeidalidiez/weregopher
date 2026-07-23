# ADR 0025: Atomic authorization consumption and Job-owned launch

- Status: Accepted
- Date: 2026-07-23

> Amended by [ADR 0026](0026-execution-contract-v2-and-pre-authorized-launch-plans.md): posture,
> resource, path, argument, quoting-expansion, and command-line representability checks now complete
> before `AuthorizedExecution` is issued. Launch consumes the resulting opaque prepared plan.
>
> Amended by [ADR 0027](0027-bounded-blocking-execution-supervision.md): the returned owner can now
> be consumed by a bounded blocking loop that automatically terminates the complete Job after policy
> invalidation or a stricter local runtime deadline.

## Context

ADR 0024 introduced a conditional, non-cloneable live authorization that owns an identity-bound executable capability and binds one policy generation. That value deliberately did not launch a process. A separate boundary still had to prove that authorization currentness, final retained-view verification, Job containment, suspended process creation, assignment verification, and resume occur as one fail-closed operation.

Passing an executable path to a later component would lose the retained-capability guarantee. Releasing the policy lock before process resume would permit replacement or revocation to race launch. Returning only a process handle would also drop the complete containing-artifact lease while the process could still resolve package-relative content.

## Decision

On Windows, `launch_authorized_execution` consumes exactly one `AuthorizedExecution` and:

1. receives only an authorization for which the local authorizer already rejected unsupported posture and semantics and prepared exact Job limits plus a Windows command line;
2. upgrades the issuing policy-store reference and holds its read lock through the remainder of launch;
3. rechecks revocation and policy generation;
4. repeats current-view verification through the retained executable capability;
5. creates and configures a kill-on-close Job Object;
6. checks that the prepared launch still names the same absolute path and full-width file identity and is paired with the exact private executable-lock instance that prepared it;
7. moves the already locked executable and prepared command line directly into `CREATE_SUSPENDED` process creation with an empty environment, no inherited handles, no console, and the executable directory as the working directory;
8. assigns the suspended process to the Job, verifies membership, and only then resumes its primary thread; and
9. returns `SupervisedExecution`, which owns the Job/process capability and retains a borrow of the complete package snapshot or managed-artifact lease.

The authorization is consumed by value and cannot be replayed. No launch step reopens the executable from an untrusted path. Every failure before successful resume drops the kill-on-close ownership chain without returning a runnable process.

`SupervisedExecution` retains the issuing policy generation and a weak reference to the policy store. `supervise_execution` consumes it, rechecks policy on a caller-selected interval beneath fixed hard ceilings, and terminates the complete Job after policy invalidation or runtime expiry. Durable protocol orchestration and privileged-effect mediation remain higher-level supervisor work.

The Windows command-line ceiling is a runtime transport limit, not authority. The smaller canonical target-contract argument limits continue to define authorized input, but quoting expansion and the complete ceiling are validated before the authorization capability exists.

## Consequences

- Policy replacement and revocation cannot interleave between the final launch check and primary-thread resume.
- Exact target resource limits become enforced Job limits rather than advisory metadata.
- Process-tree ownership, target identity, and authorization identity stay attached to one opaque owner.
- Broker-mediated and OS-contained targets fail closed at this boundary until corresponding enforcing launch implementations exist.
- Job Objects remain lifecycle and accounting controls, not sandboxes.
- A retained Windows directory handle still does not prevent a same-user process from inserting a new child after manifest verification. Package-manifest current-view evidence therefore remains point-in-time and must not be described as a sealed namespace.
- The authorization-context digest identifies logical decision equivalence, not a physical path, lock instance, or ambient dependency namespace. Exact path and lock-instance capabilities remain attached to the opaque process owner; the `vendor_default_ambient` dependency namespace is neither capability-retained nor sealed or digest-bound.
- Registry trust, forensic override approval, durable supervisor protocol integration, graceful shutdown, and certification evidence remain separate milestones.
