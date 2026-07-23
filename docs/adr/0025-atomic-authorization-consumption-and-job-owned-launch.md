# ADR 0025: Atomic authorization consumption and Job-owned launch

- Status: Accepted
- Date: 2026-07-23

## Context

ADR 0024 introduced a conditional, non-cloneable live authorization that owns an identity-bound executable capability and binds one policy generation. That value deliberately did not launch a process. A separate boundary still had to prove that authorization currentness, final retained-view verification, Job containment, suspended process creation, assignment verification, and resume occur as one fail-closed operation.

Passing an executable path to a later component would lose the retained-capability guarantee. Releasing the policy lock before process resume would permit replacement or revocation to race launch. Returning only a process handle would also drop the complete containing-artifact lease while the process could still resolve package-relative content.

## Decision

On Windows, `launch_authorized_execution` consumes exactly one `AuthorizedExecution` and:

1. rejects every security posture except `vendor-equivalent-full-trust`, because the current Windows primitive is neither a broker nor an independently tested OS sandbox;
2. converts the exact target resource limits into Job Object limits and the exact target arguments into bounded Windows arguments;
3. upgrades the issuing policy-store reference and holds its read lock through the remainder of launch;
4. rechecks revocation and policy generation;
5. repeats current-view verification through the retained executable capability;
6. creates and configures a kill-on-close Job Object;
7. moves the already locked executable directly into `CREATE_SUSPENDED` process creation with an empty environment, no inherited handles, no console, and the executable directory as the working directory;
8. assigns the suspended process to the Job, verifies membership, and only then resumes its primary thread; and
9. returns `SupervisedExecution`, which owns the Job/process capability and retains a borrow of the complete package snapshot or managed-artifact lease.

The authorization is consumed by value and cannot be replayed. No launch step reopens the executable from an untrusted path. Every failure before successful resume drops the kill-on-close ownership chain without returning a runnable process.

`SupervisedExecution` retains the issuing policy generation and a weak reference to the policy store. Supervisors can recheck policy currentness after launch and MUST terminate the Job tree before permitting further privileged effects when that check fails. This API exposes the revocation signal; continuous monitoring and automatic termination remain supervisor work.

The Windows command-line ceiling is a runtime transport limit, not authority. The smaller canonical target-contract argument limits continue to define authorized input.

## Consequences

- Policy replacement and revocation cannot interleave between the final launch check and primary-thread resume.
- Exact target resource limits become enforced Job limits rather than advisory metadata.
- Process-tree ownership, target identity, and authorization identity stay attached to one opaque owner.
- Broker-mediated and OS-contained targets fail closed at this boundary until corresponding enforcing launch implementations exist.
- Job Objects remain lifecycle and accounting controls, not sandboxes.
- A retained Windows directory handle still does not prevent a same-user process from inserting a new child after manifest verification. Package-manifest current-view evidence therefore remains point-in-time and must not be described as a sealed namespace.
- Registry trust, forensic override approval, continuous revocation enforcement, supervisor protocol integration, and certification evidence remain separate milestones.
