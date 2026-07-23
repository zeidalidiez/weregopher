//! Bounded blocking supervision for one authorized Windows process tree.

use std::{
    io,
    time::{Duration, Instant},
};

use thiserror::Error;
use weregopher_domain::{AuthorizationContextDigest, ExecutionTargetId};

use crate::{ExecutionAuthorizationError, SupervisedExecution};

const MIN_POLICY_POLL_INTERVAL: Duration = Duration::from_millis(1);
const MAX_POLICY_POLL_INTERVAL: Duration = Duration::from_mins(1);
const MAX_SUPERVISION_RUNTIME: Duration = Duration::from_hours(24);
const TERMINATION_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(5);
const SUPERVISOR_TERMINATION_EXIT_CODE: u32 = 197;

/// Hard bounds for one blocking supervision session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupervisionLimits {
    policy_poll_interval: Duration,
    max_runtime: Duration,
}

impl SupervisionLimits {
    /// Creates millisecond-representable limits within the runtime hard ceilings.
    ///
    /// A runtime limit is a stricter local operational ceiling; it cannot expand the exact target
    /// authority, launch policy, or Job limits already consumed by the process owner.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisionError::InvalidLimits`] for a poll interval below one millisecond or
    /// above one minute, a zero or above-one-day runtime, or a poll interval longer than the
    /// runtime.
    pub fn new(
        policy_poll_interval: Duration,
        max_runtime: Duration,
    ) -> Result<Self, SupervisionError> {
        if policy_poll_interval < MIN_POLICY_POLL_INTERVAL
            || max_runtime.is_zero()
            || policy_poll_interval > MAX_POLICY_POLL_INTERVAL
            || max_runtime > MAX_SUPERVISION_RUNTIME
            || policy_poll_interval > max_runtime
        {
            return Err(SupervisionError::InvalidLimits);
        }
        Ok(Self {
            policy_poll_interval,
            max_runtime,
        })
    }

    /// Returns the maximum interval between current-policy checks.
    #[must_use]
    pub const fn policy_poll_interval(self) -> Duration {
        self.policy_poll_interval
    }

    /// Returns the stricter local runtime deadline.
    #[must_use]
    pub const fn max_runtime(self) -> Duration {
        self.max_runtime
    }
}

/// Terminal reason for one bounded supervision session.
#[derive(Debug, Eq, PartialEq)]
pub enum SupervisionOutcome {
    /// The primary process exited before a policy or runtime violation was observed.
    Exited {
        /// Primary-process exit code reported by Windows.
        code: u32,
    },
    /// Current trust, policy generation, or revocation state became invalid.
    PolicyInvalidated {
        /// Exact fail-closed policy reason that triggered whole-Job termination.
        reason: ExecutionAuthorizationError,
    },
    /// The stricter local runtime deadline triggered whole-Job termination.
    RuntimeExceeded,
}

/// Identity-bound terminal report from one bounded supervision session.
#[derive(Debug, Eq, PartialEq)]
pub struct SupervisionReport {
    target_id: ExecutionTargetId,
    authorization_context_digest: AuthorizationContextDigest,
    elapsed: Duration,
    outcome: SupervisionOutcome,
}

impl SupervisionReport {
    /// Returns the exact execution target that was supervised.
    #[must_use]
    pub const fn target_id(&self) -> &ExecutionTargetId {
        &self.target_id
    }

    /// Returns the exact live-authorization context bound to the process tree.
    #[must_use]
    pub const fn authorization_context_digest(&self) -> AuthorizationContextDigest {
        self.authorization_context_digest
    }

    /// Returns monotonic elapsed time observed by this local supervisor.
    #[must_use]
    pub const fn elapsed(&self) -> Duration {
        self.elapsed
    }

    /// Returns why supervision ended.
    #[must_use]
    pub const fn outcome(&self) -> &SupervisionOutcome {
        &self.outcome
    }
}

/// Owns and monitors one authorized process tree until exit, revocation, or a runtime deadline.
///
/// This call is intentionally blocking: the borrowed package or managed-artifact lease and
/// kill-on-close Job owner stay in one lexical ownership chain. Current policy is checked at least
/// once per configured polling interval. Any policy failure or runtime deadline terminates the
/// complete Job and confirms primary-process exit before returning a report. Dropping through an
/// unexpected error still closes the Job owner and kills surviving members.
///
/// This is local lifecycle supervision, not a sandbox, compatibility result, certification record,
/// or durable background service. A caller that needs concurrent work must dedicate a runtime
/// thread to this blocking operation.
///
/// # Errors
///
/// Returns [`SupervisionError`] when Windows cannot wait for, terminate, or confirm termination of
/// the process tree. On every runtime error the consumed owner is dropped.
#[expect(
    clippy::needless_pass_by_value,
    reason = "supervision deliberately consumes the sole Job/process owner for the full session"
)]
pub fn supervise_execution(
    execution: SupervisedExecution<'_, '_>,
    limits: SupervisionLimits,
) -> Result<SupervisionReport, SupervisionError> {
    let target_id = execution.target_id().clone();
    let authorization_context_digest = execution.authorization_context_digest();
    let started = Instant::now();

    loop {
        if let Err(reason) = execution.verify_current_policy() {
            terminate_and_confirm(&execution)?;
            return Ok(SupervisionReport {
                target_id,
                authorization_context_digest,
                elapsed: started.elapsed(),
                outcome: SupervisionOutcome::PolicyInvalidated { reason },
            });
        }

        let elapsed = started.elapsed();
        if elapsed >= limits.max_runtime {
            terminate_and_confirm(&execution)?;
            return Ok(SupervisionReport {
                target_id,
                authorization_context_digest,
                elapsed: started.elapsed(),
                outcome: SupervisionOutcome::RuntimeExceeded,
            });
        }

        let observation_interval = limits
            .policy_poll_interval
            .min(limits.max_runtime.saturating_sub(elapsed));
        if let Some(code) = execution
            .wait_for(observation_interval)
            .map_err(SupervisionError::ProcessWait)?
        {
            return Ok(SupervisionReport {
                target_id,
                authorization_context_digest,
                elapsed: started.elapsed(),
                outcome: SupervisionOutcome::Exited { code },
            });
        }
    }
}

fn terminate_and_confirm(execution: &SupervisedExecution<'_, '_>) -> Result<(), SupervisionError> {
    if execution
        .wait_for(Duration::ZERO)
        .map_err(SupervisionError::ProcessWait)?
        .is_some()
    {
        return Ok(());
    }
    if let Err(error) = execution.terminate(SUPERVISOR_TERMINATION_EXIT_CODE) {
        if execution
            .wait_for(Duration::ZERO)
            .map_err(SupervisionError::ProcessWait)?
            .is_some()
        {
            return Ok(());
        }
        return Err(SupervisionError::ProcessTermination(error));
    }
    if execution
        .wait_for(TERMINATION_CONFIRMATION_TIMEOUT)
        .map_err(SupervisionError::ProcessWait)?
        .is_none()
    {
        return Err(SupervisionError::TerminationConfirmationTimeout);
    }
    Ok(())
}

/// Failure to complete one bounded supervision session.
#[derive(Debug, Error)]
pub enum SupervisionError {
    /// Limits were zero, inverted, or exceeded a fixed hard ceiling.
    #[error("execution supervision limits are invalid")]
    InvalidLimits,
    /// Waiting for or querying the primary process failed.
    #[error("execution supervisor could not wait for the primary process")]
    ProcessWait(#[source] io::Error),
    /// Whole-Job termination failed while the process remained live.
    #[error("execution supervisor could not terminate the process Job")]
    ProcessTermination(#[source] io::Error),
    /// Job termination did not produce a primary-process exit within the fixed confirmation bound.
    #[error("execution supervisor could not confirm process termination")]
    TerminationConfirmationTimeout,
}
