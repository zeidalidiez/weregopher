//! Backend-neutral renderer lifecycle and navigation generation state.

use thiserror::Error;
use weregopher_domain::RendererId;

/// Monotonic generation for one renderer navigation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NavigationGeneration(u32);

impl NavigationGeneration {
    /// Returns the nonzero numeric generation.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Normalized renderer lifecycle state used by the G1 fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RendererLifecycleState {
    /// Native view/controller creation is in progress.
    Creating,
    /// Backend controller exists and may navigate.
    Initialized,
    /// A navigation is active.
    Navigating,
    /// The active document emitted `DOMContentLoaded`.
    DomContentLoaded,
    /// The active document completed loading.
    Loaded,
    /// Deterministic close has begun.
    Closing,
    /// Controller and owned fixture state are closed.
    Closed,
    /// Backend reported an abnormal renderer exit.
    Crashed,
}

/// Closed lifecycle state machine with stale-navigation rejection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RendererLifecycle {
    renderer: RendererId,
    state: RendererLifecycleState,
    generation: u32,
}

impl RendererLifecycle {
    /// Starts one renderer in the creating state.
    #[must_use]
    pub const fn new(renderer: RendererId) -> Self {
        Self {
            renderer,
            state: RendererLifecycleState::Creating,
            generation: 0,
        }
    }

    /// Renderer identity governed by this state machine.
    #[must_use]
    pub const fn renderer(&self) -> RendererId {
        self.renderer
    }

    /// Current normalized lifecycle state.
    #[must_use]
    pub const fn state(&self) -> RendererLifecycleState {
        self.state
    }

    /// Marks successful backend initialization.
    ///
    /// # Errors
    ///
    /// Returns [`RendererLifecycleError::InvalidTransition`] outside `Creating`.
    pub fn mark_initialized(&mut self) -> Result<(), RendererLifecycleError> {
        self.transition(
            RendererLifecycleState::Creating,
            RendererLifecycleState::Initialized,
        )
    }

    /// Starts a navigation and returns its fresh monotonic generation.
    ///
    /// # Errors
    ///
    /// Returns a transition or generation-exhaustion error unless initialized or loaded.
    pub fn begin_navigation(&mut self) -> Result<NavigationGeneration, RendererLifecycleError> {
        if !matches!(
            self.state,
            RendererLifecycleState::Initialized | RendererLifecycleState::Loaded
        ) {
            return Err(RendererLifecycleError::InvalidTransition {
                from: self.state,
                operation: "begin navigation",
            });
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(RendererLifecycleError::NavigationGenerationExhausted)?;
        self.state = RendererLifecycleState::Navigating;
        Ok(NavigationGeneration(self.generation))
    }

    /// Records `DOMContentLoaded` for the exact active navigation.
    ///
    /// # Errors
    ///
    /// Rejects stale generations and out-of-order lifecycle events.
    pub fn mark_dom_content_loaded(
        &mut self,
        generation: NavigationGeneration,
    ) -> Result<(), RendererLifecycleError> {
        self.require_generation(generation)?;
        self.transition(
            RendererLifecycleState::Navigating,
            RendererLifecycleState::DomContentLoaded,
        )
    }

    /// Records load completion for the exact active navigation.
    ///
    /// # Errors
    ///
    /// Rejects stale generations and load-before-DOM events.
    pub fn mark_loaded(
        &mut self,
        generation: NavigationGeneration,
    ) -> Result<(), RendererLifecycleError> {
        self.require_generation(generation)?;
        self.transition(
            RendererLifecycleState::DomContentLoaded,
            RendererLifecycleState::Loaded,
        )
    }

    /// Records an abnormal renderer exit and invalidates active navigation state.
    ///
    /// # Errors
    ///
    /// Rejects crash notifications after close or while already closing.
    pub fn mark_crashed(&mut self) -> Result<(), RendererLifecycleError> {
        if matches!(
            self.state,
            RendererLifecycleState::Closing | RendererLifecycleState::Closed
        ) {
            return Err(RendererLifecycleError::InvalidTransition {
                from: self.state,
                operation: "mark crashed",
            });
        }
        self.state = RendererLifecycleState::Crashed;
        Ok(())
    }

    /// Begins deterministic close from any live state.
    ///
    /// # Errors
    ///
    /// Rejects duplicate close and close-after-closed operations.
    pub fn begin_close(&mut self) -> Result<(), RendererLifecycleError> {
        if matches!(
            self.state,
            RendererLifecycleState::Closing | RendererLifecycleState::Closed
        ) {
            return Err(RendererLifecycleError::InvalidTransition {
                from: self.state,
                operation: "begin close",
            });
        }
        self.state = RendererLifecycleState::Closing;
        Ok(())
    }

    /// Completes deterministic close.
    ///
    /// # Errors
    ///
    /// Returns [`RendererLifecycleError::InvalidTransition`] outside `Closing`.
    pub fn mark_closed(&mut self) -> Result<(), RendererLifecycleError> {
        self.transition(
            RendererLifecycleState::Closing,
            RendererLifecycleState::Closed,
        )
    }

    fn transition(
        &mut self,
        expected: RendererLifecycleState,
        next: RendererLifecycleState,
    ) -> Result<(), RendererLifecycleError> {
        if self.state != expected {
            return Err(RendererLifecycleError::InvalidTransition {
                from: self.state,
                operation: match next {
                    RendererLifecycleState::Initialized => "mark initialized",
                    RendererLifecycleState::DomContentLoaded => "mark DOM content loaded",
                    RendererLifecycleState::Loaded => "mark loaded",
                    RendererLifecycleState::Closed => "mark closed",
                    _ => "transition",
                },
            });
        }
        self.state = next;
        Ok(())
    }

    fn require_generation(
        &self,
        generation: NavigationGeneration,
    ) -> Result<(), RendererLifecycleError> {
        if generation.0 == self.generation {
            Ok(())
        } else {
            Err(RendererLifecycleError::StaleNavigation {
                expected: self.generation,
                actual: generation.0,
            })
        }
    }
}

/// Invalid renderer lifecycle transition or stale backend event.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RendererLifecycleError {
    /// An operation was not legal in the current state.
    #[error("cannot {operation} from renderer state {from:?}")]
    InvalidTransition {
        /// Current state.
        from: RendererLifecycleState,
        /// Rejected operation.
        operation: &'static str,
    },
    /// An event belonged to an invalidated navigation.
    #[error("stale renderer navigation generation {actual}; active generation is {expected}")]
    StaleNavigation {
        /// Active generation.
        expected: u32,
        /// Event generation.
        actual: u32,
    },
    /// Navigation generation arithmetic exhausted `u32`.
    #[error("renderer navigation generation exhausted")]
    NavigationGenerationExhausted,
}
