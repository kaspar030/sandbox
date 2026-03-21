//! Container state machine.
//!
//! States: Created -> Running -> Stopped
//!                       |          |
//!                       v          | (restart)
//!                    Stopped ------+-> Created

use crate::protocol::ContainerState;

/// Internal container state tracking.
#[derive(Debug, Clone)]
pub struct State {
    current: ContainerState,
}

impl Default for State {
    fn default() -> Self {
        Self {
            current: ContainerState::Created,
        }
    }
}

impl State {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn current(&self) -> &ContainerState {
        &self.current
    }

    /// Transition to Running state.
    pub fn start(&mut self) -> Result<(), InvalidTransition> {
        match &self.current {
            ContainerState::Created => {
                self.current = ContainerState::Running;
                Ok(())
            }
            other => Err(InvalidTransition {
                from: format!("{other:?}"),
                to: "Running".to_string(),
            }),
        }
    }

    /// Transition to Stopped state.
    pub fn stop(&mut self, exit_code: i32) -> Result<(), InvalidTransition> {
        match &self.current {
            ContainerState::Running => {
                self.current = ContainerState::Stopped { exit_code };
                Ok(())
            }
            other => Err(InvalidTransition {
                from: format!("{other:?}"),
                to: "Stopped".to_string(),
            }),
        }
    }

    /// Reset from Stopped back to Created (for restart).
    pub fn reset(&mut self) -> Result<(), InvalidTransition> {
        match &self.current {
            ContainerState::Stopped { .. } => {
                self.current = ContainerState::Created;
                Ok(())
            }
            other => Err(InvalidTransition {
                from: format!("{other:?}"),
                to: "Created".to_string(),
            }),
        }
    }

    pub fn is_created(&self) -> bool {
        matches!(self.current, ContainerState::Created)
    }

    pub fn is_running(&self) -> bool {
        matches!(self.current, ContainerState::Running)
    }

    pub fn is_stopped(&self) -> bool {
        matches!(self.current, ContainerState::Stopped { .. })
    }
}

#[derive(Debug)]
pub struct InvalidTransition {
    pub from: String,
    pub to: String,
}

impl std::fmt::Display for InvalidTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid state transition: {} -> {}", self.from, self.to)
    }
}

impl std::error::Error for InvalidTransition {}
