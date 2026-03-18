//! Errors produced by the orchestrator layer.
//!
//! The orchestrator is responsible for the `NetGuard` system lifecycle:
//! environment pre-flight checks, state-machine transitions, and supervising
//! the Python backend process.  This module exposes two error types:
//!
//! | Type | Raised by | Covers |
//! |------|-----------|--------|
//! [`EnvironmentError`] | Pre-launch validation | Python version, venv, capabilities, socket dir |
//! [`OrchestratorError`] | Runtime orchestration | State transitions, commands, supervisor, handshake |

use std::time::Duration;

use crate::orchestrator::state::SystemState;
use crate::types::Severity;

const MAX_RESTARTS: u32 = 3;

// ---------------------------------------------------------------------------
// EnvironmentError
// ---------------------------------------------------------------------------

/// Errors detected during the pre-launch environment validation phase.
///
/// The orchestrator runs a series of environment checks before attempting to
/// start the Python backend.  Each check that fails produces one of these
/// variants.  The checks are intentionally separated from [`OrchestratorError`]
/// so callers can distinguish "launch pre-condition failed" from "runtime
/// orchestration failed".
///
/// # Severity & recoverability
///
/// | Variant | Severity | Recoverable | Rationale |
/// |---------|----------|-------------|-----------|
/// | `PythonNotFound` | Fatal | No | Cannot start without an interpreter |
/// | `PythonVersionMismatch` | Fatal | No | Wrong major version; install required |
/// | `VenvMissing` | Error | Yes | User can create the venv and retry |
/// | `MissingCapability` | Error | Yes | User can grant the cap and retry |
/// | `SocketDirNotWritable` | Error | Yes | User can fix permissions and retry |
///
/// # Raising guidance
///
/// These variants should only be raised during the **pre-launch validation**
/// sequence, not during steady-state operation.  Use [`OrchestratorError`]
/// for runtime failures that occur after the system has successfully started.
#[derive(Debug, thiserror::Error)]
pub enum EnvironmentError {
    /// No Python interpreter was found in any of the searched locations.
    ///
    /// Raised when the launcher has exhausted its search list (PATH entries,
    /// hard-coded fallback paths) without finding a `python3` executable.
    /// This is always Fatal — there is no meaningful way to continue.
    #[error("Python interpreter not found in any searched location")]
    PythonNotFound,

    /// A Python interpreter was found but its version does not meet the
    /// minimum requirement.
    ///
    /// Populate `required` with the minimum acceptable version string (e.g.
    /// `"3.9"`) and `found` with the detected version string.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use netguard_launcher::orchestrator::error::EnvironmentError;
    ///
    /// let err = EnvironmentError::PythonVersionMismatch {
    ///     required: "3.9".to_string(),   // minimum version, major.minor only
    ///     found: "3.7.16".to_string(),   // detected version, major.minor.patch
    /// };
    /// ```
    #[error("Python version mismatch: required {required}, found {found}")]
    PythonVersionMismatch { required: String, found: String },

    /// The expected Python virtual environment directory does not exist.
    ///
    /// Raised when the venv path configured for `NetGuard` is absent.  This is
    /// recoverable — the user can create the venv with the suggested command
    /// and retry.
    #[error("Virtual environment is missing")]
    VenvMissing,

    /// A required Linux capability is not granted to this process.
    ///
    /// Populate `cap` with the capability name (e.g. `"cap_net_raw"`).
    /// Recoverable — the user can grant the capability and retry.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use netguard_launcher::orchestrator::error::EnvironmentError;
    ///
    /// let err = EnvironmentError::MissingCapability {
    ///     cap: "cap_net_raw".to_string(), // Linux capability name, always lowercase with "cap_" prefix
    /// };
    /// ```
    #[error("Missing required system capability: {cap}")]
    MissingCapability { cap: String },

    /// The directory where the IPC socket will be created is not writable.
    ///
    /// Raised when a write-access test on the socket directory fails.
    /// Recoverable — the user can fix permissions or choose a different path.
    #[error("Socket directory is not writable: {path}")]
    SocketDirNotWritable { path: std::path::PathBuf },
}

impl EnvironmentError {
    #[must_use = "User messages are only used for logging purposes; do not call this method unless you know what you're doing!"]
    pub fn user_message(&self) -> String {
        match self {
            Self::PythonNotFound => {
                "Python interpreter was not found in any of the expected locations.".to_string()
            }
            Self::PythonVersionMismatch { required, found } => {
                format!(
                    "Python version mismatch: NetGuard requires {required}, but {found} was found."
                )
            }
            Self::VenvMissing => {
                "The Python virtual environment required by NetGuard does not exist.".to_string()
            }
            Self::MissingCapability { cap } => {
                format!("The required system capability '{cap}' is not granted to this process.")
            }
            Self::SocketDirNotWritable { path } => {
                format!(
                    "The IPC socket directory '{}' is not writable by the current user.",
                    path.display()
                )
            }
        }
    }

    #[must_use = "Suggestions are only used for logging purposes; do not call this method unless you know what you're doing!"]
    pub fn suggestion(&self) -> Option<String> {
        match self {
            Self::PythonNotFound => {
                Some("Install Python 3.9+ and ensure it is available in your PATH.".to_string())
            }
            Self::PythonVersionMismatch { required, .. } => Some(format!(
                "Install Python {required} or later: https://www.python.org/downloads/"
            )),
            Self::VenvMissing => Some(
                "Run `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt` \
                 to create the virtual environment."
                    .to_string(),
            ),
            Self::MissingCapability { cap } => Some(format!(
                "Grant the required capability with: `sudo setcap {cap}+eip $(which netguard)`"
            )),
            Self::SocketDirNotWritable { path } => Some(format!(
                "Ensure the directory '{}' exists and is writable: \
                 `mkdir -p {0} && chmod 700 {0}`",
                path.display()
            )),
        }
    }

    #[must_use = "Severity is only used for logging purposes; do not call this method unless you know what you're doing!"]
    pub const fn severity(&self) -> Severity {
        match self {
            Self::PythonNotFound | Self::PythonVersionMismatch { .. } => Severity::Fatal,
            Self::VenvMissing
            | Self::MissingCapability { .. }
            | Self::SocketDirNotWritable { .. } => Severity::Error,
        }
    }
    #[must_use = "Recoverable is only used for logging purposes; do not call this method unless you know what you're doing!"]
    pub const fn recoverable(&self) -> bool {
        match self {
            Self::PythonNotFound | Self::PythonVersionMismatch { .. } => false,
            Self::VenvMissing
            | Self::MissingCapability { .. }
            | Self::SocketDirNotWritable { .. } => true,
        }
    }
}

// ---------------------------------------------------------------------------
// OrchestratorError
// ---------------------------------------------------------------------------

/// Errors that occur in the system orchestrator during runtime operation.
///
/// Unlike [`EnvironmentError`], these variants are raised **after** the system
/// has (or should have) started — they represent runtime failures in the
/// orchestration logic rather than pre-launch pre-conditions.
///
/// # Severity & recoverability
///
/// | Variant | Severity | Recoverable | Rationale |
/// |---------|----------|-------------|-----------|
/// | `InvalidStateTransition` | Fatal | No | State machine is corrupted; unsafe to continue |
/// | `InvalidCommandForState` | Warning | Yes | User can wait and retry the command |
/// | `EnvironmentCheckFailed` | Delegated | Delegated | Inherits from the inner `EnvironmentError` |
/// | `SupervisorFailed` | Error | Yes (below `MAX_RESTARTS`) | Process may be auto-restarted |
/// | `HandshakeTimeout` | Warning | Yes | Transient timing issue; retry is safe |
#[derive(Debug, thiserror::Error)]
pub enum OrchestratorError {
    /// The state machine attempted a transition that is not permitted.
    ///
    /// Raised when the orchestrator receives a request to move from state
    /// `from` to state `to` and no valid transition edge exists between them.
    /// This indicates a programming error (invalid command sequencing) rather
    /// than a user error.  Always Fatal and non-recoverable — the system is
    /// in an undefined state.
    #[error("Invalid state transition from {from} to {to}")]
    InvalidStateTransition { from: SystemState, to: SystemState },

    /// A command was issued that is not legal in the current system state.
    ///
    /// Raised when the user (or an external caller) sends a command that the
    /// state machine cannot accept right now (e.g. `start` when in
    /// `Connecting`).  Recoverable — the user can wait for the state to change
    /// and retry.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use netguard_launcher::orchestrator::error::OrchestratorError;
    /// use netguard_launcher::orchestrator::state::SystemState;
    ///
    /// let err = OrchestratorError::InvalidCommandForState {
    ///     command: "start".to_string(), // orchestrator command name: "start", "stop", "restart"
    ///     state: SystemState::Connecting,
    /// };
    /// ```
    #[error("Command '{command}' is not valid in state {state}")]
    InvalidCommandForState { command: String, state: SystemState },

    /// A pre-launch environment check failed.
    ///
    /// Wraps an [`EnvironmentError`] so it can be surfaced through the
    /// `OrchestratorError` type at the call site.  Severity and
    /// recoverability are delegated entirely to the inner error.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use netguard_launcher::orchestrator::error::{OrchestratorError, EnvironmentError};
    ///
    /// let err = OrchestratorError::EnvironmentCheckFailed(
    ///     EnvironmentError::MissingCapability {
    ///         cap: "cap_net_raw".to_string(), // Linux capability name, always "cap_*" prefix
    ///     },
    /// );
    /// ```
    #[error("Environment check failed: {0}")]
    EnvironmentCheckFailed(EnvironmentError),

    /// The supervised Python process failed and exceeded its restart budget.
    ///
    /// Raised when the supervisor has attempted to restart the backend
    /// `restart_count` times and the process keeps failing.  Recoverable
    /// only while `restart_count < MAX_RESTARTS` (currently `3`); once the
    /// budget is exhausted it becomes non-recoverable.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use netguard_launcher::orchestrator::error::OrchestratorError;
    ///
    /// // Still recoverable: restart_count is below MAX_RESTARTS (= 3)
    /// let err = OrchestratorError::SupervisorFailed {
    ///     reason: "exit code 1".to_string(), // process failure description, e.g. "exit code 1", "killed by signal SIGSEGV"
    ///     restart_count: 2,                  // recoverable() returns false once this reaches MAX_RESTARTS (= 3)
    /// };
    /// ```
    #[error("Supervisor failed after {restart_count} restarts: {reason}")]
    SupervisorFailed { reason: String, restart_count: u32 },

    /// The IPC handshake with the Python backend timed out.
    ///
    /// Raised when the backend does not complete the connection handshake
    /// within the configured deadline.  Recoverable — the backend may have
    /// been slow to start; a retry after a short delay is safe.
    #[error("Handshake timed out after {elapsed:?}")]
    HandshakeTimeout { elapsed: Duration },
}

impl OrchestratorError {
    #[must_use = "User messages are only used for logging purposes; do not call this method unless you know what you're doing!"]
    pub fn user_message(&self) -> String {
        match self {
            Self::InvalidStateTransition { from, to } => {
                format!("Cannot transition from the {from} state to the {to} state.")
            }
            Self::InvalidCommandForState { command, state } => format!(
                "The command '{command}' cannot be executed while the system is in the {state} state."
            ),
            Self::EnvironmentCheckFailed(e) => {
                format!("Environment validation failed: {}", e.user_message())
            }
            Self::SupervisorFailed {
                reason,
                restart_count,
            } => format!(
                "The supervisor process failed after {restart_count} restart attempt(s). Reason: {reason}."
            ),
            Self::HandshakeTimeout { elapsed } => format!(
                "The connection handshake timed out after {:.1} second(s).",
                elapsed.as_secs_f64()
            ),
        }
    }
    #[must_use = "Suggestions are only used for logging purposes; do not call this method unless you know what you're doing!"]
    pub fn suggestion(&self) -> Option<String> {
        match self {
            Self::InvalidStateTransition { .. } => None,
            Self::InvalidCommandForState { state, .. } => Some(format!(
                "Wait for the system to leave the {state} state before retrying the command."
            )),
            Self::EnvironmentCheckFailed(e) => e.suggestion(),
            Self::SupervisorFailed { .. } => Some(
                "Check the application logs for details and try restarting NetGuard.".to_string(),
            ),
            Self::HandshakeTimeout { .. } => Some(
                "Ensure the Python backend is running and the IPC socket path is accessible, \
                 then retry."
                    .to_string(),
            ),
        }
    }
    #[must_use = "Severity is only used for logging purposes; do not call this method unless you know what you're doing!"]
    pub const fn severity(&self) -> Severity {
        match self {
            Self::InvalidStateTransition { .. } => Severity::Fatal,
            Self::InvalidCommandForState { .. } | Self::HandshakeTimeout { .. } => {
                Severity::Warning
            }
            Self::EnvironmentCheckFailed(e) => e.severity(),
            Self::SupervisorFailed { .. } => Severity::Error,
        }
    }
    #[must_use]
    pub const fn recoverable(&self) -> bool {
        match self {
            Self::InvalidStateTransition { .. } => false,
            Self::InvalidCommandForState { .. } | Self::HandshakeTimeout { .. } => true,
            Self::EnvironmentCheckFailed(e) => e.recoverable(),
            Self::SupervisorFailed { restart_count, .. } => *restart_count < MAX_RESTARTS,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn invalid_state_transition_user_message() {
        let err = OrchestratorError::InvalidStateTransition {
            from: SystemState::Ready,
            to: SystemState::Fatal { reason: "test".to_string() },
        };
        let msg = err.user_message();
        assert!(msg.contains("Ready"));
        assert!(msg.contains("Fatal"));
    }

    #[test]
    fn invalid_state_transition_not_recoverable() {
        let err = OrchestratorError::InvalidStateTransition {
            from: SystemState::Ready,
            to: SystemState::Initializing,
        };
        assert!(!err.recoverable());
        assert_eq!(err.severity(), Severity::Fatal);
        assert!(err.suggestion().is_none());
    }

    #[test]
    fn invalid_command_for_state_user_message_and_suggestion() {
        let err = OrchestratorError::InvalidCommandForState {
            command: "start".to_string(),
            state: SystemState::Connecting,
        };
        let msg = err.user_message();
        assert!(msg.contains("start"));
        assert!(msg.contains("Connecting"));
        assert!(err.suggestion().is_some());
        assert!(err.recoverable());
    }

    #[test]
    fn environment_check_failed_delegates() {
        let inner = EnvironmentError::VenvMissing;
        let err = OrchestratorError::EnvironmentCheckFailed(inner);
        assert!(err.user_message().contains("virtual environment"));
        assert!(err.suggestion().is_some());
        assert!(err.recoverable());
    }

    #[test]
    fn supervisor_failed_recoverable_below_max() {
        let err = OrchestratorError::SupervisorFailed {
            reason: "segfault".to_string(),
            restart_count: 2,
        };
        assert!(err.recoverable());
    }

    #[test]
    fn supervisor_failed_not_recoverable_at_max() {
        let err = OrchestratorError::SupervisorFailed {
            reason: "segfault".to_string(),
            restart_count: MAX_RESTARTS,
        };
        assert!(!err.recoverable());
    }

    #[test]
    fn handshake_timeout_user_message_and_suggestion() {
        let err = OrchestratorError::HandshakeTimeout {
            elapsed: Duration::from_secs(5),
        };
        let msg = err.user_message();
        assert!(msg.contains("5.0"));
        assert!(err.suggestion().is_some());
        assert!(err.recoverable());
    }

    #[test]
    fn env_python_not_found_fatal_not_recoverable() {
        let err = EnvironmentError::PythonNotFound;
        assert!(!err.recoverable());
        assert_eq!(err.severity(), Severity::Fatal);
        assert!(err.suggestion().is_some());
    }

    #[test]
    fn env_venv_missing_suggestion_contains_command() {
        let err = EnvironmentError::VenvMissing;
        let sug = err.suggestion().unwrap();
        assert!(sug.contains("pip install"));
    }

    #[test]
    fn env_missing_capability_suggestion_contains_setcap() {
        let err = EnvironmentError::MissingCapability {
            cap: "cap_net_raw".to_string(),
        };
        let sug = err.suggestion().unwrap();
        assert!(sug.contains("setcap"));
    }

    #[test]
    fn env_socket_dir_not_writable_suggestion() {
        let err = EnvironmentError::SocketDirNotWritable {
            path: PathBuf::from("/run/netguard"),
        };
        assert!(err.suggestion().is_some());
        assert!(err.recoverable());
    }
}
