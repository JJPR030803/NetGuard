//! System state machine for NetGuard.
//!
//! [`SystemState`] is the single source of truth for what the system is doing
//! at any given moment. Only the `Orchestrator` is permitted to mutate it —
//! all mutations go through `Orchestrator::transition_to()`, which calls
//! [`SystemState::can_transition_to`] before applying any change.
//!
//! Invalid transitions are blocked and logged as programmer errors, not user
//! errors. If you hit a blocked transition in development, the problem is in
//! the code that requested it, not in the state machine.

use std::fmt;
use std::path::PathBuf;

// ── CommandKind ───────────────────────────────────────────────────────────────

/// Every user-visible command the orchestrator can dispatch.
///
/// Used by [`SystemState::allowed_commands`] to enforce which commands are
/// valid in each state. The orchestrator rejects commands not in the allowed
/// set before they reach the sidecar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommandKind {
    /// Begin packet capture on a network interface.
    StartCapture,
    /// Stop an active packet capture.
    StopCapture,
    /// Execute a named analysis workflow.
    RunWorkflow,
    /// List available network interfaces.
    ListInterfaces,
    /// Load and analyze an existing Parquet file.
    LoadFile,
    /// Retrieve current capture statistics from the sidecar.
    GetStats,
}

// ── ActiveOperation ───────────────────────────────────────────────────────────

/// The specific operation the system is performing while in
/// [`SystemState::Operating`].
///
/// Carried as a field on the `Operating` variant so frontends and the
/// orchestrator always know *which* operation is in progress, not just that
/// *some* operation is running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ActiveOperation {
    /// Live packet capture is running on the named interface.
    Capturing {
        /// The network interface being captured (e.g. `"eth0"`).
        interface: String,
    },
    /// An analysis workflow is executing.
    RunningWorkflow {
        /// The workflow identifier (e.g. `"daily-audit"`).
        name: String,
    },
    /// A Parquet file is being loaded for analysis.
    LoadingFile {
        /// Absolute path to the file being loaded.
        path: PathBuf,
    },
}

// ── DegradedReason ────────────────────────────────────────────────────────────

/// Why the system entered [`SystemState::Degraded`].
///
/// Each variant maps to a different recovery strategy and a different set of
/// available commands. The frontend must handle every variant — there is no
/// acceptable generic "something went wrong" screen for a degraded condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DegradedReason {
    /// The Python sidecar process exited unexpectedly.
    ///
    /// The supervisor is attempting to restart it. `restart_count` lets the
    /// frontend show "Reconnecting (attempt 2 of 3)..." rather than a generic
    /// spinner.
    SidecarCrashed {
        /// Number of restart attempts made so far.
        restart_count: u32,
    },

    /// The sidecar is alive but has not sent a heartbeat within the threshold.
    ///
    /// The supervisor will send `SIGKILL` and restart. `silent_for_secs`
    /// lets the frontend show how long the sidecar has been silent.
    SidecarUnresponsive {
        /// Seconds elapsed since the last received heartbeat.
        silent_for_secs: u64,
    },

    /// The handshake succeeded but reported incompatible versions.
    ///
    /// The system cannot proceed. The user must run `just setup` to
    /// synchronise versions. This transitions to `Fatal` after one retry.
    VersionMismatch {
        /// Version string reported by the Rust launcher.
        rust: String,
        /// Version string reported by the Python sidecar.
        python: String,
    },

    /// `cap_net_raw` / `cap_net_admin` are not set on the Python binary.
    ///
    /// Packet capture is unavailable, but analysis of existing Parquet files
    /// works normally. The frontend shows a persistent "Capture unavailable"
    /// banner — this is not a blocking error.
    CapabilitiesMissing,

    /// The requirements hash in the venv does not match `requirements.txt`.
    ///
    /// Python imports may fail. The orchestrator suggests running `uv sync`.
    PythonEnvStale,

    /// The Unix Domain Socket could not be created.
    ///
    /// The system falls back to stdio IPC with reduced capability. This is a
    /// warning, not fatal.
    IpcSocketUnavailable,
}

// ── SystemState ───────────────────────────────────────────────────────────────

/// The authoritative state of the NetGuard system.
///
/// Only [`crate::orchestrator::Orchestrator`] is permitted to write this type.
/// All frontends receive a read-only copy via [`SystemSnapshot`].
///
/// Every state transition is validated by [`SystemState::can_transition_to`]
/// before being applied. Attempting an invalid transition is logged as a
/// programmer error and silently blocked — the system remains in its current
/// state.
///
/// # State diagram
///
/// ```text
/// Initializing
///     │
///     ▼
/// CheckingEnvironment ──── fatal ────▶ Fatal
///     │
///     ├── warnings ──▶ Degraded { recovering: true }
///     │                       │
///     └───────────────────────▶ Connecting
///                                     │ handshake OK
///                                     ▼
///                                   Ready ◀────────────────┐
///                                     │                     │
///                                     ▼                     │
///                               Operating { .. } ──────────┘
///                                     │
///                                     └── crash ──▶ Degraded { recovering: true }
///                                                         │ max retries
///                                                         ▼
///                                                       Fatal
///
/// Any non-terminal state ──── shutdown ──▶ ShuttingDown
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SystemState {
    /// The orchestrator is initialising internal subsystems.
    ///
    /// No commands are accepted. Transitions immediately to
    /// `CheckingEnvironment`.
    Initializing,

    /// The environment checker is running pre-flight checks.
    ///
    /// No commands are accepted while checks are running.
    CheckingEnvironment,

    /// The orchestrator has spawned the sidecar and is waiting for a
    /// successful handshake.
    ///
    /// No commands are accepted until the handshake completes.
    Connecting,

    /// The system is fully operational and ready for commands.
    Ready,

    /// A user-initiated operation is in progress.
    ///
    /// The specific operation is carried in `operation` so frontends can
    /// display what is happening without polling.
    Operating {
        /// The operation currently in progress.
        operation: ActiveOperation,
    },

    /// The system is operational at reduced capability.
    ///
    /// `reason` explains what is degraded and determines which commands remain
    /// available. `recovering` is `true` while the supervisor is actively
    /// attempting to restore full operation.
    Degraded {
        /// Why the system entered the degraded state.
        reason: DegradedReason,
        /// `true` while the supervisor is attempting automatic recovery.
        recovering: bool,
    },

    /// A graceful shutdown is in progress.
    ///
    /// The orchestrator has signalled the sidecar and is waiting for the
    /// emergency checkpoint confirmation (or a 5-second timeout). No commands
    /// are accepted.
    ShuttingDown,

    /// An unrecoverable error has occurred.
    ///
    /// `reason` is a human-readable explanation. The only valid action from
    /// this state is process exit.
    Fatal {
        /// Human-readable explanation of why the system entered the fatal state.
        reason: String,
    },
}

impl fmt::Display for SystemState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Initializing => write!(f, "Initializing"),
            Self::CheckingEnvironment => write!(f, "Checking environment"),
            Self::Connecting => write!(f, "Connecting"),
            Self::Ready => write!(f, "Ready"),
            Self::Operating { .. } => write!(f, "Operating"),
            Self::Degraded { .. } => write!(f, "Degraded"),
            Self::ShuttingDown => write!(f, "Shutting down"),
            Self::Fatal { .. } => write!(f, "Fatal"),
        }
    }
}

// ── impl SystemState ──────────────────────────────────────────────────────────

impl SystemState {
    /// Returns `true` if the requested transition from `self` to `to` is
    /// permitted by the transition table.
    ///
    /// This is the single enforcement point for state machine correctness.
    /// The caller (`Orchestrator::transition_to`) is responsible for logging
    /// and handling a `false` return — this method only answers the question,
    /// it does not take action.
    ///
    #[must_use]
    pub(crate) fn can_transition_to(&self, to: &Self) -> bool {
        match (self, to) {
            // ── Forward startup path ──────────────────────────────────────
            (Self::Initializing, Self::CheckingEnvironment) => true,
            (Self::CheckingEnvironment, Self::Connecting) => true,
            (Self::CheckingEnvironment, Self::Degraded { .. }) => true,
            (Self::CheckingEnvironment, Self::Fatal { .. }) => true,
            (Self::Connecting, Self::Ready) => true,
            (Self::Connecting, Self::Fatal { .. }) => true,

            // ── Normal operation ──────────────────────────────────────────
            (Self::Ready, Self::Operating { .. }) => true,
            (Self::Operating { .. }, Self::Ready) => true,

            // ── Degraded / recovery path ──────────────────────────────────
            (Self::Operating { .. }, Self::Degraded { .. }) => true,
            // Analysis commands in CapabilitiesMissing need Operating state
            (
                Self::Degraded {
                    reason: DegradedReason::CapabilitiesMissing,
                    ..
                },
                Self::Operating { .. },
            ) => true,
            (Self::Degraded { .. }, Self::Connecting) => true,
            (Self::Degraded { .. }, Self::Fatal { .. }) => true,

            // ── Graceful shutdown — reachable from any non-terminal state ─
            // Fatal and ShuttingDown are terminal: no exits allowed.
            (Self::Fatal { .. }, _) | (Self::ShuttingDown, _) => false,
            (_, Self::ShuttingDown) => true,

            // ── Everything else is forbidden ──────────────────────────────
            _ => false,
        }
    }

    /// Returns the set of commands the orchestrator will accept in this state.
    ///
    /// Commands not in this slice are rejected before they reach the sidecar.
    /// The rejection is surfaced to the frontend as an error snapshot, not a
    /// panic.
    ///
    /// Note that [`DegradedReason::CapabilitiesMissing`] and
    /// [`DegradedReason::IpcSocketUnavailable`] are the only degraded reasons
    /// that permit commands — analysis of existing files does not require
    /// capture permissions or a UDS socket.
    #[must_use]
    pub(crate) fn allowed_commands(&self) -> &[CommandKind] {
        match self {
            Self::Ready => &[
                CommandKind::StartCapture,
                CommandKind::RunWorkflow,
                CommandKind::ListInterfaces,
                CommandKind::LoadFile,
            ],

            Self::Operating { .. } => &[CommandKind::StopCapture, CommandKind::GetStats],

            Self::Degraded {
                reason: DegradedReason::CapabilitiesMissing
                    | DegradedReason::IpcSocketUnavailable,
                ..
            } => &[CommandKind::RunWorkflow, CommandKind::LoadFile],

            // All other degraded reasons: no commands until recovery completes.
            Self::Degraded { .. }
            | Self::Initializing
            | Self::CheckingEnvironment
            | Self::Connecting
            | Self::ShuttingDown
            | Self::Fatal { .. } => &[],
        }
    }

    /// Returns `true` if the system is in a terminal state from which no
    /// further transitions are possible except shutdown.
    ///
    /// Useful for supervisor and orchestrator loop guards.
    #[must_use]
    pub(crate) const fn is_terminal(&self) -> bool {
        matches!(self, Self::Fatal { .. } | Self::ShuttingDown)
    }

    /// Returns `true` if the system is degraded.
    ///
    /// Convenience predicate for frontends that need a simple yes/no without
    /// pattern-matching on the reason.
    #[must_use]
    pub(crate) const fn is_degraded(&self) -> bool {
        matches!(self, Self::Degraded { .. })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// A ready `Degraded` state for use in tests that don't care about the
    /// specific reason.
    fn degraded_crashed() -> SystemState {
        SystemState::Degraded {
            reason: DegradedReason::SidecarCrashed { restart_count: 1 },
            recovering: true,
        }
    }

    fn degraded_caps_missing() -> SystemState {
        SystemState::Degraded {
            reason: DegradedReason::CapabilitiesMissing,
            recovering: false,
        }
    }

    fn operating_capture() -> SystemState {
        SystemState::Operating {
            operation: ActiveOperation::Capturing {
                interface: "eth0".to_string(),
            },
        }
    }

    fn fatal() -> SystemState {
        SystemState::Fatal {
            reason: "test fatal".to_string(),
        }
    }

    // ── Valid transitions ─────────────────────────────────────────────────────

    #[test]
    fn given_initializing_when_to_checking_environment_then_allowed() {
        assert!(SystemState::Initializing.can_transition_to(&SystemState::CheckingEnvironment));
    }

    #[test]
    fn given_checking_environment_when_to_connecting_then_allowed() {
        assert!(SystemState::CheckingEnvironment.can_transition_to(&SystemState::Connecting));
    }

    #[test]
    fn given_checking_environment_when_to_degraded_then_allowed() {
        assert!(SystemState::CheckingEnvironment.can_transition_to(&degraded_crashed()));
    }

    #[test]
    fn given_checking_environment_when_to_fatal_then_allowed() {
        assert!(SystemState::CheckingEnvironment.can_transition_to(&fatal()));
    }

    #[test]
    fn given_connecting_when_to_ready_then_allowed() {
        assert!(SystemState::Connecting.can_transition_to(&SystemState::Ready));
    }

    #[test]
    fn given_connecting_when_to_fatal_then_allowed() {
        assert!(SystemState::Connecting.can_transition_to(&fatal()));
    }

    #[test]
    fn given_ready_when_to_operating_then_allowed() {
        assert!(SystemState::Ready.can_transition_to(&operating_capture()));
    }

    #[test]
    fn given_operating_when_to_ready_then_allowed() {
        assert!(operating_capture().can_transition_to(&SystemState::Ready));
    }

    #[test]
    fn given_operating_when_to_degraded_then_allowed() {
        assert!(operating_capture().can_transition_to(&degraded_crashed()));
    }

    #[test]
    fn given_degraded_when_to_connecting_then_allowed() {
        assert!(degraded_crashed().can_transition_to(&SystemState::Connecting));
    }

    #[test]
    fn given_degraded_when_to_fatal_then_allowed() {
        assert!(degraded_crashed().can_transition_to(&fatal()));
    }

    // ── ShuttingDown reachable from every non-terminal state ──────────────────

    #[test]
    fn given_initializing_when_to_shutting_down_then_allowed() {
        assert!(SystemState::Initializing.can_transition_to(&SystemState::ShuttingDown));
    }

    #[test]
    fn given_checking_environment_when_to_shutting_down_then_allowed() {
        assert!(SystemState::CheckingEnvironment.can_transition_to(&SystemState::ShuttingDown));
    }

    #[test]
    fn given_connecting_when_to_shutting_down_then_allowed() {
        assert!(SystemState::Connecting.can_transition_to(&SystemState::ShuttingDown));
    }

    #[test]
    fn given_ready_when_to_shutting_down_then_allowed() {
        assert!(SystemState::Ready.can_transition_to(&SystemState::ShuttingDown));
    }

    #[test]
    fn given_operating_when_to_shutting_down_then_allowed() {
        assert!(operating_capture().can_transition_to(&SystemState::ShuttingDown));
    }

    #[test]
    fn given_degraded_when_to_shutting_down_then_allowed() {
        assert!(degraded_crashed().can_transition_to(&SystemState::ShuttingDown));
    }

    // ── Invalid transitions ───────────────────────────────────────────────────

    #[test]
    fn given_ready_when_to_initializing_then_blocked() {
        assert!(!SystemState::Ready.can_transition_to(&SystemState::Initializing));
    }

    #[test]
    fn given_ready_when_to_connecting_then_blocked() {
        // Ready → Connecting is not in the table; recovery goes via Degraded
        assert!(!SystemState::Ready.can_transition_to(&SystemState::Connecting));
    }

    #[test]
    fn given_initializing_when_to_ready_then_blocked() {
        // Must pass through CheckingEnvironment first
        assert!(!SystemState::Initializing.can_transition_to(&SystemState::Ready));
    }

    #[test]
    fn given_operating_when_to_connecting_then_blocked() {
        // Must go through Degraded first
        assert!(!operating_capture().can_transition_to(&SystemState::Connecting));
    }

    #[test]
    fn given_fatal_when_to_shutting_down_then_blocked() {
        assert!(!fatal().can_transition_to(&SystemState::ShuttingDown));
    }

    #[test]
    fn given_fatal_when_to_ready_then_blocked() {
        assert!(!fatal().can_transition_to(&SystemState::Ready));
    }

    #[test]
    fn given_shutting_down_when_to_ready_then_blocked() {
        assert!(!SystemState::ShuttingDown.can_transition_to(&SystemState::Ready));
    }

    #[test]
    fn given_shutting_down_when_to_fatal_then_blocked() {
        // ShuttingDown is terminal — not even Fatal is allowed from here
        assert!(!SystemState::ShuttingDown.can_transition_to(&fatal()));
    }

    #[test]
    fn given_connecting_when_to_degraded_then_blocked() {
        // Connecting can only go to Ready or Fatal
        assert!(!SystemState::Connecting.can_transition_to(&degraded_crashed()));
    }

    // ── allowed_commands ──────────────────────────────────────────────────────

    #[test]
    fn given_ready_state_then_capture_workflow_interfaces_loadfile_allowed() {
        let allowed = SystemState::Ready.allowed_commands();
        assert!(allowed.contains(&CommandKind::StartCapture));
        assert!(allowed.contains(&CommandKind::RunWorkflow));
        assert!(allowed.contains(&CommandKind::ListInterfaces));
        assert!(allowed.contains(&CommandKind::LoadFile));
    }

    #[test]
    fn given_ready_state_then_stop_capture_and_get_stats_denied() {
        let allowed = SystemState::Ready.allowed_commands();
        assert!(!allowed.contains(&CommandKind::StopCapture));
        assert!(!allowed.contains(&CommandKind::GetStats));
    }

    #[test]
    fn given_operating_state_then_stop_and_stats_allowed() {
        let op = operating_capture();
        let allowed = op.allowed_commands();
        assert!(allowed.contains(&CommandKind::StopCapture));
        assert!(allowed.contains(&CommandKind::GetStats));
    }

    #[test]
    fn given_operating_state_then_start_capture_denied() {
        let op = operating_capture();
        let allowed = op.allowed_commands();
        assert!(!allowed.contains(&CommandKind::StartCapture));
    }

    #[test]
    fn given_degraded_capabilities_missing_then_workflow_and_load_allowed() {
        let deg = degraded_caps_missing();
        let allowed = deg.allowed_commands();
        assert!(allowed.contains(&CommandKind::RunWorkflow));
        assert!(allowed.contains(&CommandKind::LoadFile));
    }

    #[test]
    fn given_degraded_capabilities_missing_then_start_capture_denied() {
        let deg = degraded_caps_missing();
        let allowed = deg.allowed_commands();
        assert!(!allowed.contains(&CommandKind::StartCapture));
    }

    #[test]
    fn given_degraded_sidecar_crashed_then_no_commands_allowed() {
        assert!(degraded_crashed().allowed_commands().is_empty());
    }

    #[test]
    fn given_fatal_state_then_no_commands_allowed() {
        assert!(fatal().allowed_commands().is_empty());
    }

    #[test]
    fn given_connecting_state_then_no_commands_allowed() {
        assert!(SystemState::Connecting.allowed_commands().is_empty());
    }

    #[test]
    fn given_initializing_state_then_no_commands_allowed() {
        assert!(SystemState::Initializing.allowed_commands().is_empty());
    }

    #[test]
    fn given_shutting_down_state_then_no_commands_allowed() {
        assert!(SystemState::ShuttingDown.allowed_commands().is_empty());
    }

    // ── Degraded → Operating transitions ─────────────────────────────────

    #[test]
    fn given_degraded_caps_missing_when_to_operating_then_allowed() {
        let workflow_op = SystemState::Operating {
            operation: ActiveOperation::RunningWorkflow {
                name: "daily-audit".to_string(),
            },
        };
        assert!(degraded_caps_missing().can_transition_to(&workflow_op));
    }

    #[test]
    fn given_degraded_crashed_when_to_operating_then_blocked() {
        // Only CapabilitiesMissing gets Degraded → Operating; other reasons must recover first
        assert!(!degraded_crashed().can_transition_to(&operating_capture()));
    }

    #[test]
    fn given_degraded_ipc_unavailable_then_workflow_and_load_allowed() {
        let deg = SystemState::Degraded {
            reason: DegradedReason::IpcSocketUnavailable,
            recovering: false,
        };
        let allowed = deg.allowed_commands();
        assert!(allowed.contains(&CommandKind::RunWorkflow));
        assert!(allowed.contains(&CommandKind::LoadFile));
        assert!(!allowed.contains(&CommandKind::StartCapture));
    }

    // ── Convenience predicates ────────────────────────────────────────────────

    #[test]
    fn given_fatal_state_then_is_terminal() {
        assert!(fatal().is_terminal());
    }

    #[test]
    fn given_shutting_down_then_is_terminal() {
        assert!(SystemState::ShuttingDown.is_terminal());
    }

    #[test]
    fn given_ready_state_then_not_terminal() {
        assert!(!SystemState::Ready.is_terminal());
    }

    #[test]
    fn given_degraded_state_then_is_degraded() {
        assert!(degraded_crashed().is_degraded());
        assert!(degraded_caps_missing().is_degraded());
    }

    #[test]
    fn given_ready_state_then_not_degraded() {
        assert!(!SystemState::Ready.is_degraded());
    }

    #[test]
    fn given_operating_state_then_not_degraded() {
        assert!(!operating_capture().is_degraded());
    }
}
