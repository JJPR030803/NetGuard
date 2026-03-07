//! Crate-level error umbrella.
//!
//! # Overview
//!
//! This module provides [`NetGuardError`], the single top-level error type
//! returned by every public fallible API in this crate.  It is an enum whose
//! variants each wrap one domain-specific error type from the subsystems
//! below.
//!
//! ```text
//! NetGuardError
//! ├── Orchestrator(OrchestratorError)   — state-machine / lifecycle failures
//! ├── Ipc(IpcError)                     — Unix-socket communication failures
//! ├── Permission(PermissionError)       — capability / privilege failures
//! ├── Python(PythonError)               — Python interpreter / venv failures
//! ├── Config(ConfigError)               — TOML config read / write failures
//! ├── Logging(LoggingError)             — logging subsystem failures
//! ├── Validation(ValidationError)       — user-supplied input failures
//! └── Display(DisplayError)             — terminal / TUI rendering failures
//! ```
//!
//! # Using the `?` operator
//!
//! Because every domain error implements `From<DomainError> for NetGuardError`
//! (via `#[from]`), you can use `?` freely in functions that return
//! `crate::Result<T>` without explicit conversions:
//!
//! ```rust,ignore
//! fn start() -> crate::Result<()> {
//!     validate_config()?;   // ValidationError  → NetGuardError::Validation
//!     check_permissions()?; // PermissionError  → NetGuardError::Permission
//!     spawn_python()?;      // PythonError      → NetGuardError::Python
//!     Ok(())
//! }
//! ```
//!
//! # Triaging errors at the call site
//!
//! Every `NetGuardError` exposes four uniform methods for decision-making:
//!
//! | Method | Returns | Use it to… |
//! |--------|---------|-----------|
//! | `user_message()` | `String` | Show a human-readable sentence to the operator |
//! | `suggestion()` | `Option<String>` | Optionally show a corrective action |
//! | `severity()` | [`Severity`] | Decide how urgently to respond (Fatal / Error / Warning) |
//! | `recoverable()` | `bool` | Decide whether to abort the process or continue |
//!
//! Typical top-level error-handling pattern:
//!
//! ```rust,ignore
//! match err.severity() {
//!     Severity::Fatal   => { log_and_exit(&err); }
//!     Severity::Error   => { log_error(&err); abort_current_operation(); }
//!     Severity::Warning => { log_warn(&err); /* continue */ }
//! }
//! ```
//!
//! # Re-exported primitives
//!
//! [`Severity`], [`IpcErrorPayload`], and [`IntoIpcError`] are defined in
//! [`crate::types`] (so module error files can import them without a circular
//! dependency) and re-exported here so callers only need one import path.

pub use crate::types::{IntoIpcError, IpcErrorPayload, Severity};

use crate::core::error::ValidationError;
use crate::display::error::DisplayError;
use crate::infra::config::error::ConfigError;
use crate::infra::ipc::error::IpcError;
use crate::infra::logging::error::LoggingError;
use crate::infra::permissions::error::PermissionError;
use crate::infra::python::error::PythonError;
use crate::orchestrator::error::OrchestratorError;

// ---------------------------------------------------------------------------
// NetGuardError
// ---------------------------------------------------------------------------

/// Top-level error type for the `netguard-launcher` crate.
///
/// All public fallible functions return `crate::Result<T>`, which is an alias
/// for `std::result::Result<T, NetGuardError>`.  This enum collects every
/// domain-specific error under one roof so callers never need to import
/// individual subsystem error types unless they want to inspect or pattern-
/// match on the inner variant.
///
/// # Variant guide
///
/// | Variant | Inner type | Raised when… |
/// |---------|-----------|--------------|
/// | `Orchestrator` | [`OrchestratorError`] | The system state machine makes an illegal transition, a supervisor exceeds its restart budget, or a handshake times out |
/// | `Ipc` | [`IpcError`] | The Unix-domain-socket layer fails to create, connect, read from, or write to a socket |
/// | `Permission` | [`PermissionError`] | A required Linux capability, macOS BPF permission, or Windows elevation is missing |
/// | `Python` | [`PythonError`] | The Python interpreter or virtual environment cannot be found, validated, or spawned |
/// | `Config` | [`ConfigError`] | A TOML config file contains invalid syntax, an unrecognised field, or cannot be read/written |
/// | `Logging` | [`LoggingError`] | The logging subscriber cannot be initialized, or the log file is not writable |
/// | `Validation` | [`ValidationError`] | A user-supplied CLI argument or config value fails semantic validation |
/// | `Display` | [`DisplayError`] | The terminal is too small, contains invalid UTF-8, or the TUI fails to render |
///
/// # Downcasting
///
/// If you need to inspect the inner error you can `match` on the variant:
///
/// ```rust,ignore
/// match err {
///     NetGuardError::Validation(v) => handle_bad_input(v),
///     NetGuardError::Ipc(i)        => handle_ipc_failure(i),
///     other                        => return Err(other),
/// }
/// ```
#[derive(Debug, thiserror::Error)]
pub enum NetGuardError {
    /// Wraps [`OrchestratorError`]: state-machine / lifecycle failures.
    ///
    /// Raised by the orchestrator layer when the system cannot transition
    /// between states, when a command is invalid in the current state, or
    /// when the supervised Python process fails too many times.
    #[error(transparent)]
    Orchestrator(#[from] OrchestratorError),

    /// Wraps [`IpcError`]: Unix-domain-socket communication failures.
    ///
    /// Raised by the IPC layer whenever a socket operation fails — including
    /// creation, binding, connection, message framing, serialization, and
    /// heartbeat monitoring.
    #[error(transparent)]
    Ipc(#[from] IpcError),

    /// Wraps [`PermissionError`]: capability / privilege failures.
    ///
    /// Raised when the process lacks the OS-level rights required to capture
    /// packets (Linux capabilities, macOS BPF access, Windows elevation).
    #[error(transparent)]
    Permission(#[from] PermissionError),

    /// Wraps [`PythonError`]: Python interpreter / virtual-environment failures.
    ///
    /// Raised when the launcher cannot locate a suitable Python interpreter,
    /// verify the virtual environment, confirm required packages are
    /// installed, or spawn the backend process.
    #[error(transparent)]
    Python(#[from] PythonError),

    /// Wraps [`ConfigError`]: TOML configuration read / write failures.
    ///
    /// Raised when a config file is syntactically invalid, contains an
    /// unrecognised or out-of-range field, or when file I/O fails.
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// Wraps [`LoggingError`]: logging subsystem failures.
    ///
    /// Raised when the tracing subscriber cannot be installed or when the
    /// target log file is not writable.
    #[error(transparent)]
    Logging(#[from] LoggingError),

    /// Wraps [`ValidationError`]: user-supplied input failures.
    ///
    /// Raised by the CLI / config validation layer when a value provided by
    /// the user (network interface name, BPF filter, IP address, duration,
    /// etc.) fails semantic validation.  Always recoverable — the user can
    /// correct the input and retry.
    #[error(transparent)]
    Validation(#[from] ValidationError),

    /// Wraps [`DisplayError`]: terminal / TUI rendering failures.
    ///
    /// Raised when the terminal environment prevents the TUI from rendering
    /// correctly (too narrow, invalid UTF-8 output, render engine panic).
    #[error(transparent)]
    Display(#[from] DisplayError),
}

impl NetGuardError {
    /// Returns a complete English sentence describing the error, suitable for
    /// display to the operator or for writing to a log file.
    ///
    /// The message is generated by the inner domain error and will always be
    /// non-empty.  It describes *what went wrong* in plain language without
    /// exposing internal implementation details.
    ///
    /// Prefer this method over `to_string()` / the `Display` impl when you
    /// want a controlled, stable presentation string — `Display` forwards to
    /// the inner `thiserror` format string which may differ in style.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// eprintln!("Error: {}", err.user_message());
    /// ```
    #[must_use]
    pub fn user_message(&self) -> String {
        match self {
            Self::Orchestrator(e) => e.user_message(),
            Self::Ipc(e) => e.user_message(),
            Self::Permission(e) => e.user_message(),
            Self::Python(e) => e.user_message(),
            Self::Config(e) => e.user_message(),
            Self::Logging(e) => e.user_message(),
            Self::Validation(e) => e.user_message(),
            Self::Display(e) => e.user_message(),
        }
    }

    /// Returns an optional actionable suggestion for the operator.
    ///
    /// When `Some`, the string contains a concrete corrective action —
    /// typically a shell command to run or a specific setting to change.
    /// When `None`, no useful advice is available for this particular error.
    ///
    /// This value is safe to display directly to the user alongside
    /// `user_message()`:
    ///
    /// ```rust,ignore
    /// if let Some(hint) = err.suggestion() {
    ///     eprintln!("Suggestion: {hint}");
    /// }
    /// ```
    #[must_use]
    pub fn suggestion(&self) -> Option<String> {
        match self {
            Self::Orchestrator(e) => e.suggestion(),
            Self::Ipc(e) => e.suggestion(),
            Self::Permission(e) => e.suggestion(),
            Self::Python(e) => e.suggestion(),
            Self::Config(e) => e.suggestion(),
            Self::Logging(e) => e.suggestion(),
            Self::Validation(e) => e.suggestion(),
            Self::Display(e) => e.suggestion(),
        }
    }

    /// Returns the [`Severity`] triage level for this error.
    ///
    /// Use this at the top-level error handler to decide how to respond:
    ///
    /// - [`Severity::Fatal`] → log and exit the process immediately.
    /// - [`Severity::Error`] → log, surface to the user, abort the current
    ///   operation (but the process may stay alive).
    /// - [`Severity::Warning`] → log, optionally notify the user, continue.
    ///
    /// See [`Severity`] for the full decision guide.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        match self {
            Self::Orchestrator(e) => e.severity(),
            Self::Ipc(e) => e.severity(),
            Self::Permission(e) => e.severity(),
            Self::Python(e) => e.severity(),
            Self::Config(e) => e.severity(),
            Self::Logging(e) => e.severity(),
            Self::Validation(e) => e.severity(),
            Self::Display(e) => e.severity(),
        }
    }

    /// Returns `true` if the application can continue after this error without
    /// a full process restart.
    ///
    /// A recoverable error means the **current operation** failed but the
    /// process state is still valid.  The caller may log the error, inform
    /// the user, and attempt a retry or a graceful degradation path.
    ///
    /// A non-recoverable error (`false`) means the process is in an undefined
    /// or unsafe state.  The only safe action is to clean up and exit.
    ///
    /// # Important
    ///
    /// `recoverable() == true` does **not** mean the error will fix itself
    /// automatically.  It only means the *process* can survive — the *user*
    /// may still need to take action (e.g. fix bad input, install a missing
    /// dependency) before retrying.
    #[must_use]
    pub const fn recoverable(&self) -> bool {
        match self {
            Self::Orchestrator(e) => e.recoverable(),
            Self::Ipc(e) => e.recoverable(),
            Self::Permission(e) => e.recoverable(),
            Self::Python(e) => e.recoverable(),
            Self::Config(e) => e.recoverable(),
            Self::Logging(e) => e.recoverable(),
            Self::Validation(e) => e.recoverable(),
            Self::Display(e) => e.recoverable(),
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

    #[test]
    fn validation_error_converts_via_from() {
        let inner = ValidationError::InvalidDuration {
            input: "bad".to_string(),
        };
        let err = NetGuardError::from(inner);
        assert!(!err.user_message().is_empty());
        assert!(err.suggestion().is_some());
        assert!(err.recoverable());
        assert_eq!(err.severity(), Severity::Warning);
    }

    #[test]
    fn display_error_converts_via_from() {
        let inner = DisplayError::TerminalTooSmall {
            width: 40,
            min_width: 80,
        };
        let err = NetGuardError::from(inner);
        assert!(err.user_message().contains("40"));
        assert!(err.recoverable());
    }

    #[test]
    fn question_mark_operator_works() {
        fn try_validate() -> crate::Result<()> {
            let e = ValidationError::InvalidIpAddress {
                input: "bad".to_string(),
            };
            Err(e)?
        }
        let result = try_validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(!err.user_message().is_empty());
    }
}
