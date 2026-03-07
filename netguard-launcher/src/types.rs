//! Shared primitive types with no intra-crate dependencies.
//!
//! This module is a **leaf** in the dependency graph — it imports nothing from
//! the rest of the crate. All other error modules depend on it, never the
//! reverse. This design avoids circular imports that would prevent
//! rust-analyzer from resolving symbols in module-level error files.
//!
//! # Types
//!
//! | Type | Purpose |
//! |------|---------|
//! | [`Severity`] | Three-level triage signal attached to every error |
//! | [`IpcErrorPayload`] | JSON-serializable envelope sent to the Python backend |
//! | [`IntoIpcError`] | Conversion trait for errors that cross the IPC boundary |
//!
//! # Usage
//!
//! Prefer importing these types via the re-exports in [`crate::error`] or the
//! crate root rather than from `crate::types` directly, unless you are writing
//! a module-level error file that must not import from `crate::error` (to
//! avoid a circular dependency).
//!
//! ```rust,ignore
//! // In module error files (avoids circular import):
//! use crate::types::Severity;
//!
//! // Everywhere else (convenience re-export):
//! use netguard_launcher::error::Severity;
//! ```

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/// Three-level triage signal that describes how serious an error is and
/// how the application should respond to it.
///
/// Every error type in this crate exposes a `severity()` method that returns
/// one of these variants. The caller — typically the top-level error handler
/// in `main` or the TUI event loop — uses the severity to decide what to do
/// next.
///
/// # Decision guide
///
/// | Severity | `recoverable()` contract | Recommended response |
/// |----------|--------------------------|----------------------|
/// | `Fatal`  | Always `false` | Log the error, show the message, shut down immediately |
/// | `Error`  | Usually `false`, sometimes `true` | Log, surface to the user, abort the current operation |
/// | `Warning`| Always `true` | Log, optionally surface to the user, continue |
///
/// # When to assign each variant
///
/// ## `Fatal`
/// Use when the process **cannot meaningfully continue** after the error.
/// Examples: Python interpreter not found, invalid state machine transition,
/// IPC socket creation failure.  After a `Fatal` error the only safe action
/// is to clean up and exit.
///
/// ## `Error`
/// Use when a specific **operation failed** but the application as a whole can
/// keep running.  Examples: failed to write a config file, heartbeat timeout,
/// permission check failure.  The user should be told something went wrong and
/// the failed sub-task should be aborted, but the process stays alive.
///
/// ## `Warning`
/// Use for **non-critical problems** where the application continues with
/// potentially degraded behaviour and the user can correct the issue
/// themselves.  Examples: bad CLI input, terminal too narrow, invalid log
/// level.  The error is surfaced as a notice rather than a hard stop.
///
/// # Example
///
/// ```rust
/// use netguard_launcher::error::Severity;
///
/// fn handle(severity: Severity, msg: &str) {
///     match severity {
///         Severity::Fatal   => { eprintln!("FATAL: {msg}"); std::process::exit(1); }
///         Severity::Error   => eprintln!("ERROR: {msg}"),
///         Severity::Warning => eprintln!("WARN:  {msg}"),
///     }
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Unrecoverable condition — the application cannot continue.
    ///
    /// Errors with this severity must cause the process to terminate.
    /// Attempting to resume normal operation after a `Fatal` error leads to
    /// undefined application state.
    Fatal,

    /// Recoverable or semi-recoverable error — an operation failed but the
    /// application process can stay alive.
    ///
    /// Whether a specific `Error`-severity error is truly recoverable is
    /// determined by the `recoverable()` method on the concrete error type.
    /// Do not assume `Error` implies `recoverable() == true`.
    Error,

    /// Non-critical problem — the application continues with degraded
    /// behaviour.
    ///
    /// All `Warning`-severity errors are recoverable (`recoverable()` always
    /// returns `true`).  The user may need to take corrective action (fix
    /// their input, resize the terminal, etc.) but the process should not
    /// exit.
    Warning,
}

// ---------------------------------------------------------------------------
// IpcErrorPayload / IntoIpcError
// ---------------------------------------------------------------------------

/// A serializable error payload transmitted over the Unix-domain-socket IPC
/// channel to the Python backend.
///
/// When the Rust launcher encounters an error that must be communicated to
/// the Python side (e.g. a socket-level problem, a handshake failure), it
/// serializes the error into an `IpcErrorPayload` and sends it as a JSON
/// frame. The Python backend can then take corrective action or surface the
/// error to the operator.
///
/// # Field semantics
///
/// | Field | Type | Description |
/// |-------|------|-------------|
/// | `code` | `String` | Stable, `SCREAMING_SNAKE_CASE` identifier (e.g. `"SOCKET_CREATION_FAILED"`). Never change a code once it is in production — the Python backend may match on it. |
/// | `message` | `String` | Human-readable English sentence suitable for log output. |
/// | `recoverable` | `bool` | `true` if the backend can retry or work around the error without restarting the launcher. |
/// | `suggestion` | `Option<String>` | Optional corrective action for the operator. Pass `None` when no actionable advice is available. |
///
/// # Stability contract
///
/// The JSON representation of this struct forms part of the IPC protocol.
/// Field names and their types are **stable** — renaming or removing a field
/// is a breaking change that requires a coordinated update to the Python
/// backend.
///
/// # Example (constructing manually)
///
/// ```rust
/// use netguard_launcher::error::IpcErrorPayload;
///
/// let payload = IpcErrorPayload {
///     code: "SOCKET_CREATION_FAILED".to_string(),
///     message: "Failed to create the IPC socket at '/run/ng.sock'.".to_string(),
///     recoverable: false,
///     suggestion: Some("Check that /run/ng/ exists and is writable.".to_string()),
/// };
/// ```
///
/// In practice, prefer implementing [`IntoIpcError`] and calling
/// `to_ipc_payload()` rather than constructing the payload manually.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct IpcErrorPayload {
    /// Stable, `SCREAMING_SNAKE_CASE` machine-readable error code.
    ///
    /// Must be unique within the IPC protocol and must never be changed once
    /// assigned.  The Python backend may `match` on this value.
    pub code: String,

    /// Human-readable English description of the error.
    ///
    /// Should be a complete sentence ending with a period.  Suitable for
    /// writing to a log file or displaying in operator tooling.
    pub message: String,

    /// `true` if the backend can continue or retry without restarting the
    /// launcher process.
    pub recoverable: bool,

    /// Optional corrective action for the operator.
    ///
    /// When present, should be a concrete, actionable instruction (e.g. a
    /// shell command to run).  Pass `None` when no useful advice is
    /// available.
    pub suggestion: Option<String>,
}

/// Implemented by error types whose instances can be transmitted to the
/// Python backend over the IPC channel.
///
/// Only implement this trait on errors that **actually cross the IPC
/// boundary** — i.e. errors that originate in the Rust launcher and that the
/// Python backend needs to know about in order to take action or inform the
/// operator. Errors that are handled entirely within the launcher (e.g.
/// [`crate::infra::config::error::ConfigError`]) do not need this trait.
///
/// # Implementation guide
///
/// 1. Assign a stable `SCREAMING_SNAKE_CASE` code to each variant.
/// 2. Delegate `message`, `recoverable`, and `suggestion` to the existing
///    `user_message()`, `recoverable()`, and `suggestion()` methods so the
///    IPC payload stays consistent with what the UI would show.
///
/// # Example
///
/// ```rust,ignore
/// use crate::types::{IntoIpcError, IpcErrorPayload};
///
/// impl IntoIpcError for MyError {
///     fn to_ipc_payload(&self) -> IpcErrorPayload {
///         IpcErrorPayload {
///             code: self.ipc_code().to_string(),
///             message: self.user_message(),
///             recoverable: self.recoverable(),
///             suggestion: self.suggestion(),
///         }
///     }
/// }
/// ```
pub trait IntoIpcError {
    /// Converts this error into an [`IpcErrorPayload`] suitable for
    /// serialization and transmission over the IPC channel.
    fn to_ipc_payload(&self) -> IpcErrorPayload;
}
