//! Errors produced by the logging subsystem.
//!
//! `NetGuard` uses [`tracing`] for structured logging.  This module covers
//! failures in the logging infrastructure itself: subscriber initialization,
//! log file access, and log level parsing.

use std::path::PathBuf;

use crate::types::Severity;

/// Errors that occur while initializing or operating the logging subsystem.
///
/// # Severity & recoverability
///
/// | Variant | Severity | Recoverable | Rationale |
/// |---------|----------|-------------|-----------|
/// | `FileNotWritable` | Warning | Yes | Fall back to stderr-only logging |
/// | `InvalidLogLevel` | Warning | Yes | Fall back to default level (`info`) |
/// | `SubscriberInitFailed` | Error | No | Cannot install a second global subscriber |
///
/// # When to raise
///
/// Raise `LoggingError` only from the logging initialization code.  Do not
/// use it for application-level log write failures during normal operation
/// (those are typically silently ignored by the `tracing` crate).
#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    /// The log file target is not writable.
    ///
    /// Raised when the logging layer attempts to open or create the log file
    /// and the OS returns a permission or I/O error.  Recoverable — the
    /// caller can fall back to writing logs to stderr only.
    #[error("Log file is not writable at {path}: {source}")]
    FileNotWritable {
        path: PathBuf,
        source: std::io::Error,
    },

    /// The log level string could not be parsed.
    ///
    /// Raised when the value provided via `--log-level` or the config file
    /// is not one of the recognised tracing filter directives (`trace`,
    /// `debug`, `info`, `warn`, `error`).  Recoverable — fall back to the
    /// default level.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use netguard_launcher::infra::logging::error::LoggingError;
    ///
    /// let err = LoggingError::InvalidLogLevel {
    ///     input: "verbose".to_string(), // the invalid string the user provided; valid values: "trace", "debug", "info", "warn", "error"
    /// };
    /// ```
    #[error("Invalid log level: '{input}'")]
    InvalidLogLevel { input: String },

    /// The global tracing subscriber could not be installed.
    ///
    /// Raised when `tracing_subscriber::set_global_default` (or equivalent)
    /// fails because a subscriber has already been installed.  This is
    /// typically caused by test harness interference or double-initialization.
    /// Not recoverable — the process must restart with a clean state.
    #[error("Failed to initialize the logging subscriber: {reason}")]
    SubscriberInitFailed { reason: String },
}

impl LoggingError {
    #[must_use = "User messages are only used for logging purposes; do not call this method unless you know what you're doing!"]
    pub fn user_message(&self) -> String {
        match self {
            Self::FileNotWritable { path, source } => format!(
                "The log file '{}' is not writable: {source}.",
                path.display()
            ),
            Self::InvalidLogLevel { input } => {
                format!("'{input}' is not a valid log level.")
            }
            Self::SubscriberInitFailed { reason } => {
                format!("Failed to initialize the logging system: {reason}.")
            }
        }
    }

    #[must_use = "User messages are only used for logging purposes; do not call this method unless you know what you're doing!"]
    pub fn suggestion(&self) -> Option<String> {
        match self {
            Self::FileNotWritable { path, .. } => {
                let parent = path.parent().unwrap_or(path.as_path());
                Some(format!(
                    "Ensure the directory '{0}' exists and is writable: \
                     `mkdir -p {0} && chmod 755 {0}`",
                    parent.display()
                ))
            }
            Self::InvalidLogLevel { .. } => Some(
                "Valid log levels are: trace, debug, info, warn, error. \
                 Example: `--log-level info`."
                    .to_string(),
            ),
            Self::SubscriberInitFailed { .. } => Some(
                "This is an internal initialization error. \
                 Check that no other logging subscriber is already installed."
                    .to_string(),
            ),
        }
    }

    #[must_use]
    pub const fn severity(&self) -> Severity {
        match self {
            Self::FileNotWritable { .. } | Self::InvalidLogLevel { .. } => Severity::Warning,
            Self::SubscriberInitFailed { .. } => Severity::Error,
        }
    }

    #[must_use]
    pub const fn recoverable(&self) -> bool {
        match self {
            Self::FileNotWritable { .. } | Self::InvalidLogLevel { .. } => true,
            Self::SubscriberInitFailed { .. } => false,
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

    fn make_io_error() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied")
    }

    #[test]
    fn file_not_writable_user_message_and_suggestion() {
        let err = LoggingError::FileNotWritable {
            path: PathBuf::from("/var/log/netguard/app.log"),
            source: make_io_error(),
        };
        let msg = err.user_message();
        assert!(msg.contains("/var/log/netguard/app.log"));
        assert!(err.suggestion().unwrap().contains("mkdir"));
        assert!(err.recoverable());
        assert_eq!(err.severity(), Severity::Warning);
    }

    #[test]
    fn invalid_log_level_user_message_and_suggestion() {
        let err = LoggingError::InvalidLogLevel {
            input: "verbose".to_string(),
        };
        let msg = err.user_message();
        assert!(msg.contains("verbose"));
        let sug = err.suggestion().unwrap();
        assert!(sug.contains("trace") || sug.contains("debug") || sug.contains("info"));
    }

    #[test]
    fn subscriber_init_failed_not_recoverable() {
        let err = LoggingError::SubscriberInitFailed {
            reason: "global default already set".to_string(),
        };
        assert!(err.user_message().contains("global default already set"));
        assert!(!err.recoverable());
        assert_eq!(err.severity(), Severity::Error);
        assert!(err.suggestion().is_some());
    }
}
