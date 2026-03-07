//! Errors produced while reading, parsing, or writing configuration files.
//!
//! The configuration layer reads a TOML file on startup and optionally writes
//! an updated file when settings change.  Errors here represent either TOML
//! syntax problems, semantic validation failures, or file I/O failures.
//!
//! # What is NOT a `ConfigError`
//!
//! - A missing *optional* field — filled from defaults, never an error.
//! - A value that fails semantic domain validation — use
//!   [`crate::core::error::ValidationError`] instead.
//! - A failed launch sequence that is not directly caused by config I/O —
//!   use [`crate::orchestrator::error::OrchestratorError`] instead.

use std::path::PathBuf;

use crate::types::Severity;

/// Errors that occur while reading, parsing, or writing configuration files.
///
/// # Severity & recoverability
///
/// | Variant | Severity | Recoverable | Rationale |
/// |---------|----------|-------------|-----------|
/// | `ParseError` | Error | Yes | Fix the TOML syntax and reload |
/// | `InvalidField` | Warning | Yes | Fix the value; field will use default |
/// | `ReadFailed` | Error | Yes | Fix file permissions/path and retry |
/// | `WriteFailed` | Warning | Yes | Fix directory permissions and retry |
/// | `FailedToLaunch` | Fatal | No | Launch sequence could not proceed |
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The configuration file contains invalid TOML syntax.
    ///
    /// Raised when `toml::from_str` fails.  The inner `source` carries the
    /// detailed parse error including line/column information which should be
    /// forwarded to the user.  Recoverable — fix the syntax and reload.
    #[error("Failed to parse configuration: {source}")]
    ParseError { source: toml::de::Error },

    /// A known configuration field has an invalid value.
    ///
    /// Raised after successful parsing when a field value fails domain
    /// validation (e.g. `log_level = "verbose"` is syntactically valid TOML
    /// but not a recognised log level).  Populate `field` with the TOML key
    /// path (e.g. `"logging.level"`) and `reason` with a human-readable
    /// explanation.
    ///
    /// For unknown/unrecognised fields, use a `Warning` log instead of
    /// raising this error — unknown fields should be tolerated for forward
    /// compatibility.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use netguard_launcher::infra::config::error::ConfigError;
    ///
    /// let err = ConfigError::InvalidField {
    ///     field: "logging.level".to_string(), // dot-separated TOML key path, e.g. "logging.level", "ipc.socket_path", "capture.interface"
    ///     reason: "expected one of: trace, debug, info, warn, error".to_string(),
    /// };
    /// ```
    #[error("Invalid configuration field '{field}': {reason}")]
    InvalidField { field: String, reason: String },

    /// The configuration file could not be read from disk.
    ///
    /// Wraps the underlying [`std::io::Error`].  Common causes: the file
    /// doesn't exist yet (first run), insufficient permissions.  Recoverable
    /// — the caller should fall back to defaults if the file is absent.
    #[error("Failed to read configuration from {path}: {source}")]
    ReadFailed {
        path: PathBuf,
        source: std::io::Error,
    },

    /// The configuration file could not be written to disk.
    ///
    /// Wraps the underlying [`std::io::Error`].  Typically caused by
    /// directory not writable or disk full.  Recoverable — the in-memory
    /// config is still valid; only persistence failed.
    #[error("Failed to write configuration to {path}: {source}")]
    WriteFailed {
        path: PathBuf,
        source: std::io::Error,
    },

    /// The launch sequence could not proceed due to a configuration-related
    /// failure.
    ///
    /// This is a catch-all Fatal variant for cases where the config layer
    /// determines that the application cannot start (e.g. required mandatory
    /// fields are absent and there is no safe default).  Always Fatal and
    /// non-recoverable.
    #[error("Failed to launch")]
    FailedToLaunch,
}

impl ConfigError {
    #[must_use]
    pub fn user_message(&self) -> String {
        match self {
            Self::ParseError { source } => {
                format!("The configuration file contains invalid TOML syntax: {source}.")
            }
            Self::InvalidField { field, reason } => {
                format!("The configuration field '{field}' has an invalid value: {reason}.")
            }
            Self::ReadFailed { path, source } => {
                format!(
                    "Failed to read the configuration file '{}': {source}.",
                    path.display()
                )
            }
            Self::WriteFailed { path, source } => {
                format!(
                    "Failed to write the configuration file '{}': {source}.",
                    path.display()
                )
            }
            Self::FailedToLaunch => "Failed at launching the network".to_owned(),
        }
    }

    #[must_use]
    pub fn suggestion(&self) -> Option<String> {
        match self {
            Self::ParseError { .. } => Some(
                "Check the configuration file for syntax errors. \
                 Use a TOML validator such as `taplo lint <file>` to identify issues."
                    .to_string(),
            ),
            Self::InvalidField { field, .. } => Some(format!(
                "Consult the NetGuard documentation for valid values for the '{field}' field, \
                 or remove it to use the default."
            )),
            Self::ReadFailed { path, .. } => Some(format!(
                "Ensure the file '{}' exists and is readable by the current user.",
                path.display()
            )),
            Self::WriteFailed { path, .. } => Some(format!(
                "Ensure the directory '{}' is writable by the current user.",
                path.parent().unwrap_or(path.as_path()).display()
            )),
            Self::FailedToLaunch => None,
        }
    }

    #[must_use]
    pub const fn severity(&self) -> Severity {
        match self {
            Self::ParseError { .. } | Self::ReadFailed { .. } => Severity::Error,
            Self::InvalidField { .. } | Self::WriteFailed { .. } => Severity::Warning,
            Self::FailedToLaunch => Severity::Fatal,
        }
    }

    #[must_use]
    pub const fn recoverable(&self) -> bool {
        match self {
            Self::ParseError { .. }
            | Self::InvalidField { .. }
            | Self::ReadFailed { .. }
            | Self::WriteFailed { .. } => true,
            Self::FailedToLaunch => false,
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

    fn make_toml_error() -> toml::de::Error {
        toml::from_str::<toml::Value>("invalid [ toml").unwrap_err()
    }

    fn make_io_error() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied")
    }

    #[test]
    fn parse_error_user_message_and_suggestion() {
        let err = ConfigError::ParseError {
            source: make_toml_error(),
        };
        let msg = err.user_message();
        assert!(msg.contains("TOML") || msg.contains("configuration"));
        let sug = err.suggestion().unwrap();
        assert!(sug.contains("TOML") || sug.contains("syntax"));
    }

    #[test]
    fn invalid_field_user_message_and_suggestion() {
        let err = ConfigError::InvalidField {
            field: "log_level".to_string(),
            reason: "expected one of: trace, debug, info, warn, error".to_string(),
        };
        let msg = err.user_message();
        assert!(msg.contains("log_level"));
        let sug = err.suggestion().unwrap();
        assert!(sug.contains("log_level"));
    }

    #[test]
    fn read_failed_user_message_and_suggestion() {
        let err = ConfigError::ReadFailed {
            path: PathBuf::from("/etc/netguard/config.toml"),
            source: make_io_error(),
        };
        let msg = err.user_message();
        assert!(msg.contains("/etc/netguard/config.toml"));
        assert!(err.suggestion().is_some());
    }

    #[test]
    fn write_failed_user_message_and_suggestion() {
        let err = ConfigError::WriteFailed {
            path: PathBuf::from("/etc/netguard/config.toml"),
            source: make_io_error(),
        };
        let msg = err.user_message();
        assert!(msg.contains("/etc/netguard/config.toml"));
        assert!(err.suggestion().is_some());
    }

    #[test]
    fn all_config_errors_are_recoverable() {
        let errors: Vec<ConfigError> = vec![
            ConfigError::ParseError {
                source: make_toml_error(),
            },
            ConfigError::InvalidField {
                field: "x".to_string(),
                reason: "y".to_string(),
            },
            ConfigError::ReadFailed {
                path: PathBuf::from("/tmp/x"),
                source: make_io_error(),
            },
            ConfigError::WriteFailed {
                path: PathBuf::from("/tmp/x"),
                source: make_io_error(),
            },
        ];
        for err in &errors {
            assert!(err.recoverable(), "expected recoverable: {err:?}");
        }
    }
}
