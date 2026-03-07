//! Errors produced by the core domain layer.
//!
//! Currently this module exposes a single error type, [`ValidationError`],
//! which covers all semantic validation of user-supplied values.  If the
//! core domain grows additional sub-concerns (e.g. packet parsing, rule
//! evaluation) their error types should be added here.

use std::path::PathBuf;

use crate::types::Severity;

/// Errors produced when validating user-supplied input before processing.
///
/// `ValidationError` is raised exclusively by the CLI / config validation
/// layer — *before* any I/O or system calls are made.  Every variant is
/// **always recoverable** (`recoverable()` returns `true`) and has
/// [`Severity::Warning`], because the user can correct their input and retry
/// without restarting the application.
///
/// # When to raise vs. when not to raise
///
/// Raise a `ValidationError` when:
/// - A value supplied by the user (CLI flag, TOML field) fails a semantic
///   rule that is independent of system state (e.g. "this string is not a
///   valid IP address").
///
/// Do **not** raise a `ValidationError` when:
/// - The failure depends on runtime state (e.g. "this interface doesn't
///   exist on this machine" — that is an environment check, use
///   [`crate::orchestrator::error::EnvironmentError`] instead).
/// - The failure is an I/O error (use [`crate::infra::config::error::ConfigError`]).
///
/// # Severity & recoverability
///
/// All variants are `Warning` / `recoverable = true` by design.  The
/// validation layer's contract is that it never puts the system into an
/// unsafe state — it only rejects bad input before anything happens.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    /// The network interface name supplied by the user does not pass
    /// syntactic or semantic validation.
    ///
    /// Raise this when the interface name string is empty, contains
    /// disallowed characters, or is otherwise structurally invalid.
    /// For runtime failures (e.g. the interface doesn't exist on this
    /// host), use [`crate::orchestrator::error::EnvironmentError::SocketDirNotWritable`]
    /// or a dedicated environment check instead.
    #[error("Invalid network interface '{name}': {reason}")]
    InvalidInterface { name: String, reason: String },

    /// The BPF filter expression could not be parsed.
    ///
    /// Raise this when `libpcap` or the filter pre-validator rejects the
    /// expression string.  Include the raw parse error from the library in
    /// `parse_error` so the user can diagnose the exact problem.
    #[error("Invalid BPF filter expression '{expression}': {parse_error}")]
    InvalidBpfFilter {
        expression: String,
        parse_error: String,
    },

    /// The output file path fails validation.
    ///
    /// Raise this when the path string is syntactically invalid or when a
    /// static check (e.g. extension not `.pcap`) fails.  Do **not** raise
    /// this for runtime I/O failures (missing directory, permission denied)
    /// — those are [`crate::infra::config::error::ConfigError::WriteFailed`].
    #[error("Invalid output path '{path}': {reason}", path = path.display())]
    InvalidOutputPath { path: PathBuf, reason: String },

    /// A duration string could not be parsed.
    ///
    /// Raise this when the user supplies a duration that cannot be
    /// interpreted (e.g. `"foo"`, `"5"`  without a unit suffix).  Valid
    /// formats are `"<n>s"`, `"<n>m"`, `"<n>h"`.
    #[error("Invalid duration value: '{input}'")]
    InvalidDuration { input: String },

    /// An IP address string could not be parsed.
    ///
    /// Raise this when a value that must be an IPv4 or IPv6 address is
    /// syntactically invalid (e.g. `"999.0.0.1"`, `"not-an-ip"`).
    #[error("Invalid IP address: '{input}'")]
    InvalidIpAddress { input: String },

    /// A numeric field value is outside its accepted range.
    ///
    /// Raise this when a number (snapshot length, port, timeout seconds,
    /// etc.) falls outside `[min, max]`.  Prefer this over ad-hoc error
    /// messages so the user always sees a consistent "value N is outside
    /// [min, max]" pattern.
    #[error("Field '{field}' value {value} is out of range [{min}, {max}]")]
    OutOfRange {
        field: String,
        value: i64,
        min: i64,
        max: i64,
    },
}

impl ValidationError {
    #[must_use]
    pub fn user_message(&self) -> String {
        match self {
            Self::InvalidInterface { name, reason } => {
                format!("The network interface '{name}' is not valid: {reason}.")
            }
            Self::InvalidBpfFilter {
                expression,
                parse_error,
            } => {
                format!(
                    "The BPF filter expression '{expression}' could not be parsed: {parse_error}."
                )
            }
            Self::InvalidOutputPath { path, reason } => {
                format!(
                    "The output path '{}' is not usable: {reason}.",
                    path.display()
                )
            }
            Self::InvalidDuration { input } => {
                format!(
                    "'{input}' is not a valid duration. \
                     Use a format like '30s', '5m', or '1h'."
                )
            }
            Self::InvalidIpAddress { input } => {
                format!(
                    "'{input}' is not a valid IP address. \
                     Provide an IPv4 or IPv6 address."
                )
            }
            Self::OutOfRange {
                field,
                value,
                min,
                max,
            } => {
                format!(
                    "The value {value} for '{field}' is outside the accepted range [{min}, {max}]."
                )
            }
        }
    }

    #[must_use]
    pub fn suggestion(&self) -> Option<String> {
        match self {
            Self::InvalidInterface { .. } => Some(
                "Run `ip link show` (Linux) or `ifconfig -l` (macOS) to list available interfaces."
                    .to_string(),
            ),
            Self::InvalidBpfFilter { .. } => Some(
                "Consult the BPF filter syntax reference: \
                 https://www.tcpdump.org/manpages/pcap-filter.7.html"
                    .to_string(),
            ),
            Self::InvalidOutputPath { .. } => Some(
                "Ensure the parent directory exists and you have write permission.".to_string(),
            ),
            Self::InvalidDuration { .. } => Some(
                "Use a duration suffix: s (seconds), m (minutes), h (hours). \
                 Example: '5m'."
                    .to_string(),
            ),
            Self::InvalidIpAddress { .. } => {
                Some("Example valid addresses: '192.168.1.1' (IPv4) or '::1' (IPv6).".to_string())
            }
            Self::OutOfRange { min, max, .. } => Some(format!(
                "Provide a value between {min} and {max} inclusive."
            )),
        }
    }
    #[must_use]
    pub const fn severity(&self) -> Severity {
        Severity::Warning
    }
    #[must_use]
    pub const fn recoverable(&self) -> bool {
        true
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
    fn invalid_interface_user_message() {
        let err = ValidationError::InvalidInterface {
            name: "eth99".to_string(),
            reason: "interface not found".to_string(),
        };
        let msg = err.user_message();
        assert!(msg.contains("eth99"));
        assert!(msg.contains("interface not found"));
        assert!(err.suggestion().unwrap().contains("ip link show"));
    }

    #[test]
    fn invalid_bpf_filter_user_message() {
        let err = ValidationError::InvalidBpfFilter {
            expression: "port abc".to_string(),
            parse_error: "expected integer".to_string(),
        };
        let msg = err.user_message();
        assert!(msg.contains("port abc"));
        assert!(msg.contains("expected integer"));
        assert!(err.suggestion().unwrap().contains("tcpdump"));
    }

    #[test]
    fn invalid_output_path_user_message() {
        let err = ValidationError::InvalidOutputPath {
            path: PathBuf::from("/no/such/dir/file.pcap"),
            reason: "parent directory does not exist".to_string(),
        };
        let msg = err.user_message();
        assert!(msg.contains("no/such/dir"));
        assert!(err.suggestion().is_some());
    }

    #[test]
    fn invalid_duration_user_message_and_suggestion() {
        let err = ValidationError::InvalidDuration {
            input: "foobar".to_string(),
        };
        let msg = err.user_message();
        assert!(msg.contains("foobar"));
        let sug = err.suggestion().unwrap();
        assert!(sug.contains("5m"));
    }

    #[test]
    fn invalid_ip_address_user_message_and_suggestion() {
        let err = ValidationError::InvalidIpAddress {
            input: "999.999.999.999".to_string(),
        };
        let msg = err.user_message();
        assert!(msg.contains("999.999.999.999"));
        let sug = err.suggestion().unwrap();
        assert!(sug.contains("192.168.1.1"));
    }

    #[test]
    fn out_of_range_user_message_and_suggestion() {
        let err = ValidationError::OutOfRange {
            field: "snaplen".to_string(),
            value: 99999,
            min: 64,
            max: 65535,
        };
        let msg = err.user_message();
        assert!(msg.contains("snaplen"));
        assert!(msg.contains("99999"));
        let sug = err.suggestion().unwrap();
        assert!(sug.contains("64"));
        assert!(sug.contains("65535"));
    }

    #[test]
    fn all_validation_errors_are_recoverable_and_warning() {
        let errors: Vec<ValidationError> = vec![
            ValidationError::InvalidInterface {
                name: "x".to_string(),
                reason: "y".to_string(),
            },
            ValidationError::InvalidBpfFilter {
                expression: "x".to_string(),
                parse_error: "y".to_string(),
            },
            ValidationError::InvalidOutputPath {
                path: PathBuf::from("/tmp"),
                reason: "y".to_string(),
            },
            ValidationError::InvalidDuration {
                input: "x".to_string(),
            },
            ValidationError::InvalidIpAddress {
                input: "x".to_string(),
            },
            ValidationError::OutOfRange {
                field: "x".to_string(),
                value: 0,
                min: 1,
                max: 10,
            },
        ];
        for err in &errors {
            assert!(err.recoverable(), "expected recoverable: {err:?}");
            assert_eq!(
                err.severity(),
                Severity::Warning,
                "expected Warning: {err:?}"
            );
        }
    }
}
