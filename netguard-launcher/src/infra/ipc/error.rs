//! Errors produced by the Unix-domain-socket IPC layer.
//!
//! The IPC layer manages the bidirectional socket channel between the Rust
//! launcher and the Python backend.  All socket lifecycle events (creation,
//! binding, connection) as well as message-level failures (framing,
//! serialization, heartbeat) are reported through [`IpcError`].
//!
//! [`IpcError`] also implements [`IntoIpcError`], which means IPC errors can
//! be serialized and transmitted back to the Python side when needed.

use std::path::PathBuf;
use std::time::Duration;

use crate::types::{IntoIpcError, IpcErrorPayload, Severity};

/// Errors that can occur in the Unix-domain-socket IPC layer.
///
/// # Severity & recoverability
///
/// | Variant | Severity | Recoverable | Rationale |
/// |---------|----------|-------------|-----------|
/// | `SocketCreationFailed` | Fatal | No | Cannot communicate without a socket |
/// | `SocketAlreadyInUse` | Error | Yes | Remove stale socket file and retry |
/// | `ConnectionRefused` | Error | Yes | Backend may not be running yet |
/// | `MessageTooLarge` | Warning | Yes | Caller should split or drop the message |
/// | `FramingError` | Error | No | Protocol corruption; restart required |
/// | `SerializationFailed` | Error | No | Internal bug; file a report |
/// | `HeartbeatTimeout` | Error | Yes | Backend may have hung; restart backend |
/// | `HandshakeFailed` | Error | No | Version mismatch; incompatible builds |
///
/// # IPC codes
///
/// Each variant maps to a stable `SCREAMING_SNAKE_CASE` code used in
/// [`IpcErrorPayload`] when the error is transmitted to the Python backend.
/// These codes are part of the IPC protocol and must not be changed once
/// deployed.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    /// The launcher failed to create the Unix-domain socket file.
    ///
    /// Raised when `bind()` or the socket file creation syscall fails.
    /// Common causes: the parent directory doesn't exist, or the process
    /// lacks write permission.  Always Fatal — IPC is fundamental to
    /// launcher operation.
    #[error("Failed to create socket at {path}: {source}")]
    SocketCreationFailed {
        path: PathBuf,
        source: std::io::Error,
    },

    /// A socket file already exists at the target path.
    ///
    /// Raised when a previous `NetGuard` instance exited without cleaning up
    /// its socket file.  Recoverable — the stale file can be removed and the
    /// launcher restarted.
    #[error("Socket already in use: {path}")]
    SocketAlreadyInUse { path: PathBuf },

    /// The backend refused the connection on the socket path.
    ///
    /// Raised when `connect()` returns `ECONNREFUSED`.  Common cause: the
    /// Python backend is not running.  Recoverable — start the backend and
    /// retry.
    #[error("Connection refused at {path}")]
    ConnectionRefused { path: PathBuf },

    /// A message to be sent exceeds the IPC protocol's size limit.
    ///
    /// Raised before the send attempt, not after a failed write.  The caller
    /// should drop or split the message.  Recoverable — the connection itself
    /// is still valid.
    #[error("Message too large: {size_bytes} bytes exceeds limit of {limit_bytes} bytes")]
    MessageTooLarge {
        size_bytes: usize,
        limit_bytes: usize,
    },

    /// The framing layer detected a protocol-level corruption.
    ///
    /// Raised when length-prefixed framing produces an inconsistency (e.g.
    /// unexpected EOF mid-frame, negative length, checksum mismatch).  Not
    /// recoverable — the stream is in an unknown state and the connection
    /// must be torn down.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use netguard_launcher::infra::ipc::error::IpcError;
    ///
    /// let err = IpcError::FramingError {
    ///     reason: "unexpected EOF mid-frame".to_string(), // diagnostic from the framing layer, e.g. "unexpected EOF mid-frame", "negative frame length"
    /// };
    /// ```
    #[error("Message framing error: {reason}")]
    FramingError { reason: String },

    /// A value could not be serialized to JSON for transmission.
    ///
    /// This represents an internal bug (a type that is not `Serialize`, a
    /// value that cannot be represented in JSON such as a map with non-string
    /// keys, etc.).  Not recoverable — file a bug report.
    #[error("Serialization failed: {source}")]
    SerializationFailed { source: serde_json::Error },

    /// The backend stopped acknowledging heartbeat pings within the deadline.
    ///
    /// Raised when no heartbeat ACK is received within the configured
    /// timeout window.  The backend process may have hung or crashed.
    /// Recoverable — restart the backend.
    #[error("Heartbeat timeout after {elapsed:?}")]
    HeartbeatTimeout { elapsed: Duration },

    /// The initial protocol handshake failed.
    ///
    /// Raised when the backend rejects the handshake (e.g. mismatched
    /// protocol version, unexpected response).  Not recoverable — the builds
    /// are incompatible and must be updated together.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use netguard_launcher::infra::ipc::error::IpcError;
    ///
    /// let err = IpcError::HandshakeFailed {
    ///     reason: "protocol version mismatch: expected 1, got 2".to_string(), // diagnostic from the handshake layer
    /// };
    /// ```
    #[error("Handshake failed: {reason}")]
    HandshakeFailed { reason: String },
}

impl IpcError {
    #[must_use]
    pub fn user_message(&self) -> String {
        match self {
            Self::SocketCreationFailed { path, .. } => {
                format!("Failed to create the IPC socket at '{}'.", path.display())
            }
            Self::SocketAlreadyInUse { path } => {
                format!(
                    "The IPC socket '{}' is already in use by another process.",
                    path.display()
                )
            }
            Self::ConnectionRefused { path } => {
                format!(
                    "Connection to the backend socket '{}' was refused.",
                    path.display()
                )
            }
            Self::MessageTooLarge {
                size_bytes,
                limit_bytes,
            } => {
                format!(
                    "A message ({size_bytes} bytes) exceeds the maximum allowed size \
                     of {limit_bytes} bytes."
                )
            }
            Self::FramingError { reason } => {
                format!("A protocol framing error occurred: {reason}.")
            }
            Self::SerializationFailed { .. } => {
                "Failed to serialize a message for transmission to the backend.".to_string()
            }
            Self::HeartbeatTimeout { elapsed } => {
                format!(
                    "The backend stopped responding to heartbeats after {:.1} second(s).",
                    elapsed.as_secs_f64()
                )
            }
            Self::HandshakeFailed { reason } => {
                format!("The connection handshake with the backend failed: {reason}.")
            }
        }
    }

    #[must_use]
    pub fn suggestion(&self) -> Option<String> {
        match self {
            Self::SocketCreationFailed { path, .. } => {
                let parent = path.parent().unwrap_or(path.as_path());
                Some(format!(
                    "Ensure the directory '{}' exists and is writable by the current user.",
                    parent.display()
                ))
            }
            Self::SocketAlreadyInUse { path } => Some(format!(
                "Remove the stale socket file and restart NetGuard: `rm {}`",
                path.display()
            )),
            Self::ConnectionRefused { .. } => Some(
                "Ensure the NetGuard Python backend is running before starting the launcher."
                    .to_string(),
            ),
            Self::MessageTooLarge { .. } => None,
            Self::FramingError { .. } => Some(
                "This may indicate a version mismatch between the Rust launcher \
                 and the Python backend."
                    .to_string(),
            ),
            Self::SerializationFailed { .. } => Some(
                "This is an internal error. Please file a bug report at \
                 https://github.com/JJPR030803/NetGuard/issues"
                    .to_string(),
            ),
            Self::HeartbeatTimeout { .. } => Some(
                "Restart the NetGuard backend. \
                 If the problem persists, check the backend logs for errors."
                    .to_string(),
            ),
            Self::HandshakeFailed { .. } => Some(
                "Ensure the Rust launcher and Python backend versions are compatible.".to_string(),
            ),
        }
    }

    #[must_use]
    pub const fn severity(&self) -> Severity {
        match self {
            Self::SocketCreationFailed { .. } => Severity::Fatal,
            Self::SocketAlreadyInUse { .. }
            | Self::ConnectionRefused { .. }
            | Self::FramingError { .. }
            | Self::SerializationFailed { .. }
            | Self::HeartbeatTimeout { .. }
            | Self::HandshakeFailed { .. } => Severity::Error,
            Self::MessageTooLarge { .. } => Severity::Warning,
        }
    }

    #[must_use]
    pub const fn recoverable(&self) -> bool {
        match self {
            Self::SocketCreationFailed { .. }
            | Self::SerializationFailed { .. }
            | Self::FramingError { .. }
            | Self::HandshakeFailed { .. } => false,
            Self::SocketAlreadyInUse { .. }
            | Self::ConnectionRefused { .. }
            | Self::MessageTooLarge { .. }
            | Self::HeartbeatTimeout { .. } => true,
        }
    }

    const fn ipc_code(&self) -> &'static str {
        match self {
            Self::SocketCreationFailed { .. } => "SOCKET_CREATION_FAILED",
            Self::SocketAlreadyInUse { .. } => "SOCKET_ALREADY_IN_USE",
            Self::ConnectionRefused { .. } => "CONNECTION_REFUSED",
            Self::MessageTooLarge { .. } => "MESSAGE_TOO_LARGE",
            Self::FramingError { .. } => "FRAMING_ERROR",
            Self::SerializationFailed { .. } => "SERIALIZATION_FAILED",
            Self::HeartbeatTimeout { .. } => "HEARTBEAT_TIMEOUT",
            Self::HandshakeFailed { .. } => "HANDSHAKE_FAILED",
        }
    }
}

impl IntoIpcError for IpcError {
    fn to_ipc_payload(&self) -> IpcErrorPayload {
        IpcErrorPayload {
            code: self.ipc_code().to_string(),
            message: self.user_message(),
            recoverable: self.recoverable(),
            suggestion: self.suggestion(),
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
    fn socket_creation_failed_user_message() {
        let err = IpcError::SocketCreationFailed {
            path: PathBuf::from("/run/netguard/ipc.sock"),
            source: make_io_error(),
        };
        let msg = err.user_message();
        assert!(msg.contains("/run/netguard/ipc.sock"));
        assert!(err.suggestion().unwrap().contains("/run/netguard"));
        assert!(!err.recoverable());
        assert_eq!(err.severity(), Severity::Fatal);
    }

    #[test]
    fn socket_already_in_use_suggestion_contains_rm() {
        let path = PathBuf::from("/tmp/ng.sock");
        let err = IpcError::SocketAlreadyInUse { path };
        let sug = err.suggestion().unwrap();
        assert!(sug.contains("rm"));
        assert!(err.recoverable());
    }

    #[test]
    fn connection_refused_user_message_and_suggestion() {
        let err = IpcError::ConnectionRefused {
            path: PathBuf::from("/tmp/ng.sock"),
        };
        assert!(err.user_message().contains("refused"));
        assert!(err.suggestion().is_some());
    }

    #[test]
    fn message_too_large_user_message_no_suggestion() {
        let err = IpcError::MessageTooLarge {
            size_bytes: 2048,
            limit_bytes: 1024,
        };
        let msg = err.user_message();
        assert!(msg.contains("2048"));
        assert!(msg.contains("1024"));
        assert!(err.suggestion().is_none());
        assert!(err.recoverable());
    }

    #[test]
    fn framing_error_user_message_not_recoverable() {
        let err = IpcError::FramingError {
            reason: "unexpected EOF".to_string(),
        };
        assert!(err.user_message().contains("unexpected EOF"));
        assert!(!err.recoverable());
        assert!(err.suggestion().is_some());
    }

    #[test]
    fn heartbeat_timeout_user_message() {
        let err = IpcError::HeartbeatTimeout {
            elapsed: Duration::from_secs(10),
        };
        let msg = err.user_message();
        assert!(msg.contains("10.0"));
        assert!(err.recoverable());
        assert!(err.suggestion().is_some());
    }

    #[test]
    fn handshake_failed_not_recoverable() {
        let err = IpcError::HandshakeFailed {
            reason: "protocol version mismatch".to_string(),
        };
        assert!(!err.recoverable());
        assert!(err.suggestion().is_some());
    }

    #[test]
    fn into_ipc_payload_has_correct_code() {
        let err = IpcError::SocketAlreadyInUse {
            path: PathBuf::from("/tmp/s.sock"),
        };
        let payload = err.to_ipc_payload();
        assert_eq!(payload.code, "SOCKET_ALREADY_IN_USE");
        assert!(payload.recoverable);
        assert!(payload.suggestion.is_some());
    }

    #[test]
    fn all_variants_have_non_empty_user_message() {
        let errors: Vec<IpcError> = vec![
            IpcError::SocketCreationFailed {
                path: PathBuf::from("/tmp/s"),
                source: make_io_error(),
            },
            IpcError::SocketAlreadyInUse {
                path: PathBuf::from("/tmp/s"),
            },
            IpcError::ConnectionRefused {
                path: PathBuf::from("/tmp/s"),
            },
            IpcError::MessageTooLarge {
                size_bytes: 1,
                limit_bytes: 0,
            },
            IpcError::FramingError {
                reason: "x".to_string(),
            },
            IpcError::HeartbeatTimeout {
                elapsed: Duration::from_secs(1),
            },
            IpcError::HandshakeFailed {
                reason: "x".to_string(),
            },
        ];
        for err in &errors {
            assert!(
                !err.user_message().is_empty(),
                "empty user_message: {err:?}"
            );
        }
    }
}
