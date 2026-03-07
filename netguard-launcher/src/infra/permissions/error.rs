//! Errors produced when checking or acquiring OS-level permissions.
//!
//! `NetGuard` requires elevated privileges for packet capture on every
//! supported platform.  This module covers the platform-specific permission
//! models: Linux capabilities, macOS BPF device access, and Windows UAC
//! elevation.

use crate::types::Severity;

/// Errors that occur when checking or acquiring system permissions.
///
/// All `PermissionError` variants have [`Severity::Error`] and are
/// **always recoverable** — the system can enter a Degraded operating mode
/// instead of exiting, and the user can grant the required permissions and
/// retry without restarting the process.
///
/// # Platform coverage
///
/// | Variant | Platform | Privilege required |
/// |---------|----------|--------------------|
/// | `MissingLinuxCapability` | Linux | `CAP_NET_RAW` / `CAP_NET_ADMIN` |
/// | `MacOsBpfAccessDenied` | macOS | `/dev/bpf*` read access |
/// | `WindowsElevationRequired` | Windows | Administrator elevation |
/// | `CapabilityCheckFailed` | Any | (meta: check itself failed) |
///
/// # When to raise
///
/// Raise a `PermissionError` during the permissions-check phase (typically
/// called from the orchestrator's pre-flight sequence).  Do **not** raise it
/// for general I/O permission failures (file not writable, etc.) — those
/// belong in [`crate::infra::config::error::ConfigError`] or
/// [`crate::infra::logging::error::LoggingError`].
#[derive(Debug, thiserror::Error)]
pub enum PermissionError {
    /// The process is missing a required Linux capability.
    ///
    /// Populate `capability` with the capability name (e.g. `"cap_net_raw"`)
    /// and `suggestion` with the exact `setcap` command needed to grant it.
    /// Embedding the suggestion directly in the error makes it available to
    /// the IPC payload and the TUI without extra logic.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use netguard_launcher::infra::permissions::error::PermissionError;
    ///
    /// let err = PermissionError::MissingLinuxCapability {
    ///     capability: "cap_net_raw".to_string(), // Linux capability name, always lowercase with "cap_" prefix
    ///     suggestion: "sudo setcap cap_net_raw+eip $(which netguard)".to_string(), // complete, runnable shell command shown to the user
    /// };
    /// ```
    #[error("Missing Linux capability: {capability}")]
    MissingLinuxCapability {
        capability: String,
        suggestion: String,
    },

    /// Access to macOS BPF devices was denied.
    ///
    /// On macOS, packet capture requires read access to `/dev/bpf*`.  Access
    /// is typically granted by adding the user to the `access_bpf` group or
    /// by running with `sudo`.  Populate `suggestion` with the platform-
    /// appropriate remedy command.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use netguard_launcher::infra::permissions::error::PermissionError;
    ///
    /// let err = PermissionError::MacOsBpfAccessDenied {
    ///     suggestion: "sudo chmod o+r /dev/bpf*".to_string(), // complete, runnable macOS shell command shown to the user
    /// };
    /// ```
    #[error("macOS BPF device access denied")]
    MacOsBpfAccessDenied { suggestion: String },

    /// The process is not running with Windows Administrator privileges.
    ///
    /// Raw socket access on Windows requires an elevated process token.
    /// Raise this when `IsUserAnAdmin()` (or equivalent) returns `false`.
    #[error("Windows elevation required: run NetGuard as Administrator")]
    WindowsElevationRequired,

    /// The capability / privilege check itself failed with an error.
    ///
    /// Raised when the *mechanism* used to query permissions fails (e.g.
    /// `libcap` is not installed, the `/proc` filesystem is unavailable).
    /// This is distinct from "we checked and the capability is missing" —
    /// it means "we couldn't even determine whether the capability is
    /// present".
    #[error("Capability check failed: {reason}")]
    CapabilityCheckFailed { reason: String },
}

impl PermissionError {
    #[must_use = "User messages are only used for logging purposes; do not call this method unless you know what you're doing!"]
    pub fn user_message(&self) -> String {
        match self {
            Self::MissingLinuxCapability { capability, .. } => format!(
                "The Linux capability '{capability}' is required for packet capture \
                 but is not granted to this process."
            ),
            Self::MacOsBpfAccessDenied { .. } => "Access to macOS BPF devices was denied. \
                 Packet capture requires special permissions on macOS."
                .to_string(),
            Self::WindowsElevationRequired => {
                "NetGuard requires Administrator privileges to capture network packets on Windows."
                    .to_string()
            }
            Self::CapabilityCheckFailed { reason } => {
                format!("Failed to check system capabilities: {reason}.")
            }
        }
    }

    #[must_use = "User messages are only used for logging purposes; do not call this method unless you know what you're doing!"]
    pub fn suggestion(&self) -> Option<String> {
        match self {
            Self::MissingLinuxCapability { suggestion, .. }
            | Self::MacOsBpfAccessDenied { suggestion, .. } => Some(suggestion.clone()),

            Self::WindowsElevationRequired => Some(
                "Right-click the NetGuard executable and select 'Run as administrator', \
                 or launch it from an elevated Command Prompt."
                    .to_string(),
            ),
            Self::CapabilityCheckFailed { .. } => Some(
                "Ensure you have the necessary permissions to query system capabilities. \
                 Try running with `sudo` to diagnose the issue."
                    .to_string(),
            ),
        }
    }

    #[must_use = "User messages are only used for logging purposes; do not call this method unless you know what you're doing!"]
    pub const fn severity(&self) -> Severity {
        Severity::Error
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

    #[test]
    fn missing_linux_capability_user_message_contains_cap() {
        let err = PermissionError::MissingLinuxCapability {
            capability: "cap_net_raw".to_string(),
            suggestion: "sudo setcap cap_net_raw+eip /usr/bin/netguard".to_string(),
        };
        let msg = err.user_message();
        assert!(msg.contains("cap_net_raw"));
        let sug = err.suggestion().unwrap();
        assert!(sug.contains("setcap"));
    }

    #[test]
    fn macos_bpf_access_denied_user_message_and_suggestion() {
        let err = PermissionError::MacOsBpfAccessDenied {
            suggestion: "sudo chmod o+r /dev/bpf*".to_string(),
        };
        assert!(err.user_message().contains("BPF"));
        let sug = err.suggestion().unwrap();
        assert!(sug.contains("bpf"));
    }

    #[test]
    fn windows_elevation_required_suggestion() {
        let err = PermissionError::WindowsElevationRequired;
        assert!(err.user_message().contains("Administrator"));
        assert!(err.suggestion().unwrap().contains("administrator"));
    }

    #[test]
    fn capability_check_failed_user_message() {
        let err = PermissionError::CapabilityCheckFailed {
            reason: "libcap not found".to_string(),
        };
        assert!(err.user_message().contains("libcap not found"));
        assert!(err.suggestion().is_some());
    }

    #[test]
    fn all_permission_errors_are_recoverable_and_error_severity() {
        let errors: Vec<PermissionError> = vec![
            PermissionError::MissingLinuxCapability {
                capability: "cap_net_raw".to_string(),
                suggestion: "setcap ...".to_string(),
            },
            PermissionError::MacOsBpfAccessDenied {
                suggestion: "chmod ...".to_string(),
            },
            PermissionError::WindowsElevationRequired,
            PermissionError::CapabilityCheckFailed {
                reason: "err".to_string(),
            },
        ];
        for err in &errors {
            assert!(err.recoverable(), "expected recoverable: {err:?}");
            assert_eq!(err.severity(), Severity::Error, "expected Error: {err:?}");
        }
    }
}
