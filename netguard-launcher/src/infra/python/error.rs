//! Errors produced when locating, validating, or spawning the Python backend.
//!
//! These errors cover the full lifecycle of Python environment management:
//! finding an interpreter, checking its version, verifying the virtual
//! environment, confirming required packages are installed, and finally
//! spawning the backend process.

use std::path::PathBuf;

use crate::types::Severity;

/// Errors that occur when locating, validating, or spawning the Python backend.
///
/// # Severity & recoverability
///
/// | Variant | Severity | Recoverable | Rationale |
/// |---------|----------|-------------|-----------|
/// | `NotFound` | Fatal | No | Cannot run without an interpreter |
/// | `VersionMismatch` | Fatal | No | Wrong Python; must install correct version |
/// | `VenvMissing` | Error | Yes | User can create the venv and retry |
/// | `DependencyMissing` | Error | Yes | User can `pip install` and retry |
/// | `SpawnFailed` | Fatal | No | OS-level failure; process cannot start |
/// | `StdioSetupFailed` | Error | Yes | Resource limit issue; may clear on retry |
///
/// # Relation to `EnvironmentError`
///
/// [`crate::orchestrator::error::EnvironmentError`] contains a subset of
/// similar concerns (Python not found, version mismatch, venv missing) used
/// by the orchestrator's pre-flight summary.  `PythonError` is the
/// **detailed** source: it carries path lists, exact version strings, and
/// I/O error sources.  The orchestrator maps `PythonError` into
/// `EnvironmentError` when it needs to summarize results.
#[derive(Debug, thiserror::Error)]
pub enum PythonError {
    /// No Python interpreter was found in any of the searched locations.
    ///
    /// Populate `searched_paths` with all directories / explicit paths that
    /// were tried so the user knows exactly where to install Python.
    #[error("Python interpreter not found in any of the searched paths")]
    NotFound { searched_paths: Vec<PathBuf> },

    /// A Python interpreter was found but its version is incompatible.
    ///
    /// Populate `required` with the minimum version string (e.g. `"3.9"`)
    /// and `found` with the full version string of the detected interpreter
    /// (e.g. `"3.7.16"`).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use netguard_launcher::infra::python::error::PythonError;
    ///
    /// let err = PythonError::VersionMismatch {
    ///     required: "3.9".to_string(),  // minimum version, major.minor only
    ///     found: "3.7.16".to_string(),  // detected version, major.minor.patch
    /// };
    /// ```
    #[error("Python version mismatch: required {required}, found {found}")]
    VersionMismatch { required: String, found: String },

    /// The expected Python virtual environment directory is absent.
    ///
    /// Populate `expected_path` with the path that was checked so the user
    /// knows exactly where to create the venv.
    #[error("Virtual environment not found at expected path: {expected_path}")]
    VenvMissing { expected_path: PathBuf },

    /// A required Python package is not installed in the active environment.
    ///
    /// Raised when an `import` check or `pip show` query fails for a package
    /// that `NetGuard` cannot operate without.  Populate `package` with the
    /// `PyPI` package name (e.g. `"scapy"`).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use netguard_launcher::infra::python::error::PythonError;
    ///
    /// let err = PythonError::DependencyMissing {
    ///     package: "scapy".to_string(), // exact PyPI package name as on pypi.org, e.g. "scapy", "cryptography", "requests"
    /// };
    /// ```
    #[error("Required Python package '{package}' is not installed")]
    DependencyMissing { package: String },

    /// The OS failed to spawn the Python backend child process.
    ///
    /// Wraps the underlying [`std::io::Error`].  Common causes: the Python
    /// executable path is wrong, the file is not executable, or the process
    /// table is full.  Always Fatal.
    #[error("Failed to spawn the Python backend process: {source}")]
    SpawnFailed { source: std::io::Error },

    /// The launcher failed to configure stdio pipes for the child process.
    ///
    /// Raised when creating the `stdin`/`stdout`/`stderr` pipes for the
    /// spawned process fails (typically an OS file-descriptor limit).
    /// Recoverable — the limit may clear after a short wait.
    #[error("Failed to configure stdio pipes for the Python backend process: {source}")]
    StdioSetupFailed { source: std::io::Error },
}

impl PythonError {
    #[must_use = "User messages are only used for logging purposes; do not call this method unless you know what you're doing!"]
    pub fn user_message(&self) -> String {
        match self {
            Self::NotFound { searched_paths } => {
                let paths: Vec<String> = searched_paths
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect();
                format!(
                    "Python interpreter was not found. Searched locations: {}.",
                    paths.join(", ")
                )
            }
            Self::VersionMismatch { required, found } => format!(
                "Python version mismatch: NetGuard requires {required}, \
                 but the installed version is {found}."
            ),
            Self::VenvMissing { expected_path } => format!(
                "The Python virtual environment was not found at '{}'.",
                expected_path.display()
            ),
            Self::DependencyMissing { package } => format!(
                "The required Python package '{package}' is not installed \
                 in the active environment."
            ),
            Self::SpawnFailed { source } => {
                format!("Failed to start the Python backend process: {source}.")
            }
            Self::StdioSetupFailed { source } => {
                format!("Failed to configure communication pipes for the Python backend: {source}.")
            }
        }
    }

    #[must_use = "User messages are only used for logging purposes; do not call this method unless you know what you're doing!"]
    pub fn suggestion(&self) -> Option<String> {
        match self {
            Self::NotFound { .. } => Some(
                "Install Python 3.9+ and ensure the interpreter is in your PATH. \
                 Download at: https://www.python.org/downloads/"
                    .to_string(),
            ),
            Self::VersionMismatch { required, .. } => Some(format!(
                "Install Python {required} or later: https://www.python.org/downloads/"
            )),
            Self::VenvMissing { expected_path } => Some(format!(
                "Create the virtual environment with: \
                 `python3 -m venv {} && {}/bin/pip install -r requirements.txt`",
                expected_path.display(),
                expected_path.display()
            )),
            Self::DependencyMissing { package } => Some(format!(
                "Install the missing package with: `pip install {package}`"
            )),
            Self::SpawnFailed { .. } => Some(
                "Ensure the Python executable is accessible and you have permission \
                 to run child processes."
                    .to_string(),
            ),
            Self::StdioSetupFailed { .. } => Some(
                "This is likely an OS resource limit issue. \
                 Check your file descriptor limits with `ulimit -n`."
                    .to_string(),
            ),
        }
    }

    #[must_use = "User messages are only used for logging purposes; do not call this method unless you know what you're doing!"]
    pub const fn severity(&self) -> Severity {
        match self {
            Self::NotFound { .. } | Self::VersionMismatch { .. } | Self::SpawnFailed { .. } => {
                Severity::Fatal
            }
            Self::VenvMissing { .. }
            | Self::DependencyMissing { .. }
            | Self::StdioSetupFailed { .. } => Severity::Error,
        }
    }

    #[must_use = "User messages are only used for logging purposes; do not call this method unless you know what you're doing!"]
    pub const fn recoverable(&self) -> bool {
        match self {
            Self::NotFound { .. } | Self::VersionMismatch { .. } | Self::SpawnFailed { .. } => {
                false
            }
            Self::VenvMissing { .. }
            | Self::DependencyMissing { .. }
            | Self::StdioSetupFailed { .. } => true,
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
        std::io::Error::new(std::io::ErrorKind::NotFound, "no such file or directory")
    }

    #[test]
    fn not_found_user_message_lists_paths() {
        let err = PythonError::NotFound {
            searched_paths: vec![
                PathBuf::from("/usr/bin/python3"),
                PathBuf::from("/usr/local/bin/python3"),
            ],
        };
        let msg = err.user_message();
        assert!(msg.contains("/usr/bin/python3"));
        assert!(msg.contains("/usr/local/bin/python3"));
        assert!(!err.recoverable());
        assert_eq!(err.severity(), Severity::Fatal);
    }

    #[test]
    fn not_found_suggestion_contains_download_link() {
        let err = PythonError::NotFound {
            searched_paths: vec![],
        };
        let sug = err.suggestion().unwrap();
        assert!(sug.contains("python.org"));
    }

    #[test]
    fn version_mismatch_user_message() {
        let err = PythonError::VersionMismatch {
            required: "3.9".to_string(),
            found: "3.7.12".to_string(),
        };
        let msg = err.user_message();
        assert!(msg.contains("3.9"));
        assert!(msg.contains("3.7.12"));
        assert!(!err.recoverable());
    }

    #[test]
    fn venv_missing_suggestion_contains_venv_command() {
        let err = PythonError::VenvMissing {
            expected_path: PathBuf::from(".venv"),
        };
        let sug = err.suggestion().unwrap();
        assert!(sug.contains("-m venv"));
        assert!(err.recoverable());
    }

    #[test]
    fn dependency_missing_suggestion_contains_pip_install() {
        let err = PythonError::DependencyMissing {
            package: "scapy".to_string(),
        };
        let sug = err.suggestion().unwrap();
        assert!(sug.contains("pip install scapy"));
        assert!(err.recoverable());
    }

    #[test]
    fn spawn_failed_user_message_not_recoverable() {
        let err = PythonError::SpawnFailed {
            source: make_io_error(),
        };
        assert!(!err.user_message().is_empty());
        assert!(!err.recoverable());
        assert_eq!(err.severity(), Severity::Fatal);
    }

    #[test]
    fn stdio_setup_failed_user_message_and_suggestion() {
        let err = PythonError::StdioSetupFailed {
            source: make_io_error(),
        };
        assert!(!err.user_message().is_empty());
        let sug = err.suggestion().unwrap();
        assert!(sug.contains("ulimit"));
    }
}
