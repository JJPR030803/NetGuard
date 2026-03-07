//! Errors produced by the terminal display / TUI layer.
//!
//! The display layer renders the `NetGuard` TUI using `crossterm` (or a
//! similar backend).  Most display failures degrade gracefully — the TUI
//! truncates, skips a frame, or redraws.  `DisplayError` is raised only for
//! conditions that prevent the TUI from functioning at all.

use crate::types::Severity;

/// Errors that occur in the terminal display layer.
///
/// # Severity & recoverability
///
/// | Variant | Severity | Recoverable | Rationale |
/// |---------|----------|-------------|-----------|
/// | `TerminalTooSmall` | Warning | Yes | User can resize the terminal |
/// | `InvalidUtf8` | Error | No | Corrupt output stream; cannot render safely |
/// | `RenderFailed` | Error | No | Render engine panicked; TUI cannot continue |
///
/// # When to raise vs. degrade silently
///
/// The TUI should prefer silent degradation (truncate a widget, skip a
/// frame) over raising `DisplayError`.  Only raise when the failure prevents
/// **any** meaningful rendering — not when a single widget fails to draw.
#[derive(Debug, thiserror::Error)]
pub enum DisplayError {
    /// The terminal is narrower than the minimum required column count.
    ///
    /// Raised when the measured terminal width is below `min_width`.  The
    /// TUI cannot lay out its panels in less space.  Recoverable — the user
    /// can resize the terminal window and the TUI will re-check on the next
    /// resize event.
    #[error(
        "Terminal is too small: width {width} columns is below the minimum of {min_width} columns"
    )]
    TerminalTooSmall { width: u16, min_width: u16 },

    /// The display output contains invalid UTF-8 bytes.
    ///
    /// Raised when the render pipeline tries to convert raw bytes to a
    /// string for terminal output and `str::from_utf8` fails.  Not
    /// recoverable — the output stream is in an undefined state and cannot
    /// be trusted.
    #[error("Invalid UTF-8 in display output: {source}")]
    InvalidUtf8 { source: std::str::Utf8Error },

    /// The render engine failed with an unrecoverable error.
    ///
    /// A catch-all for terminal/crossterm-level failures (e.g. the
    /// underlying `Write` call to the terminal fails, a layout engine
    /// panics).  Not recoverable — the TUI must be torn down and the
    /// application should exit or fall back to plain-text output.
    #[error("Render failed: {reason}")]
    RenderFailed { reason: String },
}

impl DisplayError {
    #[must_use]
    pub fn user_message(&self) -> String {
        match self {
            Self::TerminalTooSmall { width, min_width } => format!(
                "The terminal is too narrow ({width} columns) to display the NetGuard UI. \
                 A minimum of {min_width} columns is required."
            ),
            Self::InvalidUtf8 { source } => {
                format!("The output contains invalid UTF-8 data and cannot be displayed: {source}.")
            }
            Self::RenderFailed { reason } => {
                format!("The terminal UI failed to render: {reason}.")
            }
        }
    }

    #[must_use]
    pub fn suggestion(&self) -> Option<String> {
        match self {
            Self::TerminalTooSmall { min_width, .. } => Some(format!(
                "Resize the terminal window to at least {min_width} columns wide and retry."
            )),
            Self::InvalidUtf8 { .. } => Some(
                "Ensure your terminal emulator is configured to use UTF-8 encoding.".to_string(),
            ),
            Self::RenderFailed { .. } => Some(
                "Try resizing the terminal or switching to a different terminal emulator."
                    .to_string(),
            ),
        }
    }

    #[must_use]
    pub const fn severity(&self) -> Severity {
        match self {
            Self::TerminalTooSmall { .. } => Severity::Warning,
            Self::InvalidUtf8 { .. } | Self::RenderFailed { .. } => Severity::Error,
        }
    }

    #[must_use]
    pub const fn recoverable(&self) -> bool {
        match self {
            Self::TerminalTooSmall { .. } => true,
            Self::InvalidUtf8 { .. } | Self::RenderFailed { .. } => false,
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

    #[allow(invalid_from_utf8)]
    fn make_utf8_error() -> std::str::Utf8Error {
        // Bytes 0xFF and 0xFE are always invalid UTF-8; we need the error value.
        std::str::from_utf8(&[0xFF, 0xFE]).unwrap_err()
    }

    #[test]
    fn terminal_too_small_user_message_and_suggestion() {
        let err = DisplayError::TerminalTooSmall {
            width: 60,
            min_width: 80,
        };
        let msg = err.user_message();
        assert!(msg.contains("60"));
        assert!(msg.contains("80"));
        let sug = err.suggestion().unwrap();
        assert!(sug.contains("80"));
        assert!(err.recoverable());
        assert_eq!(err.severity(), Severity::Warning);
    }

    #[test]
    fn invalid_utf8_user_message_not_recoverable() {
        let err = DisplayError::InvalidUtf8 {
            source: make_utf8_error(),
        };
        assert!(!err.user_message().is_empty());
        assert!(!err.recoverable());
        assert_eq!(err.severity(), Severity::Error);
        assert!(err.suggestion().unwrap().contains("UTF-8"));
    }

    #[test]
    fn render_failed_user_message_and_suggestion() {
        let err = DisplayError::RenderFailed {
            reason: "crossterm panic".to_string(),
        };
        let msg = err.user_message();
        assert!(msg.contains("crossterm panic"));
        assert!(!err.recoverable());
        assert!(err.suggestion().is_some());
    }
}
