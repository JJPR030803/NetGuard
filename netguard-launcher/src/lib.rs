pub mod cli;
pub mod core;
pub mod display;
pub mod error;
pub mod infra;
pub mod orchestrator;
pub mod tui;
pub(crate) mod types;

pub use error::NetGuardError;

/// Crate-level `Result` alias — every fallible function in this crate returns
/// `Result<T>` which expands to `std::result::Result<T, NetGuardError>`.
pub type Result<T> = std::result::Result<T, error::NetGuardError>;
