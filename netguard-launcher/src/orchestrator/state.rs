/// The operational state of the `NetGuard` system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemState {
    Initializing,
    Ready,
    Running,
    Degraded,
    Stopping,
    Stopped,
}

impl std::fmt::Display for SystemState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initializing => write!(f, "Initializing"),
            Self::Ready => write!(f, "Ready"),
            Self::Running => write!(f, "Running"),
            Self::Degraded => write!(f, "Degraded"),
            Self::Stopping => write!(f, "Stopping"),
            Self::Stopped => write!(f, "Stopped"),
        }
    }
}
