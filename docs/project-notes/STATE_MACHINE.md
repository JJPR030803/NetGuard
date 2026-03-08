# State Machine Design Document

> **Purpose**: This document specifies the modular state machine design for
> `netguard-launcher`, following the established error module pattern.
> Use this as a reference when implementing `src/orchestrator/state.rs`.

---

## 1. Overview

### What This State Machine Does

The state machine governs the lifecycle of the NetGuard system:

```
CLI/TUI  →  OrchestratorHandle  →  Orchestrator  →  SidecarSupervisor
                                        │
                                 SystemState (single source of truth)
                                        │
                                 IPC (Unix Domain Socket)
                                        │
                                 Python Sidecar
```

### Architectural Constraints

| Constraint | Rationale |
|------------|-----------|
| `SystemState` mutated ONLY in `Orchestrator::transition_to()` | Single source of truth |
| Invalid transitions are programmer errors | Log at `error!()` + block, don't panic |
| Frontends hold only `OrchestratorHandle` | No direct state access from CLI/TUI |
| Follow two-tier pattern | Domain types compose into orchestrator layer |
| All public types have doc comments | Thesis-quality documentation |

### Current vs Target State

| Aspect | Current (`state.rs`) | Target |
|--------|---------------------|--------|
| States | 6 simple variants | 8 states with embedded data |
| Transitions | None | 12+ validated transitions |
| Commands | None | 7 commands with state guards |
| DegradedReason | None | 6 variants with capability info |
| ActiveOperation | None | 4 operation types |

---

## 2. Type Definitions

### 2.1 SystemState (Main Enum)

```rust
/// The operational state of the NetGuard system.
///
/// # State Categories
///
/// | Category | States | Accepts Commands? |
/// |----------|--------|-------------------|
/// | Startup | Initializing, CheckingEnvironment, Connecting | No |
/// | Operational | Ready, Operating | Yes (state-dependent) |
/// | Degraded | Degraded | Limited (depends on reason) |
/// | Terminal | ShuttingDown, Fatal | No |
///
/// # Invariant
///
/// `SystemState` is mutated ONLY inside `Orchestrator::transition_to()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemState {
    /// System is initializing internal structures.
    Initializing,

    /// Running pre-launch environment checks.
    CheckingEnvironment,

    /// Attempting to connect to the Python sidecar.
    Connecting,

    /// System is ready to accept commands.
    Ready,

    /// System is actively executing an operation.
    Operating { operation: ActiveOperation },

    /// System is in a degraded state but may recover.
    Degraded { reason: DegradedReason, recovering: bool },

    /// System is shutting down gracefully (10-second bounded).
    ShuttingDown,

    /// System has encountered a fatal error and cannot continue.
    Fatal { reason: String },
}
```

### 2.2 DegradedReason (Sub-Enum)

```rust
/// Reasons why the system has entered a degraded state.
///
/// # Capability Matrix
///
/// | Variant | Can Capture? | Can Analyze? | Recovery Path |
/// |---------|-------------|--------------|---------------|
/// | SidecarCrashed | No | No | Supervisor restart |
/// | SidecarUnresponsive | No | No | Kill + restart |
/// | VersionMismatch | No | No | Fatal after retry |
/// | CapabilitiesMissing | No | Yes | Manual intervention |
/// | PythonEnvStale | No | Maybe | Reinstall deps |
/// | IpcSocketUnavailable | Degraded | Degraded | Fallback stdio |
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DegradedReason {
    /// The Python sidecar process crashed unexpectedly.
    SidecarCrashed {
        /// Number of restart attempts made so far.
        restart_count: u32,
    },

    /// The sidecar stopped responding to heartbeats.
    SidecarUnresponsive {
        /// Seconds since last successful heartbeat.
        silent_for_secs: u64,
    },

    /// Version mismatch between Rust launcher and Python backend.
    VersionMismatch {
        /// Rust launcher version.
        rust_version: String,
        /// Python backend version.
        python_version: String,
    },

    /// Required Linux capabilities (cap_net_raw/cap_net_admin) are missing.
    ///
    /// **Special case**: System is still usable for analysis workflows.
    /// Frontend shows a persistent banner, NOT a blocking error.
    CapabilitiesMissing,

    /// The Python environment's dependencies are stale.
    PythonEnvStale,

    /// The IPC socket could not be created; using fallback.
    IpcSocketUnavailable,
}
```

### 2.3 ActiveOperation (Sub-Enum)

```rust
/// Operations that can be actively running in the Operating state.
///
/// Each variant represents a long-running operation that blocks
/// certain state transitions while active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveOperation {
    /// A packet capture is in progress.
    Capturing {
        /// Unique identifier for this capture session.
        session_id: String,
        /// Network interface being captured.
        interface: String,
    },

    /// An analysis workflow is executing.
    RunningWorkflow {
        /// Name of the workflow being executed.
        workflow_name: String,
    },

    /// Loading a capture file for analysis.
    LoadingFile {
        /// Path to the file being loaded.
        file_path: std::path::PathBuf,
    },

    /// Listing available network interfaces.
    ListingInterfaces,
}
```

### 2.4 OrchestratorCommand (in commands.rs)

```rust
/// Commands that can be sent to the orchestrator.
///
/// These commands are the only way to trigger state transitions or
/// operations. The orchestrator validates each command against the
/// current state using `SystemState::is_command_allowed()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrchestratorCommand {
    /// Start a packet capture session.
    StartCapture {
        interface: String,
        duration: Option<std::time::Duration>,
        filter: Option<String>,
    },

    /// Stop the currently active capture.
    StopCapture,

    /// Execute an analysis workflow.
    RunWorkflow { name: String },

    /// List available network interfaces.
    ListInterfaces,

    /// Load a capture file for analysis.
    LoadFile { path: std::path::PathBuf },

    /// Get statistics for the current operation.
    GetStats,

    /// Initiate graceful shutdown.
    Shutdown,
}
```

---

## 3. Transition Table

### Valid Transitions

| From | To | Trigger |
|------|----|---------|
| `Initializing` | `CheckingEnvironment` | Startup begins |
| `CheckingEnvironment` | `Connecting` | Environment checks pass |
| `CheckingEnvironment` | `Degraded { recovering: true }` | Warnings found (e.g., missing caps) |
| `CheckingEnvironment` | `Fatal` | Fatal issue found (e.g., no Python) |
| `Degraded` | `Connecting` | Supervisor attempts restart |
| `Connecting` | `Ready` | Handshake OK |
| `Connecting` | `Fatal` | Max retries exceeded (3 in 60s) |
| `Ready` | `Operating { .. }` | Command received |
| `Operating { .. }` | `Ready` | Operation complete |
| `Operating { .. }` | `Degraded { recovering: true }` | Sidecar crash mid-operation |
| Any (non-terminal) | `ShuttingDown` | Shutdown signal (SIGTERM) |
| `ShuttingDown` | (terminal) | 10-second bounded shutdown |
| `Fatal` | (terminal) | Unrecoverable error |

### Implementation Pattern

```rust
impl SystemState {
    /// Returns `true` if transitioning from `self` to `to` is valid.
    ///
    /// Any transition NOT in the table above is a programmer error.
    /// Log at `error!()` level and block — do not allow.
    #[must_use]
    pub fn can_transition_to(&self, to: &SystemState) -> bool {
        use SystemState::*;

        match (self, to) {
            // Startup sequence
            (Initializing, CheckingEnvironment) => true,
            (CheckingEnvironment, Connecting) => true,
            (CheckingEnvironment, Degraded { .. }) => true,
            (CheckingEnvironment, Fatal { .. }) => true,

            // Recovery path
            (Degraded { .. }, Connecting) => true,

            // Connection outcomes
            (Connecting, Ready) => true,
            (Connecting, Fatal { .. }) => true,

            // Ready state transitions
            (Ready, Operating { .. }) => true,

            // Operating state transitions
            (Operating { .. }, Ready) => true,
            (Operating { .. }, Degraded { .. }) => true,

            // Shutdown is always valid (except from terminal states)
            (_, ShuttingDown) if !self.is_terminal() => true,

            // All other transitions are invalid
            _ => false,
        }
    }

    /// Returns `true` if this is a terminal state (no valid transitions out).
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::ShuttingDown | Self::Fatal { .. })
    }
}
```

### State Diagram

```
                              ┌─────────────────┐
                              │  Initializing   │
                              └────────┬────────┘
                                       │
                              ┌────────▼────────┐
                              │CheckingEnvironment│
                              └───┬─────┬────┬──┘
                                  │     │    │
              ┌───────────────────┘     │    └────────────────────┐
              ▼                         ▼                         ▼
       ┌──────────┐              ┌──────────┐              ┌──────────┐
       │ Degraded │◄─────────────│Connecting│              │  Fatal   │
       └────┬─────┘              └────┬─────┘              └──────────┘
            │                         │                         ▲
            └─────────────────────────┤                         │
                                      ▼                         │
                               ┌──────────┐                     │
                     ┌────────►│  Ready   │◄────────┐           │
                     │         └────┬─────┘         │           │
                     │              │               │           │
                     │         ┌────▼─────┐         │           │
                     │         │Operating │─────────┘           │
                     │         └────┬─────┘                     │
                     │              │                           │
                     │         ┌────▼─────┐                     │
                     └─────────│ Degraded │─────────────────────┘
                               └──────────┘

                        Any ──────► ShuttingDown (terminal)
```

---

## 4. Command-State Matrix

### Commands Allowed Per State

| State | Allowed Commands |
|-------|------------------|
| `Ready` | `StartCapture`, `RunWorkflow`, `ListInterfaces`, `LoadFile` |
| `Operating { .. }` | `StopCapture`, `GetStats` |
| `Degraded { CapabilitiesMissing, .. }` | `RunWorkflow`, `LoadFile` |
| `Degraded { other, .. }` | None |
| `Connecting` | None |
| `Initializing` | None |
| `CheckingEnvironment` | None |
| `ShuttingDown` | None |
| `Fatal` | None |

### Implementation Pattern

```rust
impl SystemState {
    /// Returns the list of commands that are valid in the current state.
    #[must_use]
    pub fn allowed_commands(&self) -> Vec<OrchestratorCommand> {
        use OrchestratorCommand::*;

        match self {
            // Ready: most commands allowed
            SystemState::Ready => vec![
                StartCapture { interface: String::new(), duration: None, filter: None },
                RunWorkflow { name: String::new() },
                ListInterfaces,
                LoadFile { path: std::path::PathBuf::new() },
            ],

            // Operating: limited to stop/stats
            SystemState::Operating { .. } => vec![
                StopCapture,
                GetStats,
            ],

            // Degraded with CapabilitiesMissing: analysis still works
            SystemState::Degraded { reason: DegradedReason::CapabilitiesMissing, .. } => vec![
                RunWorkflow { name: String::new() },
                LoadFile { path: std::path::PathBuf::new() },
            ],

            // All other states: no commands
            _ => vec![],
        }
    }

    /// Returns `true` if the given command is valid in the current state.
    #[must_use]
    pub fn is_command_allowed(&self, cmd: &OrchestratorCommand) -> bool {
        self.allowed_commands()
            .iter()
            .any(|allowed| std::mem::discriminant(allowed) == std::mem::discriminant(cmd))
    }
}
```

---

## 5. DegradedReason Capability Matrix

| Variant | Can Capture? | Can Analyze? | Recovery | Auto-Recovering? |
|---------|-------------|--------------|----------|------------------|
| `SidecarCrashed { restart_count }` | No | No | Supervisor restart | Yes |
| `SidecarUnresponsive { silent_for_secs }` | No | No | Kill + restart | Yes |
| `VersionMismatch { rust, python }` | No | No | Manual update | No (fatal after retry) |
| `CapabilitiesMissing` | **No** | **Yes** | Manual `setcap` | No (persistent) |
| `PythonEnvStale` | No | Maybe | `uv pip sync` | No |
| `IpcSocketUnavailable` | Degraded | Degraded | Fallback stdio | Maybe |

### Implementation Pattern (Following Error Module)

```rust
impl DegradedReason {
    /// Returns a human-readable description of the degraded state.
    #[must_use]
    pub fn user_message(&self) -> String {
        match self {
            Self::SidecarCrashed { restart_count } => format!(
                "Python backend crashed unexpectedly. Restart attempt {} of 3.",
                restart_count
            ),
            Self::SidecarUnresponsive { silent_for_secs } => format!(
                "Python backend stopped responding {} seconds ago.",
                silent_for_secs
            ),
            Self::VersionMismatch { rust_version, python_version } => format!(
                "Version mismatch: launcher {} is incompatible with backend {}.",
                rust_version, python_version
            ),
            Self::CapabilitiesMissing =>
                "Packet capture unavailable: missing Linux capabilities.".to_string(),
            Self::PythonEnvStale =>
                "Python environment is out of date.".to_string(),
            Self::IpcSocketUnavailable =>
                "IPC socket unavailable; using fallback communication.".to_string(),
        }
    }

    /// Returns an actionable suggestion for resolving the degraded state.
    #[must_use]
    pub fn suggestion(&self) -> Option<String> {
        match self {
            Self::SidecarCrashed { .. } =>
                Some("Automatic restart in progress. Check logs if this persists.".to_string()),
            Self::SidecarUnresponsive { .. } =>
                Some("Restarting backend process. Run `netguard doctor` if this persists.".to_string()),
            Self::VersionMismatch { .. } =>
                Some("Update both components to matching versions.".to_string()),
            Self::CapabilitiesMissing =>
                Some("Run: sudo setcap cap_net_raw,cap_net_admin=eip $(which netguard)".to_string()),
            Self::PythonEnvStale =>
                Some("Run: uv pip sync requirements.txt".to_string()),
            Self::IpcSocketUnavailable =>
                Some("Check /tmp permissions or run `netguard doctor`.".to_string()),
        }
    }

    /// Returns `true` if the system can still perform analysis in this state.
    #[must_use]
    pub const fn can_analyze(&self) -> bool {
        matches!(self, Self::CapabilitiesMissing)
    }

    /// Returns `true` if the system can still capture packets in this state.
    #[must_use]
    pub const fn can_capture(&self) -> bool {
        false // All degraded states prevent capture
    }

    /// Returns `true` if automatic recovery is being attempted.
    #[must_use]
    pub const fn is_auto_recovering(&self) -> bool {
        matches!(self, Self::SidecarCrashed { .. } | Self::SidecarUnresponsive { .. })
    }
}
```

---

## 6. Method Interfaces Summary

### SystemState Methods

| Method | Signature | Purpose |
|--------|-----------|---------|
| `can_transition_to` | `(&self, to: &SystemState) -> bool` | Validate transitions |
| `allowed_commands` | `(&self) -> Vec<OrchestratorCommand>` | List valid commands |
| `is_command_allowed` | `(&self, cmd: &OrchestratorCommand) -> bool` | Check command validity |
| `accepts_commands` | `(&self) -> bool` | Any commands valid? |
| `is_terminal` | `(&self) -> bool` | No transitions out? |
| `is_operational` | `(&self) -> bool` | Ready or Operating? |

### DegradedReason Methods (Error Pattern)

| Method | Signature | Purpose |
|--------|-----------|---------|
| `user_message` | `(&self) -> String` | Human-readable description |
| `suggestion` | `(&self) -> Option<String>` | Actionable fix guidance |
| `can_analyze` | `(&self) -> bool` | Analysis workflows allowed? |
| `can_capture` | `(&self) -> bool` | Packet capture allowed? |
| `is_auto_recovering` | `(&self) -> bool` | Supervisor restarting? |

---

## 7. Testing Strategy

### Test Naming Convention

Follow the `given_{state}_when_{action}_then_{result}` pattern:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────
    // Transition Tests
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn given_initializing_when_transition_to_checking_then_allowed() {
        let state = SystemState::Initializing;
        assert!(state.can_transition_to(&SystemState::CheckingEnvironment));
    }

    #[test]
    fn given_ready_when_transition_to_initializing_then_rejected() {
        let state = SystemState::Ready;
        assert!(!state.can_transition_to(&SystemState::Initializing));
    }

    #[test]
    fn given_fatal_when_transition_to_any_then_rejected() {
        let state = SystemState::Fatal { reason: "test".to_string() };
        assert!(!state.can_transition_to(&SystemState::Ready));
        assert!(!state.can_transition_to(&SystemState::Connecting));
    }

    // ─────────────────────────────────────────────────────────────
    // Command Guard Tests
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn given_ready_state_when_start_capture_then_allowed() {
        let state = SystemState::Ready;
        let cmd = OrchestratorCommand::StartCapture {
            interface: "eth0".to_string(),
            duration: None,
            filter: None,
        };
        assert!(state.is_command_allowed(&cmd));
    }

    #[test]
    fn given_fatal_state_when_start_capture_then_rejected() {
        let state = SystemState::Fatal { reason: "test".to_string() };
        let cmd = OrchestratorCommand::StartCapture {
            interface: "eth0".to_string(),
            duration: None,
            filter: None,
        };
        assert!(!state.is_command_allowed(&cmd));
    }

    #[test]
    fn given_degraded_capabilities_missing_when_run_workflow_then_allowed() {
        let state = SystemState::Degraded {
            reason: DegradedReason::CapabilitiesMissing,
            recovering: false,
        };
        let cmd = OrchestratorCommand::RunWorkflow { name: "test".to_string() };
        assert!(state.is_command_allowed(&cmd));
    }

    // ─────────────────────────────────────────────────────────────
    // DegradedReason Tests
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn given_capabilities_missing_when_can_analyze_then_true() {
        let reason = DegradedReason::CapabilitiesMissing;
        assert!(reason.can_analyze());
        assert!(!reason.can_capture());
    }

    #[test]
    fn given_sidecar_crashed_when_user_message_then_contains_restart_count() {
        let reason = DegradedReason::SidecarCrashed { restart_count: 2 };
        assert!(reason.user_message().contains("2"));
        assert!(reason.suggestion().is_some());
    }
}
```

### Test Categories

| Category | Purpose | Est. Count |
|----------|---------|------------|
| Transition validity | Each valid transition | ~12 |
| Transition rejection | Sample invalid transitions | ~8 |
| Command allowed | Each command in accepting states | ~10 |
| Command rejected | Sample rejections | ~6 |
| DegradedReason methods | Each variant's behavior | ~12 |
| Display implementations | Formatting correctness | ~3 |
| **Total** | | **~51** |

### Test Helpers

```rust
// Helper functions for constructing test states
fn ready_state() -> SystemState {
    SystemState::Ready
}

fn operating_capture() -> SystemState {
    SystemState::Operating {
        operation: ActiveOperation::Capturing {
            session_id: "test-123".to_string(),
            interface: "eth0".to_string(),
        },
    }
}

fn degraded_capabilities() -> SystemState {
    SystemState::Degraded {
        reason: DegradedReason::CapabilitiesMissing,
        recovering: false,
    }
}

fn fatal_state() -> SystemState {
    SystemState::Fatal {
        reason: "test error".to_string(),
    }
}
```

---

## 8. Implementation Checklist

### Phase 1: Type Definitions
- [ ] Define `DegradedReason` enum with all 6 variants
- [ ] Define `ActiveOperation` enum with all 4 variants
- [ ] Rewrite `SystemState` enum with embedded data (8 states)
- [ ] Add `Display` implementations for all enums
- [ ] Add doc comments to all types and variants

### Phase 2: Query Methods
- [ ] Implement `SystemState::accepts_commands()`
- [ ] Implement `SystemState::is_terminal()`
- [ ] Implement `SystemState::is_operational()`
- [ ] Implement `DegradedReason::can_analyze()`
- [ ] Implement `DegradedReason::can_capture()`
- [ ] Implement `DegradedReason::is_auto_recovering()`

### Phase 3: Transition Validation
- [ ] Implement `SystemState::can_transition_to()`
- [ ] Update `OrchestratorError::InvalidStateTransition` references
- [ ] Add tracing for transition attempts

### Phase 4: Command System
- [ ] Create `commands.rs` with `OrchestratorCommand` enum
- [ ] Implement `SystemState::allowed_commands()`
- [ ] Implement `SystemState::is_command_allowed()`
- [ ] Update `mod.rs` exports

### Phase 5: DegradedReason UX
- [ ] Implement `user_message()` for all variants
- [ ] Implement `suggestion()` for all variants
- [ ] Verify messages are actionable and jargon-free

### Phase 6: Testing
- [ ] Write transition validity tests (~12)
- [ ] Write transition rejection tests (~8)
- [ ] Write command guard tests (~16)
- [ ] Write DegradedReason method tests (~12)
- [ ] Write Display tests (~3)
- [ ] Verify all tests pass with `cargo test`

### Phase 7: Integration
- [ ] Verify `cargo clippy --all-targets` passes
- [ ] Update `ARCHITECTURE.md` if needed
- [ ] Run `just check` (pre-commit gate)

---

## References

| File | Purpose |
|------|---------|
| `.claude/rules/state-machine.md` | Authoritative specification |
| `.claude/rules/error-handling.md` | Error pattern to follow |
| `src/orchestrator/error.rs` | Reference implementation |
| `src/types.rs` | Shared primitives (Severity) |
| `ARCHITECTURE.md` | Project architecture |
