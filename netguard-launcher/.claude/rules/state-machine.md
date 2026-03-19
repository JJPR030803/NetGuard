# Rule: State Machine

> Load this file before touching `orchestrator/state.rs`, adding states,
> adding transitions, or changing `allowed_commands()`.

---

## The State Enum

```rust
pub enum SystemState {
    Initializing,
    CheckingEnvironment,
    Connecting,
    Ready,
    Operating { operation: ActiveOperation },
    Degraded { reason: DegradedReason, recovering: bool },
    ShuttingDown,
    Fatal { reason: String },
}
```

**`SystemState` is mutated ONLY inside `Orchestrator::transition_to()`.**
No other code path should ever write to it. If you find yourself wanting
to mutate state from a handler, CLI function, or test — stop and send a
message to the orchestrator instead.

---

## Valid Transition Table (Complete)

| From | To | Trigger |
|------|----|---------|
| Initializing | CheckingEnvironment | startup begins |
| CheckingEnvironment | Connecting | env checks pass |
| CheckingEnvironment | Degraded { recovering: true } | warnings found |
| CheckingEnvironment | Fatal | fatal issue found |
| Degraded | Connecting | supervisor attempts restart |
| Connecting | Ready | handshake OK |
| Connecting | Fatal | max retries exceeded |
| Ready | Operating { .. } | command received |
| Operating { .. } | Ready | operation complete |
| Operating { .. } | Degraded { recovering: true } | sidecar crash mid-op |
| Degraded { CapabilitiesMissing } | Operating { .. } | analysis command received |
| Any | ShuttingDown | shutdown signal |
| ShuttingDown | (terminal) | — |
| Fatal | (terminal) | — |

**Any transition not in this table is a programmer error, not a user error.**
Log it at `error!()` level and block it — do not allow it.

---

## Allowed Commands Per State

| State | Allowed |
|-------|---------|
| Ready | StartCapture, RunWorkflow, ListInterfaces, LoadFile |
| Operating { .. } | StopCapture, GetStats |
| Degraded(CapabilitiesMissing) | RunWorkflow, LoadFile |
| Degraded(IpcSocketUnavailable) | RunWorkflow, LoadFile |
| Degraded(other) | none |
| Connecting | none |
| Initializing | none |
| CheckingEnvironment | none |
| ShuttingDown | none |
| Fatal | none |

---

## How to Add a New State or Transition

1. Write one sentence justifying why this transition is needed.
2. Add the `(from, to)` pair to `can_transition_to()`.
3. Update `allowed_commands()` if the new state has different permissions.
4. Write a unit test for the new valid transition.
5. Write a unit test for the invalid adjacent transitions that must still fail.
6. Update the transition table in this file and in `ARCHITECTURE.md`.

**Never skip the tests. Never skip the `ARCHITECTURE.md` update.**

---

## Test Naming Pattern

```rust
// Pattern: given_{state}_when_{action}_then_{result}
#[test]
fn given_ready_state_when_start_capture_then_allowed() { ... }

#[test]
fn given_fatal_state_when_start_capture_then_rejected() { ... }

#[test]
fn given_degraded_capabilities_missing_when_run_workflow_then_allowed() { ... }
```

---

## DegradedReason Reference

| Variant | Meaning | Can capture? | Can analyze? |
|---------|---------|-------------|--------------|
| SidecarCrashed { restart_count } | Python died, supervisor restarting | No | No (temporary) |
| SidecarUnresponsive { silent_for_secs } | Heartbeat timeout, killing + restarting | No | No (temporary) |
| VersionMismatch { rust, python } | Handshake failed — incompatible versions | No | No (fatal after retry) |
| CapabilitiesMissing | cap_net_raw/cap_net_admin not set | **No** | **Yes** |
| PythonEnvStale | requirements.txt hash mismatch | No | Maybe |
| IpcSocketUnavailable | Socket creation failed, using stdio fallback | Degraded | Degraded |

`CapabilitiesMissing` is the most important: the system is fully usable for
analysis. The frontend shows a persistent banner, not a blocking error screen.
