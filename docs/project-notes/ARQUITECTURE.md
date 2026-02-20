# NetGuard Architecture
**Version:** 3.0 (Planning Final)
**Date:** February 2026
**Author:** Juan Julian
**Status:** Settled — Implementation Ready

This document is the authoritative reference for every architectural decision made
before implementation began. It answers the question "why does the system work this
way" for every component. When in doubt during implementation, consult this document
before changing anything structural.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Core Design Principles](#2-core-design-principles)
3. [Layer Architecture](#3-layer-architecture)
4. [The Orchestrator](#4-the-orchestrator)
5. [System State Machine](#5-system-state-machine)
6. [Degraded Mode](#6-degraded-mode)
7. [The Sidecar](#7-the-sidecar)
8. [IPC Architecture](#8-ipc-architecture)
9. [IPC Envelope Format](#9-ipc-envelope-format)
10. [Data Plane & Checkpointing](#10-data-plane--checkpointing)
11. [Configuration Architecture](#11-configuration-architecture)
12. [Permissions Model](#12-permissions-model)
13. [Logging Architecture](#13-logging-architecture)
14. [Graceful Shutdown Sequence](#14-graceful-shutdown-sequence)
15. [First-Run Setup Wizard](#15-first-run-setup-wizard)
16. [Security Model](#16-security-model)
17. [Testing Strategy](#17-testing-strategy)
18. [MkDocs Documentation Structure](#18-mkdocs-documentation-structure)
19. [Architecture Decision Records](#19-architecture-decision-records)

---

## 1. System Overview

NetGuard is a network security analysis tool built with a hybrid Rust/Python
architecture. Rust owns the frontend, orchestration, and system integration.
Python owns packet capture, protocol analysis, machine learning, and data
processing using its mature ecosystem.

```
┌─────────────────────────────────────────────────────────────┐
│  FRONTENDS                                                  │
│  ┌──────────────────┐        ┌──────────────────┐          │
│  │   CLI (Clap)     │        │   TUI (Ratatui)  │          │
│  └────────┬─────────┘        └────────┬─────────┘          │
│           └──────────────┬────────────┘                     │
│                    OrchestratorHandle                        │
└────────────────────────┬────────────────────────────────────┘
                         │ Commands / Snapshots (broadcast)
┌────────────────────────▼────────────────────────────────────┐
│  ORCHESTRATOR                                               │
│  ├─ SystemState machine (single source of truth)           │
│  ├─ SidecarSupervisor (lifecycle + restarts)               │
│  ├─ EnvironmentChecker (just doctor logic)                 │
│  ├─ ConfigManager (netguard.toml)                          │
│  └─ LogRouter (decides where logs land)                    │
└────────────────────────┬────────────────────────────────────┘
                         │ IPC: Unix Domain Sockets
                         │ Protocol: Length-prefix + JSON envelope
┌────────────────────────▼────────────────────────────────────┐
│  PYTHON SIDECAR (thin translation layer)                    │
│  └─ ipc_sidecar.py → existing Python core                  │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│  PYTHON CORE (unchanged)                                    │
│  ├─ Scapy: packet capture                                  │
│  ├─ Polars + PyArrow: Parquet data processing              │
│  ├─ TensorFlow / scikit-learn: ML analysis                 │
│  └─ Workflows: DailyAudit, IPInvestigation, ThreatHunting  │
└─────────────────────────────────────────────────────────────┘
```

**The fundamental rule:** Frontends never communicate with Python directly.
Every interaction goes through the Orchestrator. This is enforced structurally —
frontends only hold an `OrchestratorHandle`, which gives them no path to the
sidecar or core.

---

## 2. Core Design Principles

### Principle 1: Explicit Over Implicit
Every state transition is explicit and validated. No implicit defaults scattered
across modules. All defaults live in one place (`UserPreferences::default()`).
Config resolution order is documented and enforced, never assumed.

### Principle 2: Fail Loudly, Recover Gracefully
Errors are data, not exceptions. Every error carries a user message, a suggested
fix, a severity level, and a `recoverable` boolean. The system distinguishes
between bugs (programmer errors, log and panic), user errors (display and suggest
fix), and environment errors (enter degraded mode, attempt recovery).

### Principle 3: Separation of Concerns by Layer
Presentation layer (CLI/TUI) is fully swappable. Application layer (Orchestrator)
is shared by all frontends. Infrastructure layer (IPC, permissions, Python env) is
platform-specific and isolated. Python core is unchanged — the sidecar adapts to
it, not the reverse.

### Principle 4: Least Privilege
Request only the permissions actually needed. Linux capabilities (`cap_net_raw`,
`cap_net_admin`) over full sudo. IPC socket restricted to owner only (mode 0o600).
Output Parquet files not world-readable. Capture capabilities are checked at
startup — absence triggers Degraded mode, not a fatal error, because analysis of
existing files does not require capture permissions.

### Principle 5: Testability First
All logic lives in library code (`lib.rs`), not in `main.rs`. `main.rs` is
orchestration only. Every layer is testable in isolation via dependency injection
and mock boundaries. The sidecar is tested in four independent layers, none of
which require a real network interface, root privileges, or a running Python
process.

### Principle 6: Bounded Failure
Every failure mode has a defined maximum impact. Crash during capture: bounded
data loss equal to one checkpoint interval. Sidecar crash: maximum 3 restarts in
60 seconds, then Fatal state with clear message. Socket unavailable: fallback to
stdio IPC with warning. These bounds are documented and tested.

---

## 3. Layer Architecture

```
┌──────────────────────────────────────────────────────────┐
│  PRESENTATION LAYER (Swappable)                          │
│  Knows: OrchestratorHandle API only                      │
│  Does not know: Python exists, IPC exists, state machine │
│  ┌──────────────────┐     ┌──────────────────┐          │
│  │   CLI Module     │     │   TUI Module     │          │
│  │  Clap-based      │     │  Ratatui + MVU   │          │
│  └──────────────────┘     └──────────────────┘          │
└──────────────────────────────────────────────────────────┘
                    │ OrchestratorHandle
┌──────────────────────────────────────────────────────────┐
│  ORCHESTRATION LAYER (Stable core)                       │
│  Knows: Everything                                       │
│  Does: State management, lifecycle, routing, logging     │
│  ├─ Orchestrator (run loop, command dispatch)            │
│  ├─ SystemState (state machine)                          │
│  ├─ SidecarSupervisor (lifecycle)                        │
│  ├─ EnvironmentChecker (prerequisites)                   │
│  └─ ConfigManager (netguard.toml)                        │
└──────────────────────────────────────────────────────────┘
                    │ IpcCommand / IpcEnvelope
┌──────────────────────────────────────────────────────────┐
│  INFRASTRUCTURE LAYER (Platform-specific)                │
│  ├─ IPC: Unix Domain Sockets / Named Pipes               │
│  ├─ Permissions: Linux caps / macOS sudo / Windows admin │
│  ├─ Python env: uv-managed virtualenv                    │
│  └─ Logging: tracing subscriber + file appender         │
└──────────────────────────────────────────────────────────┘
                    │ Unix socket + JSON
┌──────────────────────────────────────────────────────────┐
│  PYTHON SIDECAR (Thin adapter)                           │
│  └─ ipc_sidecar.py (translate IPC → core function calls) │
└──────────────────────────────────────────────────────────┘
                    │
┌──────────────────────────────────────────────────────────┐
│  PYTHON CORE (Unchanged)                                 │
│  Scapy / Polars / TensorFlow / Workflows                 │
└──────────────────────────────────────────────────────────┘
```

---

## 4. The Orchestrator

The Orchestrator is the heart of the system. It is the only component that has
full visibility into both the frontend state and the backend state. It owns
all state mutations. It is the only component that talks to the sidecar.

### What the Orchestrator Owns
- `SystemState` — the authoritative state of the whole system
- `BackendState` — a mirror of what Python has reported via IPC events
- `SidecarSupervisor` — the lifecycle of the Python sidecar process
- `ConfigManager` — reading and writing `netguard.toml`
- Log routing — deciding where Python and Rust logs are written

### What the Orchestrator Does NOT Own
- Frontend rendering — that is the CLI/TUI's job
- Packet capture logic — that is Python's job
- Analysis logic — that is Python's job
- IPC framing mechanics — that is the `infra::ipc` layer's job

### The OrchestratorHandle
Every frontend receives an `OrchestratorHandle` at startup. This is a lightweight
struct containing only two channels:

- A sender for `OrchestratorCommand` — frontend sends commands to orchestrator
- A broadcast receiver for `SystemSnapshot` — frontend receives state updates

The handle is the complete API surface between frontends and the orchestrator.
There is no other path. This means:

- Adding a new frontend means implementing against the handle API only
- Testing a frontend means mocking the handle channels
- A frontend cannot accidentally bypass the orchestrator

### The Run Loop
The orchestrator's `run()` method is a `tokio::select!` loop over four event
sources:

1. Commands from frontends via `command_rx`
2. IPC messages from the sidecar via `supervisor.next_message()`
3. Supervisor lifecycle events via `supervisor.next_event()`
4. Shutdown signal via `shutdown_rx`

All state mutations happen inside this loop. State is never mutated from outside.
The loop always ends with a broadcast of the current snapshot so frontends stay
current.

### Command Validation
Before any command is dispatched, the orchestrator checks
`system_state.allowed_commands()`. Commands not allowed in the current state are
rejected with an error snapshot — they do not reach the sidecar. This means the
sidecar never receives commands that are invalid for the current system state.

---

## 5. System State Machine

The `SystemState` enum is the single source of truth for what the system is doing.
Only the Orchestrator mutates it. Every mutation is validated against the
transition table before being applied. Invalid transitions are logged as bugs
(programmer error), not user errors.

### States

```
Initializing
    │ startup begins
    ▼
CheckingEnvironment  ──── fatal issue ────▶ Fatal
    │
    ├── warnings found ──▶ Degraded { recovering: true }
    │                           │
    │                           ▼
    └────────────────────▶ Connecting
                                │ handshake OK
                                ▼
                            Ready ◀──────────────────────┐
                                │                         │
                                ├── command received      │
                                ▼                         │
                            Operating { operation }       │
                                │ operation complete ─────┘
                                │
                                ├── sidecar crash ──▶ Degraded { recovering: true }
                                │                         │ supervisor restarts
                                │                         ▼
                                │                     Connecting
                                │                         │ max retries exceeded
                                │                         ▼
                                │                       Fatal
                                ▼
                           ShuttingDown
```

### Degraded State
Degraded is not an error — it is a valid operational state with a reduced
capability set. The system attempts to recover from Degraded automatically via
the supervisor. If recovery fails after the configured maximum retries,
the system transitions to Fatal.

A system in Degraded state with `DegradedReason::CapabilitiesMissing` can still
run workflows and analyze existing Parquet files. It cannot capture new packets.
The frontend renders a clear "capture disabled" indicator, not a crash screen.

### Transition Guard
Every call to `transition_to()` passes through `can_transition_to()`. If the
transition is not in the allowed table, the transition is blocked and logged as
an error-level event with the attempted from/to states. The system continues in
its current state. This makes impossible states visible during development.

### Allowed Commands Per State

| State | Allowed Commands |
|-------|-----------------|
| Ready | StartCapture, RunWorkflow, ListInterfaces, LoadFile |
| Operating | StopCapture, GetStats |
| Degraded (CapabilitiesMissing) | RunWorkflow, LoadFile |
| Degraded (other) | none |
| Connecting | none |
| Initializing | none |
| Fatal | none |
| ShuttingDown | none |

---

## 6. Degraded Mode

Degraded mode is a first-class operational state, not a fallback error handler.
The system is designed to be useful even when fully operational is not possible.

### Degraded Reasons

`SidecarCrashed { restart_count }` — Python process died unexpectedly. Supervisor
is attempting restart. Frontend shows "Reconnecting..." with attempt count.

`SidecarUnresponsive { silent_for_secs }` — heartbeat timeout exceeded. Supervisor
is killing and restarting. Same UI treatment as crash.

`VersionMismatch { rust, python }` — handshake detected incompatible versions.
Cannot proceed. User must run `just setup` to sync versions. This is Fatal after
one retry.

`CapabilitiesMissing` — `cap_net_raw`/`cap_net_admin` not set on Python binary.
Analysis of existing files is fully available. Capture is disabled. Frontend shows
"Capture unavailable — run `just setup-caps` to enable" as a persistent banner,
not a blocking error.

`PythonEnvStale` — `requirements.txt` hash does not match `.venv` state.
Orchestrator suggests running `uv sync`. System attempts to continue but Python
imports may fail.

`IpcSocketUnavailable` — could not create Unix Domain Socket. Falls back to stdio
IPC with warning. This is a Warning, not Fatal.

### Frontend Rendering Contract
Every frontend must handle all Degraded reasons in its render layer. There is no
acceptable "crash screen" for a Degraded reason. Every Degraded reason has:
- A human-readable one-line summary
- A suggested action (the `fix` field from EnvironmentChecker)
- An indicator of whether recovery is in progress

---

## 7. The Sidecar

The sidecar (`ipc_sidecar.py`) is a thin translation layer. It has exactly one
job: receive IPC commands from Rust, call the correct Python core function, and
return the result. It contains no business logic. It does not make decisions.

### What the Sidecar Is Not
- It is not a reimplementation of any Python core functionality
- It is not a configuration manager
- It is not a state machine
- It is not responsible for deciding whether a command is valid

The Orchestrator validates commands before sending them. The sidecar trusts that
any command it receives is valid and should be executed.

### Signal Handling
The sidecar registers handlers for `SIGTERM` and `SIGINT`. On receiving either:
1. Call `emergency_finalize()` on the active writer if one exists
2. Attempt one final `EMERGENCY_CHECKPOINT` IPC event if the socket is alive
3. Exit cleanly with code 0

This ensures that a supervisor-initiated restart always produces a valid partial
Parquet file before the process dies.

### Sidecar Startup Contract
When the sidecar starts, it does not begin processing commands immediately. It
waits for a `HANDSHAKE` message from Rust. Only after successfully responding to
the handshake does it enter the command processing loop. This prevents race
conditions where commands arrive before the sidecar is ready.

### Error Handling in the Sidecar
The sidecar wraps every `handle_command` call in a try/except. If the Python
core raises any exception:
- Log the full traceback to stderr (which flows to the Rust log router via IPC)
- Return an `ERROR` response with `recoverable: true`
- Continue processing the next command

The sidecar must never crash due to a Python core error. Only a socket error or
signal should terminate the sidecar.

---

## 8. IPC Architecture

### Why Unix Domain Sockets
Unix Domain Sockets (UDS) provide reliable, bidirectional, low-latency
communication between the Rust orchestrator and the Python sidecar without the
complexity of network sockets. They are a first-class OS primitive with no
external dependencies.

Key properties:
- Logs (stderr) are separate from data (socket) — no pollution of the data stream
- Bidirectional — Rust can send commands AND receive events from Python
- Latency under 1ms for control messages (benchmarked target)
- Socket file permissions restrict access to the owning user

### Socket Security
The socket file is created in the system temp directory with a PID-namespaced name
(`/tmp/netguard_{pid}.sock`). Immediately after binding, file permissions are set
to `0o600` (owner read/write only). This prevents other local users from injecting
commands or reading the data stream.

The `IpcServer` implements `Drop` to remove the socket file on shutdown, including
panic unwinds via the Rust panic hook.

### Message Framing
TCP and Unix sockets are byte streams, not message streams. Raw socket reads may
return partial messages or multiple messages in one read. Length-prefix framing
solves this:

```
┌──────────────┬──────────────────────────────┐
│  Length      │  JSON Payload                │
│  4 bytes     │  `length` bytes              │
│  big-endian  │  UTF-8 encoded               │
└──────────────┴──────────────────────────────┘
```

The receiver reads exactly 4 bytes to get the length, then reads exactly `length`
bytes to get the payload. This is reliable regardless of TCP/socket buffering.

Maximum message size: 10MB. Messages exceeding this are rejected with
`IpcError::MessageTooLarge`. This prevents memory exhaustion from malformed
messages.

### Control Plane vs Data Plane
The IPC socket is the **control plane** only. It carries commands, responses,
status events, heartbeats, and log messages. Volume is low (KB/s).

The **data plane** is files. Python writes Parquet to disk. Rust reads Parquet
from disk when the user requests analysis. Packet data never flows through the
IPC socket. This separation means:
- IPC latency is not affected by capture volume
- Large captures do not exhaust socket buffers
- The socket can be restarted without losing captured data

### Graceful Degradation: IPC Mode Selection
```
Preferred:  Unix Domain Socket (Linux, macOS)
Fallback:   Named Pipe (Windows)
Last resort: stdio JSON (if sockets unavailable)
```

The fallback chain is detected at startup by `IpcMode::detect_best()`. Stdio
fallback logs a warning and loses bidirectionality — commands still work but
real-time event streaming is unavailable.

### Heartbeat Protocol
Python sends a `HEARTBEAT` envelope every 5 seconds. Rust tracks `last_heartbeat`
in `BackendState`. The supervisor checks this timestamp every 5 seconds. If more
than 15 seconds have elapsed since the last heartbeat, the supervisor emits
`SupervisorEvent::Unresponsive` and begins restart procedures.

The heartbeat is the primary mechanism for detecting a frozen Python process that
has not crashed (which would be detected by process death) but is simply not
responding.

---

## 9. IPC Envelope Format

The envelope format is frozen. No changes should be made to the envelope structure
itself. New functionality is added by defining new `action` strings and payload
schemas, never by adding fields to the envelope.

### Envelope Schema

```json
{
  "id":        "uuid-v4 string — correlation ID, generated by sender",
  "version":   1,
  "type":      "REQUEST | RESPONSE | EVENT | HEARTBEAT | HANDSHAKE",
  "action":    "string — specific operation within the type",
  "timestamp": "integer — milliseconds since Unix epoch, sender's clock",
  "payload":   "object — action-specific data, untyped at envelope level",
  "metadata":  "object — cross-cutting concerns, optional, start empty",
  "status":    "OK | ERROR | PARTIAL | REJECTED — present on RESPONSE only",
  "error":     "object or null — present on RESPONSE when status is ERROR"
}
```

### Error Object Schema

```json
{
  "code":        "string — machine-readable error identifier",
  "message":     "string — human-readable explanation",
  "recoverable": "boolean — true if system can continue, false if Fatal",
  "suggestion":  "string or null — what the user should do"
}
```

### Message Types

`REQUEST` — sent by Rust, expects a `RESPONSE` with matching `id`.

`RESPONSE` — sent by Python in reply to a `REQUEST`. Always carries the same `id`
as the request. Always carries `status`. Carries `error` when status is `ERROR`.

`EVENT` — sent by Python unprompted. No response expected. Used for stats updates,
log forwarding, and checkpoint notifications. Does not carry `status`.

`HEARTBEAT` — sent by Python every 5 seconds. No response expected. Rust updates
`BackendState.last_heartbeat` on receipt.

`HANDSHAKE` — first message of every connection. Sent by Rust, responded by Python.
Python's response includes its version and available workflow list. If Python
cannot satisfy the handshake, it responds with `status: ERROR` and
`recoverable: false`.

### Defined Actions

| Action | Direction | Type | Description |
|--------|-----------|------|-------------|
| HANDSHAKE | Rust→Python | HANDSHAKE/RESPONSE | Version + capability exchange |
| START_CAPTURE | Rust→Python | REQUEST/RESPONSE | Begin packet capture |
| STOP_CAPTURE | Rust→Python | REQUEST/RESPONSE | Stop active capture |
| GET_STATS | Rust→Python | REQUEST/RESPONSE | Current capture statistics |
| RUN_WORKFLOW | Rust→Python | REQUEST/RESPONSE | Execute analysis workflow |
| GET_WORKFLOWS | Rust→Python | REQUEST/RESPONSE | List available workflows |
| CHECKPOINT_WRITTEN | Python→Rust | EVENT | Parquet checkpoint completed |
| EMERGENCY_CHECKPOINT | Python→Rust | EVENT | Final checkpoint on SIGTERM |
| CAPTURE_COMPLETE | Python→Rust | EVENT | Normal capture completion |
| LOG | Python→Rust | EVENT | Python log entry forwarding |
| HEARTBEAT | Python→Rust | HEARTBEAT | Liveness signal |

New actions are added to this table as features are implemented. The envelope
format does not change.

### Correlation and Concurrency
Every `REQUEST` carries a UUID v4 as its `id`. The corresponding `RESPONSE`
carries the same `id`. The orchestrator uses this to match responses to in-flight
requests when multiple operations are concurrent. Responses that arrive after a
request has timed out are discarded.

---

## 10. Data Plane & Checkpointing

### The Problem
Parquet files require a footer written at the end of the file containing schema
and row group metadata. A Python crash before the footer is written produces an
unreadable file. Without checkpointing, a 60-second capture that crashes at
second 59 loses all data.

### The Solution: Row Group Checkpointing
`CheckpointedParquetWriter` wraps PyArrow's `ParquetWriter` and writes a complete,
valid row group to disk periodically. A Parquet file with multiple row groups is
still a standard Parquet file — all existing analysis code reads it identically.

**Checkpoint triggers (whichever comes first):**
- Every 1,000 packets captured
- Every 10 seconds elapsed

After each checkpoint:
1. Current buffer is flushed as a row group via `writer.write_table()`
2. Buffer is cleared
3. A `CHECKPOINT_WRITTEN` IPC event is sent to Rust
4. Rust updates `BackendState.last_checkpoint`

**On SIGTERM (supervisor-initiated restart or graceful shutdown):**
1. `emergency_finalize()` is called
2. Remaining buffer (if any) is written as a final row group
3. `writer.close()` is called to write the Parquet footer
4. `EMERGENCY_CHECKPOINT` event is sent if socket is alive
5. Process exits cleanly

### Maximum Data Loss Bound
After implementation, the maximum data loss on any crash or shutdown is:
`min(1000 packets, 10 seconds)` worth of capture data.

On normal graceful shutdown, data loss is zero — `emergency_finalize()` flushes
the remaining buffer before exit.

### Data Loss Assessment
The orchestrator classifies data loss after a crash using `BackendState.last_checkpoint`:

- `DataLossAssessment::None` — capture completed normally before crash
- `DataLossAssessment::Partial { packets_safe, output_path }` — some data written
- `DataLossAssessment::Complete` — crashed before first checkpoint, nothing saved

This assessment is included in the `Degraded` state broadcast so frontends can
render a meaningful recovery message rather than a generic error.

### Existing Code Compatibility
`CheckpointedParquetWriter` produces standard Parquet files. `NetworkParquetAnalysis`,
`DailyAudit`, `IPInvestigation`, `ThreatHunting` — all existing analysis code
reads checkpointed files without modification.

---

## 11. Configuration Architecture

### The Two Config Categories

**Runtime config** is per-invocation configuration: which interface to capture on,
how long to capture, what BPF filter to apply. This flows through IPC as part of
the `START_CAPTURE` and `RUN_WORKFLOW` request payloads. It never touches a file.
Mismatch between Rust and Python is structurally impossible — it is just a dict.

**Persistent preferences** are user settings that survive between runs: default
output directory, log level, business hours for daily audit, TUI theme. These live
in `netguard.toml`.

### netguard.toml
`netguard.toml` is the single mandatory starting point for all configuration.
Location: `~/.config/netguard/netguard.toml`.

Written by: Rust `ConfigManager` only. Python never writes config.

Read by: Rust `ConfigManager` (via `toml` crate) and Python sidecar (via stdlib
`tomllib`, Python 3.11+ required).

All defaults live in `UserPreferences::default()` in Rust. On first run, the setup
wizard writes a complete `netguard.toml` with all defaults populated and commented.
The file is the documentation of the available configuration.

### Config Priority Chain
```
CLI arguments       (highest — always override)
    ↓
netguard.toml       (user preferences)
    ↓
UserPreferences::default()  (compiled-in defaults, never changes)
```

### Config Schema Versioning
`netguard.toml` includes a `config_version` field. `ConfigManager` checks this
on load. If the version is older than expected, it runs a migration function that
adds any new fields with their defaults and bumps the version. The migration is
idempotent — running it twice produces the same result.

Missing fields in an older config file are filled with defaults, never with errors.
Unknown fields in a newer config file are ignored with a warning. This means
downgrading NetGuard never corrupts the config file.

### No YAML
The original architecture generated YAML on-demand for Python. This is removed.
Python reads `netguard.toml` for preferences and receives runtime config via IPC
payload. There is no YAML anywhere in the system.

---

## 12. Permissions Model

### Linux
Packet capture requires `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities on the
Python binary. These are set once during setup:

```
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

This grants minimal permissions — not full sudo. NetGuard runs as a regular user
at all times. The capability check happens in `EnvironmentChecker` at startup.
Missing capabilities produce `DegradedReason::CapabilitiesMissing`, not a fatal
error. The system remains usable for analysis of existing files.

### macOS
Packet capture requires membership in the `access_bpf` group or sudo. The
environment checker detects which is available. Group membership is preferred
over sudo.

### Windows
Packet capture requires administrator privileges or Npcap installation with
appropriate user permissions. The environment checker guides the user through
Npcap setup if needed.

### Principle
Never request more permission than necessary. Never run the whole process as root.
Never silently proceed with insufficient permissions — always inform the user of
exactly what is needed and why.

---

## 13. Logging Architecture

### Split Responsibility
Python core owns log **formatting and emission** — it uses its existing established
log formats and the `logging` module. Python's loggers are already wired through
the codebase and are not changed.

The Orchestrator owns log **routing** — it receives Python log entries via IPC
`LOG` events and decides where they land. This includes the log file path (from
`netguard.toml [logging]` section), rotation policy, and whether logs are also
written to stdout in verbose mode.

Rust uses `tracing` with structured fields. Python logs forwarded via IPC are
tagged with `python_module` so they are distinguishable in the unified log stream.

### Unified Log Stream
From the user's perspective, all logs come from one place. The log file contains
interleaved Rust and Python entries, ordered by timestamp, both in structured JSON
format. A user debugging a capture issue sees the full picture without consulting
two separate log files.

### Log Levels
- `ERROR`: System cannot complete the requested operation. Always shown.
- `WARN`: Operation completed but with a degraded condition. Shown unless quiet mode.
- `INFO`: Normal operation events. Shown in verbose mode (`-v`).
- `DEBUG`: Detailed operation internals. Shown with (`-vv`).

Rust log level is configured by `RUST_LOG` environment variable and `netguard.toml`.
Python log level mirrors the Rust level and is configured by the Orchestrator at
sidecar startup via the handshake payload.

### Log File Location
Default: `~/.local/share/netguard/logs/netguard.log`
Configurable via `netguard.toml [logging].path`.
Rotation: daily, keep 7 days. Configurable.

---

## 14. Graceful Shutdown Sequence

The shutdown sequence is deterministic and bounded. Maximum wall-clock time from
shutdown signal to process exit: 10 seconds (5 second sidecar timeout + 5 second
margin).

### Sequence

```
1. User triggers quit (TUI: 'q', CLI: Ctrl+C, signal: SIGTERM to Rust)
        │
        ▼
2. Orchestrator transitions to SystemState::ShuttingDown
   Broadcasts ShuttingDown snapshot to all frontends
        │
        ▼
3. Frontends render "Shutting down..." and stop accepting new commands
        │
        ▼
4. Orchestrator sends SIGTERM to Python sidecar process
        │
        ▼
5. Python sidecar SIGTERM handler:
   a. Calls emergency_finalize() on active writer (if any)
   b. Sends EMERGENCY_CHECKPOINT IPC event with final path
   c. Exits with code 0
        │
        ▼
6. Orchestrator waits for EMERGENCY_CHECKPOINT event OR 5-second timeout
        │
        ├── Event received: Log checkpoint path, proceed to step 7
        └── Timeout: Log warning "sidecar did not confirm checkpoint",
                     send SIGKILL to sidecar, proceed to step 7
        │
        ▼
7. Orchestrator removes IPC socket file
   Flushes Rust log buffer
   Exits process with code 0
```

### Data Safety Guarantee
On normal graceful shutdown (steps 1-7 with event received in step 6):
zero data loss. The `emergency_finalize()` in step 5a flushes all remaining
buffered packets before exiting.

On timeout shutdown (SIGKILL path): data loss bounded to last checkpoint interval.
The same bound as a crash.

---

## 15. First-Run Setup Wizard

### Trigger
The Orchestrator detects first-run by the absence of `netguard.toml` at startup,
or by the presence of `setup_complete: false` in an existing config. This check
happens before the environment checker, before the sidecar, before anything else.

### Wizard Flow
The setup wizard is a TUI experience modeled on `bun init` and `vite create` —
interactive, guided, and leaves the user with a working system, not a list of
manual steps.

```
1. Display welcome screen with NetGuard description
2. Run all environment checks (reusing EnvironmentChecker)
3. For each failed check:
   a. Show what is missing in plain language
   b. Show the exact command to fix it
   c. Offer to run the fix automatically if safe to do so
   d. Wait for user confirmation or skip
4. Prompt for user preferences:
   a. Default capture interface (show detected interfaces)
   b. Default output directory
   c. Log level
   d. TUI theme
5. Write netguard.toml with all settings and commented documentation
6. Set setup_complete: true in config
7. Show summary of what was configured
8. Proceed to normal startup
```

### Safety Constraints
The wizard never runs destructive commands without explicit user confirmation.
It never modifies system files outside of NetGuard's config directory without
showing the user exactly what will be run and waiting for `y/n` confirmation.
Capability setup (`setcap`) always requires explicit user approval — it is never
done silently.

### Re-running the Wizard
`netguard setup` can be run at any time to re-run the wizard. It starts with
the current `netguard.toml` values as defaults so the user only needs to change
what they want to update.

---

## 16. Security Model

### Threat Model

**In scope (defended against):**
- Local privilege escalation via shell injection in CLI arguments
- Terminal hijacking via ANSI escape codes in packet payloads
- IPC socket access by other local users
- Memory exhaustion via malformed IPC messages
- Runaway Python processes consuming all system resources

**Out of scope (documented as not defended):**
- Malicious packet captures that exploit Scapy vulnerabilities
- Physical access to the machine running NetGuard
- Attacks from remote systems over the network
- Supply chain attacks on Python or Rust dependencies
  (mitigated by audit tooling, not eliminated)

### Input Validation
All user input is validated before use. Validation uses a whitelist approach —
only explicitly allowed characters/values are permitted, everything else is
rejected. Validation functions live in `core::validation` and are tested with
property-based tests (proptest) to verify they never panic on arbitrary input.

**Interface names:** alphanumeric, dash, underscore only, max 15 characters (Linux
`IFNAMSIZ`).

**BPF filters:** no shell metacharacters (`;`, `|`, `&`, `` ` ``, `$`, newlines),
max 500 characters. Full syntax validation happens in Scapy.

**File paths:** no `..` components, must have `.parquet` extension for output
files. Parent directory created if it does not exist.

**Durations:** integer, 1-3600 seconds. No floats, no negative values.

### No Shell Execution
Python is never invoked via `sh -c` or any shell. It is always invoked directly
with argument arrays. This eliminates shell injection as an attack surface
regardless of what user input contains.

### Terminal Sanitization
All strings that originate from packet data (payload contents, hostnames, URLs
extracted from packets) are sanitized before display in the TUI. Control
characters (Unicode category `Cc`) are replaced with the replacement character
`\u{FFFD}`. This prevents an attacker on the network from injecting ANSI escape
sequences into the TUI via crafted packet payloads.

### Resource Limits
Python sidecar processes are spawned with memory limits via `RLIMIT_AS` on Linux.
Default: 1GB. Configurable in `netguard.toml`. This prevents a malfunctioning
capture or analysis from exhausting system memory.

---

## 17. Testing Strategy

### Philosophy
Every layer of the system is independently testable. No test requires root
privileges, a real network interface, or a running Python process (except
explicit end-to-end tests, which are tagged `#[ignore]` in Rust and
`@pytest.mark.e2e` in Python and are not run in CI by default).

### Rust Testing

**Unit tests** live in the same file as the code they test (`#[cfg(test)]` blocks).
They test pure logic: state machine transitions, validation functions, config
parsing, error formatting.

**Integration tests** live in `tests/`. They test cross-module behavior: IPC
roundtrips with a mock Python client, orchestrator command routing with mock
sidecar, supervisor restart behavior with a mock process.

**Property tests** use `proptest`. They test security-critical validators. Every
validator must satisfy:
- Never panics on any input (fuzz with `"\\PC*"` strategy)
- Valid inputs are always accepted
- Invalid inputs are always rejected
- Validation is idempotent (same input always produces same result)

**Benchmarks** use `criterion`. IPC roundtrip latency must be under 1ms.
This is a thesis claim and must be measurable.

### Python Sidecar Testing (Four Layers)

**Layer 1 — Socket Mechanics:** Tests the `FramedSocket` class in isolation using
real Unix socket pairs (via `tmp_path` fixture). Verifies framing for small
messages, large messages, fragmented delivery, and clean/unclean close. No sidecar
or core code involved.

**Layer 2 — Message Dispatch:** Tests `IpcSidecar.handle_message()` with all core
dependencies mocked. Verifies that each action string routes to the correct handler,
unknown actions return `REJECTED`, correlation IDs are always preserved, and core
exceptions produce `ERROR` responses without crashing the sidecar.

**Layer 3 — Core Translation:** Tests that IPC payloads are translated to the
exact argument signatures expected by Python core functions. These tests are the
living contract between the sidecar and the existing codebase. A Python core API
change that breaks these tests must be addressed before merging.

**Layer 4 — Lifecycle:** Tests sidecar startup, shutdown, signal handling, and
heartbeat behavior. Uses threading to run the sidecar in the background. Verifies
SIGTERM calls `emergency_finalize`, socket close causes clean exit, and the sidecar
survives repeated core failures.

### Python Core Testing
Existing test suite (100+ tests) is unchanged. The checkpointed writer gets its
own test suite in `tests/capture/test_checkpointed_writer.py` covering: checkpoint
triggers, row group validity, `emergency_finalize` behavior, and thread safety.

### Test Markers

Rust:
- Default run: all tests
- `#[ignore]`: end-to-end tests requiring root or real hardware

Python:
- `unit`: no I/O, fast
- `integration`: real sockets, mocked core
- `slow`: lifecycle tests, takes >1 second
- `e2e`: requires real hardware/root (not in CI)

Default `pytest` invocation excludes `slow` and `e2e`. `just test-all` includes
`slow`. `just test-e2e` requires explicit invocation.

---

## 18. MkDocs Documentation Structure

```
docs/
├── mkdocs.yml
└── docs/
    ├── index.md
    ├── getting-started/
    │   ├── installation.md
    │   ├── first-run.md
    │   └── quick-start.md
    ├── user-guide/
    │   ├── capture.md
    │   ├── workflows.md
    │   ├── configuration.md    ← netguard.toml full reference
    │   └── troubleshooting.md  ← written with exact error strings as headings
    ├── architecture/
    │   ├── overview.md
    │   ├── orchestrator.md
    │   ├── ipc.md
    │   ├── data-plane.md
    │   └── decisions/          ← ADR index + all 18 ADR files live here
    │       └── index.md
    ├── api/
    │   ├── python/             ← auto-generated via mkdocstrings
    │   └── rust/
    │       └── index.md        ← links to cargo doc output
    └── development/
        ├── setup.md
        ├── testing.md
        ├── security.md
        └── contributing.md
```

### Key Documentation Principles
Code examples in docs are pulled from actual source files via MkDocs snippets,
not copied. This means docs cannot drift from code.

The configuration reference is the most critical user-facing page and is treated
as first-class documentation, not an afterthought.

ADRs live inside the MkDocs structure so they are searchable and linked from
relevant architecture pages.

Troubleshooting page headings match exact error strings that users will Google.

---

## 19. Architecture Decision Records

All ADRs are stored in `docs/adr/` as individual markdown files and are also
navigable via the MkDocs site under Architecture → Decisions.

### ADR Index

| # | Title | Status |
|---|-------|--------|
| 001 | Hybrid Rust/Python Architecture | Accepted |
| 002 | IPC via Unix Domain Sockets | Accepted |
| 003 | TUI MVU (Elm Architecture) Pattern | Accepted |
| 004 | Orchestrator as Single State Authority | Accepted |
| 005 | Explicit State Machine with Transition Guards | Accepted |
| 006 | Degraded Mode as First-Class State | Accepted |
| 007 | Supervisor Restart Policy | Accepted |
| 008 | Handshake and Capability Discovery | Accepted |
| 009 | PyO3 vs Sidecar + Socket | Accepted (sidecar wins) |
| 010 | Command::Async in MVU | Deferred (TUI phase) |
| 011 | IPC Envelope Format | Accepted |
| 012 | Data Plane Checkpointing | Accepted |
| 013 | Configuration Architecture | Accepted |
| 014 | Sidecar Testing Strategy | Accepted |
| 015 | Logging Architecture | Accepted |
| 016 | Graceful Shutdown Sequence | Accepted |
| 017 | First-Run Setup Wizard | Accepted |
| 018 | Centralized Configuration (netguard.toml) | Accepted |

### ADR Template
Each ADR file follows this structure:

```markdown
# ADR XXX: Title

**Status:** Accepted | Deferred | Superseded
**Date:** YYYY-MM-DD

## Context
What problem existed that required a decision?

## Options Considered
What alternatives were evaluated?

## Decision
What was chosen and why?

## Consequences
Positive, negative, and neutral consequences.

## Validation
How will we know this decision was correct?
Measurable criteria where applicable.
```