#!/usr/bin/env bash
# NetGuard Launcher — Claude Code Context Setup
# Run from the root of your netguard-launcher/ directory:
#   bash setup-claude-context.sh

set -euo pipefail

ROOT="$(pwd)"
CLAUDE_DIR="$ROOT/.claude"
RULES_DIR="$CLAUDE_DIR/rules"
COMMANDS_DIR="$CLAUDE_DIR/commands"

echo "→ Creating .claude/ directory structure in $ROOT"
mkdir -p "$RULES_DIR" "$COMMANDS_DIR"

# ─────────────────────────────────────────────────────────────────────────────
# CLAUDE.md (project root)
# ─────────────────────────────────────────────────────────────────────────────
cat > "$ROOT/CLAUDE.md" << 'CLAUDEMD'
# NetGuard Launcher — Claude Code Context

> **Before doing anything:** Read this file fully. Do not scan the project
> directory unless explicitly asked. Do not edit any file without confirming
> the intent with the user first. When in doubt, ask.

---

## 1. What This Project Is

`netguard-launcher` is the **Rust crate** that orchestrates a hybrid Rust/Python
network security analysis tool, built as a Master's thesis project. Rust owns
orchestration, system lifecycle, CLI, and IPC. Python owns packet capture,
protocol analysis, and ML — and is **not touched here** (see Python Boundary
Rules below).

This is a thesis-quality engineering project. Correctness and architecture
integrity matter more than speed of implementation.

---

## 2. Current Working Context

> **Update this block at the start of every session. Do not skip it.**

```
Phase:            1 — Foundation
Gate status:      Not yet run
Last file worked: —
Active task:      —
Blocked on:       —
```

To refresh this block from project state, run: `/update-context`

---

## 3. Project Layout (What Claude May Read)

Claude Code may freely read these paths:

```
netguard-launcher/
├── src/
│   ├── error.rs
│   ├── lib.rs
│   ├── main.rs
│   ├── orchestrator/      (state.rs, handle.rs, supervisor.rs, environment.rs, commands.rs)
│   ├── cli/               (args.rs, handlers.rs)
│   ├── core/              (models/, operations/, validation.rs)
│   ├── infra/             (ipc/, permissions/, python/, config/, logging/)
│   └── display/
├── tests/
├── benches/
├── Cargo.toml
├── Justfile
├── deny.toml
├── ARCHITECTURE.md        ← authoritative rationale for all decisions
├── IMPLEMENTATION.md      ← how to build each component
└── IMPLEMENTATION_TODO.md ← phase checklists
```

**Do not read unless explicitly asked:**
- `../netguard/` — the existing Python core (off-limits unless user says otherwise)
- `target/` — build artifacts
- `.git/` — git internals
- Any file not listed above

---

## 4. Confirm Before Acting

Claude Code **must confirm with the user before:**

- Creating any new file
- Editing any existing file (state the file path and what will change)
- Adding a new dependency to `Cargo.toml`
- Adding a new state transition to `state.rs`
- Adding a new IPC action (requires `ARCHITECTURE.md` update first)
- Running any command that is not in the approved list below

**Approved commands (no confirmation needed):**
```
cargo check
cargo test
cargo clippy
cargo fmt --check
cargo doc
just check
just test
just lint
just fmt
just doctor
```

---

## 5. Architecture in One Page

```
CLI / TUI  →  OrchestratorHandle  →  Orchestrator  →  SidecarSupervisor
                                           │
                                    SystemState (single source of truth)
                                           │
                                    IPC (Unix Domain Socket, length-prefix + JSON)
                                           │
                                    Python Sidecar (ipc_sidecar.py)
                                           │
                                    Python Core (Scapy, Polars, TensorFlow — UNCHANGED)
```

**The one rule that governs everything:**
Frontends hold only `OrchestratorHandle`. They have no path to the sidecar,
no path to Python, and no path to `SystemState`. All state mutations happen
inside `Orchestrator::transition_to()` only.

---

## 6. Build & Validation Commands

```bash
# Daily development
cargo check                     # fast syntax + type check
cargo test                      # run all unit + integration tests
cargo clippy -- \
  -D warnings \
  -D clippy::unwrap_used \
  -D clippy::expect_used \
  -D clippy::panic              # full lint — must pass clean

# Pre-commit gate (run before every commit)
just check                      # fmt + lint + test

# Phase validation gates
just doctor                     # environment health check
just test                       # Rust + Python (excludes slow/e2e)
just test-all                   # includes slow lifecycle tests
just security                   # cargo audit + bandit + pip-audit

# Python side
uv run pytest tests/ipc/        # sidecar four-layer tests
uv run pytest -m "not slow and not e2e"
```

---

## 7. Phase Status

| Phase | Goal | Gate | Status |
|-------|------|------|--------|
| 1 — Foundation | error.rs, state machine, config, validation, env checker | `cargo test` clean, `just doctor` runs | 🔲 Not started |
| 2 — IPC + Sidecar | IPC framing, envelope, supervisor, Python sidecar | Rust↔Python roundtrip, supervisor restart | 🔲 Not started |
| 3 — CLI | Orchestrator run loop, CLI commands, display, permissions | `netguard capture` produces valid Parquet | 🔲 Not started |
| 4 — Hardening | Property tests, benchmarks, security audit | `just check` + `just security` clean | 🔲 Not started |

**Do not work on Phase N+1 until Phase N gate passes.**

---

## 8. Hard Rules (Enforced by Clippy — Will Break the Build)

These are not style preferences. Violating them will fail CI.

| Rule | Reason |
|------|--------|
| No `unwrap()` in library code | `-D clippy::unwrap_used` |
| No `expect()` in library code | `-D clippy::expect_used` |
| No `panic!()` in library code | `-D clippy::panic` |
| `anyhow` only in `main.rs` and test code | Library code uses typed errors |
| `SystemState` mutated only in `Orchestrator::transition_to()` | Single source of truth |
| `BackendState` mutated only in orchestrator IPC handler | Same principle |
| No shell execution for Python — always argument arrays | Eliminates injection surface |
| All public types must have doc comments | Enforced via `cargo doc` |

**In test code:** `unwrap()` and `expect()` are acceptable.

---

## 9. Thesis & Portfolio Context

This project is a Master's thesis demonstrating:
- Hybrid systems architecture (Rust orchestration + Python ecosystem)
- Bounded failure design (every failure mode has a documented max impact)
- Security-first engineering (least privilege, no shell injection, IPC socket scoped to owner)
- Testability at every layer (no test requires root or real hardware)

**Thesis-quality claims that must be measurable:**
- IPC roundtrip latency < 1ms (via `criterion` benchmarks)
- Max data loss on crash ≤ 10 seconds / 1000 packets (via checkpoint tests)
- Zero unsafe code in first-party Rust (via `cargo geiger`)
- All input validators covered by property tests (via `proptest`)

When implementing anything, ask: *"Can I produce a measurement or test output
that supports one of these claims?"* If yes, do it that way.

---

## 10. Further Reading (Load Only When Needed)

| File | When to read it |
|------|----------------|
| `.claude/rules/error-handling.md` | Before touching `error.rs` or adding error variants |
| `.claude/rules/state-machine.md` | Before touching `state.rs` or adding transitions |
| `.claude/rules/ipc-protocol.md` | Before any IPC work (framing, envelope, supervisor) |
| `.claude/rules/python-boundary.md` | Any time Python files come up |
| `.claude/rules/adr-decisions.md` | Before suggesting any architectural alternative |

---

*ARCHITECTURE.md is the authoritative source for all architectural decisions.
When this file and ARCHITECTURE.md conflict, ARCHITECTURE.md wins.*
CLAUDEMD

echo "  ✓ CLAUDE.md"

# ─────────────────────────────────────────────────────────────────────────────
# .claude/settings.json
# ─────────────────────────────────────────────────────────────────────────────
cat > "$CLAUDE_DIR/settings.json" << 'SETTINGS'
{
  "permissions": {
    "allow": [
      "Bash(cargo check*)",
      "Bash(cargo test*)",
      "Bash(cargo clippy*)",
      "Bash(cargo fmt*)",
      "Bash(cargo doc*)",
      "Bash(cargo build*)",
      "Bash(just check*)",
      "Bash(just test*)",
      "Bash(just lint*)",
      "Bash(just fmt*)",
      "Bash(just doctor*)",
      "Bash(just bench*)",
      "Bash(uv run pytest*)",
      "Bash(uv run mypy*)",
      "Bash(uv run ruff*)",
      "Bash(git status*)",
      "Bash(git log*)",
      "Bash(git diff*)"
    ],
    "deny": [
      "Bash(sudo*)",
      "Bash(rm -rf*)",
      "Bash(setcap*)",
      "Bash(pip install*)",
      "Bash(cargo install*)"
    ]
  }
}
SETTINGS

echo "  ✓ .claude/settings.json"

# ─────────────────────────────────────────────────────────────────────────────
# .claude/rules/error-handling.md
# ─────────────────────────────────────────────────────────────────────────────
cat > "$RULES_DIR/error-handling.md" << 'EOF'
# Rule: Error Handling

> Load this file when working on `error.rs`, adding error variants, or
> writing any code that handles or propagates errors.

---

## Error Hierarchy

```
Error (top-level, in error.rs)
├── Ipc(IpcError)
├── Config(ConfigError)
├── Permission(PermissionError)
├── Validation(ValidationError)
└── Python(PythonError)
```

Every variant of every sub-enum must implement all four methods below.
Do not add a variant without implementing all four.

---

## Required Methods on Every Error Variant

```rust
// What the user sees — no Rust jargon, no technical internals
fn user_message(&self) -> String;

// What the user should do — None is acceptable if no action exists
fn suggestion(&self) -> Option<String>;

// How serious is this?
fn severity(&self) -> Severity;  // Critical | High | Medium | Low

// Can the system continue, or must it stop?
fn recoverable(&self) -> bool;
```

---

## Correct Pattern vs Wrong Pattern

### Converting Option to Result

```rust
// ✅ CORRECT
let value = some_option
    .ok_or_else(|| Error::Config(ConfigError::MissingField("interface")))?;

// ❌ WRONG — breaks the build
let value = some_option.unwrap();

// ❌ WRONG — anyhow not allowed in library code
let value = some_option.context("missing field")?;
```

### Propagating Across Layer Boundaries

```rust
// ✅ CORRECT — convert at the boundary with map_err
fn orchestrator_thing() -> Result<(), Error> {
    infra_thing().map_err(|e| Error::Ipc(IpcError::from(e)))?;
    Ok(())
}

// ❌ WRONG — leaks internal error type through layer
fn orchestrator_thing() -> Result<(), infra::Error> { ... }
```

### Error Messages

```rust
// ✅ CORRECT — actionable, no Rust jargon
fn user_message(&self) -> String {
    match self {
        Self::SocketPermissions { path } =>
            format!("Cannot access IPC socket at {}. Check file permissions.", path),
        Self::MaxRetriesExceeded =>
            "Python sidecar failed to restart after 3 attempts.".to_string(),
    }
}

fn suggestion(&self) -> Option<String> {
    match self {
        Self::SocketPermissions { .. } =>
            Some("Run `just setup` to recreate the socket with correct permissions.".to_string()),
        Self::MaxRetriesExceeded =>
            Some("Check logs with `netguard doctor` for the root cause.".to_string()),
    }
}

// ❌ WRONG — raw Rust error, no fix guidance
fn user_message(&self) -> String {
    format!("Os error: {}", self.inner)
}
```

---

## Severity Guide

| Situation | Severity | Recoverable |
|-----------|----------|-------------|
| Sidecar crashed, supervisor restarting | High | true |
| Capabilities missing (capture disabled) | Medium | true |
| Config file missing a field (using default) | Low | true |
| Version mismatch between Rust and Python | Critical | false |
| Socket could not be created | High | false |
| Invalid user input (bad interface name) | Low | true |

---

## Testing Error Variants

Every new error variant needs a unit test that verifies:
1. `user_message()` returns a non-empty, readable string
2. `suggestion()` returns `Some(...)` for errors where a fix exists
3. `recoverable()` matches the expected value

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn given_socket_permissions_error_then_message_is_actionable() {
        let err = IpcError::SocketPermissions { path: "/tmp/test.sock".into() };
        assert!(!err.user_message().is_empty());
        assert!(err.suggestion().is_some());
        assert!(!err.recoverable());
    }
}
```
EOF

echo "  ✓ .claude/rules/error-handling.md"

# ─────────────────────────────────────────────────────────────────────────────
# .claude/rules/state-machine.md
# ─────────────────────────────────────────────────────────────────────────────
cat > "$RULES_DIR/state-machine.md" << 'EOF'
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
EOF

echo "  ✓ .claude/rules/state-machine.md"

# ─────────────────────────────────────────────────────────────────────────────
# .claude/rules/ipc-protocol.md
# ─────────────────────────────────────────────────────────────────────────────
cat > "$RULES_DIR/ipc-protocol.md" << 'EOF'
# Rule: IPC Protocol

> Load this file before any work on `infra/ipc/`, `orchestrator/supervisor.rs`,
> or anything involving the Rust↔Python communication layer.

---

## The IPC Stack (Bottom Up)

```
JSON payload (action-specific schema)
    ↑
Envelope (frozen schema — never add fields)
    ↑
Length-prefix framing (4 bytes big-endian + payload bytes)
    ↑
Unix Domain Socket (/tmp/netguard_{pid}.sock, mode 0o600)
```

---

## Envelope Schema (Frozen — Do Not Add Fields)

```json
{
  "id":        "uuid-v4 — generated by sender, preserved in response",
  "version":   1,
  "type":      "REQUEST | RESPONSE | EVENT | HEARTBEAT | HANDSHAKE",
  "action":    "string — specific operation, e.g. START_CAPTURE",
  "timestamp": 1234567890123,
  "payload":   {},
  "metadata":  {},
  "status":    "OK | ERROR | PARTIAL | REJECTED (RESPONSE only)",
  "error":     null
}
```

**The envelope format is frozen.** New functionality = new `action` string
and payload schema. Never add a field to the envelope itself.

New actions must be added to `ARCHITECTURE.md` Section 9 table **before**
writing any code. Confirm this step with the user.

---

## Framing Protocol

```
┌──────────────┬──────────────────────────────┐
│  Length      │  JSON Payload                │
│  4 bytes     │  `length` bytes              │
│  big-endian  │  UTF-8 encoded               │
└──────────────┴──────────────────────────────┘
```

- Receiver reads exactly 4 bytes → gets length
- Receiver reads exactly `length` bytes → gets payload
- Max message size: **10MB** — reject anything larger with `IpcError::MessageTooLarge`

---

## Socket Security

```rust
// After binding, immediately set permissions
std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
```

Socket path: `/tmp/netguard_{pid}.sock` — PID-namespaced.
`IpcServer` implements `Drop` to remove the socket file on shutdown.

---

## Defined Actions (Current)

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
| LOG | Python→Rust | EVENT | Python log forwarding |
| HEARTBEAT | Python→Rust | HEARTBEAT | Liveness signal every 5s |

---

## Heartbeat Protocol

- Python sends `HEARTBEAT` every **5 seconds**
- Supervisor checks `last_heartbeat` every **5 seconds**
- If gap > **15 seconds** → emit `SupervisorEvent::Unresponsive` → restart

---

## Supervisor Restart Policy

- Max restarts: **3** within a **60-second** window
- Backoff: exponential (1s, 2s, 4s)
- After max retries: `SystemState::Fatal`

---

## Control Plane vs Data Plane

**IPC socket = control plane only.** Commands, responses, status, heartbeats, logs.

**Data plane = files.** Python writes Parquet to disk. Rust reads Parquet when
the user requests analysis. Packet data **never** flows through the IPC socket.

This is an architectural invariant — do not break it.

---

## How to Add a New IPC Action

1. Add to `ARCHITECTURE.md` Section 9 table — confirm with user first
2. Define the payload schema as a doc comment
3. Add `OrchestratorCommand` variant in `commands.rs`
4. Add dispatch case in orchestrator's `handle_command()`
5. Add handler branch in Python `ipc_sidecar.py handle_message()`
6. Write Layer 3 (core translation) test before implementing the handler
7. Implement until test passes
EOF

echo "  ✓ .claude/rules/ipc-protocol.md"

# ─────────────────────────────────────────────────────────────────────────────
# .claude/rules/python-boundary.md
# ─────────────────────────────────────────────────────────────────────────────
cat > "$RULES_DIR/python-boundary.md" << 'EOF'
# Rule: Python Boundary

> Load this file any time Python files are mentioned, before suggesting any
> changes to the Python side, or when debugging involves the sidecar.

---

## The Fundamental Boundary

```
netguard-launcher/src/                        ← Rust crate (always fair game)
netguard/src/netguard/ipc/                    ← New IPC layer (Phase 2+)
netguard/src/netguard/ipc_sidecar.py          ← New sidecar (Phase 2+)
netguard/src/netguard/capture/checkpointed_writer.py  ← New (Phase 2+)
══════════════════════════════════════════════════════════════════
DO NOT TOUCH without explicit user instruction:
netguard/src/netguard/workflows/
netguard/src/netguard/capture/   (except checkpointed_writer.py)
netguard/src/netguard/analysis/
netguard/src/netguard/api.py
```

---

## What "Do Not Touch" Means

- Do not read these files to answer a question unless the user asks
- Do not suggest changes to these files
- Do not reference them in new sidecar code beyond what already exists
- Do not refactor them even if you see obvious improvements

The Python core is **unchanged by design**. The sidecar adapts to it.

---

## The Sidecar's One Job

```python
# ✅ CORRECT — thin translation only
def _handle_start_capture(self, payload: dict) -> dict:
    config = CaptureConfig(
        interface=payload["interface"],
        duration=payload.get("duration"),
        bpf_filter=payload.get("filter"),
    )
    result = self.capture_manager.start(config)
    return {"status": "started", "session_id": result.session_id}

# ❌ WRONG — sidecar contains logic it shouldn't own
def _handle_start_capture(self, payload: dict) -> dict:
    if payload["duration"] > 3600:   # validation belongs in Rust
        raise ValueError("too long")
```

---

## Python Files Claude May Write (Phase 2 Only)

| File | Purpose |
|------|---------|
| `netguard/src/netguard/ipc/framing.py` | `FramedSocket` |
| `netguard/src/netguard/ipc/envelope.py` | Envelope helpers |
| `netguard/src/netguard/ipc_sidecar.py` | `IpcSidecar` class |
| `netguard/src/netguard/capture/checkpointed_writer.py` | `CheckpointedParquetWriter` |

Do not create these files during Phase 1.

---

## Python Code Standards (New Files Only)

- `from __future__ import annotations` at the top of every file
- Module-level docstring
- Full type annotations on all function signatures
- Google-style docstrings on public functions
- No `print()` — `logging` module only
- No bare `except:` — always `except Exception:`
- Passes `mypy --strict`

---

## Sidecar Error Contract

On any Python core exception:
- Log full traceback to stderr
- Return `ERROR` response with `recoverable: true`
- **Continue processing the next command**
- The sidecar must never crash due to a Python core error

---

## Sidecar Test Layers

| Layer | What it tests | What is mocked |
|-------|--------------|----------------|
| 1 — Socket Mechanics | `FramedSocket` framing | Nothing — real socket pairs |
| 2 — Dispatch | `handle_message()` routing | All Python core dependencies |
| 3 — Core Translation | Payload → correct function args | Python core return values |
| 4 — Lifecycle | Startup, shutdown, signals | Threading, real socket |

No layer requires root, a real network interface, or a live capture.
EOF

echo "  ✓ .claude/rules/python-boundary.md"

# ─────────────────────────────────────────────────────────────────────────────
# .claude/rules/adr-decisions.md
# ─────────────────────────────────────────────────────────────────────────────
cat > "$RULES_DIR/adr-decisions.md" << 'EOF'
# Rule: Architecture Decision Records

> Load this file before suggesting any architectural alternative, or when
> a question arises about "why does it work this way."
>
> Every decision below was made deliberately. Do not re-open these decisions
> unless the user explicitly asks to revisit one.

---

## The 18 ADRs — What Was Decided and What Was Rejected

### ADR 001 — Hybrid Rust/Python Architecture
**Decided:** Rust owns orchestration. Python owns capture + analysis + ML.
**Why not pure Rust:** Python's ecosystem (Scapy, Polars, TensorFlow) is irreplaceable.
**Why not pure Python:** Rust's safety guarantees are needed for orchestration.

### ADR 002 — IPC via Unix Domain Sockets
**Decided:** Unix Domain Sockets with length-prefix framing.
**Rejected:** TCP (network stack overhead), pipes (unidirectional), shared memory (unsafe).

### ADR 003 — TUI MVU (Elm Architecture)
**Decided:** Model-Update-View pattern for the TUI.
**Deferred:** Async concurrency in MVU (ADR 010) — TUI not started yet.

### ADR 004 — Orchestrator as Single State Authority
**Decided:** Only the Orchestrator holds and mutates SystemState.
**Rejected:** Distributed state — race conditions, impossible invariants.

### ADR 005 — Explicit State Machine with Transition Guards
**Decided:** `can_transition_to()` validates every transition. Invalid = programmer error, blocked + logged.
**Rejected:** Implicit state — implicit bugs are the hardest to debug in async systems.

### ADR 006 — Degraded Mode as First-Class State
**Decided:** `Degraded` is a valid operational state, not a fallback error handler.
**Why:** System is genuinely useful for analysis without capture capabilities.

### ADR 007 — Supervisor Restart Policy
**Decided:** 3 restarts in 60 seconds, exponential backoff (1s, 2s, 4s), then Fatal.

### ADR 008 — Handshake and Capability Discovery
**Decided:** Sidecar waits for HANDSHAKE before processing any commands.
Python reports version and available workflows in the handshake response.

### ADR 009 — PyO3 vs Sidecar + Socket
**Decided:** Sidecar + UDS. **PyO3 was explicitly rejected.**
**Why PyO3 was rejected:**
1. GIL conflicts with Tokio — 60-second captures would block worker threads
2. Python segfault kills entire process with PyO3; sidecar = isolated crash
3. Supervisor can restart a dead process; cannot restart a dead thread
4. Process isolation enables independent versioning

**Do not suggest PyO3** unless the user explicitly asks to revisit ADR 009.

### ADR 010 — Command::Async in MVU
**Status: DEFERRED** — Not resolved. TUI not started. Do not implement TUI concurrency.

### ADR 011 — IPC Envelope Format
**Decided:** Envelope schema is frozen. New functionality = new action strings only.
**Do not add fields to the envelope.**

### ADR 012 — Data Plane Checkpointing
**Decided:** Row group checkpointing. Triggers: 1000 packets OR 10 seconds.
**Why:** Parquet requires footer write. Without checkpointing, a crash loses everything.
Max data loss bound: 1000 packets or 10 seconds.

### ADR 013 — Configuration Architecture
**Decided:** Single `netguard.toml`. Priority: CLI args > toml > `UserPreferences::default()`.
**No YAML anywhere.** The original YAML generation was removed. Do not reintroduce it.

### ADR 014 — Sidecar Testing Strategy
**Decided:** Four independent test layers (see python-boundary.md).

### ADR 015 — Logging Architecture
**Decided:** Python owns log formatting. Rust owns log routing via IPC LOG events.
Unified single log stream from both sides.

### ADR 016 — Graceful Shutdown Sequence
**Decided:** Deterministic 10-second bounded shutdown.
SIGTERM → emergency_finalize → EMERGENCY_CHECKPOINT event → socket cleanup → exit.

### ADR 017 — First-Run Setup Wizard
**Decided:** TUI wizard triggered by missing `netguard.toml`. Modeled on `bun init`.
Never destructive without explicit user confirmation.

### ADR 018 — Centralized Configuration
**Decided:** All persistent preferences in `~/.config/netguard/netguard.toml`.
All defaults in `UserPreferences::default()` only — never scattered.

---

## Quick Decision Lookup

| If someone suggests... | The answer is... |
|------------------------|-----------------|
| "Use PyO3 instead of the sidecar" | Rejected in ADR 009. Crash containment + GIL. |
| "Store config in YAML" | Rejected in ADR 013. netguard.toml only. |
| "Add a field to the IPC envelope" | Not allowed (ADR 011). Add a new action instead. |
| "Let the CLI talk to Python directly" | Violates ADR 004. Everything through OrchestratorHandle. |
| "Use TCP sockets instead of UDS" | Rejected in ADR 002. UDS is faster and securable. |
| "Raise an exception on invalid state transition" | Wrong. Block + log programmer error (ADR 005). |
| "Implement TUI now" | Deferred — ADR 010 unresolved. Do CLI first. |
EOF

echo "  ✓ .claude/rules/adr-decisions.md"

# ─────────────────────────────────────────────────────────────────────────────
# .claude/commands/new-feature.md
# ─────────────────────────────────────────────────────────────────────────────
cat > "$COMMANDS_DIR/new-feature.md" << 'EOF'
# New Feature / Phase Work

Before writing a single line of code, complete all steps in order.
Confirm with the user before proceeding past Step 3.

## Step 1 — Load Context

Read silently:
- `CLAUDE.md` → check the "Current Working Context" block
- `IMPLEMENTATION_TODO.md` → find the current phase checklist
- `IMPLEMENTATION.md` → find the relevant "How to..." section

Report: current phase, which checklist item this maps to, any prerequisites.

## Step 2 — Check Architecture Constraints

Read `.claude/rules/adr-decisions.md`.

Identify which ADRs govern this area. Then load additional rule files as needed:
- Touches Python? → `.claude/rules/python-boundary.md`
- Adds a state transition? → `.claude/rules/state-machine.md`
- Touches IPC? → `.claude/rules/ipc-protocol.md`
- Adds error variants? → `.claude/rules/error-handling.md`

Report any constraints the implementation must respect.

## Step 3 — Write the Implementation Plan

Produce a numbered plan listing:
1. Every file that will be created or modified (full path)
2. One sentence per file describing the change
3. Which tests need to be written
4. Expected outcome of `cargo test` after completion

**Stop here. Confirm the plan with the user before writing any code.**

## Step 4 — Implement (After Confirmation)

For each file:
1. State: "I will now create/edit [file]. Confirming..."
2. Wait for confirmation
3. Make the change
4. Run `cargo check`
5. Move to the next file

Do not combine multiple file changes into one step.

## Step 5 — Write Tests

1. Write unit tests in `#[cfg(test)]` block
2. Write integration tests if cross-module behavior is involved
3. Run `cargo test` and report results
4. Fix failures before marking complete

## Step 6 — Update Context

After everything passes, run `/update-context` to refresh `CLAUDE.md`.
EOF

echo "  ✓ .claude/commands/new-feature.md"

# ─────────────────────────────────────────────────────────────────────────────
# .claude/commands/write-tests.md
# ─────────────────────────────────────────────────────────────────────────────
cat > "$COMMANDS_DIR/write-tests.md" << 'EOF'
# Write Tests

Follow this process. Confirm with the user before creating any test file.

## Step 1 — Identify Scope

Read the relevant source file. Determine:
- Module being tested
- Unit / integration / property test?
- Extending existing tests or new file?

## Step 2 — Load Relevant Rules

- Testing `state.rs` → `.claude/rules/state-machine.md`
- Testing error variants → `.claude/rules/error-handling.md`
- Testing IPC → `.claude/rules/ipc-protocol.md`
- Testing anything Python-adjacent → `.claude/rules/python-boundary.md`

## Step 3 — Plan the Tests

**Unit tests:** Name (pattern: `given_{context}_when_{action}_then_{result}`),
what property it verifies, what it does NOT test.

**Integration tests:** What real components are involved, what is mocked and why,
what the observable outcome must be.

**Property tests:** Confirm the three required properties:
1. Never panics on arbitrary input
2. Deterministic
3. Correct (valid accepted, invalid rejected)

**Confirm the plan with the user before writing any code.**

## Step 4 — Write Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // One comment explaining WHY this test exists.
    #[test]
    fn given_ready_state_when_start_capture_then_transition_allowed() {
        let state = SystemState::Ready;
        assert!(state.can_transition_to(&SystemState::Operating {
            operation: ActiveOperation::Capture,
        }));
    }
}
```

Rules:
- Use `result.unwrap()` in tests, not `assert!(result.is_ok())`
- Test naming: `given_{context}_when_{action}_then_{result}`
- Never leave `todo!()` inside a test

## Step 5 — Run and Report

```bash
cargo test [module_name]
```

Report: how many pass, any failures with full output.

## Step 6 — Coverage Check

Verify: happy path, sad path, edge cases, adjacent invalid state transitions.
Ask the user whether uncovered scenarios should be added now or deferred.
EOF

echo "  ✓ .claude/commands/write-tests.md"

# ─────────────────────────────────────────────────────────────────────────────
# .claude/commands/phase-gate.md
# ─────────────────────────────────────────────────────────────────────────────
cat > "$COMMANDS_DIR/phase-gate.md" << 'EOF'
# Phase Validation Gate

Run the gate for the current phase and report results.
Do not fix anything automatically — report only, then ask.

## Step 1 — Determine Current Phase

Read "Phase Status" table and "Current Working Context" in `CLAUDE.md`.

## Step 2 — Run Gate Commands

### Gate 1 (Phase 1)
```bash
cargo test
cargo clippy -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
cargo fmt --check
cargo run -- doctor
```

### Gate 2 (Phase 2)
```bash
cargo test
cargo test --test ipc
uv run pytest tests/ipc/ -v
```
Note: "Kill Python sidecar mid-run and verify supervisor restarts — manual verification required."

### Gate 3 (Phase 3)
```bash
cargo test
just check
netguard interfaces
netguard doctor
```
Note: "Manual check: `netguard capture --interface lo --duration 5 --output /tmp/test.parquet`"

### Gate 4 (Phase 4)
```bash
just check
just security
just test-fuzz
just bench
```

## Step 3 — Report Results

For each command:
- ✅ PASS — with output summary
- ❌ FAIL — with full error output, nothing truncated
- ⏭ SKIP — with reason

## Step 4 — Gate Summary

```
Gate [N] Status: PASS / FAIL / PARTIAL

Passing:  [list]
Failing:  [list with short description]
Blocked:  [anything that couldn't run and why]

Next step: [one sentence — what to address first]
```

Do not automatically fix anything.
EOF

echo "  ✓ .claude/commands/phase-gate.md"

# ─────────────────────────────────────────────────────────────────────────────
# .claude/commands/update-context.md
# ─────────────────────────────────────────────────────────────────────────────
cat > "$COMMANDS_DIR/update-context.md" << 'EOF'
# Update Working Context

Refresh the "Current Working Context" block in `CLAUDE.md`.
Confirm the proposed update with the user before writing.

## Step 1 — Gather State

Run silently:
```bash
cargo check 2>&1 | tail -5
cargo test 2>&1 | tail -10
git status --short 2>/dev/null | head -10
git log --oneline -3 2>/dev/null
```

Read `IMPLEMENTATION_TODO.md` to find current phase and checked-off items.

## Step 2 — Determine Each Field

**Phase:** Current phase number and name
**Gate status:** "Not yet run" / "PASS — [note]" / "FAIL — [what]" / "PARTIAL — [detail]"
**Last file worked:** Most recently modified source file (from git status or conversation)
**Active task:** One sentence on what is currently being worked on
**Blocked on:** Any known blocker, or "—"

## Step 3 — Propose Update

Present the proposed block:
```
Phase:            [value]
Gate status:      [value]
Last file worked: [value]
Active task:      [value]
Blocked on:       [value]
```

Ask: "Should I update the Current Working Context block in CLAUDE.md with this?"

## Step 4 — Write (After Confirmation)

Update only the "Current Working Context" block in `CLAUDE.md`.
Do not change any other part of the file.
Confirm the write and show the final block.
EOF

echo "  ✓ .claude/commands/update-context.md"

# ─────────────────────────────────────────────────────────────────────────────
# Done
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "✅ Done. Files created:"
find "$CLAUDE_DIR" "$ROOT/CLAUDE.md" -type f | sort | sed 's|'"$ROOT"'/||'
echo ""
echo "Next steps:"
echo "  1. Open Claude Code in this directory: claude"
echo "  2. On first session, run: /update-context"
echo "  3. To start Phase 1 work, run: /new-feature"
echo "  4. To run the current gate, run: /phase-gate"