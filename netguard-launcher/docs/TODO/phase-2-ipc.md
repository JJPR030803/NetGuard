# Phase 2 — IPC + Sidecar (Rust Side)

**Goal:** IPC framing, envelope, supervisor, Rust-side IPC server
**Gate:** Rust IPC roundtrip test passes, supervisor restart test passes
**Prerequisite:** Phase 1 gate passed

> Python sidecar work is tracked separately in the Python project.

---

## IPC Framing (Rust)

- [ ] Length-prefix frame codec (4 bytes big-endian + payload)
- [ ] Max message size enforcement (10MB limit → `IpcError::MessageTooLarge`)
- [ ] Frame read/write over `AsyncRead`/`AsyncWrite`
- [ ] Unit tests with in-memory streams

## IPC Envelope (Rust)

- [ ] `Envelope` struct matching frozen schema
- [ ] Serialization/deserialization (serde_json)
- [ ] Envelope validation (required fields, known types)
- [ ] Action string constants for all 11 defined actions
- [ ] Unit tests for roundtrip serialization

## IPC Server (Rust)

- [ ] Unix Domain Socket binding at `/tmp/netguard_{pid}.sock`
- [ ] Socket permissions set to `0o600` after bind
- [ ] `Drop` impl to clean up socket file
- [ ] Accept + frame read loop
- [ ] Message dispatch to orchestrator
- [ ] Unit tests with real socket pairs

## Health Monitoring (Rust)

- [ ] `BackendState` struct (heartbeat tracking)
- [ ] Heartbeat timeout detection (15s threshold)
- [ ] `SupervisorEvent::Unresponsive` emission
- [ ] Unit tests for timeout detection

## Sidecar Supervisor (Rust)

- [ ] `SidecarSupervisor` struct
- [ ] Process spawn with argument arrays (no shell)
- [ ] Restart policy: 3 restarts in 60s window
- [ ] Exponential backoff: 1s, 2s, 4s
- [ ] Transition to `Fatal` after max retries
- [ ] Unit tests for restart counting and backoff

## Orchestrator Commands (Rust)

- [ ] `OrchestratorCommand` enum (all 11 actions)
- [ ] `handle_command()` dispatch function
- [ ] `OrchestratorHandle` with message channel
- [ ] Integration test: command → envelope → response

## Phase 2 Gate Checklist

- [ ] IPC roundtrip test: Rust sends envelope, reads it back correctly
- [ ] Supervisor restart test: simulated crash triggers restart with backoff
- [ ] All Phase 1 tests still pass
- [ ] Clippy clean
