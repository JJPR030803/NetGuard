# NetGuard Launcher — Implementation TODO
**Date:** March 2026
**Status:** Phase 1 in progress (~40% complete)

This document defines the phases for building the `netguard-launcher` Rust crate
from its current scaffold state into a working MVP. Each phase has a clear start
condition, deliverables, and a validation gate that must pass before the next
phase begins.

The phases are **strictly sequential**. Do not begin a phase until the previous
gate passes. A working foundation is worth more than half-working features.

---

## Current State

The error handling system and state machine are complete. 96 unit tests passing.
Configuration, validation, and environment checker remain to be built.
The existing Python core (Scapy, Polars, TensorFlow, workflows) is unchanged
and working independently.

**Completed:**
- Full error hierarchy (8 domain error modules, all with 4 required methods)
- `SystemState` enum (8 variants with structured data), `ActiveOperation`,
  `DegradedReason`, `can_transition_to()`, `allowed_commands()`, `Display` impl
- 96 unit tests, all passing

**Remaining in Phase 1:**
- Configuration system (`UserPreferences`, TOML read/write)
- Validation layer (input validators)
- Environment checker (pre-flight checks)
- `main.rs` panic hook + minimal CLI wiring

---

## Phase 1 — Foundation (Error Types, State Machine, Config, Validation)

**Start condition:** Scaffold compiles (`cargo check` passes).

**What to build:**
1. `error.rs` — Full error hierarchy (`Error`, `IpcError`, `ConfigError`,
   `PermissionError`, `ValidationError`, `PythonError`) with `user_message()`,
   `suggestion()`, `severity()`, and `recoverable()` on every variant.
2. `orchestrator/state.rs` — `SystemState` enum, `DegradedReason`,
   `ActiveOperation`, transition guard (`can_transition_to`), and
   `allowed_commands()` per state.
3. `infra/config/mod.rs` — `UserPreferences` struct with `default()`,
   `ConfigManager` with `read()`, `write()`, and `migrate()` for
   `netguard.toml`.
4. `orchestrator/environment.rs` — `EnvironmentChecker` with all prerequisite
   checks (Python version, venv, deps, capture capabilities, socket, output dir).
5. `core/validation.rs` — Input validators for interface names, durations,
   BPF filters, output paths, IP addresses. Whitelist-only approach.
6. `main.rs` — Panic hook that restores terminal state on crash.

**Validation gate:**
- `cargo test` — zero failures
- `cargo clippy -- -D warnings -D clippy::unwrap_used -D clippy::expect_used` — zero errors
- `cargo fmt --check` — clean
- `cargo run -- doctor` — runs and produces structured output (even if checks fail)

---

## Phase 2 — IPC + Sidecar (Framing, Envelope, Supervisor, Python Sidecar)

**Start condition:** Phase 1 gate passes.

**What to build:**
1. `infra/ipc/server.rs` — `IpcServer` with Unix Domain Socket creation
   (`/tmp/netguard_{pid}.sock`, mode `0o600`), `accept()`, `Drop` cleanup.
2. `infra/ipc/envelope.rs` — `Envelope` struct matching the frozen schema
   (id, version, type, action, timestamp, payload, metadata, status, error).
   Constructors: `request()`, `respond_to()`, `error_response()`, `heartbeat()`,
   `event()`.
3. `infra/ipc/` — `FramedWriter`/`FramedReader` with 4-byte big-endian
   length-prefix framing, 10MB max message size.
4. `orchestrator/supervisor.rs` — `SidecarSupervisor` with `spawn()`, `kill()`,
   `perform_handshake()`, `attempt_restart()` (bounded: 3 restarts in 60s with
   exponential backoff), heartbeat monitoring (15s timeout).
5. `infra/ipc/health.rs` — Heartbeat tracking, `BackendState` updates.
6. **Python side:** `src/netguard/ipc/framing.py` (`FramedSocket`),
   `src/netguard/ipc/envelope.py` (envelope helpers),
   `src/netguard/ipc_sidecar.py` (`IpcSidecar` class with `run()`,
   `handle_message()`, signal handler, heartbeat thread).
7. **Python side:** `src/netguard/capture/checkpointed_writer.py` —
   `CheckpointedParquetWriter` with dual triggers (1000 packets / 10 seconds),
   `emergency_finalize()`, thread-safe buffer.
8. Python sidecar tests — all four layers (socket mechanics, dispatch, core
   translation, lifecycle).

**Validation gate:**
- Rust <-> Python roundtrip test passes on a real socket
- Handshake succeeds and `BackendState` is populated
- Kill Python sidecar mid-run, verify supervisor auto-restarts
- `uv run pytest tests/ipc/` — all four sidecar test layers pass

---

## Phase 3 — CLI (Orchestrator Run Loop, Commands, Display, Permissions)

**Start condition:** Phase 2 gate passes.

**What to build:**
1. `orchestrator/mod.rs` — `Orchestrator` struct with `run()` loop
   (`tokio::select!` over command_rx, sidecar messages, supervisor events,
   shutdown signal). All state mutations happen here only.
2. `orchestrator/handle.rs` — `OrchestratorHandle` (command sender + state
   broadcast receiver). This is the complete API surface for all frontends.
3. `orchestrator/commands.rs` — `OrchestratorCommand` enum, command validation
   against `allowed_commands()` before dispatch.
4. `cli/args.rs` — Clap `Commands` enum: `capture`, `interfaces`, `workflow`,
   `analyze`, `doctor`, `setup`. Global flags: `-v`, `-q`, `--config`.
5. `cli/handler.rs` — One handler per subcommand, talks only through
   `OrchestratorHandle`.
6. `display/` — Terminal output: tables (interfaces, stats, workflow results),
   progress bar (live capture), terminal sanitization (strip control chars from
   packet-derived strings).
7. `infra/permissions/` — Platform-specific capability checks
   (`cap_net_raw`/`cap_net_admin` on Linux, `access_bpf` on macOS, Npcap on
   Windows).
8. First-run setup wizard — detect missing `netguard.toml`, guided TUI
   walkthrough (env checks, preference prompts, write config).

**Validation gate:**
- `netguard interfaces` lists real network interfaces
- `netguard doctor` shows correct pass/fail for current environment
- `netguard capture --interface lo --duration 5 --output /tmp/test.parquet`
  produces a valid, Polars-readable Parquet file
- `netguard workflow daily-audit --file capture.parquet` produces a report
- All CLI integration tests pass

---

## Phase 4 — Hardening + MVP (Property Tests, Benchmarks, Security Audit)

**Start condition:** Phase 3 gate passes.

**What to build:**
1. Property tests (proptest) — Every validator never panics on arbitrary input,
   deterministic, correct. Envelope serde roundtrip. Config TOML roundtrip.
2. Benchmarks (criterion) — IPC roundtrip latency (<1ms target), envelope
   serialize/deserialize throughput, checkpoint write throughput.
3. Security audit — `cargo audit`, `cargo deny check`, `cargo geiger`,
   `bandit`, `pip-audit`. Zero unaddressed findings.
4. Documentation — Doc comments on all Rust public types, Google-style
   docstrings on all Python public functions, all 18 ADR files written.
5. End-to-end validation — Fresh machine: `just setup` -> capture -> workflow ->
   doctor, all work. Supervisor restart mid-capture verified.

**Validation gate (MVP complete):**
- `just check` (fmt + lint + test) — zero failures, zero warnings
- `just security` — zero unaddressed findings
- `just test-fuzz` — property tests pass
- `just bench` — results documented for thesis
- End-to-end on clean machine works

---

## Phase Dependency Map

```
Phase 1: Foundation
    │
    │  error.rs, state.rs, config, validation, environment checker
    │  These are the types everything else depends on.
    │
    ▼
Phase 2: IPC + Sidecar
    │
    │  Can only be built once error types and state machine exist.
    │  The supervisor uses SystemState transitions.
    │  The envelope uses the error hierarchy.
    │
    ▼
Phase 3: CLI
    │
    │  Can only be built once the orchestrator can talk to Python.
    │  The CLI handlers send commands through OrchestratorHandle.
    │  Display renders SystemSnapshot which comes from the orchestrator.
    │
    ▼
Phase 4: Hardening
    │
    │  Can only be done once features are complete.
    │  Property tests verify validators that already exist.
    │  Benchmarks measure IPC that already works.
    │  Security audit covers the final dependency set.
    │
    ▼
[MVP Complete] ──── Post-MVP: TUI (Ratatui + MVU), Web Interface, Plugins
```

---

## Post-MVP Phases (Not Scheduled)

These are documented in `docs/project-notes/TODO.md` and should not be started
until the MVP validation gate passes.

- **TUI Implementation** — Ratatui + MVU, requires resolving ADR 010
  (async concurrency in MVU) first.
- **Windows Named Pipes** — Replace stdio fallback with proper Named Pipe IPC.
- **Plugin System** — Third-party workflow discovery via plugin directory.
- **FastAPI Web Interface** — Web frontend using existing Python REST layer.
- **Prometheus Metrics** — Observability endpoint for thesis demo.
- **LaTeX Thesis Paper** — Extract narrative from MkDocs into academic format.
