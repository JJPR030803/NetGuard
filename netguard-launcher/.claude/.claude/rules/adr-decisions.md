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
